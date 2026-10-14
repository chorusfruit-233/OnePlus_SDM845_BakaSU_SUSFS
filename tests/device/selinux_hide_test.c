/* Device-only, unprivileged SELinux regression probes. No policy mutation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SELINUXFS "/sys/fs/selinux"
#define TEXT_SIZE 1024
#define MAX_SAMPLES 2048
#define MAX_OUTCOMES 16
#define WARMUP 8

struct status_page {
	uint32_t version, sequence, enforcing, policyload, deny_unknown;
};

struct result {
	int stage, error, failure;
	long rc;
	uint64_t elapsed;
	char response[TEXT_SIZE];
};

struct outcome {
	struct result result;
	unsigned int count;
	uint64_t times[MAX_SAMPLES];
};

enum { ST_OPEN, ST_WRITE, ST_READ, ST_MMAP, ST_DONE, ST_INTERNAL, ST_PREREQUISITE };
enum { PROC_SELF, PROC_INVALID, PROC_KSU, PROC_PARENT, CTX_SELF, CTX_INVALID, CTX_KSU,
	AV_SELF, AV_INVALID, AV_KSU, STATUS, PROBE_COUNT };
static const char *const names[] = {
	"setprocattr.self", "setprocattr.invalid", "setprocattr.ksu", "setprocattr.parent",
	"context.self", "context.invalid", "context.ksu",
	"access.self", "access.invalid", "access.ksu", "status.read_mmap"
};
static const char *const stages[] = {
	"open", "write", "read", "mmap", "done", "internal", "prerequisite"
};
static const char invalid_context[] = "u:r:susfs_test_missing_4e9066aa:s0";
static const char ksu_context[] = "u:r:ksu:s0";
static char self_context[TEXT_SIZE];
static unsigned int process_class;
static int class_index_error;

static void usage(FILE *stream)
{
	fputs("Usage: selinux_hide_test --device [--samples 16..2048] [--label NAME]\n"
	      "       selinux_hide_test --help\n\n"
	      "Run from a real Android untrusted_app UID/domain with SELinux Enforcing.\n"
	      "Never use su or merely change a root shell's numeric UID.\n"
	      "Only fixed query/rejection probes are available; no arbitrary context option.\n"
	      "Outputs JSONL semantics and repeated syscall timings (no timing pass threshold).\n"
	      "--help does not inspect SELinux. No arguments print this help.\n", stream);
}

static uint64_t now_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) {
		perror("clock_gettime");
		exit(2);
	}
	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static void json_string(const char *s)
{
	putchar('"');
	for (; *s; ++s) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\')
			printf("\\%c", c);
		else if (c < 32)
			printf("\\u%04x", c);
		else
			putchar(c);
	}
	putchar('"');
}

static ssize_t read_text(const char *path, char *out, size_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = read(fd, out, size - 1);
	int saved = errno;
	close(fd);
	errno = saved;
	if (n >= 0) {
		out[n] = 0;
		while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\0'))
			out[--n] = 0;
	}
	return n;
}

static int transfer(int fd, void *buf, size_t len, int sending)
{
	size_t done = 0;
	while (done < len) {
		ssize_t n = sending ? write(fd, (char *)buf + done, len - done)
			: read(fd, (char *)buf + done, len - done);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

static int timed_open(const char *path, int flags, struct result *r)
{
	uint64_t start = now_ns();
	int fd = open(path, flags | O_CLOEXEC);
	int saved = fd < 0 ? errno : 0;
	r->elapsed = now_ns() - start;
	r->stage = ST_OPEN;
	r->rc = fd < 0 ? -1 : 0;
	r->error = saved;
	return fd;
}

/* Child probes never exec, create files, or use a changed domain for other work. */
static void probe_proc(int probe, struct result *r)
{
	const char *value = (probe == PROC_SELF || probe == PROC_PARENT) ? self_context
		: probe == PROC_INVALID ? invalid_context : ksu_context;
	char path[80];
	if (probe == PROC_PARENT)
		snprintf(path, sizeof(path), "/proc/%ld/attr/current", (long)getppid());
	else
		snprintf(path, sizeof(path), "/proc/self/attr/current");
	int fd = timed_open(path, O_WRONLY, r);
	char after[TEXT_SIZE];
	if (fd < 0)
		return;
	uint64_t start = now_ns();
	r->rc = write(fd, value, strlen(value));
	r->error = r->rc < 0 ? errno : 0;
	r->elapsed = now_ns() - start;
	r->stage = ST_WRITE;
	close(fd);
	/* Read only our own context; all mutations are confined to this child. */
	if (read_text("/proc/self/attr/current", after, sizeof(after)) < 0) {
		r->failure = 1;
		snprintf(r->response, sizeof(r->response), "context-read-failed:%d", errno);
		return;
	}
	snprintf(r->response, sizeof(r->response), "%s", after);
	if (strcmp(after, self_context))
		r->failure = 1;
	if (r->rc >= 0 && (size_t)r->rc != strlen(value))
		r->failure = 1;
	if (probe != PROC_SELF && r->rc >= 0)
		r->failure = 1;
	if (probe == PROC_SELF && r->rc < 0 &&
	    r->error != EACCES && r->error != EPERM)
		r->failure = 1;
}

static void probe_query(int probe, struct result *r)
{
	int is_access = probe >= AV_SELF;
	if (is_access && !process_class) {
		r->stage = ST_PREREQUISITE;
		r->rc = -1;
		r->error = class_index_error;
		snprintf(r->response, sizeof(r->response), "process-class-index-unavailable");
		return;
	}
	int variant = is_access ? probe - AV_SELF : probe - CTX_SELF;
	const char *context = variant == 0 ? self_context
		: variant == 1 ? invalid_context : ksu_context;
	char request[TEXT_SIZE * 2 + 32], response[TEXT_SIZE];
	if (is_access)
		snprintf(request, sizeof(request), "%s %s %u", self_context,
			 context, process_class);
	else
		snprintf(request, sizeof(request), "%s", context);
	int fd = timed_open(is_access ? SELINUXFS "/access" : SELINUXFS "/context",
			    O_RDWR, r);
	if (fd < 0)
		return;
	uint64_t start = now_ns();
	r->rc = write(fd, request, strlen(request));
	r->error = r->rc < 0 ? errno : 0;
	r->elapsed = now_ns() - start;
	r->stage = ST_WRITE;
	if (r->rc >= 0) {
		if ((size_t)r->rc != strlen(request))
			r->failure = 1;
		ssize_t n = read(fd, response, sizeof(response) - 1);
		if (n < 0) {
			r->stage = ST_READ;
			r->rc = -1;
			r->error = errno;
			r->failure = 1;
		} else {
			response[n] = 0;
			r->stage = ST_DONE;
			if (is_access) {
				unsigned int allowed, decided, auditallow, auditdeny, seq, flags;
				char trailing;
				if (sscanf(response, "%x %x %x %x %u %x %c", &allowed,
					   &decided, &auditallow, &auditdeny, &seq, &flags,
					   &trailing) != 6) {
					r->failure = 1;
					snprintf(r->response, sizeof(r->response), "invalid-access-response");
				} else {
					/* Policy seqno is recorded by status, not a semantic difference. */
					snprintf(r->response, sizeof(r->response),
						 "allowed=%x decided=%x auditallow=%x auditdeny=%x flags=%x",
						 allowed, decided, auditallow, auditdeny, flags);
				}
			} else {
				snprintf(r->response, sizeof(r->response), "%s", response);
				if (variant == 0 && strcmp(response, self_context))
					r->failure = 1;
			}
			if (variant == 1)
				r->failure = 1;
		}
	}
	close(fd);
}

static void probe_status(struct result *r)
{
	struct status_page a, b, c;
	int fd = timed_open(SELINUXFS "/status", O_RDONLY, r);
	if (fd < 0)
		return;
	uint64_t start = now_ns();
	r->rc = pread(fd, &a, sizeof(a), 0);
	r->error = r->rc < 0 ? errno : 0;
	r->elapsed = now_ns() - start;
	r->stage = ST_READ;
	if (r->rc != sizeof(a)) {
		r->failure = 1;
		close(fd);
		return;
	}
	void *mapping = mmap(NULL, (size_t)sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED) {
		r->stage = ST_MMAP;
		r->rc = -1;
		r->error = errno;
		close(fd);
		return;
	}
	/* Take a seqlock-style snapshot; do not compare changing policy generations. */
	int stable = 0;
	volatile const struct status_page *page = mapping;
	for (unsigned int retry = 0; retry < 100; ++retry) {
		uint32_t sequence = __atomic_load_n(&page->sequence, __ATOMIC_ACQUIRE);
		if (sequence & 1)
			continue;
		b.version = __atomic_load_n(&page->version, __ATOMIC_RELAXED);
		b.sequence = sequence;
		b.enforcing = __atomic_load_n(&page->enforcing, __ATOMIC_RELAXED);
		b.policyload = __atomic_load_n(&page->policyload, __ATOMIC_RELAXED);
		b.deny_unknown = __atomic_load_n(&page->deny_unknown, __ATOMIC_RELAXED);
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		if (sequence == __atomic_load_n(&page->sequence, __ATOMIC_RELAXED)) {
			stable = 1;
			break;
		}
	}
	ssize_t n = pread(fd, &c, sizeof(c), 0);
	munmap(mapping, (size_t)sysconf(_SC_PAGESIZE));
	close(fd);
	int comparable = stable && n == sizeof(c) && !(a.sequence & 1) &&
		!(c.sequence & 1) && a.sequence == b.sequence && b.sequence == c.sequence;
	int equal = comparable && !memcmp(&a, &b, sizeof(a)) && !memcmp(&b, &c, sizeof(b));
	r->stage = ST_DONE;
	r->failure = a.version != 1 || a.enforcing != 1 ||
		(stable && (b.version != 1 || b.enforcing != 1)) ||
		(n == sizeof(c) && (c.version != 1 || c.enforcing != 1)) ||
		(comparable && !equal) || n != sizeof(c);
	snprintf(r->response, sizeof(r->response),
		 "version=%u enforcing=%u deny_unknown=%u read_mmap=%s sequence=%u policyload=%u",
		 a.version, a.enforcing, a.deny_unknown,
		 comparable ? (equal ? "equal" : "different") : "generation-changed-or-busy",
		 a.sequence, a.policyload);
}

static struct result run_probe(int probe)
{
	struct result r = { .stage = ST_INTERNAL, .rc = -1, .failure = 1 };
	if (probe > PROC_PARENT) {
		memset(&r, 0, sizeof(r));
		if (probe == STATUS)
			probe_status(&r);
		else
			probe_query(probe, &r);
		return r;
	}
	int fds[2], status = 0;
	if (pipe2(fds, O_CLOEXEC))
		return r;
	pid_t pid = fork();
	if (pid == 0) {
		close(fds[0]);
		memset(&r, 0, sizeof(r));
		probe_proc(probe, &r);
		int rc = transfer(fds[1], &r, sizeof(r), 1);
		_exit(rc ? 2 : 0);
	}
	close(fds[1]);
	int rc = pid < 0 ? -1 : transfer(fds[0], &r, sizeof(r), 0);
	close(fds[0]);
	if (pid >= 0) {
		while (waitpid(pid, &status, 0) < 0) {
			if (errno != EINTR) {
				rc = -1;
				break;
			}
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status))
			rc = -1;
	}
	if (rc) {
		memset(&r, 0, sizeof(r));
		r.stage = ST_INTERNAL;
		r.rc = -1;
		r.failure = 1;
	}
	return r;
}

static int cmp_time(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static int same_outcome(const struct result *a, const struct result *b)
{
	return a->stage == b->stage && a->error == b->error && a->rc == b->rc &&
		a->failure == b->failure && !strcmp(a->response, b->response);
}

static int sample_probe(int probe, unsigned int samples)
{
	static struct outcome outcomes[MAX_OUTCOMES];
	unsigned int count = 0, failures = 0, warmup_failures = 0, overflow = 0;
	memset(outcomes, 0, sizeof(outcomes));
	for (unsigned int i = 0; i < WARMUP; ++i)
		warmup_failures += !!run_probe(probe).failure;
	for (unsigned int i = 0; i < samples; ++i) {
		struct result r = run_probe(probe);
		failures += !!r.failure;
		unsigned int k;
		for (k = 0; k < count && !same_outcome(&r, &outcomes[k].result); ++k)
			;
		if (k == MAX_OUTCOMES) {
			++overflow;
			continue;
		}
		if (k == count) {
			outcomes[k].result = r;
			++count;
		}
		outcomes[k].times[outcomes[k].count++] = r.elapsed;
	}
	printf("{\"type\":\"probe\",\"name\":\"%s\",\"samples\":%u,\"failures\":%u,"
	       "\"warmup_failures\":%u,\"unrecorded_outcomes\":%u,\"coverage_note\":",
	       names[probe], samples, failures, warmup_failures, overflow);
	json_string(probe == PROC_PARENT
		    ? "proc-opener-mm-rejection-only;lsm-current-ne-p-uncovered"
		    : "permission-dependent");
	fputs(",\"outcomes\":[", stdout);
	for (unsigned int k = 0; k < count; ++k) {
		struct outcome *o = &outcomes[k];
		qsort(o->times, o->count, sizeof(o->times[0]), cmp_time);
		if (k)
			putchar(',');
		printf("{\"stage\":\"%s\",\"rc\":%ld,\"errno\":%d,\"count\":%u,"
		       "\"failure\":%s,\"response\":", stages[o->result.stage],
		       o->result.rc, o->result.error, o->count, o->result.failure ? "true" : "false");
		json_string(o->result.response);
		printf(",\"timing_ns\":{\"min\":%" PRIu64 ",\"median\":%" PRIu64
		       ",\"p95\":%" PRIu64 ",\"max\":%" PRIu64 "}}",
		       o->times[0], o->times[o->count / 2],
		       o->times[(o->count * 95 - 1) / 100], o->times[o->count - 1]);
	}
	puts("]}");
	fflush(stdout);
	return failures || warmup_failures || overflow;
}

int main(int argc, char **argv)
{
	unsigned int samples = 128;
	const char *label = "unlabelled";
	int device = 0;
	if (argc == 1) {
		usage(stdout);
		return 0;
	}
	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--help")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(argv[i], "--device")) {
			device = 1;
		} else if (!strcmp(argv[i], "--samples") && i + 1 < argc) {
			char *end;
			unsigned long n = strtoul(argv[++i], &end, 10);
			if (*end || n < 16 || n > MAX_SAMPLES)
				goto bad_args;
			samples = (unsigned int)n;
		} else if (!strcmp(argv[i], "--label") && i + 1 < argc) {
			label = argv[++i];
			if (!*label || strlen(label) > 80 ||
			    strspn(label, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != strlen(label))
				goto bad_args;
		} else {
			goto bad_args;
		}
	}
	if (!device)
		goto bad_args;
	/* Refuse privileged callers before opening any SELinux interface. */
	uid_t uid = getuid(), euid = geteuid();
	if (uid != euid || uid % 100000 < 10000 || uid % 100000 >= 20000) {
		fputs("Refusing: run as an ordinary Android application UID (not root/shell).\n", stderr);
		return 2;
	}
	if (read_text("/proc/self/attr/current", self_context, sizeof(self_context)) <= 0 ||
	    strncmp(self_context, "u:r:untrusted_app", 17) ||
	    (self_context[17] != ':' && self_context[17] != '_')) {
		fputs("Refusing: require the application's actual untrusted_app domain.\n", stderr);
		return 2;
	}
	char text[64], *end;
	if (read_text(SELINUXFS "/enforce", text, sizeof(text)) <= 0 || strcmp(text, "1")) {
		fputs("Refusing: cannot confirm SELinux Enforcing.\n", stderr);
		return 2;
	}
	ssize_t index_len = read_text(SELINUXFS "/class/process/index", text, sizeof(text));
	if (index_len <= 0) {
		class_index_error = index_len < 0 ? errno : EINVAL;
	} else {
		unsigned long cls = strtoul(text, &end, 10);
		if (*end || !cls || cls > UINT16_MAX)
			class_index_error = EINVAL;
		else
			process_class = (unsigned int)cls;
	}
	struct utsname u;
	if (uname(&u)) {
		perror("uname");
		return 2;
	}
	printf("{\"type\":\"metadata\",\"schema\":1,\"label\":");
	json_string(label);
	printf(",\"uid\":%lu,\"euid\":%lu,\"context\":", (unsigned long)uid, (unsigned long)euid);
	json_string(self_context);
	fputs(",\"kernel\":", stdout);
	json_string(u.release);
	printf(",\"enforcing\":1,\"process_class\":%u,\"class_index_errno\":%d,"
	       "\"samples\":%u,\"warmup\":%d}\n", process_class, class_index_error, samples, WARMUP);
	int failures = 0;
	for (int probe = 0; probe < PROBE_COUNT; ++probe)
		failures += sample_probe(probe, samples);
	/* Recheck the parent identity and Enforcing state after all child probes. */
	char after[TEXT_SIZE];
	int parent_failure = read_text("/proc/self/attr/current", after, sizeof(after)) < 0 ||
	    strcmp(after, self_context) || read_text(SELINUXFS "/enforce", text, sizeof(text)) <= 0 ||
	    strcmp(text, "1");
	printf("{\"type\":\"summary\",\"failed_probe_groups\":%d,\"parent_state_failure\":%s,"
	       "\"invariant_failures\":%d,\"timing_verdict\":\"requires-controlled-device-comparison\"}\n",
	       failures, parent_failure ? "true" : "false", failures + !!parent_failure);
	return failures || parent_failure ? 1 : 0;
bad_args:
	usage(stderr);
	return 2;
}
