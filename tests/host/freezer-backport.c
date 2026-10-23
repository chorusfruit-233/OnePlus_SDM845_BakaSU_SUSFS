/* SPDX-License-Identifier: GPL-2.0 */
/* Supplemental 4.9 freezer regression tests. Disposable QEMU guests only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
	fprintf(stderr, "FAIL %s:%d: %s (errno=%d)\n", __func__, __LINE__, #x, errno); \
	exit(1); } } while (0)

static const char *v2 = "/sys/fs/cgroup";
static const char *v1 = "/tmp/cgroup-v1";
static char base[512];
static unsigned long *shared;

static unsigned long counter(int n)
{
	return __atomic_load_n(&shared[n], __ATOMIC_SEQ_CST);
}

static void increment(int n)
{
	__atomic_add_fetch(&shared[n], 1, __ATOMIC_SEQ_CST);
}

static void path(char *out, size_t size, const char *group, const char *name)
{
	CHECK(snprintf(out, size, "%s/%s", group, name) < (int)size);
}

static ssize_t put(const char *group, const char *name, const char *value)
{
	char p[1024];
	int fd, saved;
	ssize_t n;
	path(p, sizeof(p), group, name);
	fd = open(p, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = write(fd, value, strlen(value));
	saved = errno;
	close(fd);
	errno = saved;
	return n;
}

static void get(const char *group, const char *name, char *out, size_t size)
{
	char p[1024];
	int fd;
	ssize_t n;
	path(p, sizeof(p), group, name);
	fd = open(p, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	n = read(fd, out, size - 1);
	CHECK(n >= 0);
	out[n] = 0;
	CHECK(close(fd) == 0);
}

static bool contains(const char *group, const char *name, const char *value)
{
	char buf[512];
	get(group, name, buf, sizeof(buf));
	return strstr(buf, value) != NULL;
}

static void wait_value(const char *group, const char *name, const char *value)
{
	for (int i = 0; i < 5000; i++) {
		if (contains(group, name, value))
			return;
		usleep(1000);
	}
	fprintf(stderr, "timed out waiting for %s/%s = %s\n", group, name, value);
	CHECK(false);
}

static void request(const char *group, bool freeze)
{
	CHECK(put(group, "cgroup.freeze", freeze ? "1" : "0") == 1);
}

static void freeze(const char *group, bool frozen)
{
	request(group, frozen);
	wait_value(group, "cgroup.events", frozen ? "frozen 1\n" : "frozen 0\n");
}

static void group(char *out, const char *name)
{
	path(out, 512, base, name);
	CHECK(mkdir(out, 0700) == 0);
}

static void move_to(const char *group, pid_t pid)
{
	char value[32];
	snprintf(value, sizeof(value), "%d", pid);
	CHECK(put(group, "cgroup.procs", value) == (ssize_t)strlen(value));
}

static void progress(int n)
{
	unsigned long start = counter(n);
	for (int i = 0; i < 5000; i++) {
		if (counter(n) > start)
			return;
		usleep(1000);
	}
	CHECK(false);
}

static void stopped(int first, int count)
{
	unsigned long before[8];
	CHECK(count <= 8);
	for (int i = 0; i < count; i++)
		before[i] = counter(first + i);
	usleep(30000);
	for (int i = 0; i < count; i++)
		CHECK(counter(first + i) == before[i]);
}

static void usr1(int signal)
{
	(void)signal;
	increment(8);
}

static void *thread_fn(void *arg)
{
	int n = (int)(long)arg;
	for (;;) {
		increment(n);
		usleep(1000);
	}
	return NULL;
}

static pid_t worker(const char *group, int threads, bool forks)
{
	pid_t pid = fork();
	CHECK(pid >= 0);
	if (pid != 0) {
		for (int i = 0; i < threads; i++)
			progress(i);
		return pid;
	}
	move_to(group, getpid());
	CHECK(signal(SIGUSR1, usr1) != SIG_ERR);
	if (forks) {
		for (;;) {
			pid_t child = fork();
			CHECK(child >= 0);
			if (child == 0) {
				increment(0);
				_exit(0);
			}
			while (waitpid(child, NULL, 0) < 0)
				CHECK(errno == EINTR);
		}
	}
	for (int i = 1; i < threads; i++) {
		pthread_t thread;
		CHECK(pthread_create(&thread, NULL, thread_fn, (void *)(long)i) == 0);
	}
	thread_fn(NULL);
	_exit(0);
}

static void reap(pid_t pid)
{
	int status;
	CHECK(kill(pid, SIGKILL) == 0);
	for (int i = 0; i < 5000; i++) {
		pid_t result = waitpid(pid, &status, WNOHANG);
		if (result == pid) {
			CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
			return;
		}
		CHECK(result == 0 || (result < 0 && errno == EINTR));
		usleep(1000);
	}
	CHECK(false);
}

static void empty(const char *group)
{
	wait_value(group, "cgroup.events", "populated 0\n");
	CHECK(rmdir(group) == 0);
}

static void test_interface(void)
{
	char a[512], p[1024];
	path(p, sizeof(p), v2, "cgroup.freeze");
	CHECK(access(p, F_OK) < 0 && errno == ENOENT);
	group(a, "interface");
	CHECK(contains(a, "cgroup.freeze", "0\n"));
	freeze(a, true);
	CHECK(put(a, "cgroup.freeze", "2") < 0 && errno == ERANGE);
	CHECK(put(a, "cgroup.freeze", "-1") < 0 && errno == ERANGE);
	CHECK(put(a, "cgroup.freeze", "invalid") < 0 && errno == EINVAL);
	CHECK(contains(a, "cgroup.freeze", "1\n"));
	freeze(a, false);
	empty(a);
}

static void test_threads_and_signals(void)
{
	char a[512];
	group(a, "threads");
	pid_t pid = worker(a, 4, false);
	freeze(a, true);
	stopped(0, 4);
	unsigned long signals = counter(8);
	CHECK(kill(pid, SIGUSR1) == 0);
	CHECK(kill(pid, SIGCONT) == 0);
	stopped(0, 4);
	CHECK(counter(8) == signals);
	freeze(a, false);
	for (int i = 0; i < 4; i++)
		progress(i);
	for (int i = 0; counter(8) == signals && i < 5000; i++)
		usleep(1000);
	CHECK(counter(8) == signals + 1);
	freeze(a, true);
	/* SIGKILL must work without first thawing the cgroup. */
	reap(pid);
	wait_value(a, "cgroup.events", "frozen 1\n");
	empty(a);
}

static void test_hierarchy(void)
{
	char a[512], b[512], c[512];
	group(a, "hierarchy");
	path(b, sizeof(b), a, "child");
	CHECK(mkdir(b, 0700) == 0);
	pid_t pid = worker(b, 1, false);
	freeze(a, true);
	wait_value(b, "cgroup.events", "frozen 1\n");
	CHECK(contains(b, "cgroup.freeze", "0\n"));
	/* A local thaw cannot override an ancestor's freeze. */
	request(b, false);
	stopped(0, 1);
	path(c, sizeof(c), a, "created-while-frozen");
	CHECK(mkdir(c, 0700) == 0);
	wait_value(c, "cgroup.events", "frozen 1\n");
	CHECK(rmdir(c) == 0);
	request(b, true);
	freeze(a, false);
	stopped(0, 1);
	freeze(b, false);
	progress(0);
	reap(pid);
	empty(b);
	empty(a);
}

static void test_migration(void)
{
	char a[512], b[512];
	group(a, "source");
	group(b, "destination");
	pid_t pid = worker(a, 4, false);
	freeze(a, true);
	stopped(0, 4);
	move_to(b, pid);
	for (int i = 0; i < 4; i++)
		progress(i);
	move_to(a, pid);
	wait_value(a, "cgroup.events", "frozen 1\n");
	stopped(0, 4);
	freeze(b, true);
	move_to(b, pid);
	wait_value(b, "cgroup.events", "frozen 1\n");
	stopped(0, 4);
	freeze(a, false);
	stopped(0, 4);
	freeze(b, false);
	for (int i = 0; i < 4; i++)
		progress(i);
	reap(pid);
	empty(a);
	empty(b);
}

static void test_fork_race(void)
{
	char a[512];
	group(a, "fork-race");
	pid_t pid = worker(a, 1, true);
	for (int i = 0; i < 50; i++) {
		freeze(a, true);
		stopped(0, 1);
		freeze(a, false);
		progress(0);
	}
	/* Kill the worker while thawed so it can reap its last short-lived child. */
	reap(pid);
	empty(a);
}

static void test_ptrace_detach(void)
{
	char a[512];
	group(a, "ptrace-detach");
	pid_t pid = worker(a, 1, false);
	for (int i = 0; i < 20; i++) {
		int status;
		siginfo_t info;
		freeze(a, true);
		CHECK(ptrace(PTRACE_SEIZE, pid, NULL, NULL) == 0);
		CHECK(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == 0);
		CHECK(waitpid(pid, &status, 0) == pid && WIFSTOPPED(status));
		CHECK(ptrace(PTRACE_GETSIGINFO, pid, NULL, &info) == 0);
		CHECK(ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0);
		wait_value(a, "cgroup.events", "frozen 1\n");
		stopped(0, 1);
		freeze(a, false);
		progress(0);
	}
	reap(pid);
	empty(a);
}

static void test_job_stop_preserved(void)
{
	char a[512];
	int status;
	group(a, "job-stop");
	pid_t pid = worker(a, 4, false);
	CHECK(kill(pid, SIGSTOP) == 0);
	CHECK(waitpid(pid, &status, WUNTRACED) == pid && WIFSTOPPED(status));
	for (int i = 0; i < 50; i++) {
		freeze(a, true);
		freeze(a, false);
		/* Thaw must not cancel job-control stops, for any thread. */
		stopped(0, 4);
	}
	CHECK(kill(pid, SIGCONT) == 0);
	for (int i = 0; i < 4; i++)
		progress(i);
	reap(pid);
	empty(a);
}

static void test_legacy_coexistence(void)
{
	char a[512], legacy[512];
	group(a, "coexistence");
	path(legacy, sizeof(legacy), v1, "freezer-backport");
	CHECK(mkdir(legacy, 0700) == 0);
	pid_t pid = worker(a, 1, false);
	move_to(legacy, pid);
	freeze(a, true);
	CHECK(put(legacy, "freezer.state", "FROZEN") == 6);
	wait_value(legacy, "freezer.state", "FROZEN");
	freeze(a, false);
	stopped(0, 1);
	CHECK(put(legacy, "freezer.state", "THAWED") == 6);
	progress(0);
	CHECK(put(legacy, "freezer.state", "FROZEN") == 6);
	wait_value(legacy, "freezer.state", "FROZEN");
	stopped(0, 1);
	CHECK(put(legacy, "freezer.state", "THAWED") == 6);
	progress(0);
	reap(pid);
	empty(a);
	CHECK(rmdir(legacy) == 0);
}

int main(int argc, char **argv)
{
	char cmdline[2048];
	get("/proc", "cmdline", cmdline, sizeof(cmdline));
	CHECK(strstr(cmdline, "freezer_backport_qemu=1") != NULL);
	if (argc == 2 && strcmp(argv[1], "--shutdown") == 0) {
		sync();
		return reboot(RB_POWER_OFF);
	}
	CHECK(argc == 1);
	setvbuf(stdout, NULL, _IOLBF, 0);
	shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	CHECK(shared != MAP_FAILED);
	snprintf(base, sizeof(base), "%s/freezer-backport-%d", v2, getpid());
	CHECK(mkdir(base, 0700) == 0);
#define RUN(fn) do { printf("RUN %s\n", #fn); fn(); printf("PASS %s\n", #fn); } while (0)
	RUN(test_interface);
	RUN(test_threads_and_signals);
	RUN(test_hierarchy);
	RUN(test_migration);
	RUN(test_fork_race);
	RUN(test_ptrace_detach);
	RUN(test_job_stop_preserved);
	RUN(test_legacy_coexistence);
	CHECK(rmdir(base) == 0);
	CHECK(munmap(shared, 4096) == 0);
	puts("FREEZER_BACKPORT_PASS");
	return 0;
}
