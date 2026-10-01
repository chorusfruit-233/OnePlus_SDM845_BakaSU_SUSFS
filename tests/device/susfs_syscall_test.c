/* Small device-side regression test for the 4.9 SUSFS namei/proc hooks. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000
#endif
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

struct linux_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

static int failures;

static void check(int ok, const char *what)
{
	if (!ok) {
		fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", what, errno,
			strerror(errno));
		failures++;
	} else {
		printf("PASS: %s\n", what);
	}
}

static void expect_missing(const char *what, long result)
{
	check(result < 0 && (errno == ENOENT || errno == ENOTDIR), what);
}

static int contains_fd(int fd, const char *needle)
{
	char buf[8192];
	ssize_t n, used = 0;

	while (used < (ssize_t)sizeof(buf) - 1) {
		n = read(fd, buf + used, sizeof(buf) - 1 - used);
		if (n <= 0)
			break;
		used += n;
	}
	buf[used] = '\0';
	return needle == NULL || strstr(buf, needle) != NULL;
}

static int contains_file(const char *path, const char *needle)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	int found;

	if (fd < 0)
		return 0;
	found = contains_fd(fd, needle);
	close(fd);
	return found;
}

static void test_hidden_path(const char *path)
{
	char moved[PATH_MAX];
	char buf[8];
	int fd;

	printf("Testing hidden SUS_PATH: %s\n", path);
	check(stat(path, &(struct stat){0}) < 0 && errno == ENOENT,
		"hidden stat -> ENOENT");
	expect_missing("hidden statx -> ENOENT",
		syscall(SYS_statx, AT_FDCWD, path, 0, STATX_BASIC_STATS,
			&(struct statx){0}));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	expect_missing("hidden open -> ENOENT", fd);
	if (fd >= 0)
		close(fd);
	expect_missing("hidden access -> ENOENT", access(path, F_OK));
	expect_missing("hidden readlink -> ENOENT", readlink(path, buf, sizeof(buf)));
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	expect_missing("hidden getdents open -> ENOENT", fd);
	if (fd >= 0) {
		char dents[256];
		expect_missing("hidden getdents64 -> ENOENT",
			syscall(SYS_getdents64, fd, dents, sizeof(dents)));
		close(fd);
	}
	expect_missing("hidden unlink -> ENOENT", unlink(path));
	snprintf(moved, sizeof(moved), "%s.susfs-rename", path);
	expect_missing("hidden rename -> ENOENT", rename(path, moved));
	fd = open(path, O_PATH | O_CLOEXEC);
	expect_missing("hidden O_PATH -> ENOENT", fd);
	if (fd >= 0)
		close(fd);
	fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	expect_missing("hidden O_TRUNC -> ENOENT", fd);
	if (fd >= 0)
		close(fd);
}

static void test_statx(const char *path, uint64_t expected_ino)
{
	struct statx stx = {0};
	int rc = syscall(SYS_statx, AT_FDCWD, path, 0, STATX_BASIC_STATS, &stx);

	check(rc == 0, "statx readable");
	if (rc == 0) {
		check((stx.stx_mask & STATX_INO) && stx.stx_ino == expected_ino,
			"statx inode agrees with expected inode");
		check(!(stx.stx_mask & 0x30000000U),
			"statx does not expose internal SUSFS discriminator bits");
	}
}

static void test_inotify_inode(const char *path, uint64_t expected_ino)
{
	char fdinfo[PATH_MAX], token[128];
	int fd = inotify_init1(IN_CLOEXEC);
	int wd;

	check(fd >= 0, "inotify_init1");
	if (fd < 0)
		return;
	wd = inotify_add_watch(fd, path, IN_ATTRIB);
	check(wd >= 0, "inotify_add_watch");
	if (wd >= 0) {
		snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", fd);
		snprintf(token, sizeof(token), "inotify wd:%x ino:%llx ", wd,
			(unsigned long long)expected_ino);
		check(contains_file(fdinfo, token), "inotify fdinfo expected inode");
		inotify_rm_watch(fd, wd);
	}
	close(fd);
}

static void test_kstat_path(const char *path, uint64_t expected_ino)
{
	struct stat st = {0};
	char fdinfo[PATH_MAX], token[128];
	int fd;

	check(stat(path, &st) == 0 && (uint64_t)st.st_ino == expected_ino,
		"SUS_KSTAT stat expected inode");
	test_statx(path, expected_ino);
	test_inotify_inode(path, expected_ino);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	check(fd >= 0, "SUS_KSTAT open");
	if (fd < 0)
		return;
	check(fstat(fd, &st) == 0 && (uint64_t)st.st_ino == expected_ino,
		"SUS_KSTAT fstat expected inode");
	snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", fd);
	snprintf(token, sizeof(token), "ino:\t%llu\n",
		(unsigned long long)expected_ino);
	check(contains_file(fdinfo, token), "SUS_KSTAT fdinfo expected inode");
	close(fd);
}

static int test_visible_tree(const char *root, const char *mount_token,
		const char *fdinfo_token)
{
	char file[PATH_MAX], link[PATH_MAX], dir[PATH_MAX], entry[PATH_MAX];
	char renamed[PATH_MAX], fdinfo[PATH_MAX];
	char dents[1024];
	struct stat st = {0};
	int fd, dirfd, found = 0;
	ssize_t n;

	snprintf(file, sizeof(file), "%s/target", root);
	snprintf(link, sizeof(link), "%s/link", root);
	snprintf(dir, sizeof(dir), "%s/dir", root);
	snprintf(entry, sizeof(entry), "%s/dir/entry", root);
	snprintf(renamed, sizeof(renamed), "%s/renamed", root);
	check(mkdir(dir, 0700) == 0, "mkdir fixture");
	fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	check(fd >= 0, "open fixture");
	if (fd < 0)
		return -1;
	check(write(fd, "susfs", 5) == 5, "write fixture");
	close(fd);
	check(stat(file, &st) == 0 && st.st_size == 5, "stat fixture");
	test_statx(file, (uint64_t)st.st_ino);
	test_inotify_inode(file, (uint64_t)st.st_ino);
	check(access(file, R_OK | W_OK) == 0, "access fixture");
	fd = open(file, O_RDONLY | O_CLOEXEC);
	check(fd >= 0 && read(fd, dents, 5) == 5, "open/read fixture");
	if (fd >= 0)
		close(fd);
	check(symlink("target", link) == 0, "create symlink");
	n = readlink(link, dents, sizeof(dents) - 1);
	check(n == 6 && !memcmp(dents, "target", 6), "readlink fixture");
	fd = open(entry, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	check(fd >= 0, "open getdents entry");
	if (fd >= 0)
		close(fd);
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	check(dirfd >= 0, "open directory");
	if (dirfd >= 0) {
		n = syscall(SYS_getdents64, dirfd, dents, sizeof(dents));
		while (n > 0 && found == 0) {
			ssize_t off = 0;
			while (off < n) {
				struct linux_dirent64 *d =
					(struct linux_dirent64 *)(dents + off);
				if (!strcmp(d->d_name, "entry"))
					found = 1;
				off += d->d_reclen;
			}
			if (found || n == 0)
				break;
			n = syscall(SYS_getdents64, dirfd, dents, sizeof(dents));
		}
		check(found, "getdents64 fixture");
		snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", dirfd);
		check(contains_file(fdinfo, "pos:") &&
			contains_file(fdinfo, "flags:"), "SUS_MOUNT fdinfo fields");
		if (fdinfo_token)
			check(!contains_file(fdinfo, fdinfo_token),
				"SUS_MOUNT fdinfo hidden token");
		close(dirfd);
	}
	fd = open(file, O_PATH | O_CLOEXEC);
	check(fd >= 0, "O_PATH fixture");
	if (fd >= 0)
		close(fd);
	fd = open(file, O_WRONLY | O_TRUNC | O_CLOEXEC);
	check(fd >= 0, "O_TRUNC fixture");
	if (fd >= 0)
		close(fd);
	check(stat(file, &st) == 0 && st.st_size == 0, "O_TRUNC size");
	check(rename(file, renamed) == 0, "rename fixture");
	check(unlink(renamed) == 0, "unlink fixture");
	check(unlink(entry) == 0 && unlink(link) == 0 && rmdir(dir) == 0,
		"cleanup fixture");
	check(contains_file("/proc/self/mountinfo", NULL),
		"SUS_MOUNT mountinfo readable");
	if (mount_token)
		check(!contains_file("/proc/self/mountinfo", mount_token),
			"SUS_MOUNT mountinfo hidden token");
	return 0;
}

int main(int argc, char **argv)
{
	char root_template[] = "/data/local/tmp/susfs-regression.XXXXXX";
	const char *hidden = NULL, *mount_token = NULL, *fdinfo_token = NULL;
	char *root = NULL;
	const char *kstat_path = NULL;
	uint64_t kstat_ino = 0;
	int i, rc;

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--hidden") && i + 1 < argc)
			hidden = argv[++i];
		else if (!strcmp(argv[i], "--mount-token") && i + 1 < argc)
			mount_token = argv[++i];
		else if (!strcmp(argv[i], "--fdinfo-token") && i + 1 < argc)
			fdinfo_token = argv[++i];
		else if (!strcmp(argv[i], "--kstat") && i + 2 < argc) {
			char *end;
			kstat_path = argv[++i];
			errno = 0;
			kstat_ino = strtoull(argv[++i], &end, 0);
			if (errno || *end || !*argv[i] || argv[i][0] == '-') {
				fprintf(stderr, "invalid KSTAT inode: %s\n", argv[i]);
				return 2;
			}
		}
		else if (!strcmp(argv[i], "--root") && i + 1 < argc)
			root = argv[++i];
		else {
			fprintf(stderr, "usage: %s [--root DIR] [--hidden PATH] "
				"[--mount-token TOKEN] [--fdinfo-token TOKEN] "
				"[--kstat PATH EXPECTED_INO]\n", argv[0]);
			return 2;
		}
	}
	if (!root && !kstat_path) {
		root = mkdtemp(root_template);
		if (!root) {
			perror("mkdtemp");
			return 2;
		}
	}
	rc = root ? test_visible_tree(root, mount_token, fdinfo_token) : 0;
	if (kstat_path)
		test_kstat_path(kstat_path, kstat_ino);
	if (hidden)
		test_hidden_path(hidden);
	if (rc < 0)
		failures++;
	if (!failures)
		printf("SUSFS syscall regression: PASS\n");
	else
		printf("SUSFS syscall regression: %d failure(s)\n", failures);
	return failures ? 1 : 0;
}
