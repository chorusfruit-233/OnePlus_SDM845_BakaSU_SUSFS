#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/nsfs.h>
#include <linux/rtnetlink.h>
#include <linux/stat.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s (errno=%d %s)\n", __func__, __LINE__, \
            #expr, errno, strerror(errno)); exit(1); } } while (0)
#define EXPECT_ERROR(expr, error) do { errno = 0; \
    CHECK((expr) == -1); CHECK(errno == (error)); } while (0)
#define P_PIDFD_VALUE 3
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef TIOCGPTPEER
#define TIOCGPTPEER 0x5441
#endif
#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
#endif
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
#ifndef RTM_GETNEXTHOP
#define RTM_NEWNEXTHOP 104
#define RTM_GETNEXTHOP 106
#define RTNLGRP_NEXTHOP 32
#endif

_Static_assert(sizeof(struct statx) == 256, "statx ABI size");
_Static_assert(offsetof(struct statx, stx_attributes_mask) == 0x38, "statx attribute mask ABI");
_Static_assert(offsetof(struct statx, stx_mnt_id) == 0x90, "statx mount ID ABI");

static char temporary[] = "/tmp/droidspaces-XXXXXX";
static char file_path[PATH_MAX], mount_path[PATH_MAX], link_path[PATH_MAX];

static void child_case(void (*function)(void))
{
    pid_t child = fork();
    int status;
    CHECK(child >= 0);
    if (!child) { function(); _exit(0); }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_pidfd(void)
{
    siginfo_t info;
    int pidfd = -123;
    EXPECT_ERROR(syscall(SYS_waitid, P_PIDFD_VALUE, INT_MAX, &info, WEXITED, NULL), EBADF);
    int regular = open("/dev/null", O_RDONLY);
    CHECK(regular >= 0);
    EXPECT_ERROR(syscall(SYS_waitid, P_PIDFD_VALUE, regular, &info, WEXITED, NULL), EBADF);
    close(regular);
    pid_t child = syscall(SYS_clone, CLONE_PIDFD | SIGCHLD, NULL, &pidfd, NULL, NULL);
    CHECK(child >= 0);
    if (!child) _exit(42);
    CHECK(pidfd >= 0);
    struct pollfd pollfd = { .fd = pidfd, .events = POLLIN };
    CHECK(poll(&pollfd, 1, 3000) == 1 && (pollfd.revents & POLLIN));
    memset(&info, 0, sizeof(info));
    CHECK(syscall(SYS_waitid, P_PIDFD_VALUE, pidfd, &info, WEXITED | WNOWAIT, NULL) == 0);
    CHECK(info.si_pid == child && info.si_status == 42 && info.si_code == CLD_EXITED);
    CHECK(syscall(SYS_waitid, P_PIDFD_VALUE, pidfd, &info, WEXITED, NULL) == 0);
    close(pidfd);
    child = fork();
    CHECK(child >= 0);
    if (!child) { for (;;) pause(); }
    pidfd = syscall(SYS_pidfd_open, child, 0);
    CHECK(pidfd >= 0);
    CHECK(syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0) == 0);
    CHECK(syscall(SYS_waitid, P_PIDFD_VALUE, pidfd, &info, WEXITED, NULL) == 0);
    CHECK(info.si_pid == child && info.si_code == CLD_KILLED && info.si_status == SIGTERM);
    close(pidfd);
}

static struct statx stat_path(int fd, const char *path, int flags)
{
    struct statx stat;
    memset(&stat, 0xa5, sizeof(stat));
    CHECK(syscall(SYS_statx, fd, path, flags, STATX_BASIC_STATS | STATX_MNT_ID, &stat) == 0);
    CHECK(stat.stx_mask & STATX_MNT_ID);
    CHECK(stat.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT);
    CHECK(stat.__spare2 == 0);
    for (size_t i = 0; i < sizeof(stat.__spare3) / sizeof(stat.__spare3[0]); i++)
        CHECK(stat.__spare3[i] == 0);
    return stat;
}

static void test_statx(void)
{
    struct statx root = stat_path(AT_FDCWD, "/", 0);
    struct statx file = stat_path(AT_FDCWD, file_path, 0);
    struct statx proc = stat_path(AT_FDCWD, "/proc", 0);
    CHECK(root.stx_attributes & STATX_ATTR_MOUNT_ROOT);
    CHECK(!(file.stx_attributes & STATX_ATTR_MOUNT_ROOT));
    CHECK(proc.stx_attributes & STATX_ATTR_MOUNT_ROOT);
    CHECK(proc.stx_mnt_id != root.stx_mnt_id);
    CHECK(mount(temporary, mount_path, NULL, MS_BIND, NULL) == 0);
    struct statx bind = stat_path(AT_FDCWD, mount_path, 0);
    CHECK(bind.stx_attributes & STATX_ATTR_MOUNT_ROOT);
    CHECK(bind.stx_mnt_id != file.stx_mnt_id);
    int fd = open(mount_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0);
    struct statx empty = stat_path(fd, "", AT_EMPTY_PATH);
    CHECK(empty.stx_mnt_id == bind.stx_mnt_id);
    CHECK(empty.stx_attributes & STATX_ATTR_MOUNT_ROOT);
    /* This tree also exposes its older NULL-filename fd extension. */
    struct statx by_fd = stat_path(fd, NULL, 0);
    CHECK(by_fd.stx_mnt_id == bind.stx_mnt_id);
    close(fd);
    CHECK(umount(mount_path) == 0);
}

static void test_utimensat(void)
{
    int fd = open(file_path, O_PATH | O_CLOEXEC);
    /* SYS_utimensat is the original long-sized ABI, even with a time64 libc. */
    struct {long tv_sec, tv_nsec;} times[2] = {{1700000000, 123456789}, {1700000001, 234567890}};
    CHECK(fd >= 0);
    CHECK(syscall(SYS_utimensat, fd, "", times, AT_EMPTY_PATH) == 0);
    struct statx stat = stat_path(fd, "", AT_EMPTY_PATH);
    CHECK(stat.stx_mtime.tv_sec == times[1].tv_sec && stat.stx_mtime.tv_nsec == times[1].tv_nsec);
    EXPECT_ERROR(syscall(SYS_utimensat, fd, "", times, AT_EMPTY_PATH | 0x40000000), EINVAL);
    close(fd);
}

static void access_ids(void)
{
    CHECK(setresuid(10001, 0, 0) == 0);
    EXPECT_ERROR(syscall(SYS_faccessat2, AT_FDCWD, file_path, R_OK, 0), EACCES);
    CHECK(syscall(SYS_faccessat2, AT_FDCWD, file_path, R_OK, AT_EACCESS) == 0);
    CHECK(getuid() == 10001 && geteuid() == 0);
    CHECK(syscall(SYS_faccessat2, AT_FDCWD, file_path, R_OK, AT_EACCESS) == 0);
}

static void test_faccessat2(void)
{
    int fd = open(file_path, O_PATH | O_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(syscall(SYS_faccessat2, fd, "", F_OK, AT_EMPTY_PATH) == 0);
    CHECK(syscall(SYS_faccessat2, AT_FDCWD, link_path, F_OK, AT_SYMLINK_NOFOLLOW) == 0);
    EXPECT_ERROR(syscall(SYS_faccessat2, AT_FDCWD, link_path, F_OK, 0), ENOENT);
    EXPECT_ERROR(syscall(SYS_faccessat2, fd, "", F_OK, 0x40000000), EINVAL);
    close(fd);
    child_case(access_ids);
}

static void close_fds(void)
{
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(fcntl(fd, F_DUPFD_CLOEXEC, 100) == 100);
    CHECK(fcntl(fd, F_DUPFD_CLOEXEC, 101) == 101);
    CHECK(fcntl(fd, F_DUPFD_CLOEXEC, 102) == 102);
    close(fd);
    CHECK(syscall(SYS_close_range, 101, 101, 0) == 0);
    CHECK(fcntl(100, F_GETFD) >= 0 && fcntl(102, F_GETFD) >= 0);
    EXPECT_ERROR(fcntl(101, F_GETFD), EBADF);
    EXPECT_ERROR(syscall(SYS_close_range, 102, 100, 0), EINVAL);
    EXPECT_ERROR(syscall(SYS_close_range, 100, 102, 1), EINVAL);
    CHECK(syscall(SYS_close_range, 100, UINT_MAX, 0) == 0);
    EXPECT_ERROR(fcntl(100, F_GETFD), EBADF);
    EXPECT_ERROR(fcntl(102, F_GETFD), EBADF);
}

static void test_close_range(void) { child_case(close_fds); }

static void test_bindtoifindex(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int index = if_nametoindex("lo"), value = -1;
    socklen_t size = sizeof(value);
    CHECK(fd >= 0 && index > 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof(index)) == 0);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &value, &size) == 0);
    CHECK(size == sizeof(value) && value == index);
    index = -1;
    EXPECT_ERROR(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof(index)), EINVAL);
    index = 0;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &index, sizeof(index)) == 0);
    close(fd);
}

static void peer_groups(void)
{
    gid_t groups[2] = {100, 200}, received[2] = {0, 0};
    int pair[2];
    CHECK(setgroups(2, groups) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    socklen_t size = sizeof(gid_t);
    EXPECT_ERROR(getsockopt(pair[0], SOL_SOCKET, SO_PEERGROUPS, received, &size), ERANGE);
    CHECK(size == sizeof(groups));
    CHECK(getsockopt(pair[0], SOL_SOCKET, SO_PEERGROUPS, received, &size) == 0);
    CHECK(size == sizeof(groups) && !memcmp(groups, received, sizeof(groups)));
    close(pair[0]); close(pair[1]);
}

static void test_peergroups(void) { child_case(peer_groups); }

static void test_nsfs(void)
{
    int mnt = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    int user = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
    uid_t owner = (uid_t)-1;
    CHECK(mnt >= 0 && user >= 0);
    CHECK(ioctl(mnt, NS_GET_NSTYPE) == CLONE_NEWNS);
    CHECK(ioctl(user, NS_GET_NSTYPE) == CLONE_NEWUSER);
    CHECK(ioctl(user, NS_GET_OWNER_UID, &owner) == 0 && owner == 0);
    EXPECT_ERROR(ioctl(mnt, NS_GET_OWNER_UID, &owner), EINVAL);
    EXPECT_ERROR(ioctl(user, NS_GET_OWNER_UID, (void *)1), EFAULT);
    close(mnt); close(user);
}

static void test_ptypeer(void)
{
    int fd = open("/dev/pts/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    int unlock = 0;
    CHECK(fd >= 0 && ioctl(fd, TIOCSPTLCK, &unlock) == 0);
    int peer = ioctl(fd, TIOCGPTPEER, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    CHECK(peer >= 0);
    CHECK(fcntl(peer, F_GETFD) & FD_CLOEXEC);
    CHECK(fcntl(peer, F_GETFL) & O_NONBLOCK);
    CHECK(write(peer, "x", 1) == 1);
    char byte;
    CHECK(read(fd, &byte, 1) == 1 && byte == 'x');
    close(peer); close(fd);
}

static void test_ptypeer_error(void)
{
    CHECK(mkdir("/dev/droidspaces-pty", 0700) == 0);
    int fd = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC), unlock = 0;
    CHECK(fd >= 0 && ioctl(fd, TIOCSPTLCK, &unlock) == 0);
    CHECK(rename("/dev/ptmx", "/dev/droidspaces-pty/ptmx") == 0);
    errno = 0;
    int peer = ioctl(fd, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    int error = errno;
    CHECK(rename("/dev/droidspaces-pty/ptmx", "/dev/ptmx") == 0);
    CHECK(peer == -1 && (error == ENOENT || error == ENODEV));
    close(fd);
    CHECK(rmdir("/dev/droidspaces-pty") == 0);
}

static void test_nexthop(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    int group = RTNLGRP_NEXTHOP;
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    CHECK(fd >= 0);
    CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) == 0);
    struct {struct nlmsghdr header; uint8_t payload[8];} request = {
        .header = {.nlmsg_len = NLMSG_LENGTH(8), .nlmsg_type = RTM_GETNEXTHOP,
                   .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = 123},
    };
    CHECK(sendto(fd, &request, request.header.nlmsg_len, 0,
                 (struct sockaddr *)&address, sizeof(address)) == (ssize_t)request.header.nlmsg_len);
    char response[4096];
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    CHECK(poll(&ready, 1, 2000) == 1);
    ssize_t size = recv(fd, response, sizeof(response), 0);
    CHECK(size >= (ssize_t)sizeof(struct nlmsghdr));
    struct nlmsghdr *header = (struct nlmsghdr *)response;
    CHECK(header->nlmsg_seq == 123 && header->nlmsg_type == NLMSG_DONE);
    request.header.nlmsg_type = RTM_NEWNEXTHOP;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.header.nlmsg_seq = 124;
    CHECK(sendto(fd, &request, request.header.nlmsg_len, 0,
                 (struct sockaddr *)&address, sizeof(address)) == (ssize_t)request.header.nlmsg_len);
    CHECK(poll(&ready, 1, 2000) == 1);
    size = recv(fd, response, sizeof(response), 0);
    CHECK(size >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)));
    header = (struct nlmsghdr *)response;
    CHECK(header->nlmsg_seq == 124 && header->nlmsg_type == NLMSG_ERROR);
    CHECK(((struct nlmsgerr *)NLMSG_DATA(header))->error == -EOPNOTSUPP);
    close(fd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("DROIDSPACES_ABI=%zu\n", sizeof(void *) * 8);
    CHECK(mkdtemp(temporary) && chmod(temporary, 0755) == 0);
    CHECK(snprintf(file_path, sizeof(file_path), "%s/file", temporary) > 0);
    CHECK(snprintf(mount_path, sizeof(mount_path), "%s/mount", temporary) > 0);
    CHECK(snprintf(link_path, sizeof(link_path), "%s/link", temporary) > 0);
    int fd = open(file_path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && close(fd) == 0 && mkdir(mount_path, 0700) == 0);
    CHECK(symlink("missing", link_path) == 0);
    struct {const char *name; void (*function)(void);} tests[] = {
        {"pidfd", test_pidfd}, {"statx", test_statx}, {"utimensat", test_utimensat},
        {"faccessat2", test_faccessat2}, {"close_range", test_close_range},
        {"bindtoifindex", test_bindtoifindex}, {"peergroups", test_peergroups},
        {"nsfs", test_nsfs}, {"ptypeer", test_ptypeer},
        {"ptypeer_error", test_ptypeer_error}, {"nexthop", test_nexthop},
    };
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        tests[i].function();
        printf("PASS droidspaces_%s\n", tests[i].name);
    }
    CHECK(unlink(file_path) == 0 && unlink(link_path) == 0);
    CHECK(rmdir(mount_path) == 0 && rmdir(temporary) == 0);
    return 0;
}
