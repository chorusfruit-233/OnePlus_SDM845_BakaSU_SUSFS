// SPDX-License-Identifier: GPL-2.0-only
// Actual hm1, ext4/inotify, modern CAKE netlink and memcg-swap guest checks.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <linux/gen_stats.h>
#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s (errno=%d: %s)\n", __FILE__, __LINE__, \
            #condition, errno, strerror(errno)); exit(1); } } while (0)

struct hm_payload {
    uint64_t magic;
    uint32_t cmd, target_uid;
    int32_t status;
    uint32_t arg1, data_size;
    char buffer[4068];
} __attribute__((packed));
struct hm_rule { uint32_t flags, uid; uint16_t v_len, r_len; } __attribute__((packed));
struct hm_delete { uint32_t uid; uint16_t v_len; } __attribute__((packed));
static struct hm_payload *hm;

static void hm_prepare(unsigned int command)
{
    memset(hm, 0, sizeof(*hm));
    hm->magic = UINT64_C(0x4859425249444D4F);
    hm->cmd = command;
    hm->status = INT_MIN;
}

static int hm_request(void)
{
    uint64_t address = (uintptr_t)hm;
    errno = 0;
    long result = syscall(SYS_add_key, "hybridmount", "regression", &address,
                          sizeof(address), KEY_SPEC_PROCESS_KEYRING);
    CHECK(result == -1 && errno == ECANCELED);
    CHECK(hm->status != INT_MIN);
    return hm->status;
}

static void hm_add(const char *virtual_path, const char *real_path, uint32_t flags, uint32_t uid)
{
    hm_prepare(2);
    struct hm_rule rule = {flags, uid, strlen(virtual_path), strlen(real_path)};
    memcpy(hm->buffer, &rule, sizeof(rule));
    memcpy(hm->buffer + sizeof(rule), virtual_path, rule.v_len);
    memcpy(hm->buffer + sizeof(rule) + rule.v_len, real_path, rule.r_len);
    hm->data_size = sizeof(rule) + rule.v_len + rule.r_len;
    CHECK(hm_request() == 0 && hm->arg1 == hm->data_size);
}

static void write_file(const char *path, const char *data)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, data, strlen(data)) == (ssize_t)strlen(data));
    CHECK(close(fd) == 0);
}

static void expect_file(const char *path, const char *expected)
{
    char buffer[128] = {0};
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(read(fd, buffer, sizeof(buffer) - 1) == (ssize_t)strlen(expected));
    CHECK(!strcmp(buffer, expected));
    CHECK(close(fd) == 0);
}

static void test_hybridmount(void)
{
    CHECK(sizeof(*hm) == 4096);
    CHECK(posix_memalign((void **)&hm, 4096, sizeof(*hm)) == 0);
    hm_prepare(1);
    CHECK(hm_request() == 0 && hm->data_size == 3 && !memcmp(hm->buffer, "hm1", 3));
    hm_prepare(6); CHECK(hm_request() == 0);
    for (unsigned int i = 0; i < 2; i++) {
        hm_prepare(10); hm->arg1 = i ? UINT32_MAX : 0x80000000U;
        CHECK(hm_request() == 0 && !hm->data_size);
    }
    puts("PASS components_hm_protocol_and_uid_cursor");

    CHECK(mkdir("/testfs/parent", 0777) == 0);
    CHECK(mkdir("/testfs/backdir", 0777) == 0);
    write_file("/testfs/a", "alpha"); write_file("/testfs/b", "beta");
    write_file("/testfs/backdir/native", "native");
    CHECK(setxattr("/testfs/a", "user.regression", "ok", 2, 0) == 0);
    hm_add("/testfs/parent/file", "/testfs/a", 0, 0);
    expect_file("/testfs/parent/file", "alpha");
    char attribute[8];
    CHECK(getxattr("/testfs/parent/file", "user.regression", attribute, sizeof(attribute)) == 2);
    CHECK(!memcmp(attribute, "ok", 2));
    struct stat st;
    CHECK(stat("/testfs/parent/file", &st) == 0);
    DIR *dir = opendir("/testfs/parent"); CHECK(dir);
    struct dirent *entry; bool found = false;
    while ((entry = readdir(dir))) if (!strcmp(entry->d_name, "file")) {
        CHECK(entry->d_ino == st.st_ino); found = true;
    }
    CHECK(found && closedir(dir) == 0);
    puts("PASS components_hm_redirect_stat_readdir_xattr");

    /* Owned dentries are not cached. Keep the fabricated inode alive so that
     * its weak inotify mark still exists when fdinfo reaches the encoder. */
    int retained = open("/testfs/parent/file", O_RDONLY); CHECK(retained >= 0);
    int notify = inotify_init1(IN_CLOEXEC); CHECK(notify >= 0);
    int synthetic_watch = inotify_add_watch(notify, "/testfs/parent/file", IN_ATTRIB | IN_MODIFY);
    int native_watch = inotify_add_watch(notify, "/testfs/a", IN_ATTRIB | IN_MODIFY);
    CHECK(synthetic_watch >= 0 && native_watch >= 0 && synthetic_watch != native_watch);
    char fdinfo[64], info[4096]; snprintf(fdinfo, sizeof(fdinfo), "/proc/self/fdinfo/%d", notify);
    int fd = open(fdinfo, O_RDONLY); CHECK(fd >= 0);
    ssize_t count = read(fd, info, sizeof(info) - 1); CHECK(count > 0);
    info[count] = 0; CHECK(strstr(info, "inotify wd:"));
    char watch_line[64]; snprintf(watch_line, sizeof(watch_line), "inotify wd:%x ", synthetic_watch);
    CHECK(strstr(info, watch_line));
    /* A native watch proves the export encoder is live; the fabricated inode
     * must be rejected by the HM proxy before ext4 private data is accessed. */
    CHECK(strstr(info, "fhandle-type:"));
    CHECK(close(fd) == 0 && close(notify) == 0 && close(retained) == 0);
    puts("PASS components_hm_ext4_inotify_fdinfo");

    hm_add("/testfs/parent/file", "/testfs/b", 0, 0);
    expect_file("/testfs/parent/file", "beta");
    hm_add("/testfs/parent/file", "/testfs/a", 0, 0);
    hm_add("/testfs/parent/file", "/testfs/b", 0, 10001);
    hm_add("/testfs/parent/file", "", 4, 10002);
    CHECK(setfsuid(10001) == 0); expect_file("/testfs/parent/file", "beta");
    CHECK(setfsuid(0) == 10001);
    CHECK(setfsuid(10002) == 0);
    errno = 0; CHECK(open("/testfs/parent/file", O_RDONLY) == -1 && errno == ENOENT);
    CHECK(setfsuid(0) == 10002); expect_file("/testfs/parent/file", "alpha");
    puts("PASS components_hm_rule_replacement_uid_and_whiteout");

    hm_add("/testfs/parent/derived", "/testfs/backdir", 0, 0);
    hm_add("/testfs/parent/derived/survivor", "/testfs/a", 0, 0);
    expect_file("/testfs/parent/derived/native", "native");
    hm_prepare(3);
    const char *parent = "/testfs/parent/derived";
    struct hm_delete deletion = {0, strlen(parent)};
    memcpy(hm->buffer, &deletion, sizeof(deletion));
    memcpy(hm->buffer + sizeof(deletion), parent, deletion.v_len);
    hm->data_size = sizeof(deletion) + deletion.v_len;
    CHECK(hm_request() == 0);
    expect_file("/testfs/parent/derived/survivor", "alpha");
    errno = 0; CHECK(open("/testfs/parent/derived/native", O_RDONLY) == -1 && errno == ENOENT);
    fd = open("/testfs/parent/file", O_RDONLY); CHECK(fd >= 0);
    hm_prepare(7); CHECK(hm_request() == 0);
    memset(info, 0, sizeof(info)); CHECK(read(fd, info, sizeof(info)) == 5 && !memcmp(info, "alpha", 5));
    CHECK(close(fd) == 0);
    errno = 0; CHECK(open("/testfs/parent/file", O_RDONLY) == -1 && errno == ENOENT);
    puts("PASS components_hm_parent_conversion_and_open_fd_lifetime");
    free(hm);
}

struct tc_request { struct nlmsghdr header; struct tcmsg tc; char attrs[512]; };
static unsigned int sequence;

static struct rtattr *append_attr(struct nlmsghdr *header, unsigned short type,
                                  const void *data, unsigned short length)
{
    unsigned int offset = NLMSG_ALIGN(header->nlmsg_len);
    struct rtattr *attr = (void *)((char *)header + offset);
    CHECK(offset + RTA_SPACE(length) <= sizeof(struct tc_request));
    attr->rta_type = type; attr->rta_len = RTA_LENGTH(length);
    if (length) memcpy(RTA_DATA(attr), data, length);
    header->nlmsg_len = offset + RTA_SPACE(length);
    return attr;
}

static int netlink_ack(int socket_fd, struct tc_request *request)
{
    request->header.nlmsg_seq = ++sequence;
    CHECK(send(socket_fd, request, request->header.nlmsg_len, 0) == request->header.nlmsg_len);
    char buffer[8192];
    ssize_t length = recv(socket_fd, buffer, sizeof(buffer), 0); CHECK(length > 0);
    for (struct nlmsghdr *h = (void *)buffer; NLMSG_OK(h, length); h = NLMSG_NEXT(h, length))
        if (h->nlmsg_seq == sequence && h->nlmsg_type == NLMSG_ERROR)
            return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
    CHECK(false); return -1;
}

static void test_cake(void)
{
    int control = socket(AF_INET, SOCK_DGRAM, 0); CHECK(control >= 0);
    struct ifreq link = {.ifr_name = "lo"};
    CHECK(ioctl(control, SIOCGIFFLAGS, &link) == 0);
    link.ifr_flags |= IFF_UP; CHECK(ioctl(control, SIOCSIFFLAGS, &link) == 0); close(control);
    int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); CHECK(nl >= 0);
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    CHECK(bind(nl, (void *)&address, sizeof(address)) == 0);
    struct timeval timeout = {5, 0};
    CHECK(setsockopt(nl, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    struct tc_request request = {.header = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .nlmsg_type = RTM_NEWQDISC, .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE},
        .tc = {.tcm_ifindex = if_nametoindex("lo"), .tcm_handle = 0x10000, .tcm_parent = TC_H_ROOT}};
    append_attr(&request.header, TCA_KIND, "cake", 5);
    struct rtattr *options = append_attr(&request.header, TCA_OPTIONS, NULL, 0);
    uint64_t bandwidth = 12500000; uint32_t flow = CAKE_FLOW_TRIPLE, split = 1, mark = 0xff;
    append_attr(&request.header, TCA_CAKE_BASE_RATE64, &bandwidth, sizeof(bandwidth));
    append_attr(&request.header, TCA_CAKE_FLOW_MODE, &flow, sizeof(flow));
    append_attr(&request.header, TCA_CAKE_SPLIT_GSO, &split, sizeof(split));
    append_attr(&request.header, TCA_CAKE_FWMARK, &mark, sizeof(mark));
    options->rta_len = (char *)&request + request.header.nlmsg_len - (char *)options;
    CHECK(netlink_ack(nl, &request) == 0);
    puts("PASS components_cake_modern_netlink_configuration");
    int server = socket(AF_INET, SOCK_DGRAM, 0), client = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(server >= 0 && client >= 0);
    struct sockaddr_in endpoint = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(server, (void *)&endpoint, sizeof(endpoint)) == 0);
    socklen_t size = sizeof(endpoint); CHECK(getsockname(server, (void *)&endpoint, &size) == 0);
    CHECK(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    char packet[512] = {0};
    for (int i = 0; i < 64; i++) {
        CHECK(sendto(client, packet, sizeof(packet), 0, (void *)&endpoint, sizeof(endpoint)) == sizeof(packet));
        CHECK(recv(server, packet, sizeof(packet), 0) == sizeof(packet));
    }
    close(client); close(server);
    memset(&request, 0, sizeof(request));
    request.header = (struct nlmsghdr){.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .nlmsg_type = RTM_GETQDISC, .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = ++sequence};
    CHECK(send(nl, &request, request.header.nlmsg_len, 0) == request.header.nlmsg_len);
    bool found = false, stats = false, done = false;
    while (!done) {
        char buffer[16384]; ssize_t length = recv(nl, buffer, sizeof(buffer), 0); CHECK(length > 0);
        for (struct nlmsghdr *h = (void *)buffer; NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
            if (h->nlmsg_type == NLMSG_DONE) {done = true; break;}
            CHECK(h->nlmsg_type != NLMSG_ERROR);
            if (h->nlmsg_type != RTM_NEWQDISC) continue;
            struct tcmsg *tc = NLMSG_DATA(h);
            if (tc->tcm_ifindex != (int)if_nametoindex("lo") || tc->tcm_handle != 0x10000) continue;
            int remaining = TCA_PAYLOAD(h);
            for (struct rtattr *a = TCA_RTA(tc); RTA_OK(a, remaining); a = RTA_NEXT(a, remaining)) {
                if (a->rta_type == TCA_KIND) found = !strcmp(RTA_DATA(a), "cake");
                if (a->rta_type == TCA_STATS2) {
                    int nested = RTA_PAYLOAD(a);
                    for (struct rtattr *s = RTA_DATA(a); RTA_OK(s, nested); s = RTA_NEXT(s, nested)) {
                        if (s->rta_type == TCA_STATS_BASIC) {
                            struct gnet_stats_basic basic = {0};
                            /* The netlink basic statistics payload is packed (12 bytes). */
                            CHECK(RTA_PAYLOAD(s) >= sizeof(basic.bytes) + sizeof(basic.packets));
                            memcpy(&basic, RTA_DATA(s), sizeof(basic.bytes) + sizeof(basic.packets));
                            CHECK(basic.bytes >= 64 * 512 && basic.packets >= 64); stats = true;
                        }
                    }
                }
            }
        }
    }
    CHECK(found && stats); close(nl);
    puts("PASS components_cake_packet_delivery_and_statistics");
}

int main(void)
{
    setbuf(stdout, NULL); umask(0);
    CHECK(access("/tmp/memcg/memory.memsw.usage_in_bytes", R_OK) == 0);
    CHECK(access("/tmp/memcg/memory.memsw.limit_in_bytes", R_OK) == 0);
    puts("PASS components_memcg_swap_enabled_by_default");
    test_hybridmount(); test_cake();
    puts("COMPONENTS_RUNTIME_PASS");
    return 0;
}
