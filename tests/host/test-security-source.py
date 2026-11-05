#!/usr/bin/env python3
"""Execute prepared production functions with forced lifetime/error interleavings.

Kernel primitives are modeled; guest tests separately exercise actual syscalls.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def extract(source, name):
    match = re.search(r'^.*\b' + re.escape(name) + r'\([^;]*?\)\s*\{', source, re.M)
    if not match:
        raise ValueError(name)
    end, depth = match.end(), 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


COMMON = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define __user
#define READ_ONCE(x) (x)
#define smp_load_acquire(x) (*(x))
#define GFP_KERNEL 0
#define likely(x) (x)
#define unlikely(x) (x)
'''


def peers(source):
    body = source.split('\tcase SO_PEERGROUPS:\n', 1)[1].split('\n\tcase SO_PEERNAME:', 1)[0]
    return COMMON + r'''
struct group_info { int ngroups; gid_t group; };
struct cred { int refs; struct group_info *group_info; };
struct sock { const struct cred *sk_peer_cred; int sk_peer_lock; };
static struct group_info ga = {1, 123}, gb = {1, 456};
static struct cred ca, cb;
static struct sock endpoint;
static bool replaced, fail_copy, fail_len;
static void replace(void) {
    if (replaced || !endpoint.sk_peer_cred) return;
    replaced = true;
    assert(ca.refs > 0);
    ca.refs--;
    endpoint.sk_peer_cred = &cb;
}
static void spin_lock(int *p) { assert(!*p); *p = 1; }
static void spin_unlock(int *p) { assert(*p); *p = 0; replace(); }
static const struct cred *get_cred(const struct cred *p) {
    assert(endpoint.sk_peer_lock && p->refs > 0); ((struct cred *)p)->refs++; return p;
}
static void put_cred(const struct cred *p) { assert(p->refs > 0); ((struct cred *)p)->refs--; }
static int groups_to_user(gid_t *out, struct group_info *g) {
    replace();
    assert(!endpoint.sk_peer_lock && ca.refs > 0 && g == &ga);
    if (fail_copy) return -EFAULT;
    *out = g->group; return 0;
}
static int store_length(int n, int *p) {
    replace(); assert(!endpoint.sk_peer_lock);
    if (fail_len) return -EFAULT;
    *p = n; return 0;
}
#define put_user(value, ptr) store_length(value, ptr)
static int query(struct sock *sk, gid_t *optval, int *optlen) {
    int len = *optlen;
''' + body + r'''
lenout: return put_user(len, optlen);
}
int main(void) {
    for (int mode = 0; mode < 5; mode++) {
        ca = (struct cred){1, &ga}; cb = (struct cred){1, &gb};
        endpoint = (struct sock){mode == 4 ? NULL : &ca, 0};
        replaced = false; fail_copy = mode == 1; fail_len = mode == 3;
        int len = (mode == 2 || mode == 3) ? 0 : sizeof(gid_t);
        gid_t result = 0;
        int ret = query(&endpoint, &result, &len);
        int expected[] = {0, -EFAULT, -ERANGE, -EFAULT, -ENODATA};
        assert(ret == expected[mode]);
        assert(!endpoint.sk_peer_lock && cb.refs == 1);
        assert(ca.refs == (mode == 4 ? 1 : 0));
        if (!mode) assert(result == 123 && len == sizeof(gid_t));
    }
    puts("PASS peer credential replacement, usercopy faults and reference balance");
}
'''


def netlink(source):
    return COMMON + r'''
#include <linux/netlink.h>
#define CONFIG_PROC_FS 1
#define CAP_SYS_ADMIN 21
#define NLMSG_HDRLEN ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
struct sk_buff { unsigned int len; char data[256]; };
static bool allowed, rekernel_ready = true;
static int node, removals, rekernel_proc_lock;
static int *rekernel_dir;
static bool netlink_capable(struct sk_buff *s, int cap) { return allowed; }
#define nlmsg_hdr(s) ((struct nlmsghdr *)(s)->data)
#define nlmsg_ok(h,len) NLMSG_OK(h,len)
#define nlmsg_len(h) ((h)->nlmsg_len - NLMSG_HDRLEN)
#define nlmsg_data(h) NLMSG_DATA(h)
#define nlmsg_total_size(n) NLMSG_SPACE(n)
static void mutex_lock(int *p) { assert(!*p); *p = 1; }
static void mutex_unlock(int *p) { assert(*p); *p = 0; }
static void proc_remove(int *p) { assert(p == &node && !removals); removals++; }
''' + extract(source, 'netlink_rcv_msg') + r'''
static void send_msg(unsigned int declared, unsigned int actual, bool privileged) {
    struct sk_buff skb = {.len = actual};
    struct nlmsghdr *h = nlmsg_hdr(&skb);
    h->nlmsg_len = declared;
    memcpy(nlmsg_data(h), "#proc_remove", 13);
    allowed = privileged;
    netlink_rcv_msg(&skb);
}
int main(void) {
    rekernel_dir = &node;
    send_msg(NLMSG_LENGTH(12), NLMSG_LENGTH(12), false);
    assert(!removals);
    unsigned int lengths[] = {0, 1, NLMSG_HDRLEN - 1, NLMSG_HDRLEN, 17, 27, 30, 256, UINT32_MAX};
    for (unsigned int i = 0; i < sizeof(lengths)/sizeof(*lengths); i++) {
        send_msg(lengths[i], NLMSG_LENGTH(12), true); assert(!removals);
    }
    send_msg(NLMSG_LENGTH(12), NLMSG_HDRLEN - 1, true); assert(!removals);
    rekernel_ready = false;
    send_msg(NLMSG_LENGTH(12), NLMSG_LENGTH(12), true); assert(!removals);
    rekernel_ready = true;
    send_msg(NLMSG_LENGTH(12), NLMSG_LENGTH(12), true); assert(removals == 1);
    for (int i = 0; i < 3; i++) send_msg(NLMSG_LENGTH(13), NLMSG_LENGTH(13), true);
    assert(removals == 1 && !rekernel_dir && !rekernel_proc_lock);
    puts("PASS ReKernel authorization, truncated/oversized/empty input and repeated removal");
}
'''


def susfs(source):
    funcs = '\n'.join(extract(source, n) for n in (
        'susfs_sus_kstat_spoof_inotify_fdinfo', 'susfs_sus_kstat_spoof_proc_fd_seq_show',
        'susfs_open_redirect_spoof_vfs_readlink'))
    return COMMON + r'''
#define SUSFS_LOGI(...) ((void)0)
#define SUSFS_LOGE(...) ((void)0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define srcu_read_lock(x) (1)
#define srcu_read_unlock(x,i) ((void)0)
struct super_block { dev_t s_dev; };
struct inode { unsigned long i_ino; struct super_block *i_sb; };
struct st_susfs_sus_kstat_hlist {
    unsigned long target_ino; dev_t target_dev; bool is_fuse;
    int spoofed_mnt_id;
    struct { unsigned long spoofed_ino; dev_t spoofed_dev; } info;
    struct st_susfs_sus_kstat_hlist *next;
};
struct st_susfs_open_redirect_hlist {
    unsigned long target_ino; dev_t target_dev; bool reversed_lookup_only;
    struct { char target_pathname[32], redirected_pathname[32]; } info;
    struct st_susfs_open_redirect_hlist *next;
};
static struct st_susfs_sus_kstat_hlist *SUS_KSTAT_HLIST;
static struct st_susfs_open_redirect_hlist *OPEN_REDIRECT_HLIST;
#define hash_for_each_possible_rcu(table, entry, node, key) \
    for (entry = (table); entry; entry = entry->next)
static int copy_to_user(void *dst, const void *src, size_t n) { memcpy(dst, src, n); return 0; }
''' + funcs + r'''
int main(void) {
    /* Deliberately put a wrong inode from the same device first in the bucket. */
    struct st_susfs_sus_kstat_hlist right = {.target_ino=10, .target_dev=5,
        .spoofed_mnt_id=7, .info={20, 6}};
    struct st_susfs_sus_kstat_hlist wrong = right;
    wrong.target_ino=11; wrong.info.spoofed_ino=999; wrong.next=&right;
    SUS_KSTAT_HLIST=&wrong;
    unsigned long ino=10; dev_t dev=5;
    susfs_sus_kstat_spoof_inotify_fdinfo(&ino, &dev);
    assert(ino==20 && dev==6);
    ino=10; int mnt=0;
    susfs_sus_kstat_spoof_proc_fd_seq_show(&mnt, &ino, 5);
    assert(ino==20 && mnt==7);
    ino=12; dev=5;
    susfs_sus_kstat_spoof_inotify_fdinfo(&ino, &dev); assert(ino==12 && dev==5);
    struct st_susfs_open_redirect_hlist r = {.target_ino=10, .target_dev=5,
        .reversed_lookup_only=true, .info={"source", "correct"}};
    struct st_susfs_open_redirect_hlist w=r;
    w.target_ino=11; strcpy(w.info.redirected_pathname, "wrong"); w.next=&r;
    OPEN_REDIRECT_HLIST=&w;
    struct super_block sb={5}; struct inode inode={10, &sb}; char buf[32]={0};
    assert(susfs_open_redirect_spoof_vfs_readlink(&inode, buf, sizeof(buf))==7);
    assert(!memcmp(buf,"correct",7));
    memset(buf, 0xa5, sizeof(buf));
    assert(susfs_open_redirect_spoof_vfs_readlink(&inode,buf,1)==1);
    assert(buf[0]=='c' && (unsigned char)buf[1]==0xa5);
    assert(susfs_open_redirect_spoof_vfs_readlink(&inode,buf,7)==7);
    assert(!memcmp(buf,"correct",7) && (unsigned char)buf[7]==0xa5);
    inode.i_ino=12;
    assert(susfs_open_redirect_spoof_vfs_readlink(&inode,buf,sizeof(buf))==-ENOENT);
    puts("PASS SUSFS same-device inode hash collisions and missing keys");
}
'''


def hybrid(source):
    return extract(source, 'hm_process_payload')


def bbr(source, tcp_input):
    declarations = '\n'.join(re.search(
        r'^(?:static )?struct ' + name + r'\s.*?^};', source, re.M | re.S
    ).group() for name in ('tcp_plb_state', 'bbr3'))
    fallback = re.search(r'^static struct tcp_congestion_ops bbr3_reno_fallback.*?^};',
                         source, re.M | re.S)
    return COMMON + r'''
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#define __read_mostly
#define GFP_ATOMIC 0
#define TCP_CONG_NON_RESTRICTED 1
#define THIS_MODULE (&module_owner)
#define TCP_INFINITE_SSTHRESH UINT32_MAX
#define TCP_CA_Open 0
#define BBR_ACKS_INIT 0
#define TCP_ECN_ECT_PERMANENT 1
#define tcp_jiffies32 100U
#define min(a,b) ((a)<(b)?(a):(b))
#define bbr_param(sk,name) 0
struct sock;
struct rate_sample { int acked_sacked; };
struct tcp_congestion_ops {
    int flags; char name[16]; void *owner;
    u32 (*ssthresh)(struct sock *);
    void (*cong_avoid)(struct sock *, u32, u32);
    void (*cong_control)(struct sock *, const struct rate_sample *);
};
struct inet_connection_sock { struct tcp_congestion_ops *icsk_ca_ops; void *priv; };
struct tcp_sock {
    u32 snd_cwnd, prior_cwnd, snd_ssthresh, delivered, ecn_flags;
    u32 rcv_nxt, delivered_ce;
    struct { u64 stamp_us; } delivered_mstamp;
};
struct sock { struct inet_connection_sock icsk; struct tcp_sock tcp; };
#define tcp_sk(sk) (&(sk)->tcp)
#define inet_csk(sk) (&(sk)->icsk)
#define inet_csk_ca(sk) (&(sk)->icsk.priv)
#define tcp_snd_cwnd(tp) ((tp)->snd_cwnd)
static int module_owner, fail_alloc, reductions, growth, pacing, bbr_calls;
static bool recovering;
static u32 tcp_min_rtt(struct tcp_sock *tp) { return 1000; }
static void *kmalloc(size_t n, int flags) { return fail_alloc ? NULL : malloc(n); }
static u32 tcp_reno_ssthresh(struct sock *sk) { return sk->tcp.snd_cwnd / 2; }
static void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 n) { growth++; }
static void bbr_init_pacing_rate_from_rtt(struct sock *sk) { pacing++; }
static void bbr_reset_startup_mode(struct sock *sk) {}
static void bbr_reset_congestion_signals(struct sock *sk) {}
static void bbr_reset_full_bw(struct sock *sk) {}
static bool bbr_can_use_ecn(struct sock *sk) { return false; }
static bool tcp_in_cwnd_reduction(struct sock *sk) { return recovering; }
static void tcp_cwnd_reduction(struct sock *sk, u32 n, int flags) { reductions++; }
static bool tcp_may_raise_cwnd(struct sock *sk, int flags) { return flags; }
static void tcp_cong_avoid(struct sock *sk, u32 ack, u32 n) {
    sk->icsk.icsk_ca_ops->cong_avoid(sk, ack, n);
}
static void tcp_update_pacing_rate(struct sock *sk) { pacing++; }
static void fake_bbr_control(struct sock *sk, const struct rate_sample *rs) { bbr_calls++; }
static struct tcp_congestion_ops normal = {.owner=THIS_MODULE, .cong_control=fake_bbr_control};
''' + declarations + '\n' + (fallback.group() if fallback else '') + '\n' + \
        extract(source, 'bbr3_init') + '\n' + extract(tcp_input, 'tcp_cong_control') + r'''
int main(void) {
    struct sock sk = {.icsk={.icsk_ca_ops=&normal}, .tcp={.snd_cwnd=20}};
    struct rate_sample rs = {.acked_sacked=1};
    fail_alloc=1;
    bbr3_init(&sk);
    assert(!sk.icsk.priv && sk.icsk.icsk_ca_ops->owner == THIS_MODULE);
    assert(!sk.icsk.icsk_ca_ops->cong_control);
    assert(sk.icsk.icsk_ca_ops->ssthresh(&sk)==10);
    recovering=true;
    tcp_cong_control(&sk, 0, 1, 1, &rs);
    assert(reductions==1 && growth==0 && pacing==1 && bbr_calls==0);
    recovering=false;
    tcp_cong_control(&sk, 0, 1, 1, &rs);
    assert(reductions==1 && growth==1 && pacing==2 && bbr_calls==0);
    tcp_cong_control(&sk, 0, 0, 0, &rs);
    assert(growth==1 && pacing==3);
    fail_alloc=0; sk.icsk.icsk_ca_ops=&normal;
    bbr3_init(&sk);
    assert(sk.icsk.icsk_ca_ops==&normal);
    assert(sk.icsk.priv && ((struct bbr3 *)sk.icsk.priv)->initialized);
    free(sk.icsk.priv);
    puts("PASS BBR allocation failure uses full Reno recovery/pacing and retains module ownership");
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--case', choices=('peers','netlink','susfs','hybrid','bbr'))
    args = parser.parse_args()
    cases = {'peers': (peers, 'net/core/sock.c'),
             'netlink': (netlink, 'drivers/rekernel/rekernel.c'),
             'susfs': (susfs, 'fs/susfs.c'),
             'hybrid': (hybrid, 'fs/hybridmount/hybridmount.c'),
             'bbr': (lambda s: bbr(s, (args.source / 'net/ipv4/tcp_input.c').read_text()),
                     'net/ipv4/tcp_bbr3.c')}
    with tempfile.TemporaryDirectory(prefix='security-source-') as tmp:
        directory = Path(tmp)
        for name, (generate, relative) in cases.items():
            if args.case and args.case != name: continue
            source = directory / (name + '.c'); binary = directory / name
            source.write_text(generate((args.source / relative).read_text()))
            if name == 'hybrid':
                (directory / 'production.h').write_text(source.read_text())
                source.write_text(Path(__file__).with_name('security-hybrid-fixture.c').read_text())
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
                '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-unused-variable',
                '-Wno-sign-compare', str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=15)


if __name__ == '__main__':
    main()
