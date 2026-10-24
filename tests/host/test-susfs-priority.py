#!/usr/bin/env python3
"""Fault-inject the actual SUSFS priority UID filter on the 4.9 port.

Credentials, VFS and RCU are mocked; this does not test Android SELinux or the
syscall ABI. The test exercises validation, publication, rollback and refresh.
"""
import argparse
import os
from pathlib import Path
import re
import runpy
import shlex
import subprocess
import tempfile


PREFIX = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint64_t u64;
#define __user
#define __rcu
#define GFP_KERNEL 1
#define __GFP_NOWARN 2
#define LOOKUP_FOLLOW 1
#define STATX_BASIC_STATS 0x7ff
#define SUSFS_PRIORITY_UID_FILTER_MIN_UID 10000
#define SUSFS_PRIORITY_UID_FILTER_MAX_UID 19999
#define SUSFS_PRIORITY_UID_FILTER_UID_NUM 10000
#define SUSFS_PRIORITY_UID_FILTER_BITMAP_LEN ((10000 + 63) / 64)
#define SUSFS_APP_STR_BUF_SIZE 65535
#define SUSFS_LOGE(...) ((void)0)
#define SUSFS_LOGI(...) ((void)0)
#define likely(x) (x)
#define READ_ONCE(x) (x)
#define DEFINE_MUTEX(name) int name
#define lockdep_is_held(p) (*(p))
#define mutex_lock(p) do { assert(!*(p)); *(p)=1; } while(0)
#define mutex_unlock(p) do { assert(*(p)); *(p)=0; } while(0)
struct rcu_head { int unused; };
static int rcu_depth;
#define rcu_read_lock() (rcu_depth++)
#define rcu_read_unlock() (rcu_depth--)
#define rcu_dereference(p) (assert(rcu_depth > 0), (p))
#define rcu_dereference_protected(p, cond) (assert(cond), (p))
#define rcu_assign_pointer(p, v) ((p)=(v))
static int allocations, fail_allocation, live_allocations;
static void *allocate(size_t size) {
    allocations++;
    if (fail_allocation && allocations >= fail_allocation) return NULL;
    void *p=calloc(1,size); assert(p); live_allocations++; return p;
}
static void release(void *p) { if(p) {live_allocations--; free(p);} }
#define kzalloc(size,flags) allocate(size)
#define vzalloc(size) allocate(size)
#define kfree(p) release(p)
#define kvfree(p) release(p)
#define kfree_rcu(p,member) release(p)
struct cred { int domain; };
static int current_domain, deny_domain;
static struct cred *prepare_creds(void) {
    struct cred *p=allocate(sizeof(*p)); if(p) p->domain=current_domain; return p;
}
static void abort_creds(struct cred *p) { release(p); }
static void commit_creds(struct cred *p) { current_domain=p->domain; release(p); }
static void setup_selinux(const char *name, struct cred *p) { p->domain=!deny_domain; }
static bool susfs_is_current_ksu_domain(void) { return current_domain==1; }
struct path { uid_t uid; };
struct kstat { uid_t uid; };
static int init_user_ns;
static int kern_path(const char *, int, struct path *);
static int vfs_getattr(struct path *p, struct kstat *st, unsigned int mask, unsigned int flags)
{ st->uid=p->uid; return 0; }
static void path_put(struct path *p) { }
#define from_kuid(ns,uid) (uid)
#define scnprintf snprintf
static char *strim(char *s) {
    while(isspace((unsigned char)*s))s++;
    size_t n=strlen(s); while(n && isspace((unsigned char)s[n-1]))s[--n]=0; return s;
}
static void set_bit(unsigned int bit, unsigned long *bits) { bits[bit/64]|=1UL<<(bit%64); }
static int test_bit(unsigned int bit, unsigned long *bits) { return !!(bits[bit/64]&(1UL<<(bit%64))); }
typedef struct { int value; } atomic_t;
#define ATOMIC_INIT(v) {v}
static int atomic_cmpxchg(atomic_t *p,int old,int new) {int v=p->value;if(v==old)p->value=new;return v;}
static void atomic_set(atomic_t *p,int v) {p->value=v;}
static int (*queued_worker)(void *);
static int fail_thread, launched_threads;
static void *kthread_run(int (*worker)(void *),void *data,const char *name) {
    if(fail_thread) return (void *)-1L; launched_threads++; queued_worker=worker; return (void *)1;
}
#define IS_ERR(p) ((p)==(void *)-1L)
static int fail_copy_from;
static int copy_from_user(void *out, const void *in, size_t size) {
    if(fail_copy_from)return 1; memcpy(out,in,size);return 0;
}
static int copy_to_user(void *out, const void *in, size_t size) {memcpy(out,in,size);return 0;}
struct st_susfs_priority_uid_filter { char app_strings[65535]; int err; };
"""

SUFFIX = r"""
static int alpha_uid=10001, bump_generation, beta_present=1;
static int kern_path(const char *name,int flags,struct path *path) {
    assert(current_domain==1);
    if(bump_generation) {susfs_priority_app_generation++;bump_generation=0;}
    if(!strcmp(name,"/data/data/com.alpha"))path->uid=alpha_uid;
    else if(beta_present && !strcmp(name,"/data/data/com.beta"))path->uid=19999;
    else return -ENOENT;
    return 0;
}
static int configure(const char *names) {
    struct st_susfs_priority_uid_filter *info=calloc(1,sizeof(*info));assert(info);
    if(names)strncpy(info->app_strings,names,sizeof(info->app_strings));
    else memset(info->app_strings,'x',sizeof(info->app_strings));
    void *arg=info; susfs_set_priority_uid_filter(&arg);
    int ret=info->err;free(info);assert(current_domain==0);return ret;
}
static bool filtered(uid_t uid) {
    rcu_read_lock(); bool ret=susfs_is_priority_uid_filtered(uid);rcu_read_unlock();return ret;
}
static void susfs_set_avc_log_spoofing(void **p) {assert(0);}
static void susfs_get_enabled_features(void **p) {assert(0);}
static void susfs_show_variant(void **p) {assert(0);}
static void susfs_show_version(void **p) {assert(0);}
/* DISPATCH */
int main(void) {
    assert(!filtered(10001));
    susfs_parse_priority_app_strings(); assert(!queued_worker);
    assert(configure(" com.alpha ,, com.beta ")==0);
    assert(filtered(10001) && filtered(19999) && filtered(110001));
    assert(!filtered(9999) && !filtered(20000) && !filtered(1199999+1));
    assert(!strcmp(susfs_priority_app_strings," com.alpha ,, com.beta "));
    struct st_susfs_priority_uid_filter cmd={.app_strings="com.alpha,com.beta",.err=-1};
    void *arg=&cmd;assert(!ksu_handle_susfs_cmd(CMD_SUSFS_SET_PRIORITY_UID_FILTER,&arg));
    assert(!cmd.err && filtered(10001) && filtered(19999));
    puts("PASS: app ID boundaries, Android multi-user mapping and unmodified stored package list");
    for(int i=0;i<5;i++) {
        const char *bad[]={"",NULL,"../escape","com/alpha","com.missing"};
        assert(configure(bad[i])<0);
        assert(filtered(10001)&&filtered(19999));
    }
    fail_copy_from=1;assert(configure("com.alpha")==-EFAULT);fail_copy_from=0;
    deny_domain=1;assert(configure("com.alpha")==-EINVAL);deny_domain=0;
    puts("PASS: empty, unterminated, traversal, invalid name, missing app, bad copy and denied domain preserve old filter");
    int baseline=live_allocations;
    for(int i=1;i<=5;i++) {
        allocations=0;fail_allocation=i;
        assert(configure("com.alpha")==-(i<=3 ? ENOMEM : EINVAL));
        assert(live_allocations==baseline && current_domain==0);
        assert(filtered(10001)&&filtered(19999));
    }
    fail_allocation=0;
    puts("PASS: allocation failure paths free temporary state and restore original credentials");
    fail_thread=1;susfs_parse_priority_app_strings();assert(!susfs_priority_app_strings_running.value);
    fail_thread=0;susfs_parse_priority_app_strings();assert(queued_worker);
    int launches=launched_threads;susfs_parse_priority_app_strings();assert(launched_threads==launches);
    alpha_uid=10002;assert(queued_worker(NULL)==0);queued_worker=NULL;
    assert(!filtered(10001)&&filtered(10002)&&filtered(19999));
    assert(current_domain==0 && !susfs_priority_app_strings_running.value);
    puts("PASS: failed thread creation recovers; package refresh updates UID bitmap and resets worker state");
    struct susfs_priority_uid_filter_bitmap *old=priority_uid_filter_bitmap;
    bump_generation=1;alpha_uid=10003;susfs_parse_priority_app_strings();assert(queued_worker(NULL)==0);
    assert(priority_uid_filter_bitmap==old && filtered(10002)&&!filtered(10003));
    assert(live_allocations==baseline && current_domain==0);
    puts("PASS: stale refresh cannot publish over a newer configuration generation");
    allocations=0;fail_allocation=1;susfs_parse_priority_app_strings();queued_worker(NULL);
    assert(priority_uid_filter_bitmap==old && !susfs_priority_app_strings_running.value);
    assert(current_domain==0 && live_allocations==baseline);fail_allocation=0;
    beta_present=0;susfs_parse_priority_app_strings();assert(!queued_worker(NULL));
    assert(filtered(10003)&&!filtered(19999)&&!susfs_priority_app_strings_running.value);
    puts("PASS: failed refresh releases worker state; uninstalled apps are removed on the next refresh");
    release(priority_uid_filter_bitmap);release(susfs_priority_app_strings);
    assert(!live_allocations && !rcu_depth);
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    source = (args.source / "fs/susfs.c").read_text()
    helpers = source[source.index("static void *susfs_kvzalloc"):source.index("/* sus_path */")]
    priority = source[source.index("/* priority uid filter */"):source.index("/* susfs avc log spoofing */")]
    extract = runpy.run_path(str(Path(__file__).with_name("test-selinux-cleanup.py")))["extract_function"]
    dispatch = extract((args.source / "KernelSU/kernel/supercall/dispatch.c").read_text(),
                       "ksu_handle_susfs_cmd")
    definitions = (args.source / "include/linux/susfs_def.h").read_text()
    commands = "\n".join(re.findall(r"^#define CMD_SUSFS_\w+ 0x[0-9a-fA-F]+", definitions, re.M))
    with tempfile.TemporaryDirectory(prefix="susfs-priority-") as directory:
        program = Path(directory) / "priority.c"
        executable = Path(directory) / "priority"
        program.write_text(PREFIX + commands + "\n" + helpers + priority +
                           SUFFIX.replace("/* DISPATCH */", dispatch))
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
            "-Wno-unused-variable", "-Wno-sign-compare", "-Wno-misleading-indentation",
            str(program), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True, timeout=30)


if __name__ == "__main__":
    main()
