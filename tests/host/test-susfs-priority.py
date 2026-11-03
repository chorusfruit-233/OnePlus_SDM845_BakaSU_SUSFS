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
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint64_t u64;
#define __user
#define CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER 1
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
#define vmalloc(size) allocate(size)
#define vfree(p) release(p)
#define kfree(p) release(p)
#define kvfree(p) release(p)
/* 4.9 kfree_rcu() dereferences its argument; unlike 6.1 it rejects NULL. */
#define kfree_rcu(p,member) do { assert(p); release(p); } while(0)
struct cred { int domain; };
static int current_domain, deny_domain;
static struct cred *prepare_creds(void) {
    struct cred *p=allocate(sizeof(*p)); if(p) p->domain=current_domain; return p;
}
static void abort_creds(struct cred *p) { release(p); }
static void commit_creds(struct cred *p) { current_domain=p->domain; release(p); }
static void setup_selinux(const char *name, struct cred *p) { p->domain=!deny_domain; }
static bool susfs_is_current_ksu_domain(void) { return current_domain==1; }
struct file { int unused; };
static struct file *filp_open(const char *, int, int);
static int filp_close(struct file *, void *);
#define file_inode(p) (p)
static loff_t i_size_read(struct file *);
static int kernel_read(struct file *, loff_t, char *, unsigned long);
static int kstrtoul(const char *s, unsigned int base, unsigned long *value) {
    char *end; errno=0;
    if(!s || !*s || *s=='-')return -EINVAL;
    *value=strtoul(s,&end,base);
    return errno || end==s || *end ? -EINVAL : 0;
}
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
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
static int fail_copy_from;
static int copy_from_user(void *out, const void *in, size_t size) {
    if(fail_copy_from)return 1; memcpy(out,in,size);return 0;
}
static int copy_to_user(void *out, const void *in, size_t size) {memcpy(out,in,size);return 0;}
struct st_susfs_priority_uid_filter { char app_strings[65535]; int err; };
"""

SUFFIX = r"""
static int alpha_uid=10001, bump_generation, beta_present=1;
static struct file mock_file;
static int open_files, fail_open, fail_read, early_eof, read_calls;
static loff_t forced_size=-1;
static const char *packages_override;
static char packages[1024];
static struct file *filp_open(const char *name,int flags,int mode) {
    assert(current_domain==1);
    assert(!strcmp(name,"/data/system/packages.list"));
    assert(flags==(O_RDONLY|O_NOATIME) && mode==0);
    if(bump_generation) {susfs_priority_app_generation++;bump_generation=0;}
    if(fail_open)return (void *)(intptr_t)-fail_open;
    if(packages_override)snprintf(packages,sizeof(packages),"%s",packages_override);
    else {
        int n=snprintf(packages,sizeof(packages),"com.alpha %d 0 /data/user/0/com.alpha\n",alpha_uid);
        if(beta_present)snprintf(packages+n,sizeof(packages)-n,"com.beta 19999 0 /data/user/0/com.beta\n");
    }
    assert(!open_files);open_files++;return &mock_file;
}
static loff_t i_size_read(struct file *file) {
    assert(file==&mock_file && open_files==1);
    return forced_size>=0 ? forced_size : (loff_t)strlen(packages);
}
static int kernel_read(struct file *file,loff_t offset,char *out,unsigned long size) {
    assert(file==&mock_file && open_files==1 && current_domain==1);
    read_calls++;
    if(fail_read)return -EIO;
    if(early_eof)return 0;
    assert(offset>=0 && (size_t)offset<=strlen(packages));
    if(size>7)size=7;
    if(size>strlen(packages)-(size_t)offset)size=strlen(packages)-(size_t)offset;
    memcpy(out,packages+offset,size);return (int)size;
}
static int filp_close(struct file *file,void *unused) {
    assert(file==&mock_file && open_files==1);open_files--;return 0;
}
static int configure(const char *names) {
    struct st_susfs_priority_uid_filter *info=calloc(1,sizeof(*info));assert(info);
    if(names)strncpy(info->app_strings,names,sizeof(info->app_strings));
    else memset(info->app_strings,'x',sizeof(info->app_strings));
    void *arg=info; susfs_set_priority_uid_filter(&arg);
    int ret=info->err;free(info);assert(current_domain==0 && !open_files);return ret;
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
    for(int i=0;i<4;i++) {
        const char *bad[]={"",NULL,"../escape","com/alpha"};
        assert(configure(bad[i])<0);
        assert(filtered(10001)&&filtered(19999));
    }
    fail_copy_from=1;assert(configure("com.alpha")==-EFAULT);fail_copy_from=0;
    deny_domain=1;assert(configure("com.alpha")==-EINVAL);deny_domain=0;
    puts("PASS: empty, unterminated, traversal, invalid name, bad copy and denied domain preserve old filter");
    assert(configure("com.alpha,com.missing")==0 && filtered(10001) && !filtered(19999));
    assert(configure("com.missing")==0 && !filtered(10001) && !filtered(19999));
    assert(configure("com.alpha,com.beta")==0);
    puts("PASS: packages not installed yet are stored for later refresh without rejecting the configuration");
    int reads_before=read_calls;
    packages_override="\n \tcom.alpha \t 110001 0 /data/user/1/com.alpha\ncom.beta 19999 0 /data/user/0/com.beta";
    assert(configure("com.alpha,com.beta")==0 && filtered(10001) && filtered(19999));
    assert(read_calls>reads_before+2);
    packages_override=NULL;
    fail_open=EACCES;assert(configure("com.alpha")==-EACCES);
    fail_open=ENOENT;assert(configure("com.alpha")==-ENODATA);fail_open=0;
    fail_read=1;assert(configure("com.alpha")==-EIO);fail_read=0;
    early_eof=1;assert(configure("com.alpha")==-EIO);early_eof=0;
    forced_size=0;assert(configure("com.alpha")==-EFBIG);
    forced_size=4*1024*1024+1;assert(configure("com.alpha")==-EFBIG);forced_size=-1;
    const char *malformed[]={"com.alpha\n","com.alpha invalid\n","com.alpha 4294967296\n","com.alpha 9999\n"};
    for(unsigned int i=0;i<sizeof(malformed)/sizeof(*malformed);i++) {
        packages_override=malformed[i];assert(configure("com.alpha")==-EINVAL);
        assert(filtered(10001)&&filtered(19999));
    }
    packages_override=NULL;
    puts("PASS: short reads, whitespace, multi-user IDs and final unterminated line parse; file errors and malformed UIDs roll back");
    int baseline=live_allocations;
    for(int i=1;i<=6;i++) {
        allocations=0;fail_allocation=i;
        assert(configure("com.alpha")==-(i<=3 || i==6 ? ENOMEM : EINVAL));
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
    fail_read=1;susfs_parse_priority_app_strings();assert(queued_worker(NULL)==-EIO);
    assert(priority_uid_filter_bitmap==old && current_domain==0 && !open_files);
    assert(!susfs_priority_app_strings_running.value && live_allocations==baseline);fail_read=0;
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
    helpers = ("#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER\n" + source[
        source.index("static void *susfs_kvzalloc"):source.index("/* sus_path */")])
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
