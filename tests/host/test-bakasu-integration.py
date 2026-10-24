#!/usr/bin/env python3
"""Fault-inject actual BakaSU preinit helpers and the 4.9 module syscall hooks.

VFS, user copies and fd services are mocked. This checks ownership/error paths,
not Android boot, policy behavior or live module insertion.
"""
import argparse
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import tempfile

extract = runpy.run_path(str(Path(__file__).with_name("test-selinux-cleanup.py")))["extract_function"]

PREFIX = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#define __user
#define INIT_PATH "/system/bin/init"
#define LOOKUP_FOLLOW 1
#define likely(x) (x)
#define READ_ONCE(x) (x)
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define xchg(p,v) ({ __auto_type old = *(p); *(p) = (v); old; })
struct file { int unused; } staged;
struct path { int unused; };
struct user_arg_ptr { const char *arg1; };
struct filename { const char *name; unsigned char storage[4096 + 8]; };
static struct file *ksu_preinit_file;
static int next_fd, installed_fd, filename_puts, closes, releases, fail_alloc, fail_path;
static bool fd_open;
static const char *get_user_arg_ptr(struct user_arg_ptr p, int n)
{ assert(n == 1); return p.arg1; }
static long strncpy_from_user(char *out, const char *in, size_t size)
{ strncpy(out, in, size); return strnlen(in, size); }
static int get_unused_fd_flags(int flags) { assert(flags == O_CLOEXEC); return next_fd; }
static void fd_install(int fd, struct file *file)
{ assert(fd >= 0 && file == &staged && !fd_open); installed_fd=fd; fd_open=true; }
static int kern_path(const char *path, int flags, struct path *p)
{ assert(!strncmp(path,"/proc/self/fd/",14) && flags==LOOKUP_FOLLOW); return fail_path; }
static void path_put(struct path *p) { }
static void fput(struct file *file) { assert(file==&staged); releases++; }
static void ksu_close_fd(int fd)
{ assert(fd_open && fd == installed_fd); fd_open=false; closes++; }
static struct filename *make_name(const char *name)
{
    struct filename *p = malloc(sizeof(*p));
    assert(p);
    memset(p->storage, 0xa5, sizeof(p->storage));
    size_t length = strlen(name);
    assert(length < 4096);
    memcpy(p->storage,name,length + 1);
    p->name=(char *)p->storage;
    return p;
}
static struct filename *getname_kernel(const char *name)
{ return fail_alloc ? ERR_PTR(-ENOMEM) : make_name(name); }
static void putname(struct filename *name)
{
    for (int i=4096; i<4104; i++) assert(name->storage[i] == 0xa5);
    filename_puts++; free(name);
}
"""

PREINIT_TESTS = r"""
static void reset(void)
{
    ksu_preinit_file=&staged; next_fd=0; installed_fd=-1;
    filename_puts=closes=releases=fail_alloc=fail_path=0; fd_open=false;
}
int main(void)
{
    struct user_arg_ptr argv={"selinux_setup"};
    int syscall_fd=-100, flags=0, retval, fd;
    for (int i=0; i<4; i++) {
        static const int fds[]={0,9,100,INT_MAX};
        reset(); next_fd=fds[i];
        struct filename *name=make_name(INIT_PATH);
        fd=ksu_setup_preinit_file(&name,&argv);
        assert(fd==next_fd && filename_puts==1 && !ksu_preinit_file);
        char expected[32]; snprintf(expected,sizeof(expected),"/proc/self/fd/%d",fd);
        assert(!strcmp(name->name,expected));
        assert(ksu_setup_preinit_file(&name,&argv)==-EINVAL); /* one shot */
        retval=-ENOEXEC;
        assert(ksu_preinit_handle_post_execveat(&syscall_fd,&name,&argv,0,&flags,&retval,&fd)<0);
        assert(closes==1 && !fd_open && fd==-1 && !strcmp(name->name,INIT_PATH));
        assert(!ksu_preinit_handle_post_execveat(&syscall_fd,&name,&argv,0,&flags,&retval,&fd));
        assert(closes==1); putname(name);
    }
    puts("PASS: fd 0 and long fd paths preserve owned, terminated filenames; failed exec closes once and restores init");
    reset(); next_fd=4;
    struct filename *name=make_name(INIT_PATH);
    fd=ksu_setup_preinit_file(&name,&argv); assert(fd==4);
    fd_open=false; /* the successful exec already applied O_CLOEXEC */
    retval=0;
    assert(!ksu_preinit_handle_post_execveat(&syscall_fd,&name,&argv,0,&flags,&retval,&fd));
    assert(!closes); putname(name);
    puts("PASS: successful exec does not close a reused descriptor");
    for (int failure=0; failure<3; failure++) {
        reset(); name=make_name(INIT_PATH);
        if (!failure) next_fd=-EMFILE;
        if (failure==1) fail_path=1;
        if (failure==2) fail_alloc=1;
        assert(ksu_setup_preinit_file(&name,&argv)<0);
        assert(!strcmp(name->name,INIT_PATH) && !filename_puts && !fd_open && !ksu_preinit_file);
        assert(failure ? closes==1 : releases==1);
        putname(name);
    }
    puts("PASS: fd allocation, path lookup and filename allocation failures keep original init and release ownership");
    reset(); name=make_name(INIT_PATH);
    struct user_arg_ptr wrong={"second_stage"};
    assert(ksu_setup_preinit_file(&name,&wrong)==-EINVAL);
    wrong.arg1=ERR_PTR(-EFAULT);
    assert(ksu_setup_preinit_file(&name,&wrong)==-EINVAL);
    assert(ksu_setup_preinit_file(&name,0)==-EINVAL);
    assert(ksu_preinit_file==&staged && !fd_open && !filename_puts); putname(name);
    puts("PASS: non-preinit arguments and failed user-pointer lookup do not consume the staged runner");
}
"""

MODULE_PREFIX = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#define CONFIG_KSU_SUSFS 1
#define __user
#define SYSCALL_DEFINE3(n,t1,a1,t2,a2,t3,a3) long test_##n(t1 a1,t2 a2,t3 a3)
#define MODULE_INIT_IGNORE_MODVERSIONS 1
#define MODULE_INIT_IGNORE_VERMAGIC 2
#define READING_MODULE 0
#define INT_MAX 2147483647
#define pr_debug(...) ((void)0)
typedef long loff_t;
struct load_info { void *hdr; long len; };
static int permission_error,copy_error,load_result,loads,hooks;
static int may_init_module(void) { return permission_error; }
static int copy_module_from_user(void *p,unsigned long len,struct load_info *info) { return copy_error; }
static int kernel_read_file_from_fd(int fd,void **hdr,loff_t *size,int max,int why) { return copy_error; }
static int load_module(struct load_info *info,const char *args,int flags) { loads++; return load_result; }
#define ksu_handle_init_module actual_init_hook
#define ksu_handle_finit_module actual_finit_hook
"""
MODULE_BRIDGE = r"""
#undef ksu_handle_init_module
#undef ksu_handle_finit_module
static void ksu_handle_init_module(int *r) { hooks++; actual_init_hook(r); }
static void ksu_handle_finit_module(int *r) { hooks++; actual_finit_hook(r); }
"""
MODULE_TESTS = r"""
static long call(int which,int flags)
{ return which ? test_finit_module(3,"",flags) : test_init_module(0,0,""); }
int main(void)
{
    for(int which=0;which<2;which++) {
        permission_error=-EPERM; copy_error=loads=hooks=0;
        assert(call(which,0)==-EPERM && !loads && !hooks);
        permission_error=0;copy_error=-EFAULT;
        assert(call(which,0)==-EFAULT && !loads && !hooks);
        copy_error=0;
        if(which) assert(call(which,0x8000)==-EINVAL && !loads && !hooks);
        load_result=-EPERM;
        assert(call(which,0)==0 && loads==1 && hooks==1);
        load_result=-ENOMEM;
        assert(call(which,0)==-ENOMEM && loads==2 && hooks==2);
        load_result=0;
        assert(call(which,0)==0 && loads==3 && hooks==3);
    }
    puts("PASS: both real module syscall bodies retain permission/input errors and call blacklist handling only after load_module");
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2] / "kernel")
    args = parser.parse_args()
    kernel = args.source.resolve()
    ksu = kernel / "KernelSU/kernel"
    source = (ksu / "preinit/preinit.c").read_text()
    # Ignore the tracepoint/manual implementations; this port uses SUSFS inline hooks.
    setup = source.index("int ksu_setup_preinit_file(")
    preinit = "\n".join(extract(source, name) for name in ("is_selinux_setup",))
    preinit += "\n" + "\n".join(extract(source[setup:], name) for name in
                              ("ksu_setup_preinit_file", "ksu_preinit_handle_post_execveat"))
    module = (kernel / "kernel/module.c").read_text()
    start = module.index("SYSCALL_DEFINE3(init_module,")
    end = module.index("static inline int within(", start)
    hooks = (ksu / "feature/module_blacklist.c").read_text()
    module_hooks = "\n".join(extract(hooks, name) for name in
                              ("ksu_handle_init_module", "ksu_handle_finit_module"))
    compiler = shlex.split(os.environ.get("CC", "cc"))
    with tempfile.TemporaryDirectory(prefix="bakasu-integration-") as temporary:
        for name, text in (("preinit", PREFIX + preinit + PREINIT_TESTS),
                           ("modules", MODULE_PREFIX + module_hooks + MODULE_BRIDGE + module[start:end] + MODULE_TESTS)):
            path = Path(temporary) / (name + ".c")
            binary = Path(temporary) / name
            path.write_text(text)
            subprocess.run(compiler + ["-std=gnu11", "-O2", "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra",
                                       "-Werror", "-Wno-unused-parameter", str(path), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
