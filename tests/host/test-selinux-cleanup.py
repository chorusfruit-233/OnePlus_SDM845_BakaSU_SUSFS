#!/usr/bin/env python3
"""Compile actual BakaSU cleanup functions with failed-restore injection.

The kernel source is extracted at runtime. The harness mocks kernel services
and checks callback/resource ownership; it does not emulate ARM64 patching,
concurrent callbacks, device boot, or SELinux policy behavior.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


FUNCTIONS = (
    "ksu_selinux_hide_unhook",
    "ksu_selinux_hide_disable",
    "selinux_hide_feature_get",
    "selinux_hide_feature_set",
    "ksu_selinux_hide_drop_backup_if_unused",
)


def extract_function(source, name):
    """Find a C definition and balance braces, ignoring strings/comments."""
    pattern = (r"(?m)^(?:static\s+)?(?:inline\s+)?(?:void|int)\s+"
               + re.escape(name) + r"\s*\([^;]*?\)\s*\{")
    match = re.search(pattern, source)
    if match is None:
        raise ValueError(f"Missing function definition: {name}")
    depth = 1
    index = match.end()
    state = "code"
    while index < len(source):
        char = source[index]
        following = source[index:index + 2]
        if state in ("string", "char"):
            if char == "\\":
                index += 2
                continue
            if char == ('"' if state == "string" else "'"):
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if following == "*/":
                state = "code"
                index += 2
                continue
        elif following in ("//", "/*"):
            state = "line_comment" if following == "//" else "block_comment"
            index += 2
            continue
        elif char in ('"', "'"):
            state = "string" if char == '"' else "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 1]
        index += 1
    raise ValueError(f"Unterminated function definition: {name}")


HARNESS_PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(4,9,337)
#define KSU_PATCH_TEXT_FLUSH_DCACHE 1
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
typedef uint64_t u64;
typedef int (*write_op_fn)(void*,char*,size_t);
static int original(void *a,char *b,size_t c) {(void)a;(void)b;(void)c;return 0;}
static int installed(void *a,char *b,size_t c) {(void)a;(void)b;(void)c;return 0;}
static write_op_fn context_slot, access_slot, setprocattr_slot;
static write_op_fn *context_write=&context_slot,*access_write=&access_slot;
static write_op_fn orig_context_write,orig_access_write,ksu_orig_setprocattr;
static uintptr_t selinux_setprocattr_hook_ptr;
static bool ksu_selinux_hide_running,ksu_selinux_hide_enabled,ksu_selinux_hide_cleanup_pending;
static int selinux_hide_mutex;
struct policydb { int unused; };
struct sidtab { int unused; };
static struct policydb policy_resource,*backup_policydb;
static struct sidtab sid_resource,*backup_sidtab;
static void *failing_slot;
static int enable_calls,destroy_calls;
static void mutex_lock(int *m) {(void)m;}
static void mutex_unlock(int *m) {(void)m;}
static void sidtab_destroy(struct sidtab *s) {(void)s;destroy_calls++;}
static void ksu_destroy_policydb(struct policydb *p) {(void)p;}
static void kfree(void *p) {(void)p;}
static int ksu_patch_text(void *dst,void *value,size_t size,int flags) {
    (void)flags;
    if (dst == failing_slot) return -EIO;
    memcpy(dst,value,size);
    return 0;
}
static int ksu_selinux_hide_enable(void) {enable_calls++; return 0;}
static void reset(bool running) {
    context_slot=access_slot=setprocattr_slot=installed;
    orig_context_write=orig_access_write=ksu_orig_setprocattr=original;
    selinux_setprocattr_hook_ptr=(uintptr_t)&setprocattr_slot;
    ksu_selinux_hide_running=ksu_selinux_hide_enabled=running;
    ksu_selinux_hide_cleanup_pending=false;
    failing_slot=NULL;
    enable_calls=destroy_calls=0;
    backup_policydb=&policy_resource;
    backup_sidtab=&sid_resource;
}
"""

HARNESS_MAIN = r"""
int main(void) {
    u64 value=99;
    reset(true);
    assert(selinux_hide_feature_set(0)==0);
    assert(!ksu_selinux_hide_running && !ksu_selinux_hide_enabled);
    assert(!ksu_selinux_hide_cleanup_pending);
    assert(!orig_context_write && !orig_access_write && !ksu_orig_setprocattr);
    assert(context_slot==original && access_slot==original && setprocattr_slot==original);
    ksu_selinux_hide_drop_backup_if_unused();
    assert(!backup_policydb && !backup_sidtab && destroy_calls==1);
    puts("PASS: successful disable restores callbacks and releases unused backup");

    void *slots[]={&context_slot,&access_slot,&setprocattr_slot};
    for(unsigned int i=0;i<3;i++) {
        reset(true);
        failing_slot=slots[i];
        assert(selinux_hide_feature_set(0)==-EIO);
        assert(ksu_selinux_hide_running && ksu_selinux_hide_enabled);
        assert(ksu_selinux_hide_cleanup_pending);
        assert((i==0?orig_context_write:i==1?orig_access_write:ksu_orig_setprocattr)==original);
        assert(selinux_hide_feature_get(&value)==-EAGAIN);
        ksu_selinux_hide_drop_backup_if_unused();
        assert(backup_policydb && backup_sidtab && !destroy_calls);
        failing_slot=NULL;
        assert(selinux_hide_feature_set(0)==0);
        assert(!ksu_selinux_hide_running && !ksu_selinux_hide_enabled && !ksu_selinux_hide_cleanup_pending);
        assert(!orig_context_write && !orig_access_write && !ksu_orig_setprocattr);
        ksu_selinux_hide_drop_backup_if_unused();
        assert(!backup_policydb && !backup_sidtab && destroy_calls==1);
    }
    puts("PASS: each restore failure retains its original callback and backup; disable retry completes");

    reset(false);
    failing_slot=&context_slot;
    assert(ksu_selinux_hide_unhook()==-EIO);
    assert(ksu_selinux_hide_cleanup_pending && !ksu_selinux_hide_running);
    ksu_selinux_hide_drop_backup_if_unused();
    assert(backup_policydb && backup_sidtab && !destroy_calls);
    assert(selinux_hide_feature_set(1)==-EIO && !enable_calls);
    assert(!ksu_selinux_hide_running && !ksu_selinux_hide_enabled);
    failing_slot=NULL;
    assert(selinux_hide_feature_set(1)==0 && enable_calls==1);
    assert(ksu_selinux_hide_running && ksu_selinux_hide_enabled && !ksu_selinux_hide_cleanup_pending);
    puts("PASS: partial initialization rollback blocks enabling until cleanup succeeds");

    reset(false);
    failing_slot=&context_slot;
    assert(ksu_selinux_hide_unhook()==-EIO);
    failing_slot=NULL;
    assert(selinux_hide_feature_set(0)==0 && !enable_calls);
    assert(!ksu_selinux_hide_running && !ksu_selinux_hide_enabled && !ksu_selinux_hide_cleanup_pending);
    puts("PASS: failed initialization rollback can be retried as a disable");

    reset(true);
    failing_slot=&context_slot;
    assert(selinux_hide_feature_set(0)==-EIO);
    failing_slot=NULL;
    assert(selinux_hide_feature_set(1)==0 && enable_calls==1);
    assert(ksu_selinux_hide_running && ksu_selinux_hide_enabled && !ksu_selinux_hide_cleanup_pending);
    puts("PASS: failed disable is cleaned up before a new enable");
    return 0;
}
"""


def source_file(value):
    path = Path(value)
    if path.is_dir():
        for suffix in ("KernelSU/kernel/feature/selinux_hide.c",
                       "kernel/feature/selinux_hide.c",
                       "feature/selinux_hide.c"):
            candidate = path / suffix
            if candidate.is_file():
                return candidate
        raise ValueError(f"No BakaSU SELinux source in {path}")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(Path(__file__).resolve().parents[2]
                        / "kernel/KernelSU/kernel/feature/selinux_hide.c"),
                        help="selinux_hide.c, kernel root, or BakaSU checkout")
    args = parser.parse_args()
    try:
        path = source_file(args.source)
        source = path.read_text(encoding="utf-8")
        definitions = [extract_function(source, name) for name in FUNCTIONS]
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler:
            raise ValueError("CC cannot be empty")
        with tempfile.TemporaryDirectory(prefix="selinux-cleanup-") as temporary:
            root = Path(temporary)
            test_source = root / "cleanup.c"
            binary = root / "cleanup"
            test_source.write_text(HARNESS_PREFIX + "\n\n".join(definitions)
                                   + HARNESS_MAIN, encoding="utf-8")
            subprocess.run(compiler + ["-O2", "-UNDEBUG", "-Wall", "-Wextra", "-Werror",
                           str(test_source), "-o", str(binary)], check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=10)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"SELinux cleanup regression failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
