#!/usr/bin/env python3
"""Exercise upstream ARM64 ABI helpers and syscall generation for Linux 4.9.

Uses the actual BakaSU header/generator and the prepared kernel's unistd32.h.
Kernel register/task services are mocked; this does not test device syscalls.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
static int compat_task;
struct pt_regs { unsigned long regs[31], sp, pc; };
#include "arch.h"
#include "syscall_no.h"

int main(void)
{
    struct pt_regs regs = {0};
    (void)compat_task;
    regs.regs[0] = 0xfeedface12345678UL;
    regs.regs[1] = 0xabcdef0187654321UL;
    regs.regs[3] = 0xfeedface87654321UL;
    regs.regs[7] = 11;
    regs.regs[8] = 221;
    assert(PT_REGS_PARM1(&regs) == regs.regs[0]);
    assert((uintptr_t)PT_REGS_USER_PTR(&regs, 2) == regs.regs[1]);
    assert(PT_REGS_ORIG_SYSCALL(&regs) == 221);
    assert(ksu_get_syscall_no(reboot) == 142);
    assert(ksu_get_syscall_no(execveat) == 281);
#ifdef CONFIG_COMPAT
    _Static_assert(__NR_compat32_read == 3, "AArch32 read ABI");
    _Static_assert(__NR_compat32_execve == 11, "AArch32 execve ABI");
    _Static_assert(__NR_compat32_reboot == 88, "AArch32 reboot ABI");
    _Static_assert(__NR_compat32_fstat64 == 197, "AArch32 fstat64 ABI");
    _Static_assert(__NR_compat32_execveat == 387, "AArch32 execveat ABI");
    compat_task = 1;
    assert(PT_REGS_PARM1(&regs) == 0x12345678UL);
    assert((uintptr_t)PT_REGS_USER_PTR(&regs, 2) == 0x87654321UL);
    assert((uintptr_t)PT_REGS_SYSCALL_PARM1_USER_PTR(&regs) == 0x12345678UL);
    assert(PT_REGS_ORIG_SYSCALL(&regs) == 11);
    PT_REGS_ORIG_SYSCALL(&regs) = 387;
    assert(regs.regs[7] == 387 && regs.regs[8] == 221);
    assert(ksu_get_syscall_no(reboot) == 88);
    assert(ksu_get_syscall_no(execveat) == 387);
    assert(ksu_get_compat_syscall_no(read) == 3);
    /* Kernel C calls and writable slots retain the full native register. */
    assert(PT_REGS_CCALL_PARM4(&regs) == 0xfeedface87654321UL);
    PT_REGS_NATIVE_PARM2(&regs) = 0xabcdef0112345678UL;
    assert(regs.regs[1] == 0xabcdef0112345678UL);
    assert((uintptr_t)PT_REGS_USER_PTR(&regs, 2) == 0x12345678UL);
    compat_task = 0;
    PT_REGS_ORIG_SYSCALL(&regs) = 281;
    assert(regs.regs[8] == 281 && regs.regs[7] == 387);
#endif
    return 0;
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).resolve().parents[2] / "kernel",
                        help="prepared Linux kernel source directory")
    args = parser.parse_args()
    kernel = args.source.resolve()
    ksu = kernel / "KernelSU/kernel"
    compiler = shlex.split(os.environ.get("CC", "cc"))

    def run(command):
        subprocess.run(command, check=True)

    with tempfile.TemporaryDirectory(prefix="bakasu-compat-") as temp:
        root = Path(temp)
        stubs = {
            "linux/version.h": "#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))\n"
                               "#define LINUX_VERSION_CODE KERNEL_VERSION(4,9,337)\n",
            "linux/types.h": "#pragma once\ntypedef unsigned int u32;\n#define __user\n",
            "linux/compat.h": "#pragma once\ntypedef unsigned int compat_uptr_t;\n"
                              "#define is_compat_task() compat_task\n"
                              "static inline void *compat_ptr(compat_uptr_t p) "
                              "{ return (void *)(unsigned long)p; }\n",
            "asm/unistd.h": "#define __NR_reboot 142\n#define __NR_execveat 281\n",
            "asm/syscall.h": "/* kernel syscall services are not used here */\n",
        }
        for name, content in stubs.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        generator = root / "syscall_no"
        run(compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(ksu / "tools/code_generation/syscall_no/syscall_no.c"),
                        "-o", str(generator)])
        harness = root / "harness.c"
        harness.write_text(HARNESS)
        for compat in (True, False):
            flags = ["--arm64-compat", str(kernel / "arch/arm64/include/asm/unistd32.h")] \
                if compat else ["--arm64"]
            run([str(generator), str(root / "syscall_no.h")] + flags)
            output = root / "harness"
            defines = ["-DCONFIG_COMPAT=1"] if compat else []
            run(compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            "-D__aarch64__=1"] + defines +
                ["-I", str(root), "-I", str(ksu / "include"),
                 str(harness), "-o", str(output)])
            run([str(output)])
            print(f"PASS: ARM64 registers, pointers and syscall numbers "
                  f"(CONFIG_COMPAT={'y' if compat else 'n'})")


if __name__ == "__main__":
    main()
