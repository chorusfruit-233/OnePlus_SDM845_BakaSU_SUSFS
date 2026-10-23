#!/usr/bin/env python3
"""Run upstream and supplemental freezer tests in a disposable ARM64 guest."""
import argparse
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

UPSTREAM_TESTS = (
    "simple", "tree", "forkbomb", "mkdir", "rmdir", "migrate", "ptrace",
    "stopped", "ptraced", "vfork",
)
BACKPORT_TESTS = (
    "interface", "threads_and_signals", "hierarchy", "migration", "fork_race",
    "ptrace_detach", "job_stop_preserved", "legacy_coexistence",
)


def cpio_entry(name, data, inode, mode, rdev=(0, 0)):
    name = name.encode() + b"\0"
    fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, *rdev, len(name), 0)
    prefix = b"070701" + b"".join(f"{v:08x}".encode() for v in fields) + name
    return prefix + bytes(-len(prefix) % 4) + data + bytes(-len(data) % 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--busybox", required=True, type=Path)
    parser.add_argument("--upstream-test", required=True, type=Path)
    parser.add_argument("--backport-test", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--cpus", type=int, choices=range(1, 9), default=2)
    parser.add_argument("--qemu", default=os.environ.get("QEMU_AARCH64", "qemu-system-aarch64"))
    args = parser.parse_args()
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("install qemu-system-arm or set --qemu")
    init = b"""#!/bin/sh
export PATH=/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
/bin/busybox mkdir -p /sys/fs/cgroup /tmp/cgroup-v1 || exit 1
mount -t cgroup2 none /sys/fs/cgroup || exit 1
mount -t cgroup -o freezer freezer /tmp/cgroup-v1 || exit 1
failed=0
/test_freezer || failed=1
/backport.test || failed=1
if [ "$failed" = 0 ]; then echo FREEZER_QEMU_PASS; else echo FREEZER_QEMU_FAIL; fi
/backport.test --shutdown
exit 1
"""
    entries = [(d, b"", 0o040755, (0, 0)) for d in
               (".", "bin", "dev", "proc", "sys", "tmp")]
    entries += [("dev/console", b"", 0o020600, (5, 1)),
                ("init", init, 0o100755, (0, 0)),
                ("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)),
                ("bin/sh", b"busybox", 0o120777, (0, 0)),
                ("bin/mount", b"busybox", 0o120777, (0, 0)),
                ("test_freezer", args.upstream_test.read_bytes(), 0o100755, (0, 0)),
                ("backport.test", args.backport_test.read_bytes(), 0o100755, (0, 0)),
                ("TRAILER!!!", b"", 0, (0, 0))]
    archive = b"".join(cpio_entry(name, data, i, mode, rdev)
                       for i, (name, data, mode, rdev) in enumerate(entries, 1))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="freezer-qemu-") as temporary:
        initrd = Path(temporary) / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", "cortex-a57", "-m", "1024",
                   "-smp", str(args.cpus), "-nographic", "-nodefaults", "-serial", "stdio",
                   "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel.resolve()),
                   "-initrd", str(initrd),
                   "-object", "rng-random,id=rng0,filename=/dev/urandom",
                   "-device", "virtio-rng-device,rng=rng0", "-append",
                   "console=ttyAMA0 rdinit=/init panic=-1 random.trust_cpu=on freezer_backport_qemu=1"]
        with args.log.open("w") as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"Freezer QEMU timed out; see {args.log}")
    output = args.log.read_text(errors="replace").replace("\r\n", "\n")
    if result.returncode or "FREEZER_QEMU_PASS\n" not in output or re.search(
            r"not ok|# SKIP|FAIL |Kernel panic|BUG:|WARNING:", output):
        raise SystemExit(f"Freezer regression failed; see {args.log}")
    for test in UPSTREAM_TESTS:
        if not re.search(rf"^ok \d+ test_cgfreezer_{test}$", output, re.M):
            raise SystemExit(f"Missing upstream {test} result; see {args.log}")
    for test in BACKPORT_TESTS:
        if f"PASS test_{test}\n" not in output:
            raise SystemExit(f"Missing supplemental {test} result; see {args.log}")
    print(f"PASS: 10 upstream + 8 supplemental freezer tests, {args.cpus} CPUs; log: {args.log}")


if __name__ == "__main__":
    main()
