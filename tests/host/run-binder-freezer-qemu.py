#!/usr/bin/env python3
"""Check real Binder transactions and cgroup freezing in a disposable guest."""
import argparse
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

TESTS = (
    "interface", "sync_rejected", "async_cgroup", "pending_rollback",
    "timeout_rollback", "wait_drain", "interrupted_rollback", "outgoing_pending",
    "thread_exit", "process_exit", "delivery_fault", "exit_during_wait",
    "multiple_contexts", "repeated_cycles",
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
    parser.add_argument("--test", required=True, type=Path)
    parser.add_argument("--compat-test", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=180)
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
/bin/busybox mkdir -p /sys/fs/cgroup || exit 1
mount -t cgroup2 none /sys/fs/cgroup || exit 1
failed=0
echo BINDER_ARM64_BEGIN
/binder-freezer.test || failed=1
echo BINDER_ARM64_END
echo BINDER_ARM32_BEGIN
/binder-freezer-arm32.test || failed=1
echo BINDER_ARM32_END
if [ "$failed" = 0 ]; then echo BINDER_FREEZER_QEMU_PASS; else echo BINDER_FREEZER_QEMU_FAIL; fi
/binder-freezer.test --shutdown
exit 1
"""
    entries = [(name, b"", 0o040755, (0, 0)) for name in
               (".", "bin", "dev", "proc", "sys", "tmp")]
    entries += [("dev/console", b"", 0o020600, (5, 1)),
                ("init", init, 0o100755, (0, 0)),
                ("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)),
                ("bin/sh", b"busybox", 0o120777, (0, 0)),
                ("bin/mount", b"busybox", 0o120777, (0, 0)),
                ("binder-freezer.test", args.test.read_bytes(), 0o100755, (0, 0)),
                ("binder-freezer-arm32.test", args.compat_test.read_bytes(), 0o100755, (0, 0)),
                ("TRAILER!!!", b"", 0, (0, 0))]
    archive = b"".join(cpio_entry(name, data, i, mode, rdev)
                       for i, (name, data, mode, rdev) in enumerate(entries, 1))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="binder-freezer-qemu-") as temporary:
        initrd = Path(temporary) / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", "cortex-a57", "-m", "1024",
                   "-smp", str(args.cpus), "-nographic", "-nodefaults", "-serial", "stdio",
                   "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel.resolve()),
                   "-initrd", str(initrd), "-object", "rng-random,id=rng0,filename=/dev/urandom",
                   "-device", "virtio-rng-device,rng=rng0", "-append",
                   "console=ttyAMA0 rdinit=/init panic=-1 random.trust_cpu=on binder_freezer_backport_qemu=1"]
        with args.log.open("w") as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"Binder freezer QEMU timed out; see {args.log}")
    output = args.log.read_text(errors="replace").replace("\r\n", "\n")
    if result.returncode or "BINDER_FREEZER_QEMU_PASS\n" not in output or re.search(
            r"not ok|# SKIP|FAIL |Kernel panic|BUG:|WARNING:", output):
        raise SystemExit(f"Binder freezer regression failed; see {args.log}")
    for bits in (64, 32):
        section = re.search(rf"BINDER_ARM{bits}_BEGIN\n(.*?)BINDER_ARM{bits}_END\n", output, re.S)
        if not section or f"BINDER_FREEZER_ABI={bits}\n" not in section[1]:
            raise SystemExit(f"Missing actual ARM{bits} execution; see {args.log}")
        for test in TESTS:
            if f"PASS binder_{test}\n" not in section[1]:
                raise SystemExit(f"Missing ARM{bits} Binder {test} result; see {args.log}")
    print(f"PASS: {len(TESTS)} Binder freezer transaction tests on ARM64 and ARM32, "
          f"{args.cpus} CPUs; log: {args.log}")


if __name__ == "__main__":
    main()
