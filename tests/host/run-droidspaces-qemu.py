#!/usr/bin/env python3
"""Exercise the systemd backport interfaces on real ARM64 and AArch32 syscalls."""
import argparse
import gzip
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile


cpio_entry = runpy.run_path(str(Path(__file__).with_name("run-binder-freezer-qemu.py")))["cpio_entry"]
TESTS = ("pidfd", "statx", "utimensat", "faccessat2", "close_range", "bindtoifindex",
         "peergroups", "nsfs", "ptypeer", "ptypeer_error", "nexthop")
INIT = b"""#!/bin/sh
export PATH=/bin
fail() { echo DROIDSPACES_QEMU_FAIL; /control --shutdown; exit 1; }
trap fail EXIT
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
/bin/busybox mkdir -p /dev/pts || exit 1
mount -t devpts -o ptmxmode=0666,mode=0620 devpts /dev/pts || exit 1
if [ ! -e /dev/ptmx ]; then /bin/busybox mknod /dev/ptmx c 5 2 || exit 1; fi
echo DROIDSPACES_ARM64_BEGIN
/arm64.test || exit 1
echo DROIDSPACES_ARM64_END
echo DROIDSPACES_ARM32_BEGIN
/arm32.test || exit 1
echo DROIDSPACES_ARM32_END
echo DROIDSPACES_QEMU_PASS
/control --shutdown
exit 1
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kernel", "busybox", "test", "compat-test", "control", "log"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    parser.add_argument("--qemu", default=os.environ.get("QEMU_AARCH64", "qemu-system-aarch64"))
    args = parser.parse_args()
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("install qemu-system-arm or set --qemu")
    entries = [(name, b"", 0o040755, (0, 0)) for name in
               (".", "bin", "dev", "proc", "sys", "tmp")]
    entries += [("dev/console", b"", 0o020600, (5, 1)),
                ("init", INIT, 0o100755, (0, 0)),
                ("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)),
                ("bin/sh", b"busybox", 0o120777, (0, 0)),
                ("bin/mount", b"busybox", 0o120777, (0, 0)),
                ("arm64.test", args.test.read_bytes(), 0o100755, (0, 0)),
                ("arm32.test", args.compat_test.read_bytes(), 0o100755, (0, 0)),
                ("control", args.control.read_bytes(), 0o100755, (0, 0)),
                ("TRAILER!!!", b"", 0, (0, 0))]
    archive = b"".join(cpio_entry(name, data, i, mode, rdev)
                       for i, (name, data, mode, rdev) in enumerate(entries, 1))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="droidspaces-qemu-") as temporary:
        initrd = Path(temporary) / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", "cortex-a57", "-m", "1024", "-smp", "2",
                   "-nographic", "-nodefaults", "-serial", "stdio", "-monitor", "none", "-no-reboot",
                   "-kernel", str(args.kernel.resolve()), "-initrd", str(initrd), "-object",
                   "rng-random,id=rng0,filename=/dev/urandom", "-device", "virtio-rng-device,rng=rng0",
                   "-append", "console=ttyAMA0 rdinit=/init oops=panic panic=-1 freezer_backport_qemu=1"]
        with args.log.open("w") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=120)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"Droidspaces guest timed out; see {args.log}")
    output = args.log.read_text(errors="replace").replace("\r\n", "\n")
    if result.returncode or "DROIDSPACES_QEMU_PASS\n" not in output or re.search(
            r"FAIL |DROIDSPACES_QEMU_FAIL|Kernel panic|BUG:|WARNING:", output):
        raise SystemExit(f"Droidspaces backport regression failed; see {args.log}")
    for bits in (64, 32):
        section = re.search(rf"DROIDSPACES_ARM{bits}_BEGIN\n(.*?)DROIDSPACES_ARM{bits}_END\n", output, re.S)
        if not section or f"DROIDSPACES_ABI={bits}\n" not in section[1]:
            raise SystemExit(f"Missing actual ARM{bits} execution; see {args.log}")
        for name in TESTS:
            if f"PASS droidspaces_{name}\n" not in section[1]:
                raise SystemExit(f"Missing ARM{bits} {name} result; see {args.log}")
    print(f"PASS: {len(TESTS)} Droidspaces syscall groups on ARM64 and ARM32; log: {args.log}")


if __name__ == "__main__":
    main()
