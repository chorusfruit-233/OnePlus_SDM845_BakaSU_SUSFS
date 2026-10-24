#!/usr/bin/env python3
"""Run real hm1/ext4/inotify, CAKE and memcg-swap checks in a disposable guest."""
import argparse
import gzip
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile

cpio_entry = runpy.run_path(str(Path(__file__).with_name("run-freezer-qemu.py")))["cpio_entry"]

CASES = (
    "memcg_swap_enabled_by_default", "hm_protocol_and_uid_cursor",
    "hm_redirect_stat_readdir_xattr", "hm_ext4_inotify_fdinfo",
    "hm_rule_replacement_uid_and_whiteout", "hm_parent_conversion_and_open_fd_lifetime",
    "cake_modern_netlink_configuration", "cake_packet_delivery_and_statistics",
)

INIT = b"""#!/bin/sh
set -x
export PATH=/bin
trap 'echo COMPONENTS_QEMU_FAIL; /control --shutdown' EXIT
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
/bin/busybox mkdir -p /testfs /tmp/memcg || exit 1
/bin/busybox mknod /dev/loop0 b 7 0 2>/dev/null || true
/bin/busybox losetup /dev/loop0 /fs.img || exit 1
mount -t ext4 /dev/loop0 /testfs || exit 1
mount -t cgroup -o memory none /tmp/memcg || exit 1
if /components.test; then echo COMPONENTS_QEMU_PASS; else echo COMPONENTS_QEMU_FAIL; fi
/control --shutdown
exit 1
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kernel", "busybox", "test", "control", "log"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--qemu", default=os.environ.get("QEMU_AARCH64", "qemu-system-aarch64"))
    parser.add_argument("--mke2fs", default="mke2fs")
    args = parser.parse_args()
    qemu, mke2fs = shutil.which(args.qemu), shutil.which(args.mke2fs)
    if not qemu or not mke2fs:
        parser.error("install qemu-system-arm and e2fsprogs, or pass --qemu and --mke2fs")
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="components-qemu-") as directory:
        directory = Path(directory)
        image = directory / "ext4.img"
        with image.open("wb") as output:
            output.truncate(32 * 1024 * 1024)
        # Keep the fixture mountable on 4.9 with modern host e2fsprogs.
        subprocess.run([mke2fs, "-q", "-F", "-t", "ext4", "-b", "4096", "-I", "256",
                        "-O", "^orphan_file,^metadata_csum_seed", str(image)], check=True)
        entries = [(name, b"", 0o040755, (0, 0)) for name in
                   (".", "bin", "dev", "proc", "sys", "tmp", "testfs")]
        entries += [("dev/console", b"", 0o020600, (5, 1)),
                    ("init", INIT, 0o100755, (0, 0)),
                    ("fs.img", image.read_bytes(), 0o100600, (0, 0)),
                    ("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)),
                    ("bin/sh", b"busybox", 0o120777, (0, 0)),
                    ("bin/mount", b"busybox", 0o120777, (0, 0)),
                    ("components.test", args.test.read_bytes(), 0o100755, (0, 0)),
                    ("control", args.control.read_bytes(), 0o100755, (0, 0)),
                    ("TRAILER!!!", b"", 0, (0, 0))]
        archive = b"".join(cpio_entry(name, data, i, mode, rdev)
                           for i, (name, data, mode, rdev) in enumerate(entries, 1))
        initrd = directory / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", "cortex-a57", "-m", "1024", "-smp", "2",
                   "-nographic", "-nodefaults", "-serial", "stdio", "-monitor", "none", "-no-reboot",
                   "-kernel", str(args.kernel.resolve()), "-initrd", str(initrd), "-append",
                   "console=ttyAMA0 rdinit=/init panic=-1 random.trust_cpu=on freezer_backport_qemu=1"]
        with args.log.open("w") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=120)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"Component regression guest timed out; see {args.log}")
    output = args.log.read_text(errors="replace").replace("\r\n", "\n")
    if result.returncode or "COMPONENTS_QEMU_PASS\n" not in output or re.search(
            r"FAIL |Kernel panic|BUG:|WARNING:", output):
        raise SystemExit(f"Component runtime regression failed; see {args.log}")
    for case in CASES:
        if f"PASS components_{case}\n" not in output:
            raise SystemExit(f"Missing executed component case {case}; see {args.log}")
    print(f"PASS: {len(CASES)} real Hybrid Mount/CAKE/memcg cases on 4.9; log: {args.log}")


if __name__ == "__main__":
    main()
