#!/usr/bin/env python3
"""Run the production preinit ELF on 4.9 with disposable metadata fixtures.

This checks real nolibc syscalls/actions and return to an init stub. It does not
boot Android, load SELinux policy, or execute the phone's kernel hooks.
"""
import argparse
import gzip
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile

CASES = ("empty", "action", "unsafe_config", "bootcount", "exec_failure", "timeout")
cpio_entry = runpy.run_path(str(Path(__file__).with_name("run-binder-freezer-qemu.py")))["cpio_entry"]

INIT = b"""#!/bin/sh
export PATH=/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
export ORIGINAL_TOKEN=preserved
failed=0
run_case() {
    export EXPECT_CASE="$1"
    if /preinit-runner selinux_setup keep-argv; then
        echo "PASS preinit_$1"
    else
        echo "FAIL preinit_$1"
        failed=1
    fi
}
run_case empty
/bin/busybox mkdir -p /metadata/vold/ksu/preinit/demo
conf=/metadata/vold/ksu/preinit/demo/preinit.conf
counter=/metadata/vold/ksu/.preinit_bootcount
echo 'exec /bin/busybox sh /work/action.sh' > "$conf"
/bin/busybox chmod 600 "$conf"
run_case action
/bin/busybox rm -f /tmp/preinit-marker "$counter"
/bin/busybox chmod 666 "$conf"
run_case unsafe_config
/bin/busybox chmod 600 "$conf"
echo 3 > "$counter"
run_case bootcount
/bin/busybox rm -f "$counter"
echo 'exec /missing-program' > "$conf"
run_case exec_failure
/bin/busybox rm -f "$counter"
echo 'exec -t 200 /bin/busybox sh /work/action.sh spin' > "$conf"
run_case timeout
if [ "$failed" = 0 ]; then echo BAKASU_PREINIT_QEMU_PASS; else echo BAKASU_PREINIT_QEMU_FAIL; fi
/control --shutdown
exit 1
"""
REAL_INIT = b"""#!/bin/sh
[ "$1" = selinux_setup ] && [ "$2" = keep-argv ] && [ "$ORIGINAL_TOKEN" = preserved ] || exit 1
if [ "$EXPECT_CASE" = action ]; then
    [ "$(/bin/busybox cat /tmp/preinit-marker)" = action-ok ] || exit 1
else
    [ ! -e /tmp/preinit-marker ] || exit 1
fi
echo "RETURNED_TO_INIT_$EXPECT_CASE"
exit 0
"""
ACTION = b"""#!/bin/sh
[ "$KSU" = true ] && [ "$KSU_PREINIT" = 1 ] && [ "$MODID" = demo ] || exit 1
[ "$PREINIT_DIR" = /metadata/vold/ksu/preinit/demo ] || exit 1
if [ "$1" = spin ]; then /bin/busybox sleep 10; fi
echo action-ok > /tmp/preinit-marker
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--busybox", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--qemu", default=os.environ.get("QEMU_AARCH64", "qemu-system-aarch64"))
    args = parser.parse_args()
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("install qemu-system-arm or set --qemu")
    entries = [(name, b"", 0o040755, (0, 0)) for name in
               (".", "bin", "dev", "proc", "sys", "tmp", "system", "system/bin", "work")]
    entries += [("dev/console", b"", 0o020600, (5, 1)),
                ("init", INIT, 0o100755, (0, 0)),
                ("system/bin/init", REAL_INIT, 0o100755, (0, 0)),
                ("work/action.sh", ACTION, 0o100755, (0, 0)),
                ("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)),
                ("bin/sh", b"busybox", 0o120777, (0, 0)),
                ("bin/mount", b"busybox", 0o120777, (0, 0)),
                ("control", args.control.read_bytes(), 0o100755, (0, 0)),
                ("preinit-runner", args.runner.read_bytes(), 0o100755, (0, 0)),
                ("TRAILER!!!", b"", 0, (0, 0))]
    archive = b"".join(cpio_entry(name, data, i, mode, rdev)
                       for i, (name, data, mode, rdev) in enumerate(entries, 1))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="bakasu-preinit-qemu-") as directory:
        initrd = Path(directory) / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", "cortex-a57", "-m", "1024", "-smp", "2",
                   "-nographic", "-nodefaults", "-serial", "stdio", "-monitor", "none", "-no-reboot",
                   "-kernel", str(args.kernel.resolve()), "-initrd", str(initrd), "-append",
                   "console=ttyAMA0 rdinit=/init panic=-1 random.trust_cpu=on "
                   "freezer_backport_qemu=1 bakasu_preinit_qemu=1"]
        with args.log.open("w") as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"BakaSU preinit QEMU timed out; see {args.log}")
    output = args.log.read_text(errors="replace").replace("\r\n", "\n")
    if result.returncode or "BAKASU_PREINIT_QEMU_PASS\n" not in output or re.search(
            r"FAIL |Kernel panic|BUG:|WARNING:", output):
        raise SystemExit(f"BakaSU preinit regression failed; see {args.log}")
    for case in CASES:
        if f"PASS preinit_{case}\n" not in output or f"RETURNED_TO_INIT_{case}\n" not in output:
            raise SystemExit(f"Missing executed preinit {case} result; see {args.log}")
    if "timed out after 200 ms" not in output:
        raise SystemExit(f"Exec timeout was not exercised; see {args.log}")
    print(f"PASS: production BakaSU preinit ELF, {len(CASES)} action/failure/init-return cases on 4.9; log: {args.log}")


if __name__ == "__main__":
    main()
