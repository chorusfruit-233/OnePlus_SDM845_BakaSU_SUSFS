#!/usr/bin/env python3
"""Run the AK3 kernel-only path on synthetic boot images, without device writes.

Executes the fetched AK3 split_boot/flash_boot and packaged ARM magiskboot using
qemu-arm. Partition discovery, blockdev and the zero-fill are mocked. All writes
target temporary regular files. No CPIO extraction/rebuild is permitted.
"""
import argparse
import gzip
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile


def cpio_entry(name, data, inode, mode, uid=0, gid=0, links=1):
    name = name.encode() + b"\0"
    fields = (inode, mode, uid, gid, links, 123456, len(data), 0, 0, 0, 0, len(name), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    prefix = header + name
    return prefix + b"\0" * (-len(prefix) % 4) + data + b"\0" * (-len(data) % 4)


def boot_image(version, kernel, ramdisk):
    page = 4096
    header = struct.pack("<8s10I16s512s32s1024s", b"ANDROID!", len(kernel),
                         0x80008000, len(ramdisk), 0x81000000, 0, 0,
                         0x80000100, page, version, 0, b"fajita", b"fixture=preserve",
                         bytes(32), bytes(1024))
    if version == 2:
        header += struct.pack("<IQIIQ", 0, 0, 1660, 0, 0)
    padded = lambda data: data + bytes(-len(data) % page)
    image = padded(header) + padded(kernel) + padded(ramdisk)
    return image + bytes(256 * 1024 - len(image))


def dtb(label):
    value = label.encode() + b"\0"
    tree = (struct.pack(">I4sIII", 1, bytes(4), 3, len(value), 0) + value +
            bytes(-len(value) % 4) + struct.pack(">II", 2, 9))
    strings = b"compatible\0"
    header = struct.pack(">10I", 0xd00dfeed, 56 + len(tree) + len(strings),
                         56, 56 + len(tree), 40, 17, 16, 0, len(strings), len(tree))
    return header + bytes(16) + tree + strings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    builder = Path(__file__).resolve().parents[2]
    parser.add_argument("--anykernel", type=Path, default=builder / "anykernel3")
    parser.add_argument("--template", type=Path, default=builder / "ak3/anykernel.sh")
    args = parser.parse_args()
    source = args.anykernel.resolve()
    qemu = os.environ.get("QEMU_ARM") or shutil.which("qemu-arm")
    if not qemu:
        parser.error("install qemu-user or set QEMU_ARM to qemu-arm")
    core = (source / "tools/ak3-core.sh").read_text()
    assert re.search(r"\nsetup_ak;\s*$", core), "AK3 setup entry point changed"
    # Keep the upstream functions intact; only replace device services and
    # reject the archive extraction/rebuild paths this package does not need.
    mocks = r"""
setup_ak() { BLOCK=$AKHOME/partition.img; CUSTOMDD=bs=1048576; }
blockdev() { return 0; }
dd() {
  case " $* " in *" if=/dev/zero "*) return 0;; esac
  command dd "$@";
}
unpack_ramdisk() { echo 'Unexpected ramdisk extraction' >&2; exit 71; }
repack_ramdisk() { echo 'Unexpected ramdisk rebuild' >&2; exit 72; }
cpio() { echo 'Unexpected cpio execution' >&2; exit 73; }
setup_ak;
"""
    core = re.sub(r"\nsetup_ak;\s*$", "\n" + mocks, core)
    archive = b"".join([
        cpio_entry(".", b"", 1, 0o40750),
        cpio_entry("init", b"system/bin/init", 2, 0o120777),
        cpio_entry("hardlink-a", b"", 3, 0o100640, 1000, 2000, 2),
        cpio_entry("hardlink-b", b"keep permissions, owners and links\n", 3,
                   0o100640, 1000, 2000, 2),
        cpio_entry("TRAILER!!!", b"", 0, 0),
    ])
    magiskboot = [qemu, str(source / "tools/magiskboot")]

    def run(command, cwd):
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"Command failed: {command[0]}\n{result.stdout}\n{result.stderr}")

    with tempfile.TemporaryDirectory(prefix="ak3-ramdisk-") as temp:
        for version in (0, 2):
            for compression in ("gzip", "lz4_legacy"):
                root = Path(temp) / f"v{version}-{compression}"
                (root / "tools").mkdir(parents=True)
                (root / "tools/ak3-core.sh").write_text(core)
                wrapper = root / "tools/magiskboot"
                wrapper.write_text("#!/bin/sh\nexec " + shlex.join(magiskboot) + ' "$@"\n')
                wrapper.chmod(0o755)
                (root / "original.cpio").write_bytes(archive)
                if compression == "gzip":
                    ramdisk = gzip.compress(archive, mtime=0)
                else:
                    run(magiskboot + ["compress=lz4_legacy", "original.cpio", "compressed"], root)
                    ramdisk = (root / "compressed").read_bytes()
                original = boot_image(version, gzip.compress(b"original kernel") +
                                      dtb("fixture,original"), ramdisk)
                (root / "partition.img").write_bytes(original)
                replacement = b"replacement kernel" * 100
                replacement_dtb = dtb("fixture,replacement")
                (root / "Image.gz-dtb").write_bytes(gzip.compress(replacement) + replacement_dtb)
                shutil.copyfile(args.template, root / "anykernel.sh")
                # No mkbootfs is installed: model the new manager's environment.
                environment = dict(os.environ, AKHOME=str(root), OUTFD="1",
                                   PATH=str(root / "tools") + os.pathsep + os.environ["PATH"])
                result = subprocess.run(["bash", "anykernel.sh"], cwd=root, env=environment,
                                        capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError(f"AK3 failed:\n{result.stdout}\n{result.stderr}")
                flashed = (root / "partition.img").read_bytes()
                assert flashed == (root / "boot-new.img").read_bytes()
                assert flashed != original
                assert struct.unpack_from("<I", flashed, 40)[0] == version
                assert flashed[64:576] == original[64:576], "cmdline changed"
                verify = root / "verify"
                verify.mkdir()
                run(magiskboot + ["unpack", "-h", str(root / "partition.img")], verify)
                assert (verify / "ramdisk.cpio").read_bytes() == archive, "ramdisk CPIO changed"
                assert (verify / "kernel").read_bytes() == replacement, "kernel not replaced"
                kernel_size = struct.unpack_from("<I", flashed, 8)[0]
                assert flashed[4096:4096 + kernel_size].endswith(replacement_dtb), "appended DTB not replaced"
                print(f"PASS: boot v{version}, {compression}: kernel/DTB replaced; ramdisk CPIO unchanged")


if __name__ == "__main__":
    main()
