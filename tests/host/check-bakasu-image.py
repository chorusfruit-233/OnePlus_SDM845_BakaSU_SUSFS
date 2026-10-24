#!/usr/bin/env python3
"""Check real preinit embedding and exact-name blacklist lookup in vmlinux."""
import argparse
from pathlib import Path
import struct
import subprocess


def segments(data):
    assert data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64"
    assert struct.unpack_from("<H", data, 18)[0] == 183, "expected AArch64 ELF"
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    assert size >= 56
    for index in range(count):
        yield struct.unpack_from("<IIQQQQQQ", data, offset + size * index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vmlinux", type=Path, required=True)
    parser.add_argument("--runner", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--nm", default="aarch64-linux-gnu-nm")
    args = parser.parse_args()
    if args.source:
        for name in ("arch/arm64/include/generated", "include/generated"):
            assert not (args.source / name).exists(), f"generated files leaked into source tree: {name}"
    symbols = {}
    output = subprocess.check_output([args.nm, "--defined-only", str(args.vmlinux)], text=True)
    for line in output.splitlines():
        columns = line.split()
        if len(columns) == 3:
            symbols.setdefault(columns[2], []).append(int(columns[0], 16))
    assert len(symbols.get("module_blacklist", [])) == 1, "ambiguous kernel module_blacklist symbol"
    assert len(symbols.get("ksu_module_blacklist_slot", [])) == 1, "driver private slot missing"
    for name in ("ksu_handle_init_module", "ksu_handle_finit_module", "ksu_setup_preinit_file",
                 "ksu_preinit_handle_post_execveat", "ksu_preinit_runner_start", "ksu_preinit_runner_end",
                 "susfs_set_priority_uid_filter", "susfs_is_priority_uid_filtered", "hm_encode_fh",
                 "cake_qdisc_ops"):
        assert len(symbols.get(name, [])) == 1, f"missing or ambiguous {name}"
    runner = args.runner.read_bytes()
    assert struct.unpack_from("<H", runner, 16)[0] == 2, "preinit runner must be executable"
    assert all(header[0] not in (2, 3) for header in segments(runner)), "runner has a dynamic dependency"
    start, end = (symbols[name][0] for name in ("ksu_preinit_runner_start", "ksu_preinit_runner_end"))
    assert end - start == len(runner), "embedded preinit length differs"
    image = args.vmlinux.read_bytes()
    for kind, flags, offset, address, physical, size, memory_size, align in segments(image):
        if kind == 1 and address <= start and end <= address + size:
            begin = offset + start - address
            assert image[begin:begin + len(runner)] == runner, "embedded preinit bytes differ"
            break
    else:
        raise AssertionError("embedded preinit is outside file-backed load segments")
    print("PASS: unique kernel blacklist symbol, linked hooks and exact static AArch64 preinit ELF embedding")


if __name__ == "__main__":
    main()
