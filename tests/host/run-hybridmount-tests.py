#!/usr/bin/env python3
"""Run the vendored Hybrid Mount regression fixtures against the prepared port.

These compile actual production functions with mocked kernel primitives. They
verify lifetime/error/dispatch boundaries, not VFS ABI or Android behavior.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="prepared kernel directory")
    args = parser.parse_args()
    environment = dict(os.environ, HYBRIDMOUNT_SOURCE=str(
        (args.source / "fs/hybridmount/hybridmount.c").resolve()))
    fixtures = Path(__file__).with_name("hybridmount")
    for name in ("uid_cursor", "child_rules", "hook_transaction", "inode_lifecycle",
                 "reader_lifetime", "vfs_semantics"):
        print(f"Hybrid Mount: {name}", flush=True)
        subprocess.run([sys.executable, str(fixtures / f"{name}.py")],
                       env=environment, check=True)


if __name__ == "__main__":
    main()
