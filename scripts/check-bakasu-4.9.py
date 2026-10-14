#!/usr/bin/env python3
"""Allow new BakaSU commits whose reviewed legacy integration is unchanged."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help="BakaSU Git checkout")
    args = parser.parse_args()
    metadata = Path(__file__).resolve().parent.parent / "configs/vendored-upstreams.json"
    profile = json.loads(metadata.read_text())["susfs"]
    changed = []
    # Read committed upstream content, not the local adaptation's patched files.
    # The caller separately checks that the full local patch is present.
    for name, expected in profile["bakasu_reviewed_files"].items():
        result = subprocess.run(
            ["git", "-C", str(args.checkout), "show", f"HEAD:{name}"],
            capture_output=True,
        )
        if result.returncode or hashlib.sha256(result.stdout).hexdigest() != expected:
            changed.append(name)
    if changed:
        print("BakaSU's Linux 4.9 integration changed; update and verify the adaptation:",
              file=sys.stderr)
        for name in changed:
            print(f"  {name}", file=sys.stderr)
        return 1
    revision = subprocess.check_output(
        ["git", "-C", str(args.checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    print(f"BakaSU {revision}: reviewed 4.9 integration unchanged "
          f"(patch base {profile['bakasu_patch_base']}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
