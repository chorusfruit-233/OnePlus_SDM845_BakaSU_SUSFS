#!/usr/bin/env python3
"""Reject stale patch-audit records and verify the prepared security fixes."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    config = json.loads((ROOT / 'configs/security-backports.json').read_text())
    audit = json.loads((ROOT / 'docs/custom-patch-audit-20261105.json').read_text())
    actual = {str(p.relative_to(ROOT)) for p in (ROOT / 'patches').rglob('*.patch')}
    recorded = {row['file'] for row in audit['patches']}
    if actual != recorded:
        raise SystemExit(f'Patch audit coverage changed: {sorted(actual ^ recorded)}')
    for row in audit['patches'] + audit['integration_files']:
        if digest(ROOT / row['file']) != row['sha256']:
            raise SystemExit(f"Re-review changed integration: {row['file']}")
    for row in config['series']:
        if digest(ROOT / 'patches/lineage-4.9/security' / row['file']) != row['sha256']:
            raise SystemExit(f"Security patch checksum mismatch: {row['file']}")
    if args.source:
        for path, expected in audit['prepared_security_files'].items():
            if digest(args.source / path) != expected:
                raise SystemExit(f'Re-review changed prepared security source: {path}')
    print(f"PASS: {len(recorded)} patch records, {len(config['series'])} security/hardening patches"
          + (', prepared source hashes match' if args.source else ''))


if __name__ == '__main__':
    main()
