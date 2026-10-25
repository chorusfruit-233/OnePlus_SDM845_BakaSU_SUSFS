#!/usr/bin/env python3
"""Verify clean, reproducible source commits using real nested Git repositories."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/source_revisions.py"


def git(repo, *args, **kwargs):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, **kwargs).strip()


def setup(root):
    upstream = {}
    for name in (".", "KernelSU", "Baseband-guard"):
        repo = root / name
        repo.mkdir(parents=True, exist_ok=True)
        git(repo, "init", "--quiet")
        (repo / "source.c").write_text("upstream\n")
        (repo / ".gitignore").write_text("*.bin\n*.fw\n*.o\n")
        git(repo, "add", "source.c", ".gitignore")
        env = dict(os.environ, GIT_AUTHOR_NAME="Upstream", GIT_AUTHOR_EMAIL="upstream@localhost",
                   GIT_COMMITTER_NAME="Upstream", GIT_COMMITTER_EMAIL="upstream@localhost",
                   GIT_AUTHOR_DATE="1700000000 +0000", GIT_COMMITTER_DATE="1700000000 +0000")
        git(repo, "-c", "commit.gpgSign=false", "commit", "--quiet", "-m", "Upstream", env=env)
        git(repo, "checkout", "--quiet", "--detach")
        git(repo, "tag", "v1.0")
        upstream[name] = git(repo, "rev-parse", "HEAD")
        (repo / "source.c").write_text("adapted\n")
        (repo / "new.h").write_text("new integration\n")
        # The source commit must not depend on the CI runner's Git identity.
        git(repo, "config", "user.name", str(root))
        git(repo, "config", "user.email", "different-runner@localhost")
    for name in ("htc_9271.fw", "rt2870.bin", "mt7601u.bin"):
        firmware = root / "firmware" / name
        firmware.parent.mkdir(exist_ok=True)
        firmware.write_bytes(b"firmware-input")
    for name in ("out", "out-bpf-qemu", "out-bakasu-fresh-phone"):
        directory = root / name
        directory.mkdir()
        (directory / "do-not-commit.c").write_text("generated output\n")
    marker = root / "KernelSU/kernel/.susfs-4.9-auto-reviewed"
    marker.parent.mkdir()
    marker.write_text("lineage-4.9-auto-v1\n")
    return upstream


def run(root, *args, success=True):
    result = subprocess.run([sys.executable, str(SCRIPT), str(root), *args], capture_output=True, text=True)
    assert (result.returncode == 0) == success, result.stdout + result.stderr
    return result


def manifest(root):
    directory = Path(git(root, "rev-parse", "--absolute-git-dir"))
    return json.loads((directory / "source-revisions.json").read_text())


def main():
    with tempfile.TemporaryDirectory(prefix="source-revisions-") as temporary:
        roots = [Path(temporary) / name for name in ("first", "second")]
        for root in roots:
            upstream = setup(root)
            run(root)
            run(root, "--check")
            data = manifest(root)
            for name, key in ((".", "kernel"), ("KernelSU", "bakasu"), ("Baseband-guard", "baseband_guard")):
                repo = root / name
                assert run(repo, "--upstream").stdout.strip() == upstream[name]
                assert git(repo, "rev-parse", "v1.0") == upstream[name]
                assert git(repo, "show", "HEAD:source.c") == "adapted"
                assert git(repo, "show", "HEAD:new.h") == "new integration"
                assert "dirty" not in git(repo, "describe", "--tags", "--dirty")
                assert git(repo, "rev-parse", "HEAD^") == upstream[name]
            entries = git(root, "ls-tree", "-r", "HEAD")
            assert "160000 commit " + data["sources"]["bakasu"]["prepared"] in entries
            assert "do-not-commit.c" not in entries
            for name in ("htc_9271.fw", "rt2870.bin", "mt7601u.bin"):
                assert git(root, "show", f"HEAD:firmware/{name}") == "firmware-input"
            assert git(root / "KernelSU", "show", "HEAD:kernel/.susfs-4.9-auto-reviewed") == "lineage-4.9-auto-v1"
            run(root)
            assert manifest(root) == data, "repeated preparation changed the commit"
        assert manifest(roots[0]) == manifest(roots[1]), "identical inputs produced different commits"
        print("PASS: stable commits, upstream/tag retention, firmware inputs, nested revisions and output exclusion")
        root = roots[0]
        (root / "KernelSU/source.c").write_text("changed after preparation\n")
        run(root, "--check", success=False)
        run(root, success=False)
        (root / "KernelSU/source.c").write_text("adapted\n")
        (root / "source.c").write_text("changed after preparation\n")
        run(root, "--check", success=False)
        print("PASS: later driver/kernel source changes fail verification instead of being hidden")


if __name__ == "__main__":
    main()
