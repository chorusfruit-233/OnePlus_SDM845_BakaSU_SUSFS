#!/usr/bin/env python3
"""Commit prepared build sources and retain their original upstream revisions."""
import argparse
import json
import os
from pathlib import Path
import subprocess


UPSTREAM_REF = "refs/build/upstream"
PREPARED_REF = "refs/build/prepared"


def git(repo, *args, **kwargs):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, **kwargs
    ).strip()


def optional_ref(repo, ref):
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", ref],
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def upstream_commit(repo):
    """Resolve the original revision, checking any locally prepared child."""
    head = git(repo, "rev-parse", "HEAD")
    upstream = optional_ref(repo, UPSTREAM_REF)
    prepared = optional_ref(repo, PREPARED_REF)
    if upstream is None and prepared is None:
        return head
    parents = git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if not upstream or prepared != head or parents != [head, upstream]:
        raise ValueError(f"{repo}: prepared commit no longer matches its recorded upstream")
    return upstream


def check_clean(repo):
    # Like the upstream version generators, ignore untracked build outputs.
    status = git(repo, "status", "--porcelain", "--untracked-files=no")
    if status:
        raise ValueError(f"{repo}: source changed after preparation:\n{status}")


def commit_sources(repo, *, kernel=False):
    upstream = upstream_commit(repo)
    if optional_ref(repo, PREPARED_REF):
        check_clean(repo)
    else:
        if kernel:
            # Nested sources are committed separately and recorded as gitlinks.
            # Never stage any of the O= output directories used by this builder.
            git(repo, "add", "--all", "--", ".", ":(top,exclude)out",
                ":(top,exclude)out-*", ":(top,exclude)KernelSU",
                ":(top,exclude)Baseband-guard")
            git(repo, "add", "--force", "--", "firmware/htc_9271.fw",
                "firmware/rt2870.bin", "firmware/mt7601u.bin")
            for name in ("KernelSU", "Baseband-guard"):
                revision = git(repo / name, "rev-parse", "HEAD")
                git(repo, "update-index", "--add", "--cacheinfo", f"160000,{revision},{name}")
        else:
            git(repo, "add", "--all", "--", ".")
        tree = git(repo, "write-tree")
        # Content, parent and fixed metadata determine the commit, not CI time,
        # runner identity or the location/mtime of the checkout.
        timestamp = git(repo, "show", "-s", "--format=%ct", upstream)
        environment = dict(os.environ)
        for role in ("AUTHOR", "COMMITTER"):
            environment[f"GIT_{role}_NAME"] = "OnePlus SDM845 Build"
            environment[f"GIT_{role}_EMAIL"] = "kernel-build@localhost"
            environment[f"GIT_{role}_DATE"] = f"{timestamp} +0000"
        message = f"Apply OnePlus SDM845 build adaptations\n\nUpstream: {upstream}\n"
        prepared = git(repo, "-c", "commit.gpgSign=false", "commit-tree", tree,
                       "-p", upstream, input=message, env=environment)
        # Publish all three refs together, leaving the original upstream intact.
        git(repo, "update-ref", "--stdin", input=(
            f"start\nupdate HEAD {prepared} {upstream}\n"
            f"create {UPSTREAM_REF} {upstream}\n"
            f"create {PREPARED_REF} {prepared}\nprepare\ncommit\n"
        ))
        check_clean(repo)
    return {
        "upstream": upstream,
        "prepared": git(repo, "rev-parse", "HEAD"),
        "tree": git(repo, "rev-parse", "HEAD^{tree}"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="prepared kernel source directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify committed sources are unchanged")
    mode.add_argument("--upstream", action="store_true", help="print the original revision of one repository")
    args = parser.parse_args()
    root = args.source.resolve()
    if args.upstream:
        print(upstream_commit(root))
        return
    git_dir = Path(git(root, "rev-parse", "--absolute-git-dir"))
    manifest = git_dir / "source-revisions.json"
    repositories = {"bakasu": root / "KernelSU",
                    "baseband_guard": root / "Baseband-guard", "kernel": root}
    revisions = {}
    for name, repo in repositories.items():
        if args.check:
            if not optional_ref(repo, PREPARED_REF):
                raise ValueError(f"{repo}: sources have not been committed")
            upstream = upstream_commit(repo)
            check_clean(repo)
            revisions[name] = {"upstream": upstream,
                               "prepared": git(repo, "rev-parse", "HEAD"),
                               "tree": git(repo, "rev-parse", "HEAD^{tree}")}
        else:
            revisions[name] = commit_sources(repo, kernel=name == "kernel")
    data = {"schema": 1, "sources": revisions}
    if args.check:
        if json.loads(manifest.read_text()) != data:
            raise ValueError("Source revision manifest differs from the prepared repositories")
    else:
        manifest.write_text(json.dumps(data, indent=2) + "\n")
    for name, revision in revisions.items():
        print(f"{name}: upstream={revision['upstream']} prepared={revision['prepared']}")
    print("PASS: prepared source commits are clean; upstream revisions retained")


if __name__ == "__main__":
    main()
