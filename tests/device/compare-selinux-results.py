#!/usr/bin/env python3
"""Report device SELinux semantics/timings without claiming a side-channel fix."""
import argparse
import json
import sys

PROBE_NAMES = {
    "setprocattr.self", "setprocattr.invalid", "setprocattr.ksu", "setprocattr.parent",
    "context.self", "context.invalid", "context.ksu",
    "access.self", "access.invalid", "access.ksu", "status.read_mmap",
}


def bounded_integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def load(path):
    metadata = summary = None
    probes = {}
    with open(path, encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: record must be an object")
            kind = row.get("type")
            if kind == "metadata" and metadata is None:
                metadata = row
            elif kind == "summary" and summary is None:
                summary = row
            elif kind == "probe" and row.get("name") not in probes:
                probes[row["name"]] = row
            else:
                raise ValueError(f"{path}:{number}: duplicate or unknown record")
    if metadata is None or summary is None or not probes:
        raise ValueError(f"{path}: incomplete result file")
    if metadata.get("schema") != 1 or metadata.get("enforcing") != 1:
        raise ValueError(f"{path}: require schema 1 and Enforcing metadata")
    for key in ("label", "kernel", "uid", "euid", "context", "process_class", "samples", "warmup"):
        if key not in metadata:
            raise ValueError(f"{path}: metadata missing {key}")
    if not bounded_integer(metadata["samples"], 16, 2048) or metadata["warmup"] != 8:
        raise ValueError(f"{path}: invalid sample/warmup metadata")
    uid = metadata["uid"]
    context = metadata["context"]
    if not bounded_integer(uid, 0, (1 << 32) - 1) or metadata["euid"] != uid or \
            not 10000 <= uid % 100000 < 20000:
        raise ValueError(f"{path}: require an ordinary application UID/eUID")
    if not isinstance(context, str) or not (
            context.startswith("u:r:untrusted_app:") or context.startswith("u:r:untrusted_app_")):
        raise ValueError(f"{path}: require an untrusted_app context")
    if not bounded_integer(metadata["process_class"], 0, 65535):
        raise ValueError(f"{path}: invalid process class metadata")
    if not bounded_integer(summary.get("invariant_failures"), 0, len(PROBE_NAMES) + 1):
        raise ValueError(f"{path}: invalid invariant failure count")
    if type(summary.get("parent_state_failure")) is not bool:
        raise ValueError(f"{path}: missing/invalid parent state result")
    if not bounded_integer(summary.get("failed_probe_groups"), 0, len(PROBE_NAMES)):
        raise ValueError(f"{path}: invalid failed probe group count")
    if set(probes) != PROBE_NAMES:
        raise ValueError(f"{path}: schema 1 requires all eleven probe records")
    failure_groups = 0
    for name, probe in probes.items():
        if not isinstance(probe.get("outcomes"), list) or not probe["outcomes"]:
            raise ValueError(f"{path}: {name}: no recorded outcomes")
        samples = probe.get("samples")
        if not bounded_integer(samples, 16, 2048):
            raise ValueError(f"{path}: {name}: invalid sample count")
        overflow = probe.get("unrecorded_outcomes")
        measured_failures = probe.get("failures")
        warmup_failures = probe.get("warmup_failures")
        if not bounded_integer(overflow, 0, samples) or not bounded_integer(measured_failures, 0, samples):
            raise ValueError(f"{path}: {name}: invalid failure/overflow count")
        if not bounded_integer(warmup_failures, 0, metadata["warmup"]):
            raise ValueError(f"{path}: {name}: invalid warmup failure count")
        total = overflow
        recorded_failures = 0
        for item in probe["outcomes"]:
            # Validate fields consumed below, instead of accepting truncated captures.
            for key in ("stage", "rc", "errno", "response", "failure", "count"):
                if key not in item:
                    raise ValueError(f"{path}: {name}: missing {key}")
            if not bounded_integer(item["count"], 1, samples):
                raise ValueError(f"{path}: {name}: invalid outcome count")
            if type(item["failure"]) is not bool:
                raise ValueError(f"{path}: {name}: invalid outcome failure flag")
            timings = item["timing_ns"]
            if not 0 <= timings["min"] <= timings["median"] <= timings["p95"] <= timings["max"]:
                raise ValueError(f"{path}: {name}: invalid timing summary")
            total += item["count"]
            recorded_failures += item["count"] if item["failure"] else 0
        if total != probe["samples"]:
            raise ValueError(f"{path}: {name}: sample counts disagree")
        if probe["samples"] != metadata["samples"]:
            raise ValueError(f"{path}: {name}: metadata sample count disagrees")
        if not recorded_failures <= measured_failures <= recorded_failures + overflow:
            raise ValueError(f"{path}: {name}: outcome failures disagree with aggregate")
        failure_groups += bool(measured_failures or warmup_failures or overflow)
    if summary.get("failed_probe_groups") != failure_groups or \
            summary["invariant_failures"] != failure_groups + int(summary["parent_state_failure"]):
        raise ValueError(f"{path}: invariant failure summary disagrees")
    return metadata, probes, summary


def semantic(item, probe_name):
    response = item["response"]
    if probe_name == "status.read_mmap":
        # Keep generation diagnostics in the report, not the semantic verdict.
        response = response.partition(" sequence=")[0]
    return item["stage"], item["rc"], item["errno"], response, item["failure"]


def report_outcomes(label, probe):
    if probe["name"] == "setprocattr.parent":
        print("  Coverage: legacy proc opener/mm rejection only; SELinux current != p is untested.")
    if probe.get("warmup_failures"):
        print(f"  WARNING: {label} warmup invariant failures={probe['warmup_failures']}")
    for item in probe["outcomes"]:
        t = item["timing_ns"]
        print(f"  {label}: stage={item['stage']} rc={item['rc']} errno={item['errno']} "
              f"n={item['count']} invariant_failure={item['failure']}")
        if item["response"]:
            print(f"    response: {item['response']}")
        print(f"    ns: min={t['min']} median={t['median']} p95={t['p95']} max={t['max']}")
        if item["stage"] in ("open", "prerequisite"):
            print("    Coverage unavailable: the tested hook was not reached.")
        elif item["stage"] == "mmap":
            print("    Read-only status mmap was unavailable; read/mmap consistency is untested.")
        elif item["stage"] == "write" and item["errno"] in (1, 13):
            print("    Permission denial: context parsing/backup-policy coverage is not established.")
    if probe.get("unrecorded_outcomes"):
        print("  WARNING: outcome recording overflow; this run is incomplete.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="JSONL from a controlled baseline device run")
    parser.add_argument("candidate", help="JSONL from the candidate on the same device/app")
    args = parser.parse_args()
    try:
        bm, bp, bs = load(args.baseline)
        cm, cp, cs = load(args.candidate)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid device results: {exc}", file=sys.stderr)
        return 2
    print(f"Baseline: {bm['label']} kernel={bm['kernel']} uid={bm['uid']} context={bm['context']}")
    print(f"Candidate: {cm['label']} kernel={cm['kernel']} uid={cm['uid']} context={cm['context']}")
    for key in ("uid", "euid", "context", "process_class", "samples", "warmup"):
        if bm.get(key) != cm.get(key):
            print(f"WARNING: {key} differs; control this variable before interpreting timings.")
    for name in sorted(set(bp) | set(cp)):
        if name not in bp or name not in cp:
            print(f"\n{name}: missing in one capture")
            continue
        before = {semantic(item, name) for item in bp[name]["outcomes"]}
        after = {semantic(item, name) for item in cp[name]["outcomes"]}
        print(f"\n{name}: semantic outcome set {'unchanged' if before == after else 'CHANGED'}")
        report_outcomes("baseline", bp[name])
        report_outcomes("candidate", cp[name])
    print("\nRepeated timing summaries are observations, not a side-channel pass/fail test.")
    print("Compare multiple controlled runs/reboots; review changed or untested semantics separately.")
    failures = bs["invariant_failures"] or cs["invariant_failures"]
    print(f"Device invariant failure groups: baseline={bs['invariant_failures']} "
          f"candidate={cs['invariant_failures']}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
