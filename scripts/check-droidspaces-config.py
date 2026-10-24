#!/usr/bin/env python3
"""Check the configured 4.9 kernel against the recorded Droidspaces release."""
import argparse
import json
import re
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path, help="prepared kernel source directory")
    parser.add_argument("--config", default="out/.config", help="generated kernel config")
    args = parser.parse_args()
    builder = Path(__file__).resolve().parent.parent
    profile = json.loads((builder / "configs/droidspaces.json").read_text())
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = args.kernel / config_path
    config = dict(re.findall(r"^(CONFIG_\w+)=(.*)$", config_path.read_text(), re.M))
    missing = [option for option in profile["required_builtin"] if config.get(option) != "y"]
    errors = [f"Missing built-in option: {option}=y" for option in missing]
    if config.get("CONFIG_ANDROID_PARANOID_NETWORK", "n") != "n":
        errors.append("CONFIG_ANDROID_PARANOID_NETWORK must be disabled.")

    cpu_quota = config.get("CONFIG_CFS_BANDWIDTH") == "y"
    if profile["cpu_quota_policy"] == "preserve_walt":
        if config.get("CONFIG_SCHED_WALT") != "y" or cpu_quota:
            errors.append("The recorded profile preserves WALT without CFS CPU quotas.")
    elif profile["cpu_quota_policy"] == "cfs_bandwidth":
        if config.get("CONFIG_SCHED_WALT", "n") != "n" or not cpu_quota:
            errors.append("CPU quotas require CFS_BANDWIDTH=y and SCHED_WALT=n on this tree.")
    else:
        errors.append("Unknown CPU quota policy in the compatibility profile.")

    cgroup = (args.kernel / "kernel/cgroup.c").read_text()
    if "kernfs_create_link(cgrp->kn, name, kn)" not in cgroup or \
            "cgroup_on_dfl(cgrp) ? cft->ss->name" not in cgroup:
        errors.append("The legacy cgroup noprefix compatibility repair is missing.")
    if (args.kernel / "net/netfilter/xt_qtaguid.c").exists():
        errors.append("This profile expects the LineageOS baseline without xt_qtaguid.")

    # A compiled-in command line can disable controllers despite their config.
    # Bootloader arguments and Android mount/policy restrictions need device checks.
    command_line = config.get("CONFIG_CMDLINE", "").strip('"')
    if "swapaccount=0" in command_line.split():
        errors.append("Swap accounting disabled by CONFIG_CMDLINE: swapaccount=0")
    for token in command_line.split():
        if token.startswith("cgroup_disable="):
            disabled = set(token.partition("=")[2].split(","))
            if disabled & {"all", "memory", "cpu", "cpuacct", "pids"}:
                errors.append(f"Resource controllers disabled by CONFIG_CMDLINE: {token}")

    report = {
        "droidspaces_version": profile["version"],
        "requirements_commit": profile["commit"],
        "config_checks_passed": not errors,
        "configured_features": {
            "macvlan": config.get("CONFIG_MACVLAN") == "y",
            "ipv6_nat": all(config.get(key) == "y" for key in
                            ("CONFIG_IP6_NF_NAT", "CONFIG_IP6_NF_TARGET_MASQUERADE")),
            "memory_limit": config.get("CONFIG_MEMCG") == "y",
            "swap_limit": config.get("CONFIG_MEMCG_SWAP") == "y" and
                          config.get("CONFIG_MEMCG_SWAP_ENABLED") == "y",
            "pids_limit": config.get("CONFIG_CGROUP_PIDS") == "y",
            "cpu_accounting": config.get("CONFIG_CGROUP_CPUACCT") == "y",
            "cpu_quota": cpu_quota,
        },
        "cpu_quota_policy": profile["cpu_quota_policy"],
        "unavailable_options": profile["unavailable_options"],
        "runtime_tested": False,
        "errors": errors,
    }
    for error in errors:
        print(f"Droidspaces config: {error}", file=sys.stderr)
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
