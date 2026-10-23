#!/usr/bin/env python3
"""Boot the backported 4.9 ARM64 Image and execute real BPF tests in QEMU.

The guest is disposable. No disk, network interface, or host filesystem is
attached. All test binaries must be statically linked Linux/ARM64 executables.
"""
import argparse
import gzip
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

MIHOMO_TESTS = (
    "TestSharedRewriteProgramRoundTripIntegration",
    "TestSharedRewritePolicyIntegration",
    "TestSharedNetworkSetUDPTimeoutReachesTheControlMapIntegration",
    "TestSharedRewriteUDPChecksumDeliveryIntegration",
    "TestBackportCgroupSocketRoundTripIntegration",
    "TestBackportCgroupOwnerSafetyIntegration",
    "TestCgroupProgramMatrixIntegration",
    "TestCgroupUDPFlowCacheRevalidatesRedirectIntegration",
    "TestCgroupBypassRefreshAndRollbackIntegration",
    "TestCgroupTakeFallbackRetainsRedirectIntegration",
    "TestCgroupSetUDPTimeoutReachesTheControlMapIntegration",
    "TestCgroupBackendsShareACgroupIntegration",
    "TestBackportTCLegacyLoadIntegration",
    "TestBackportTCFailedAssignmentRetainsFlowIntegration",
    "TestBackportTCSocketDeliveryIntegration",
    "TestBackportTCReturnLifetimeIntegration",
    "TestTCProgramRunIntegration",
    "TestTCIPv6PathIsolationIntegration",
    "TestTCFragmentPolicyIntegration",
    "TestTCScopedBypassTablesIntegration",
    "TestTCUDPAssignmentRetirementIntegration",
    "TestTCAssignmentSweepGenerationAndBudgetIntegration",
    "TestTCIsolatedVerifierIntegration",
    "TestTCLocalClassifierLoadIntegration",
)
# 4.19 reports the blinded translated bytecode when hardening is enabled.
# Mihomo conservatively refuses to replace owners it cannot identify; test its
# pass-through owner inspection in the two modes that expose plain bytecode.
OWNER_TESTS = (
    "TestCgroupDetachRestoresADisplacedOwnerIntegration",
    "TestCgroupBackendTakesOverPinnedNetdPlaceholderIntegration",
    "TestCgroupBackendTakesOverUnpinnedPassThroughOwnerIntegration",
    "TestCgroupBackendReclaimRestoresPinnedNetdPlaceholderIntegration",
    "TestCgroupBackendReclaimKeepsNetdHookSingleProgramIntegration",
    "TestCgroupBackendReclaimDetachesStaleProgramWithoutNetdIntegration",
    "TestCgroupBackendKeepsNetdProgramWithLogicIntegration",
    "TestOptionalCgroupAttachKeepsNetdPlaceholderIntegration",
    "TestInspectPassThroughIntegration",
)
DEFAULT_TEST_SELECTOR = "^(" + "|".join(MIHOMO_TESTS + OWNER_TESTS) + ")$"
INBOUND_TESTS = (
    "TestTCIsolatedRoundTripIntegration",
    "TestTCIsolatedListenerPortCollisionIntegration",
)
INBOUND_TEST_SELECTOR = "^(" + "|".join(INBOUND_TESTS) + ")$"
PROBE_TESTS = (
    "TestSubprogramExecution", "TestAtomicMapUpdates", "TestLegacyEBPFPacketLoads",
    "TestLRUEviction", "TestLPMUpdateDelete", "TestVerifierRejectsInvalidAccess",
    "TestUnsupportedTypesRejected", "TestPinnedMapRoundTrip", "TestRunUserBufferBounds",
    "TestSeccompCompatibility", "TestClassicSocketFilters",
    "TestCgroupContextValidation", "TestCgroupQueryAndInheritance",
    "TestCgroupExclusiveParent",
    "TestMapLookupAndDelete",
    "TestLRUSmallMapCPUHandoff",
    "TestSocketReferenceValidation", "TestSocketLookupAndAssign",
    "TestPacketPointersInvalidatedByHelpers", "TestSKBChangeHead",
    "TestBoundedScalarSpills",
)


def cpio_entry(name, data, inode, mode, rdev=(0, 0)):
    name = name.encode() + b"\0"
    fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0,
              *rdev, len(name), 0)
    prefix = b"070701" + b"".join(f"{v:08x}".encode() for v in fields) + name
    return prefix + bytes(-len(prefix) % 4) + data + bytes(-len(data) % 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--busybox", required=True, type=Path)
    parser.add_argument("--mihomo-test", required=True, type=Path)
    parser.add_argument("--inbound-test", required=True, type=Path)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--cpu", default="cortex-a57")
    parser.add_argument("--cpus", type=int, choices=range(1, 9), default=2)
    parser.add_argument("--modes", nargs="+", choices=("interpreter", "jit", "hardened"),
                        default=("interpreter", "jit", "hardened"))
    parser.add_argument("--mihomo-run", default=DEFAULT_TEST_SELECTOR)
    parser.add_argument("--qemu", default=os.environ.get("QEMU_AARCH64", "qemu-system-aarch64"))
    args = parser.parse_args()
    qemu = shutil.which(args.qemu)
    if not qemu:
        parser.error("install qemu-system-arm or set --qemu")
    tests = shlex.quote(args.mihomo_run)
    hardened_tests = shlex.quote("^(" + "|".join(MIHOMO_TESTS) + ")$"
                                if args.mihomo_run == DEFAULT_TEST_SELECTOR else args.mihomo_run)
    init = f"""#!/bin/sh
export PATH=/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
mount -t bpf bpf /sys/fs/bpf || exit 1
/bin/busybox mkdir -p /sys/fs/cgroup || exit 1
mount -t cgroup2 none /sys/fs/cgroup || exit 1
export SING_BOX_EBPF_INTEGRATION=1
export GOMAXPROCS=2
ulimit -l unlimited || exit 1
failed=0
/probe.test -test.v -test.run='^TestQEMUNetworkSetup$' || failed=1
for mode in {' '.join(args.modes)}; do
    echo "BPF_EXECUTION_MODE=$mode"
    case "$mode" in
        interpreter) echo 0 > /proc/sys/net/core/bpf_jit_enable; echo 0 > /proc/sys/net/core/bpf_jit_harden;;
        jit) echo 1 > /proc/sys/net/core/bpf_jit_enable; echo 0 > /proc/sys/net/core/bpf_jit_harden;;
        hardened) echo 1 > /proc/sys/net/core/bpf_jit_enable; echo 2 > /proc/sys/net/core/bpf_jit_harden;;
    esac
    /probe.test -test.v -test.timeout=90s || failed=1
    case "$mode" in
        hardened) /mihomo.test -test.v -test.timeout=90s -test.run={hardened_tests} || failed=1;;
        *) /mihomo.test -test.v -test.timeout=90s -test.run={tests} || failed=1;;
    esac
    /mihomo-inbound.test -test.v -test.timeout=180s -test.run={shlex.quote(INBOUND_TEST_SELECTOR)} || failed=1
done
if [ "$failed" = 0 ]; then echo EBPF_QEMU_PASS; else echo EBPF_QEMU_FAIL; fi
BACKPORT_QEMU_SHUTDOWN=1 /probe.test -test.run='^TestQEMUShutdown$'
while :; do /bin/busybox sleep 1; done
""".encode()
    entries = []
    for directory in (".", "bin", "dev", "proc", "sys", "tmp"):
        entries.append((directory, b"", 0o40755, (0, 0)))
    entries.append(("dev/console", b"", 0o20600, (5, 1)))
    entries.append(("init", init, 0o100755, (0, 0)))
    entries.append(("bin/busybox", args.busybox.read_bytes(), 0o100755, (0, 0)))
    for command in ("sh", "mount"):
        entries.append((f"bin/{command}", b"busybox", 0o120777, (0, 0)))
    entries.append(("probe.test", args.probe.read_bytes(), 0o100755, (0, 0)))
    entries.append(("mihomo.test", args.mihomo_test.read_bytes(), 0o100755, (0, 0)))
    entries.append(("mihomo-inbound.test", args.inbound_test.read_bytes(), 0o100755, (0, 0)))
    entries.append(("TRAILER!!!", b"", 0, (0, 0)))
    archive = b"".join(cpio_entry(n, data, i, mode, rdev)
                       for i, (n, data, mode, rdev) in enumerate(entries, 1))
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ebpf-qemu-") as temporary:
        initrd = Path(temporary) / "initramfs.cpio.gz"
        initrd.write_bytes(gzip.compress(archive, mtime=0))
        command = [qemu, "-machine", "virt", "-cpu", args.cpu, "-m", "1024",
                   "-smp", str(args.cpus), "-nographic", "-nodefaults", "-serial", "stdio",
                   "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel.resolve()),
                   "-initrd", str(initrd),
                   "-object", "rng-random,id=rng0,filename=/dev/urandom",
                   "-device", "virtio-rng-device,rng=rng0", "-append",
                   "console=ttyAMA0 rdinit=/init panic=-1 random.trust_cpu=on bpf_backport_qemu=1"]
        with args.log.open("w") as log:
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"QEMU timed out; see {args.log}")
    output = args.log.read_text(errors="replace")
    if result.returncode or "EBPF_QEMU_PASS" not in output or re.search(
            r"--- (SKIP|FAIL):|Kernel panic|BUG:|WARNING:|no tests to run", output):
        raise SystemExit(f"BPF regression failed; see {args.log}")
    for mode in args.modes:
        expected = PROBE_TESTS + INBOUND_TESTS
        if args.mihomo_run == DEFAULT_TEST_SELECTOR:
            expected += MIHOMO_TESTS + (() if mode == "hardened" else OWNER_TESTS)
        marker = f"BPF_EXECUTION_MODE={mode}\n"
        normalized = output.replace("\r\n", "\n")
        if marker not in normalized:
            raise SystemExit(f"Missing execution mode {mode}; see {args.log}")
        block = normalized.split(marker, 1)[1].split("BPF_EXECUTION_MODE=", 1)[0]
        for test in expected:
            if f"--- PASS: {test} (" not in block:
                raise SystemExit(f"Missing {test} result for {mode}; see {args.log}")
    print(f"PASS: {', '.join(args.modes)} on {args.cpu}, {args.cpus} CPUs; log: {args.log}")


if __name__ == "__main__":
    main()
