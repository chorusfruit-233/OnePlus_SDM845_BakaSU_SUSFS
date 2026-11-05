#!/usr/bin/env bash
# Inject real-kernel fault regressions into the QEMU build, then restore sources.
set -euo pipefail
kernel=${1:?prepared kernel is required}
output=${2:?output directory relative to kernel is required}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_source="$kernel/lib/test_security_backport.c"
test_makefile="$kernel/lib/Makefile"
[[ ! -e "$test_source" ]]
saved=$(mktemp)
cp "$test_makefile" "$saved"
restore() {
    cp "$saved" "$test_makefile"
    rm -f "$saved" "$test_source"
}
trap restore EXIT
cp "$repo/tests/host/security-kernel.c" "$test_source"
# Only the disposable QEMU Image gets this object; the phone Image is built first.
printf '\nobj-y += test_security_backport.o\n' >> "$test_makefile"
make -C "$kernel" O="$output" ARCH=arm64 \
    HOSTCC="${HOSTCC:-gcc}" CROSS_COMPILE="${CROSS_COMPILE:-ccache aarch64-linux-gnu-}" \
    KCFLAGS=-Wno-error -j"${BUILD_JOBS:-$(nproc)}" Image
