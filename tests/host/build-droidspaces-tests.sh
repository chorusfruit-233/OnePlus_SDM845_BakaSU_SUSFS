#!/usr/bin/env bash
set -euo pipefail
kernel=${1:?prepared kernel source is required}
output=${2:?output directory is required}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$output/include/linux"
output=$(cd "$output" && pwd)
# Overlay only the ABI under test, leaving target libc's architecture headers intact.
cp "$kernel/include/uapi/linux/stat.h" "$kernel/include/uapi/linux/nsfs.h" "$output/include/linux/"
for abi in arm64 arm32; do
    if [[ "$abi" == arm64 ]]; then
        compiler=${CROSS_COMPILE:-aarch64-linux-gnu-}gcc
    else
        compiler=${CROSS_COMPILE_COMPAT:-arm-linux-gnueabihf-}gcc
    fi
    "$compiler" -std=gnu11 -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror \
        -static -I"$output/include" "$repo/tests/host/droidspaces-backports.c" \
        -o "$output/droidspaces-$abi.test"
done
(cd "$output" && sha256sum droidspaces-*.test include/linux/*.h > SHA256SUMS)
