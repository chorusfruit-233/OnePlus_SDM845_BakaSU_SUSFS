#!/usr/bin/env bash
set -euo pipefail
kernel=${1:?prepared kernel source is required}
output=${2:?output directory is required}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$output/include/linux/android"
output=$(cd "$output" && pwd)
cp "$kernel/include/uapi/linux/android/binder.h" "$output/include/linux/android/binder.h"
compiler=${CROSS_COMPILE:-aarch64-linux-gnu-}gcc
"$compiler" -std=gnu11 -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror \
    -static -pthread -I"$output/include" "$repo/tests/host/binder-freezer.c" \
    -o "$output/binder-freezer.test"
compat_compiler=${CROSS_COMPILE_COMPAT:-arm-linux-gnueabihf-}gcc
"$compat_compiler" -std=gnu11 -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror \
    -static -pthread -I"$output/include" "$repo/tests/host/binder-freezer.c" \
    -o "$output/binder-freezer-arm32.test"
"$compiler" -dumpfullversion > "$output/compiler-arm64.txt"
"$compat_compiler" -dumpfullversion > "$output/compiler-arm32.txt"
(cd "$output" && sha256sum binder-freezer.test binder-freezer-arm32.test \
    include/linux/android/binder.h compiler-arm64.txt compiler-arm32.txt > SHA256SUMS)
