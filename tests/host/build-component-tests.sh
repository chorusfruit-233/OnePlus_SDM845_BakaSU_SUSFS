#!/usr/bin/env bash
set -euo pipefail
kernel=${1:?prepared kernel directory is required}
output=${2:?output directory is required}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$output/include/linux"
cp "$kernel/include/uapi/linux/pkt_sched.h" "$output/include/linux/pkt_sched.h"
compiler=${CROSS_COMPILE:-aarch64-linux-gnu-}gcc
"$compiler" -std=gnu11 -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror \
    -static -I"$output/include" "$repo/tests/host/components-runtime.c" \
    -o "$output/components-runtime.test"
