#!/usr/bin/env bash
set -euo pipefail

upstream=${1:?pinned Linux git checkout is required}
output=${2:?output directory is required}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
upstream=$(cd "$upstream" && pwd)
mkdir -p "$output"
output=$(cd "$output" && pwd)
expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' \
    "$repo/configs/freezer-test.json")
actual=$(git -C "$upstream" rev-parse HEAD)
if [[ "$actual" != "$expected" ]]; then
    echo "Freezer self-tests require Linux $expected; found $actual" >&2
    exit 1
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mapfile -t files < <(python3 -c \
    'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["files"]))' \
    "$repo/configs/freezer-test.json")
for name in "${files[@]}"; do
    mkdir -p "$stage/$(dirname "$name")"
    git -C "$upstream" show "$expected:$name" > "$stage/$name"
done
git -C "$stage" init -q
for patch in freezer-selftest-waits.patch freezer-selftest-fortify.patch; do
    git -C "$stage" apply --check "$repo/patches/tests/$patch"
    git -C "$stage" apply "$repo/patches/tests/$patch"
done
compiler=${CROSS_COMPILE:-aarch64-linux-gnu-}gcc
"$compiler" -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -static -pthread \
    "$stage/tools/testing/selftests/cgroup/test_freezer.c" \
    "$stage/tools/testing/selftests/cgroup/cgroup_util.c" \
    -o "$output/test_freezer"
"$compiler" -std=gnu11 -O2 -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror -static -pthread \
    "$repo/tests/host/freezer-backport.c" -o "$output/freezer-backport.test"
cp "$repo/configs/freezer-test.json" "$output/upstream.json"
cp "$repo/patches/tests/freezer-selftest-waits.patch" "$output/"
cp "$repo/patches/tests/freezer-selftest-fortify.patch" "$output/"
(cd "$output" && sha256sum freezer-selftest-waits.patch \
    freezer-selftest-fortify.patch test_freezer freezer-backport.test > SHA256SUMS)
