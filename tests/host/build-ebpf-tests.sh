#!/usr/bin/env bash
set -euo pipefail

mihomo_root=$(realpath "${1:?pinned Mihomo checkout is required}")
output=$(realpath -m "${2:?output directory is required}")
builder=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
go_binary=${GO_BINARY:-go}
expected=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commit"])' \
    "$builder/configs/mihomo-ebpf-test.json")
test "$(git -C "$mihomo_root" rev-parse HEAD)" = "$expected"
mkdir -p "$output"

export CGO_ENABLED=0 GOOS=linux GOARCH=arm64
(
    cd "$mihomo_root"
    "$go_binary" test -p 2 -trimpath -c -tags='with_ebpf ebpf_integration' \
        -o "$output/mihomo-ebpf.test" ./common/ebpf
)
(
    cd "$builder/tests/device/ebpf-backport"
    "$go_binary" test -p 2 -trimpath -c -o "$output/ebpf-backport.test"
)
cp "$builder/configs/mihomo-ebpf-test.json" "$output/"
(
    cd "$output"
    sha256sum ./*.test > test-binaries.sha256
)
