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
overlay_directory=$(mktemp -d)
trap 'rm -rf "$overlay_directory"' EXIT
python3 - "$mihomo_root" "$builder" "$overlay_directory/overlay.json" <<'PY'
import json
from pathlib import Path
import sys
mihomo, builder, output = map(Path, sys.argv[1:])
output.write_text(json.dumps({"Replace": {
    str(mihomo / "common/ebpf/backport_socket_integration_test.go"):
        str(builder / "tests/host/mihomo-cgroup-runtime_test.go"),
    str(mihomo / "common/ebpf/backport_tc_integration_test.go"):
        str(builder / "tests/host/mihomo-tc-runtime_test.go")
}}))
PY

export CGO_ENABLED=0 GOOS=linux GOARCH=arm64
(
    cd "$mihomo_root"
    "$go_binary" test -p 2 -trimpath -overlay="$overlay_directory/overlay.json" -c -tags='with_ebpf ebpf_integration' \
        -o "$output/mihomo-ebpf.test" ./common/ebpf
    "$go_binary" test -p 2 -trimpath -c -tags='with_ebpf ebpf_integration' \
        -o "$output/mihomo-ebpf-inbound.test" ./listener/sing_ebpf
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
