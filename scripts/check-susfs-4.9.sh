#!/usr/bin/env bash
# Source checks for the pinned LineageOS 4.9/BakaSU automatic SELinux path.
# This does not certify runtime behavior; device regression tests are required.
set -euo pipefail

kernel_root=$(realpath "${1:?kernel source directory is required}")
mode=${2:---check}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
builder_root=$(dirname "$script_dir")
config="$builder_root/configs/enchilada.json"
ksu_root="$kernel_root/KernelSU"
marker="$ksu_root/kernel/.susfs-4.9-auto-reviewed"

fail() { echo "SUSFS 4.9 adaptation: $*" >&2; exit 1; }
require() { grep -qE "$1" "$2" || fail "Missing $1 in $2"; }

case "$mode" in
    --prepare) rm -f "$marker" ;;
    --check) ;;
    --config) [[ $# == 3 ]] || fail '--config requires a .config path' ;;
    *) fail "Unknown mode: $mode" ;;
esac

[[ $(git -C "$kernel_root" rev-parse HEAD) == "$(jq -er .kernel_base "$config")" ]] ||
    fail 'Kernel base changed; review the adaptation before building.'
python3 "$script_dir/check-bakasu-4.9.py" "$ksu_root"
actual_bakasu=$(git -C "$ksu_root" rev-parse HEAD)
[[ $(awk '$1 == "VERSION" {print $3}' "$kernel_root/Makefile") == 4 &&
   $(awk '$1 == "PATCHLEVEL" {print $3}' "$kernel_root/Makefile") == 9 ]] ||
    fail 'Only the Linux 4.9 automatic SELinux path is supported.'

# Verify every hunk of the BakaSU adaptation is present, including the
# explicit-policy access calculation and failure handling, before marking it.
git -C "$ksu_root" apply --reverse --check \
    "$builder_root/patches/lineage-4.9/bakasu-selinux-4.9.patch" ||
    fail 'BakaSU SELinux adaptation is absent or incomplete.'

require '^#define SUSFS_VERSION "v2\.3\.0"$' "$kernel_root/include/linux/susfs.h"
require 'ksu_handle_selinux_setprocattr\(struct task_struct \*p' \
    "$ksu_root/kernel/feature/selinux_hide.c"
require 'static int selinux_setprocattr\(struct task_struct \*p,' \
    "$kernel_root/security/selinux/hooks.c"
require 'int selinux_kernel_status_page|struct page \*selinux_kernel_status_page' \
    "$kernel_root/security/selinux/ss/status.c"
require 'DEFINE_RWLOCK\(policy_rwlock\)' "$kernel_root/security/selinux/ss/services.c"
if grep -qE 'struct selinux_state |ksu_selinux_hide_running|ksu_hide_setprocattr|fake_state' \
        "$kernel_root/security/selinux/include/security.h" \
        "$kernel_root/security/selinux/hooks.c" \
        "$kernel_root/security/selinux/selinuxfs.c"; then
    fail 'GKI SELinux state/manual hooks cannot use the reviewed legacy auto path.'
fi

require 'ksu_handle_execveat_sucompat' "$kernel_root/fs/exec.c"
require 'ksu_handle_post_execveat_sucompat' "$kernel_root/fs/exec.c"
require 'ksu_handle_faccessat' "$kernel_root/fs/open.c"
require 'ksu_handle_stat' "$kernel_root/fs/stat.c"
require 'ksu_handle_sys_read' "$kernel_root/fs/read_write.c"
require 'ksu_handle_setresuid' "$kernel_root/kernel/sys.c"
require 'ksu_handle_sys_reboot' "$kernel_root/kernel/reboot.c"
require 'ksu_handle_input_handle_event' "$kernel_root/drivers/input/input.c"

if [[ "$mode" == --config ]]; then
    cfg=$3
    [[ "$cfg" == /* ]] || cfg="$kernel_root/$cfg"
    for option in CONFIG_ARM64 CONFIG_KSU CONFIG_KSU_SUSFS CONFIG_KALLSYMS \
                  CONFIG_KALLSYMS_ALL CONFIG_SECURITY_SELINUX; do
        grep -qx "${option}=y" "$cfg" || fail "Missing ${option}=y"
    done
    if grep -qE '^CONFIG_(KSU_MANUAL_HOOK|KSU_TRACEPOINT_HOOK|KPROBES)=[ym]$' "$cfg"; then
        fail 'The adaptation requires the SUSFS inline/SELinux automatic hook combination.'
    fi
fi

if [[ "$mode" == --prepare ]]; then
    printf '%s\n' lineage-4.9-auto-v1 > "$marker"
else
    [[ -f "$marker" && $(cat "$marker") == lineage-4.9-auto-v1 ]] ||
        fail 'Run source preparation to create the reviewed-source marker.'
fi
echo "SUSFS 4.9 source checks passed (BakaSU $actual_bakasu, automatic SELinux hooks)."
