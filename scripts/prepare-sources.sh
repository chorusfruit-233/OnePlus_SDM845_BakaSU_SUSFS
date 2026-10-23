#!/usr/bin/env bash
set -euo pipefail

kernel_root=${1:?kernel source directory is required}
bakasu_repo=${2:?BakaSU repository is required}
bakasu_ref=${3:?BakaSU ref is required}
patch_root=${4:?patch directory is required}
cake_repo=${5:?CAKE repository is required}
cake_ref=${6:?CAKE ref is required}
cake_checkout=${7:?CAKE checkout directory is required}
bbg_repo=${8:?Baseband Guard repository is required}
bbg_ref=${9:?Baseband Guard ref is required}
patches_repo=${10:?kernel patches repository is required}
patches_ref=${11:?kernel patches ref is required}
patches_checkout=${12:?kernel patches checkout directory is required}
rtl8812au_repo=${13:?rtl8812au repository is required}
rtl8812au_ref=${14:?rtl8812au ref is required}
rtl8812au_checkout=${15:?rtl8812au checkout directory is required}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

clone_ref() {
    local repo=$1 ref=$2 destination=$3
    rm -rf "$destination"
    git clone --filter=blob:none --no-checkout "$repo" "$destination"
    git -C "$destination" fetch --depth=1 origin "$ref"
    git -C "$destination" checkout --detach FETCH_HEAD
}

clone_sparse_ref() {
    local repo=$1 ref=$2 destination=$3 path=$4
    rm -rf "$destination"
    git clone --filter=blob:none --no-checkout "$repo" "$destination"
    git -C "$destination" sparse-checkout init --cone
    git -C "$destination" sparse-checkout set "$path"
    git -C "$destination" fetch --depth=1 origin "$ref"
    git -C "$destination" checkout --detach FETCH_HEAD
}

clone_ref "$bakasu_repo" "$bakasu_ref" "$kernel_root/KernelSU"
python3 "$script_dir/check-bakasu-4.9.py" "$kernel_root/KernelSU"
git -C "$kernel_root/KernelSU" apply --check "$patch_root/bakasu-selinux-4.9.patch"
git -C "$kernel_root/KernelSU" apply --whitespace=nowarn "$patch_root/bakasu-selinux-4.9.patch"
ln -sfn ../KernelSU/kernel "$kernel_root/drivers/kernelsu"

# Supplement the base container configuration for the recorded Droidspaces release.
git -C "$kernel_root" apply --check "$patch_root/droidspaces-4.9.patch"
git -C "$kernel_root" apply --whitespace=nowarn "$patch_root/droidspaces-4.9.patch"

# SUSFS v2.3.0 is vendored as a self-contained 4.9 patch (based on
# JackA1ltman/NonGKI_Kernel_Build_2nd), so no upstream git fetch is needed.
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/susfs-4.9.patch"

# Hybrid Mount VFS provider: vendored, independent hm1 keyring protocol.
# NoMount and Hybrid Mount both replace inode operations and must not coexist.
if [[ -d "$kernel_root/fs/nomount" ]] ||
   grep -Eq 'CONFIG_NOMOUNT|fs/nomount/' "$kernel_root/fs/Makefile" "$kernel_root/fs/Kconfig"; then
    echo "Remove NoMount before integrating Hybrid Mount VFS" >&2
    exit 1
fi
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/hybridmount-4.9.patch"

# Rename ath9k_htc HTC symbols so the in-tree USB Wi-Fi drivers can
# coexist with the OnePlus qcacld-3.0 WLAN (same htc_* symbol names).
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/ath9k-htc-symbols.patch"

# ReKernel-X v9.2 (drivers/rekernel + binder/signal hooks).
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/rekernel-4.9.patch"

# Replace KernelSU's kprobe hooks with SUSFS inline hooks (no-kprobe mode).
bash "$script_dir/susfs-inline-hook.sh" "$kernel_root"

clone_ref "$cake_repo" "$cake_ref" "$cake_checkout"
install -D -m 0644 "$cake_checkout/sch_cake.c" \
    "$kernel_root/net/sched/sch_cake.c"
install -D -m 0644 "$cake_checkout/cobalt.h" \
    "$kernel_root/include/net/cobalt.h"
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/cake-4.9-adaptation.patch"

clone_ref "$bbg_repo" "$bbg_ref" "$kernel_root/Baseband-guard"
git -C "$kernel_root/Baseband-guard" apply --whitespace=nowarn \
    "$patch_root/bbg-slot-allow.patch"
ln -sfn ../Baseband-guard "$kernel_root/security/baseband-guard"
ln -sfn ../../../Baseband-guard/tracing/tracing.h \
    "$kernel_root/security/selinux/include/bbg_tracing.h"

clone_sparse_ref "$patches_repo" "$patches_ref" "$patches_checkout" \
    common/bbrv3
git -C "$kernel_root" apply --whitespace=nowarn \
    --include=net/ipv4/tcp_bbr3.c \
    "$patches_checkout/common/bbrv3/0001-net-tcp-backport-BBRv3-to-android12-5.10.patch"
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/bbrv3-4.9-adaptation.patch"

# Out-of-tree USB Wi-Fi: rtl8812au/8821au/8814au (aircrack-ng). Built into
# the kernel image via CONFIG_88XXAU, adapted to this tree's backported
# cfg80211 ABI by rtl8812au-4.9-adaptation.patch.
clone_ref "$rtl8812au_repo" "$rtl8812au_ref" "$rtl8812au_checkout"
rm -rf "$kernel_root/drivers/net/wireless/realtek/rtl8812au"
mkdir -p "$kernel_root/drivers/net/wireless/realtek/rtl8812au"
tar -C "$rtl8812au_checkout" \
    --exclude=.git --exclude=docs --exclude='*.pdf' \
    -cf - . | tar -C "$kernel_root/drivers/net/wireless/realtek/rtl8812au" -xf -
git -C "$kernel_root" apply --whitespace=nowarn \
    "$patch_root/rtl8812au-4.9-adaptation.patch"

# USB Wi-Fi firmware embedded via CONFIG_EXTRA_FIRMWARE (ath9k_htc,
# rt2800usb and mt7601u). Sourced from the official linux-firmware tree.
fetch_firmware() {
    local url=$1 dest=$2 min_size=$3
    mkdir -p "$(dirname "$dest")"
    curl -fsSL --retry 3 -o "$dest" "$url"
    test -s "$dest"
    test "$(stat -c %s "$dest")" -ge "$min_size"
    head -c 200 "$dest" | grep -q '<!DOCTYPE html>' && return 1 || true
}
FW_BASE=https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain
fetch_firmware "$FW_BASE/htc_9271.fw" "$kernel_root/firmware/htc_9271.fw" 40000
fetch_firmware "$FW_BASE/rt2870.bin" "$kernel_root/firmware/rt2870.bin" 4000
fetch_firmware "$FW_BASE/mediatek/mt7601u.bin" "$kernel_root/firmware/mt7601u.bin" 40000

test -L "$kernel_root/drivers/kernelsu"
test -f "$kernel_root/fs/susfs.c"
test -f "$kernel_root/include/linux/susfs.h"
test -f "$kernel_root/include/linux/susfs_def.h"
test -f "$kernel_root/fs/hybridmount/hybridmount.c"
test -f "$kernel_root/fs/hybridmount/hybridmount.h"
test -f "$kernel_root/net/sched/sch_cake.c"
test -f "$kernel_root/net/ipv4/tcp_bbr3.c"
test -L "$kernel_root/security/baseband-guard"
test -f "$kernel_root/firmware/htc_9271.fw"
test -f "$kernel_root/firmware/rt2870.bin"
test -f "$kernel_root/firmware/mt7601u.bin"
grep -q 'ath9k_htc_hst_connect_service' \
    "$kernel_root/drivers/net/wireless/ath/ath9k/htc_hst.h"
test -f "$kernel_root/drivers/rekernel/rekernel.c"
grep -q 'rekernel_binder_transaction' "$kernel_root/drivers/android/binder.c"
grep -q 'rekernel_report(SIGNAL' "$kernel_root/kernel/signal.c"
grep -q 'KSTAT_SPOOF_CTIME_TV_SEC (1 << 8)' "$kernel_root/include/linux/susfs.h"
grep -q 'SUSFS_VERSION "v2.3.0"' "$kernel_root/include/linux/susfs.h"
grep -q 'ksu_handle_execveat_sucompat' "$kernel_root/fs/exec.c"
grep -q '^[[:space:]]*(void)ksu_handle_post_execveat_sucompat' "$kernel_root/fs/exec.c"
grep -q 'susfs_sus_kstat_spoof_inotify_fdinfo' "$kernel_root/fs/notify/fdinfo.c"
grep -q 'susfs_sus_kstat_spoof_proc_fd_seq_show' "$kernel_root/fs/proc/fd.c"
grep -q 'HYBRIDMOUNT_VERSION "hm1"' "$kernel_root/fs/hybridmount/hybridmount.h"
grep -q '.name = "hybridmount"' "$kernel_root/fs/hybridmount/hybridmount.c"
grep -q 'HYBRIDMOUNT_HAS_STATX' "$kernel_root/fs/hybridmount/Makefile"
grep -q 'ksu_handle_faccessat' "$kernel_root/fs/open.c"
grep -q 'ksu_handle_stat' "$kernel_root/fs/stat.c"
grep -q 'ksu_handle_sys_reboot' "$kernel_root/kernel/reboot.c"
grep -q '^int filename_lookup(' "$kernel_root/fs/namei.c"
grep -q 'atomic_t filter_count' "$kernel_root/include/linux/seccomp.h"
test -f "$kernel_root/drivers/net/wireless/realtek/rtl8812au/os_dep/linux/ioctl_cfg80211.c"
grep -q 'CONFIG_RTW_CFG80211_NEW_ABI' \
    "$kernel_root/drivers/net/wireless/realtek/rtl8812au/Makefile"
grep -q 'rtl8812au' "$kernel_root/drivers/net/wireless/realtek/Makefile"

bash "$script_dir/check-susfs-4.9.sh" "$kernel_root" --prepare

# Mihomo eBPF backport: packet_rewrite, cgroup and TC socket assignment.
git -C "$kernel_root" apply --check "$patch_root/mihomo-ebpf-4.9.patch"
git -C "$kernel_root" apply --whitespace=nowarn "$patch_root/mihomo-ebpf-4.9.patch"
git -C "$kernel_root" apply --check "$patch_root/mihomo-cgroup-4.9.patch"
git -C "$kernel_root" apply --whitespace=nowarn "$patch_root/mihomo-cgroup-4.9.patch"
git -C "$kernel_root" apply --check "$patch_root/mihomo-tc-4.9.patch"
git -C "$kernel_root" apply --whitespace=nowarn "$patch_root/mihomo-tc-4.9.patch"

# Experimental cgroup v2 freezer; preserve the v1 freezer and WALT.
git -C "$kernel_root" apply --check "$patch_root/cgroup-v2-freezer-4.9.patch"
git -C "$kernel_root" apply --whitespace=nowarn "$patch_root/cgroup-v2-freezer-4.9.patch"

echo "BakaSU commit: $(git -C "$kernel_root/KernelSU" rev-parse HEAD)"
echo "Mihomo eBPF backport: $(sha256sum "$patch_root/mihomo-ebpf-4.9.patch" | cut -c1-12)"
echo "Mihomo cgroup backport: $(sha256sum "$patch_root/mihomo-cgroup-4.9.patch" | cut -c1-12)"
echo "Mihomo TC backport: $(sha256sum "$patch_root/mihomo-tc-4.9.patch" | cut -c1-12)"
echo "Cgroup v2 freezer: $(sha256sum "$patch_root/cgroup-v2-freezer-4.9.patch" | cut -c1-12)"
echo "BakaSU SELinux adaptation: $(sha256sum "$patch_root/bakasu-selinux-4.9.patch" | cut -c1-12)"
echo "SUSFS patch: $patch_root/susfs-4.9.patch ($(sha256sum "$patch_root/susfs-4.9.patch" | cut -c1-12))"
echo "Hybrid Mount VFS patch: $patch_root/hybridmount-4.9.patch ($(sha256sum "$patch_root/hybridmount-4.9.patch" | cut -c1-12))"
echo "rtl8812au commit: $(git -C "$rtl8812au_checkout" rev-parse HEAD)"
echo "CAKE commit: $(git -C "$cake_checkout" rev-parse HEAD)"
echo "Baseband Guard commit: $(git -C "$kernel_root/Baseband-guard" rev-parse HEAD)"
echo "Kernel patches commit: $(git -C "$patches_checkout" rev-parse HEAD)"
