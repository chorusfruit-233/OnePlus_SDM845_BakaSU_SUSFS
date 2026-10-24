# Host BakaSU regressions

## Kernel-only installation

```sh
python3 tests/host/test-ak3-ramdisk.py --anykernel anykernel3
```

Requires `qemu-arm` from qemu-user (or set QEMU_ARM). Runs the fetched AK3
`split_boot` / `flash_boot` functions and its ARM magiskboot on temporary boot
v0/v2 images with gzip/lz4 ramdisks. It checks kernel/appended-DTB replacement,
header/cmdline retention and byte-identical ramdisk CPIO, including symlinks,
ownership, modes and hardlink records. Ramdisk extraction/rebuild is rejected;
no mkbootfs is provided, matching the new manager's installation path.

Partition discovery, blockdev and zero-fill are mocked. All reads/writes use
temporary regular files; no device is flashed. This does not prove device boot
or exercise the manager's slot selection, AVB signing or Magisk ramdisk handling.

## BakaSU ABI

```sh
python3 tests/host/test-bakasu-compat.py --source kernel
```

The ABI test compiles the actual upstream syscall-number generator against this
kernel's ARM64 `unistd32.h`, then exercises the actual BakaSU `arch.h` helpers
with mocked register/task services. It checks native and compat syscall numbers,
32-bit user-pointer truncation, writable native register slots, and preservation
of the native kernel C-call ABI. Both CONFIG_COMPAT=y and n are exercised.
This does not execute AArch32 programs or syscalls on a device.

## SELinux cleanup

```sh
python3 tests/host/test-selinux-cleanup.py
python3 tests/host/test-selinux-cleanup.py --source kernel
```

`--source` accepts `selinux_hide.c`, the kernel root, or the BakaSU checkout.
The default reads `kernel/KernelSU/kernel/feature/selinux_hide.c` relative to
the builder repository. Set `CC` to select a host C compiler; the default is
`cc`. No kernel build is invoked.

The test extracts the actual cleanup, feature-state, and backup-release
functions, compiles their Linux 4.9 branches with mocked kernel services, and
injects failure at each callback restore. It checks that failed restores retain
the original callbacks and backup resources, report an incomplete state, and
allow a later cleanup retry before enabling again. It also checks successful
disable and startup-rollback recovery.

This covers failure bookkeeping. ARM64 memory patching, concurrent callbacks,
device boot, SELinux decisions, and timing behavior still require device tests.

## Integrated components

```sh
python3 tests/host/test-susfs-priority.py --source kernel
python3 tests/host/run-hybridmount-tests.py --source kernel
bash tests/host/build-component-tests.sh kernel artifacts/component-tests
python3 tests/host/run-components-qemu.py \
  --kernel kernel/out-bpf-qemu/arch/arm64/boot/Image \
  --busybox anykernel3/tools/busybox \
  --test artifacts/component-tests/components-runtime.test \
  --control artifacts/freezer-tests/freezer-backport.test \
  --log artifacts/component-tests/qemu.log
```

The SUSFS test compiles the actual filter and BakaSU command dispatcher with
mocked credentials/VFS/RCU. It checks invalid input, allocation failures,
credential restoration, multi-user UID matching and stale refresh publication.
The RCU stub rejects NULL as 4.9 does, including the first configuration with no
previous bitmap; it must not silently model the newer NULL-safe helper.
The [vendored Hybrid Mount fixtures](hybridmount/README.md) exercise production
functions with controlled failure injection.

The QEMU test uses the built kernel and a temporary ext4 image made by
`e2fsprogs`. It invokes the real hm1 keyring interface and checks redirects,
xattrs/stat/readdir, ext4 inotify fdinfo, UID-specific whiteouts, rule replacement,
parent conversion and retained open FDs. It also configures CAKE through the
modern netlink API, delivers UDP packets and reads packet/byte statistics, and
checks that memcg swap accounting is exposed without a boot override. The guest
has no host disk or network attached. Android SELinux and the phone still need
device validation.

This 4.9 ext4 uses the generic file-handle encoder. The custom export encoder
guard is checked separately by the production-function hook fixtures.
