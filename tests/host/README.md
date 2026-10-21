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
