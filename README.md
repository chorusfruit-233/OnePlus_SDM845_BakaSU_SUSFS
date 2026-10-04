<div align="center">

# OnePlus 6/6T ReSukiSU + SUSFS

基于 LineageOS Linux 4.9.337 的可复现 AnyKernel3 自动构建项目

[![Build AK3](https://github.com/chorusfruit-233/OnePlus_SDM845_ReSukiSU_SUSFS/actions/workflows/build-ak3.yml/badge.svg)](https://github.com/chorusfruit-233/OnePlus_SDM845_ReSukiSU_SUSFS/actions/workflows/build-ak3.yml)
[![Kernel](https://img.shields.io/badge/kernel-4.9.337-informational)](https://github.com/LineageOS/android_kernel_oneplus_sdm845)
[![ReSukiSU](https://img.shields.io/badge/ReSukiSU-integrated-success)](https://github.com/ReSukiSU/ReSukiSU)
[![SUSFS](https://img.shields.io/badge/SUSFS-v2.3.0_inline_hook-orange)](https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd)
[![Devices](https://img.shields.io/badge/devices-OnePlus_6%20%7C%206T-blue)](#兼容性)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](#许可证)

</div>

本仓库不是 kernel 源码仓库，而是一套独立的拉取、移植、编译、验证和打包流程。
每次有效构建都会从固定的 LineageOS 4.9 最新基线开始，解析各上游项目的实际提交，
应用本仓库维护的 4.9 适配补丁（SUSFS 以自包含补丁形式 vendored 在仓库内），
最终输出可刷入的 AnyKernel3 ZIP。

> [!WARNING]
> 刷写自定义内核存在无法开机、数据损坏或需要恢复原厂 `boot` 的风险。请先备份当前
> `boot.img`，确认 bootloader 已解锁并准备好可用的恢复手段。你需要自行承担刷写风险。

## 兼容性

| 项目 | 支持情况 |
| --- | --- |
| 设备 | OnePlus 6 / 6T |
| Codename | `enchilada` / `fajita` |
| AK3 设备名 | `enchilada`、`fajita`、`OnePlus6`、`OnePlus6T` |
| Android | Android 15 |
| Kernel | LineageOS 4.9.337，`lineage-22.2` |
| 架构 | ARM64 |
| 分区 | A/B `boot` 分区 |

构建固定在配置文件记录的 kernel commit（当前为 `228c16bfcd25`）。其他 ROM 即使使用相同设备，也可能因
ramdisk、内核模块或 vendor 接口差异而不兼容。不要在未备份原始 `boot.img` 的情况下
跨 ROM 盲刷。

## 已集成功能

### ReSukiSU 与 SUSFS

- 动态拉取 ReSukiSU `main` 的最新提交；
- SUSFS **v2.3.0** 以自包含补丁形式 vendored（`patches/lineage-4.9/susfs-4.9.patch`，
  基于 [JackA1ltman/NonGKI_Kernel_Build_2nd](https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd)
  的 `susfs_patch_to_4.9.patch` 移植，并同步官方
  `gki-android14-6.1 @ 24743360ea08` 的修复），构建不再依赖 GitLab 上游；
- 使用 SUSFS 官方 inline hook 方式（`scripts/susfs-inline-hook.sh`）替换 KernelSU
  的 kprobe 钩子，覆盖 exec、faccessat、stat/fstat、read、input、reboot、
  setresuid 与 selinux 路径，构建产物无 kprobe 依赖；
- 同步 KSTAT 的 statfs、inotify fdinfo 与普通 fdinfo 处理、cmdline 快照读取、
  KSTAT 更新失败释放与 enabled-features 分配失败处理；exec 后置 hook 仅在
  exec 成功后安装 su fd，避免提前安装；
- 启用 SUS_PATH、SUS_MOUNT、SUS_KSTAT、SPOOF_UNAME、SUS_MAP、cmdline spoof、
  符号隐藏与 **OPEN_REDIRECT**；
- SUS_PATH 覆盖 open、stat、access、readlink、getdents64、unlink、rename、
  `O_PATH` 与 `O_TRUNC`，open redirect 覆盖普通 open、`O_PATH`、`O_TMPFILE`、
  readlink、`/proc/self/fd`、maps/smaps 与 statfs。

### NoMount

- [maxsteeel/NoMount](https://github.com/maxsteeel/nomount)（dev @
  `e00741165d10`）以自包含补丁 vendored（`patches/lineage-4.9/nomount-4.9.patch`）；
- NoMount 通过劫持目录 inode 操作实现路径重定向与虚拟文件注入，不需要真正的
  mount，配合 SUSFS 的 SUS_MOUNT 使用可进一步隐藏模块挂载痕迹；
- 内核侧启用 `CONFIG_NOMOUNT=y`（同时启用 `CONFIG_KEYS=y` 提供 keyring
  用户态接口），userspace 规则通过 `nomount` 密钥类型下发；
- 同步 dev 的规则/UID 数据结构调整及 dentry 固定，防止劫持的目录项被
  dcache 回收；
- 针对本树回移的 statx API 做了适配：`-DNOMOUNT_HAS_STATX` 强制走四参数
  `vfs_getattr_nosec()` 路径，保留上游 `-std=gnu11` 兼容新实现（4.9 默认
  `-std=gnu89`）。

### USB Wi-Fi（Kali/渗透测试）

- 启用 Linux 4.9 树内已有的 USB Wi-Fi 驱动：
  `ath9k_htc`（AR9271）、`rt2800usb`（RT3070/5370/5572，含 5GHz）、
  `mt7601u`、`carl9170`、`ar5523`、`rt2500usb`、`rt73usb`、`rtl8xxxu`；
- 额外集成树外驱动 [aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au)
  （固定 `v5.6.4.2`），支持 **RTL8812AU / RTL8821AU / RTL8814AU** USB 网卡
  （monitor 模式与注入，Kali/aircrack-ng 常用芯片）。构建时克隆到
  `drivers/net/wireless/realtek/rtl8812au/`，由
  `patches/lineage-4.9/rtl8812au-4.9-adaptation.patch` 适配本树回移的
  cfg80211 ABI（新 `cfg80211_roamed`/`cfg80211_connect_bss` 签名）并以
  `CONFIG_88XXAU=y` 内建进 `Image.gz-dtb`（无需打包 `.ko`，镜像约 +0.9MB）；
- 固件通过 `CONFIG_EXTRA_FIRMWARE` 内嵌进内核镜像（`htc_9271.fw`、
  `rt2870.bin`、`mt7601u.bin`，构建时从 linux-firmware 拉取），不依赖
  `/vendor` 固件目录；
- `patches/lineage-4.9/ath9k-htc-symbols.patch` 将 ath9k 的 HTC 协议符号
  加上 `ath9k_htc_hst_` 前缀，避免与 OnePlus 内置 `qcacld-3.0` WLAN 的
  同名 `htc_*` 符号冲突（两者需同时编入内核）；
- 驱动与固件全部 `=y` 编入 `Image.gz-dtb`，无需打包 `.ko`。

### KPM（KPatch-Next）

- 内核启用 `CONFIG_KALLSYMS=y` + `CONFIG_KALLSYMS_ALL=y`（ReSukiSU 自动
  select），满足 [KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next)
  的镜像静态 patch 要求 —— KPatch-Next 直接 patch 编译好的内核镜像，
  **不需要任何内核源码补丁**；
- 与 SUSFS 符号隐藏兼容：隐藏只作用于 `/proc/kallsyms` 输出，不影响镜像内
  编译生成的 kallsyms 符号表；
- 使用方式：刷入 [KPatch-Next-Module](https://github.com/KernelSU-Next/KPatch-Next-Module)
  （Magisk/KernelSU 通用模块，自带 kpatch/kpimg 与 WebUI），用其管理 KPM
  模块即可；本仓库的内核无需额外配置；
- Actions 会检查 `CONFIG_KALLSYMS`/`CONFIG_KALLSYMS_ALL`，缺失即终止构建。

### Re:Kernel

- [Sakion-Team/Re-Kernel](https://github.com/Sakion-Team/Re-Kernel)（Integrate，
  rekernel 源码与 ReKernel-X upstream/v9.2 相同）以自包含补丁 vendored
  （`patches/lineage-4.9/rekernel-4.9.patch`）；
- 新增 `drivers/rekernel/`（netlink 上报模块，`CONFIG_REKERNEL=y`，
  `CONFIG_REKERNEL_NETWORK=y`）；
- `drivers/android/binder.c`：移植冻结进程的 async 事务合并处理
  （`binder_can_update_transaction`/`binder_find_outdated_transaction_ilocked`，
  4.9 变体不含 `binder_buffer->pid` 与 `proc->outstanding_txns`）+ 事务上报
  hook；`kernel/signal.c`：SIGKILL/SIGTERM/SIGABRT/SIGQUIT 上报；
- 4.9 适配：`JOBCTL_TRAP_FREEZE` 为 4.11+ 引入，`jobctl_frozen()` 回退使用
  `frozen()/freezing()`；
- 启用 IPv4/IPv6 入站 TCP 网络事件上报，通过 netlink 向 ReKernel 用户态
  发送应用 UID、IP 版本与数据长度；纯 ACK 等无数据且无 SYN/FIN/RST 的包不触发上报；
- 配合 ReKernel 用户态（tombstone 冻结优化）使用；Actions 检查
  `CONFIG_REKERNEL` 与 `CONFIG_REKERNEL_NETWORK`。

### 网络与容器

- zram 支持 LZO、LZ4 与 Zstd，LZ4/Zstd 压缩与解压后端内置于内核；默认算法仍为 LZO，
  ROM 或管理工具可在 zram 初始化前通过 `/sys/block/zram0/comp_algorithm`
  选择 `lz4` 或 `zstd`；该节点也可用于查看可用算法及当前算法（方括号标记）；
- PSI 压力监测默认启用，提供 `/proc/pressure/cpu`、`memory`、`io` 统计及
  poll 触发器；Android LMKD 是否使用 PSI 还取决于 ROM 的配置与运行状态；

- BBRv1 与 BBRv3，可在运行时保留 BBRv1 作为回退；
- CAKE、FQ、FQ_CODEL 与 PIE qdisc；
- TTL/HL target、IPSet、IPv6 NAT；
- Droidspaces/LXC 所需的 namespaces、cgroups、seccomp、veth、bridge、netfilter、
  overlayfs、TMPFS XATTR/POSIX ACL 等基础配置；
- Actions 会在编译前逐项检查关键 Droidspaces 配置，缺失时直接终止构建。

### 安全与通用优化

- Baseband Guard 通过 Linux 4.9 旧式 LSM/SELinux 路径接入；
- 默认不阻止 boot/recovery 写入，避免干扰正常刷写和救砖流程；
- `bbg-slot-allow.patch`（构建时应用到 Baseband Guard）修复 A/B 槽位放行
  缺陷：原版在内核 cmdline 存在 `androidboot.slot_suffix` 时只放行当前槽
  分区，导致 root 工具无法刷写 **inactive 槽**（OTA/手动更新另一槽内核时报
  EPERM）；修复后 allowlist 分区（boot/dtbo/vbmeta 等）的 `_a`/`_b` 两个槽
  均可写。
- 可选的 CPUfreq `scaling_min_freq_limit`；
- arm64 copy prefetch、页面与 `struct file` 对齐、VFS cache pressure 调整；
- F2FS urgent GC 间隔和 alarmtimer 精确唤醒窗口优化。

## 获取构建产物

1. 打开 [Actions 页面](https://github.com/chorusfruit-233/OnePlus_SDM845_ReSukiSU_SUSFS/actions/workflows/build-ak3.yml)。
2. 选择最近一次成功且实际执行了 `build` job 的运行。
3. 在页面底部下载 `OnePlus6-6T-lineage-4.9-ak3` artifact。
4. 解压 artifact，核对 `SHA256SUMS` 后再使用其中的 AK3 ZIP。

artifact 包含：

| 文件 | 用途 |
| --- | --- |
| `OnePlus6-6T-ReSukiSU-*-SUSFS-*-AK3.zip` | 可刷入的 AnyKernel3 包 |
| `Image.gz-dtb` | 编译得到的内核镜像 |
| `SHA256SUMS` | AK3 ZIP 的 SHA256 校验值 |
| `build-info.txt` | 本次构建使用的全部上游 commit |
| `device-tests/` | AArch64 SUSFS syscall 真机回归测试 |

> [!NOTE]
> Actions artifact 是一个下载容器。刷入前需要先解压 artifact，再刷其中名称以
> `-AK3.zip` 结尾的文件，不要直接刷 artifact 外层压缩包。

## 刷入

推荐使用支持 AnyKernel3 的内核刷写工具或自定义 recovery：

1. 备份当前可正常启动的 `boot.img`；
2. 确认下载的包与设备、Android 版本和当前 ROM 匹配；
3. 用 `SHA256SUMS` 校验 AK3 ZIP；
4. 刷入 `*-AK3.zip`；
5. 重启后检查内核版本、ReSukiSU 管理器状态和基本网络功能。

出现 bootloop 时，刷回备份的原始 `boot.img`。本项目不会修改 system/vendor 分区，
但这并不能替代可靠的 boot 备份。

## 手动构建

在 Actions 页面选择 **Run workflow**。可用输入如下：

| 输入 | 默认值 | 说明 |
| --- | --- | --- |
| `resukisu_ref` | `main` | ReSukiSU branch、tag 或完整 commit |
| `bbg_ref` | `main` | Baseband Guard branch、tag 或完整 commit |
| `kernel_patches_ref` | `main` | WildKernels patches branch、tag 或完整 commit |
| `anykernel_ref` | `master` | AnyKernel3 branch、tag 或完整 commit |
| `force_rebuild` | `false` | 忽略无变化标记并强制完整构建 |

定时任务每天在 `18:17 UTC`（北京时间次日 `02:17`）检查一次上游。workflow 会先将
branch/tag 解析成不可变 commit，再把 kernel 基线、builder、补丁（含 vendored
SUSFS 补丁的哈希）和所有上游 commit 共同组成 build key：

- build key 未变化时，只运行约数秒的解析 job，跳过内核编译；
- 输入变化时恢复最多 2 GiB 的 `ccache`，只重编译受影响对象；
- `force_rebuild=true` 可绕过无变化跳过，但仍会使用编译缓存。

## 构建来源

| 组件 | 上游 | 策略 |
| --- | --- | --- |
| Kernel | [LineageOS/android_kernel_oneplus_sdm845](https://github.com/LineageOS/android_kernel_oneplus_sdm845) | 固定基线 commit |
| ReSukiSU | [ReSukiSU/ReSukiSU](https://github.com/ReSukiSU/ReSukiSU) | 默认跟踪 `main` |
| SUSFS v2.3.0 | 自包含补丁（源自 [JackA1ltman/NonGKI_Kernel_Build_2nd](https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd)） | vendored，随仓库版本变化 |
| NoMount | [maxsteeel/nomount](https://github.com/maxsteeel/nomount)（dev 分支） | vendored，固定 `e00741165d10` |
| RTL8812AU/8821AU/8814AU | [aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au) | 默认跟踪 `v5.6.4.2`（构建时克隆 + 适配补丁） |
| CAKE | [dtaht/sch_cake](https://github.com/dtaht/sch_cake) | 固定最后一版兼容旧 qdisc API 的基线 |
| BBRv3 patches | [WildKernels/kernel_patches](https://github.com/WildKernels/kernel_patches) | 稀疏拉取 `common/bbrv3` |
| Baseband Guard | [vc-teahouse/Baseband-guard](https://github.com/vc-teahouse/Baseband-guard) | 默认跟踪 `main` |
| AnyKernel3 | [osm0sis/AnyKernel3](https://github.com/osm0sis/AnyKernel3) | 默认跟踪 `master` |

vendored 组件的确切来源记录在 `configs/vendored-upstreams.json`。SUSFS 官方来源、
4.9 移植来源和 NoMount dev 均固定到提交；同一 SUSFS 版本号内也可能存在源码差异。
每次构建的确切版本以 artifact 内的 `build-info.txt` 为准，不应只根据 branch 名推断。

## 真机回归测试

`device-tests/` 中包含静态链接的 ARM64 测试程序和执行脚本。推送到已 root 的设备：

```sh
adb push device-tests/susfs_syscall_test /data/local/tmp/
adb push device-tests/run-susfs-regression.sh /data/local/tmp/
adb shell su -c 'chmod 0755 /data/local/tmp/susfs_syscall_test /data/local/tmp/run-susfs-regression.sh'
adb shell su -c '/data/local/tmp/run-susfs-regression.sh'
```

需要验证已标记的 SUS_PATH 时，在对应 SUSFS 隐藏身份/namespace 中运行：

```sh
adb shell su -c '/data/local/tmp/run-susfs-regression.sh \
  /data/local/tmp/susfs_syscall_test --hidden /path/to/marked-entry'
```

测试覆盖 `stat/statx/open/access/readlink/getdents64/unlink/rename/O_PATH/O_TRUNC`，
以及 SUS_MOUNT 的 `/proc/self/mountinfo` 和 fdinfo。`--kstat` 可检查伪装 inode 在
stat、fstat、statx、普通 fdinfo 和 inotify fdinfo 中的一致性。完整参数见
[`tests/device/README.md`](tests/device/README.md)。

## 已知限制

- LTO 未启用。该 4.9 树需要可用的 AArch64 GNU gold/LLVMgold 组合；GitHub runner
  默认的主机 gold 不能链接 AArch64 kernel；
- BBRv3 的 ECN-low、PLB 和逐丢包回调依赖较新的 TCP/route ABI，本 backport 不提供；
- CAKE 固定在 `15f1f6c` 兼容基线，当前 upstream `master` 依赖新版 `tcf_block` 和
  extack API，不能直接放入 4.9；
- 编译成功不等于所有 ROM 上均已完成启动、基带、网络和容器稳定性验证；
- `kernel_base` 变化后必须重新生成并验证 `kernel-4.9-adaptation.patch` 和
  `susfs-4.9.patch`，不能只修改配置中的 commit 绕过基线检查；
- `susfs-4.9.patch` 内嵌 SUSFS v2.3.0 源码；升级 SUSFS 版本时需要重新移植
  `fs/susfs.c`、`include/linux/susfs.h`、`include/linux/susfs_def.h` 及内核钩子，
  并同步更新 `scripts/susfs-inline-hook.sh` 的版本说明；
- `nomount-4.9.patch` 内嵌 NoMount `dev` 分支快照；NoMount 用户态组件（模块
  ZIP 与 `nomount` 工具）不属于本仓库构建产物，需要从上游 release 单独获取；
- USB Wi-Fi 覆盖 4.9 树内驱动（AR9271/RT3070/5370/5572/MT7601U 等）与树外的
  rtl8812au/8821au/8814au；RTL8188EUS、MT76x2U、MT7921U、RTW88/RTW89 等仍需
  各自第三方驱动或较新内核，不在支持范围；
- `ath9k-htc-symbols.patch` 只改动了 ath9k 私有 HTC 协议符号名，不影响
  `qcacld-3.0`；若上游 ath9k 代码大幅重构，需要重新生成该补丁。

## 仓库结构

```text
.github/workflows/   GitHub Actions 构建流程
ak3/                 OnePlus 6/6T AnyKernel3 模板
configs/             设备、kernel 和上游配置
patches/lineage-4.9/ Linux 4.9 主补丁及 SUSFS/CAKE/BBRv3 适配
scripts/             动态拉取上游、SUSFS inline hook 与 AK3 打包脚本
tests/device/        SUSFS 设备端 syscall 回归测试
```

这个边界是有意保留的：kernel 源码负责内核实现，本仓库负责可复现构建、动态上游追踪
和产物发布。不要把 workflow、构建缓存或外部源码 checkout 复制回 kernel 仓库。

## 许可证

本仓库（构建脚本、workflow 与 4.9 适配补丁）以 [GPL-3.0](LICENSE) 发布。
集成的各上游组件（内核基线、ReSukiSU、SUSFS、NoMount、AnyKernel3、Baseband
Guard、CAKE、BBRv3 补丁等）的许可证以**各自上游仓库声明为准**，本仓库不代为
声明。

刷写和使用本构建产物前，请确保你所在地区与用途允许修改和分发内核二进制。

## 问题反馈

提交 issue 时请至少附上：

- 设备型号与 codename；
- ROM 名称、Android 版本和构建日期；
- Actions run 链接及 artifact 中的 `build-info.txt`；
- 刷写方式、是否能进入 fastboot/recovery；
- `dmesg`、`logcat` 或明确的复现步骤。

只有“无法启动”而没有 ROM、构建 commit 和日志的信息，通常不足以定位 4.9 backport
或 ramdisk 兼容问题。

## 致谢

- [ReSukiSU Team](https://github.com/ReSukiSU/ReSukiSU)
- [simonpunk / SUSFS](https://gitlab.com/simonpunk/susfs4ksu)
- [LineageOS](https://github.com/LineageOS)
- [WildKernels](https://github.com/WildKernels)
- [vc-teahouse / Baseband Guard](https://github.com/vc-teahouse/Baseband-guard)
- [dtaht / sch_cake](https://github.com/dtaht/sch_cake)
- [osm0sis / AnyKernel3](https://github.com/osm0sis/AnyKernel3)
- [ravindu644 / Droidspaces](https://github.com/ravindu644/Droidspaces-OSS)
- [huangdihd / OnePlus_ReSukiSU_SUSFS](https://github.com/huangdihd/OnePlus_ReSukiSU_SUSFS)
- [JackA1ltman / NonGKI_Kernel_Build_2nd](https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd)
- [maxsteeel / NoMount](https://github.com/maxsteeel/nomount)
