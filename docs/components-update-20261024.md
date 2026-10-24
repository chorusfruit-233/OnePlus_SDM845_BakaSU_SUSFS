# 2026-10-24 集成组件更新

本轮继续使用 LineageOS Linux 4.9.337 基线，BakaSU 跟踪 `main`，保留 WALT、
Mihomo eBPF、cgroup V2 freezer 和 Binder 冻结适配。BakaSU 的独立输出目录修复
已在 [CI #130](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/40109240760)
全流程通过；下面的组件更新另做完整构建与回归。

| 组件 | 本轮核对的上游 | 处理 |
| --- | --- | --- |
| BakaSU | `main @ d5e9e025b8b4` | UAPI v6 / preinit / 热安装、SUSFS 新命令与 UID 刷新；同步最新生成器构建修复 |
| SUSFS | `gki-android14-6.1 @ 27e0a0e42745`，仍为 v2.3.0 | 同步新核心功能及 4.9 mount 修复 |
| Non-GKI SUSFS port | `mainline @ dcd789634247` | 同步 `clone_mnt()` 的 unshared ID 标记；保留本地正确的 ctime bitmask |
| Hybrid Mount | `dev @ e5120adea50d`，`hm1` | 更新内建驱动，保留 4.9 ABI 适配 |
| CAKE | `master @ 53ff94d4b580` | 更新调度器、旧内核兼容层及 netlink UAPI |
| Droidspaces | v7.0.0；主线要求 `847ecdd2c943` | 开启默认 swap 记账，保留 WALT / 无 CFS CPU 配额 |
| ReKernel | `main @ ac08296174d7` | Non-GKI 集成源码未变；记录最新来源，保留 V2/Binder 适配 |
| Baseband Guard | `main @ a54e0dc6cf0a` | 无更新，继续跟踪 main |
| BBRv3 patch set | `main @ fa76c90e2cb2` | 无更新，保留 4.9 适配 |
| RTL8812AU | `v5.6.4.2 @ 734485506a30` | 无更新，保留 cfg80211 兼容层 |
| AnyKernel3 | `master @ 020dfeccf9d7` | 无更新，保留 kernel-only / 原 ramdisk 安装方式 |
| Mihomo 测试目标 | `Alpha @ 02581ff38100` | 无更新，继续执行真实 eBPF 程序测试 |

## SUSFS

核心更新来自 `08066fa`。新接口 `0x60030` 使用应用包名配置 UID 位图，过滤
普通应用对目标 UID 的 priority/ioprio 查询。4.9 的四个系统调用保留原来的
RCU 和 tasklist 锁边界；BakaSU 的 root-only SUSFS dispatcher 已接入命令。
UID 更新从公共 package tracker 触发，覆盖旧版 rename LSM 钩子，无需在
4.9 上开启新版 fsnotify observer。

移植保留 inode `i_state` 存储、statx 私有标记和已有 OPEN_REDIRECT 等功能。
新增分配使用私有 kmalloc/vmalloc 兼容函数；配置代次检查防止旧后台刷新
覆盖较新配置。4.9 的 `kfree_rcu()` 不接受空指针，首次配置还没有旧位图，
因此两处旧位图释放都增加非空检查；宿主模型按实际 4.9 的 RCU 约束测试，
修复前可复现首次配置断言失败，修复后首次配置和后续更新均通过。
SELinux 继续使用已适配的 NonGKI 自动 hooks。

新功能需要包含 `set_priority_uid_filter` 命令的最新版官方 SUSFS 工具。
本仓库更新内核及接口，不打包替换管理器、SUSFS 工具或 Hybrid Mount 元模块。

## Hybrid Mount 与 CAKE

Hybrid Mount 同步 UID 子项选择、规则替换缓存、父目录转换、RCU/引用计数、
seqcount 写侧、内存分配失败回滚和 ext4 export encoder 防护。最新源码仍用
`hm1` keyring 协议；保留本树的四参数 getattr/statx 和 C 字符串 name snapshot
适配。内建 export encoder 防护让 fabricated inode 的 inotify fdinfo 不再
调用依赖 ext4 私有 inode 状态的原始编码器。

上游为了避免悬空回调，保留已复制的目录 fops 及相关文件系统引用到卸载时；
本仓库内建驱动的生命周期为本次开机。清除规则后，相关资源也可能继续保留
到重启，大量 inode 更替会增加这部分占用。

CAKE 使用当前独立上游，包含 TCP options 解析越界修复。同步
`TCA_CAKE_BASE_RATE64`、GSO/fwmark 和嵌套统计接口，避免新实现与旧 UAPI 混用。
使用 CAKE 配置工具时需要支持现代 CAKE netlink 接口的 iproute2/tc。

## 固件核对

重新下载官方 linux-firmware 当前版本，三个文件与当前内核内嵌文件一致：

| 文件 | 字节 | SHA-256 |
| --- | --- | --- |
| `htc_9271.fw` | 50980 | `b5c123f9a8f2b0388eddd630860c100b4fe889ccdb4fcf24bc88b0fe2df3e59e` |
| `rt2870.bin` | 8192 | `251b8918391eac6415d60dca239e415aad0177e885376f2a17782e64fcbbe317` |
| `mediatek/mt7601u.bin` | 45412 | `4511b1d840e22aea2bf5fdca419c91c0d94cbfb291b9ac4f8be6d9100d1a7046` |

## 验证

- 从原始基线重新执行全部内核补丁及 inline hook，144 个内核路径和
  9 个 BakaSU 文件与实际源码逐字节一致。
- SUSFS 实际函数与 BakaSU dispatcher 的输入/分配/权限域失败注入通过；
  覆盖 multi-user app ID、包 UID 更新和过期刷新。
- Hybrid Mount 的六组上游生产函数测试通过，含 UID cursor、分配回滚、
  inode 生命周期、读取引用和 VFS 语义。
- 完整手机 `Image.gz-dtb`、符号/嵌入 ELF 检查和增强 QEMU guest 均通过。
- QEMU 的八项实际 hm1/ext4/inotify、规则生命周期、CAKE 和 memcg 测试通过。
  4.9 ext4 使用通用文件句柄编码；自定义 export encoder 防护另由上游生产
  函数测试验证。
- 最终 [GitHub CI #133](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/40112046834)
  全通过，构建提交 `77cb9e8099ec674a8849ed29a1c2b6c9d20d9e8f`，
  BakaSU 实际提交 `d5e9e025b8b49155f8014684d64c91742b465f65`。
- CI 同时通过手机镜像及 ELF 校验、kernel-only 安装测试、SUSFS 与 135 项
  Hybrid Mount 宿主检查、八项组件实测、Mihomo interpreter/JIT/hardened、
  18 项 V2 freezer、ARM64/ARM32 Binder 冻结和六项生产 preinit 测试。

集成提交 `29cd530` 推送时，上游 BakaSU 新增 `d5e9e025`，只给代码生成器
增加 `CONFIG_KSU` 条件。已审核并更新对应指纹；#131 被后续构建取代。
#132 随后由包含上述 RCU 空指针修复的最终完整构建取代。

QEMU 新增实际 hm1/ext4/inotify、规则缓存和 UID 隔离、CAKE 配置与 UDP 包统计、
默认 memcg swap 记账测试；原有 Mihomo、V2/Binder 和 preinit 测试继续执行。
宿主故障注入使用模拟内核服务；QEMU 不启动 Android SELinux policy 或系统框架。
本轮更新仍需 OnePlus 6T / LOS 22.2 真机刷入后的启动、root 与模块行为反馈。

## 刷机包

下载 [CI #133 的 OnePlus6-6T-lineage-4.9-ak3 artifact](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/40112046834/artifacts/12567093965)，
解压 artifact 后，刷入其中的 AK3 ZIP：

`OnePlus6-6T-BakaSU-d5e9e025-SUSFS-2678ee10-DS7-1c4b0962-TC-eBPF-FreezerV2-Binder-experimental-AK3.zip`

CI 已执行 ZIP 完整性检查，AK3 ZIP 的 SHA-256 为：

```text
ecd5a9b40d2cde0a7f3718442c385ecbd296e609db323ac6e5d1c1a3c447f105
```

artifact 同时提供 `build-info.txt`、`SHA256SUMS`、内核镜像、Droidspaces 配置
检查结果和真机测试工具。各组 CI 运行日志位于同一 run 的测试 artifacts 中。
