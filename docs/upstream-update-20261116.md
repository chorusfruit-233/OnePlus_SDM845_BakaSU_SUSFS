# 2026-11-16 上游同步

本次同步 BakaSU main、SUSFS v2.4.0 和 Hybrid Mount dev，并更新 Droidspaces 与 Mihomo 的兼容性测试目标。保留 WALT、真实 cgroup V2 freezer、Binder freezer、蓝牙 UART ioctl 修复，以及 2026-11-05 的 10 个安全修复补丁。

## 上游核对

| 部件 | 核对版本 / 提交 | 处理 |
| --- | --- | --- |
| LineageOS SDM845 | `lineage-22.2 @ 228c16bfcd25` | 无新提交，仍为 4.9.337 |
| BakaSU | `main @ 5d6d1843c893` | 更新；继续跟踪 main |
| SUSFS | `gki-android14-6.1 @ f76b81f2a6bf` | 更新到 v2.4.0 |
| SUSFS 4.9 移植来源 | `mainline @ bbe032eb06c5` | 核对 VFS 改动并适配 |
| Hybrid Mount | `dev @ f5db43f0ea54` | 更新内建 VFS 驱动，协议仍为 hm1 |
| Droidspaces | `v7.2.0 @ cdadb9eb5d0f` | 更新配置要求和兼容性记录 |
| Droidspaces backports | `main @ be24159e5cc2` | 无更新，保留已适配的系统调用补丁 |
| Mihomo | `Alpha @ 574c6db4a5db` | 更新实际 eBPF 对象和上游集成测试目标 |
| CAKE | `master @ 53ff94d4b580` | 无更新 |
| Baseband Guard | `main @ 028ff7fd509e` | 无更新 |
| WildKernels 补丁源 | `main @ 10c98a49a212` | 仓库已更新；本项目使用的 BBRv3 源码未变 |
| ReKernel | `main @ ac08296174d7` | 无更新，保留本地修复和 freezer 适配 |
| RTL8812AU | `v5.6.4.2 @ 734485506a30` | 所选驱动分支无更新 |
| AnyKernel3 | `master @ 41f04bdb4ee3` | 无更新 |
| freezer 测试来源 | Linux `5.10.274 @ 3a323bc22b88` | 更新测试来源；五个所用测试文件内容未变 |

上述是本次核对的提交。每次构建实际解析的浮动分支、固件 SHA256 和适配后提交另见 `build-info.txt`、`source-revisions.json`；这次更新没有把 Linux 4.9 整体升级成 5.10。

## 适配内容

- BakaSU：使用官方 preinit 递归构建修复，移除重复的 `KBUILD_SRC` 覆盖；保留 UAPI 头文件缺失时直接报错，以及原有 preinit 资源清理和 4.9 ABI 适配。重新审核新增的 fstat inline hook 检查。
- SUSFS：接入 `0x55554` 路径 UID 允许列表命令，安装或卸载应用后重新解析 UID。路径过滤采用上游 v2.4 行为，不再依赖旧的卸载标记和文件所有者豁免；配置的应用 ID 可见已标记路径。使用新功能需要支持 v2.4.0 的 SUSFS 用户态工具。
- SUSFS 4.9：保留 inode `i_state` 标志存储；两个 UID 列表都使用已加固的 `packages.list` 解析，保留短读、长度和整数检查、错误回滚、刷新代次保护、凭据恢复及 NULL 安全的 RCU 释放。目录过滤使用真实文件的 superblock，移除旧的 FUSE `/data` 映射。关闭 priority filter 或日志时仍能编译路径过滤。
- SELinux：继续使用 BakaSU 的 NonGKI 自动 hooks 和本地 legacy policy 适配；官方 SUSFS 中面向 GKI `selinux_state` 的手动 setxattr/策略 hooks 不套用到这个后端。本次版本号更新不代表这些 GKI hooks 已在 4.9 上实现。
- Hybrid Mount：同步 backing 权限检查、noexec/nodev、set-ID/capability 处理、原生目录隔离、只读 backing 文件缓存、独立文件位置、dentry 回调与生命周期修复。保留本树 statx ABI、KEYS 依赖及用户共享页请求快照，避免重新引入并发修改请求的问题。
- Droidspaces：v7.2.0 的 IPv4/IPv6 REJECT 配置已具备；仍使用真实 V2 freezer，跳过上游的固定 `frozen 0` 占位实现。新 mount API 的 systemd 回退由 Droidspaces 用户态提供；保留 WALT，因此仍不提供 CFS CPU 配额。

## 验证与产物

发布流程要求完整手机内核编译、SUSFS 配置组合编译，以及 BakaSU/preinit、Mihomo eBPF、Droidspaces 系统调用、freezer、Binder 和组件的主机/QEMU 回归通过。新增路径 UID 列表的故障注入与实际 inode 可见性测试，并同步 Hybrid Mount 上游主机测试。

主机测试使用受控内核原语；QEMU 不覆盖一加硬件。此次同步尚无新的真机开机、蓝牙或 SELinux 检测结果。近期安全修复的覆盖范围仍以 `security-advisories-20261105.json` 为准，未修改 Android 安全补丁级别。

刷入 `*-AK3.zip` 前核对 `SHA256SUMS`。该文件同时覆盖镜像和版本/审查记录；Release 标签指向通过构建的 builder 提交。用户态管理器、Hybrid Mount 元模块、Droidspaces 和 Mihomo 应用不包含在内核 ZIP 中。
