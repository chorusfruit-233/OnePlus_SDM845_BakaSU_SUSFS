# OnePlus 6 / 6T 上游同步 · 2026-11-28

适用于 Android 15 / LineageOS 22.2 的 OnePlus 6（enchilada）与 6T（fajita）。Release 附件中的 AK3.zip 是刷机包，SHA256SUMS 可用于校验下载内容。

定时 CI #189 在源码准备阶段失败。BakaSU main 改动了 SELinux 自动后端和策略符号查询，触发 4.9 源码检查。已将上一版的 4.9 兼容补丁重基到新提交，保留旧 MLS 接口适配和钩子回滚处理。新版策略符号快照不可用时会回退到策略表查询。

| 部件 | 本次核对的上游提交 | 对本版本的影响 |
| --- | --- | --- |
| BakaSU | main · 4ca505a878d9 | 同步内核来源，适配新版策略查询回退逻辑 |
| SUSFS 官方 / 4.9 移植 | v2.4.0 · f76b81f2a6bf / b3fdebf20660 | 官方版本仍为 v2.4.0。同步 sdcardfs 的跨存储视图标记和所有者访问处理，延续已有的 UID 位图空指针保护 |
| HybridMount | dev · 025a6a09a0a5 | 仓库更新了 Wear 打包和 WebUI，内建 VFS 驱动及内核测试文件逐字节一致 |
| linux-firmware | main · 66a9a75560fc | 更新下载提交，三份内建 USB Wi-Fi 固件逐字节一致 |
| LineageOS | lineage-22.2 · 228c16bfcd25 | 基线仍为 4.9.337 |
| Baseband Guard / ReKernel | 48d9fdea643b / ac08296174d7 | 所用分支无更新 |
| Droidspaces | main · 77e63323c937 / v7.2.0 · cdadb9eb5d0f | 正式版和内核要求无变化 |
| Droidspaces backports / Mihomo Alpha | be24159e5cc2 / 574c6db4a5db | 所用分支无更新 |
| WildKernels / CAKE / RTL8812AU | 70c394f16d82 / 53ff94d4b580 / 734485506a30 | 所用分支无更新 |
| AnyKernel3 | master · 41f04bdb4ee3 | 打包来源无更新 |
| cgroup freezer / Binder freezer 参考来源 | Linux 5.10.274 · 3a323bc22b88 / android13-5.10 · 9536d991bb59 | 两个来源均无更新 |

Go 1.27.4 和 GitHub Actions 构建依赖已核对。构建包含 WALT、V2 freezer、Binder freezer、蓝牙 UART 兼容修复及既有的十个安全修复和加固补丁。实际构建提交见 build-info.txt、source-revisions.json 和 vendored-upstreams.json。真机开机、蓝牙连接及 Android 上的 sdcardfs 行为仍待验证。
