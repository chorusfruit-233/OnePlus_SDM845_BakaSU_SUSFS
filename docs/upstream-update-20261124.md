# OnePlus 6 / 6T 上游同步 · 2026-11-24

适用于 Android 15 / LineageOS 22.2 的 OnePlus 6（enchilada）与 6T（fajita）。Release 附件中的 AK3.zip 可用于刷入，SHA256SUMS 可用于核对下载内容。

定时 CI #184 在源码准备阶段报错。BakaSU main 更新了 SELinux 自动后端，触发了 4.9 源码审阅检查。此次审阅确认，上游新增的 context hash 更新受现代内核的能力检测控制，LineageOS 4.9 沿用旧的 SID 处理接口。更新了审阅记录，保留 BakaSU main 跟踪、旧内核兼容补丁和源码检查。

| 部件 | 本次核对的上游提交 | 对本版本的影响 |
| --- | --- | --- |
| BakaSU | main · 57b2db6076f4 | 同步内核来源，刷新 4.9 审阅记录 |
| Baseband Guard | main · 48d9fdea643b | 同步最新驱动，继续使用 4.9 块设备接口和 A/B 槽位白名单补丁 |
| Droidspaces | main · 77e63323c937 / v7.2.0 · cdadb9eb5d0f | 主线新增用户态修复，内核配置要求无变化。正式版仍为 v7.2.0 |
| linux-firmware | main · 16a7a3f83c2f | 11 月 25 日发布前更新下载提交，三份内建 USB Wi-Fi 固件逐字节一致 |
| LineageOS | lineage-22.2 · 228c16bfcd25 | 基线仍为 4.9.337 |
| SUSFS / 4.9 移植来源 | v2.4.0 · f76b81f2a6bf / ec069a4e34f9 | 两个来源均无更新 |
| HybridMount / ReKernel | b0fa65581aff / ac08296174d7 | 两个来源均无更新 |
| WildKernels / CAKE / RTL8812AU | 70c394f16d82 / 53ff94d4b580 / 734485506a30 | 所用分支均无更新 |
| Droidspaces backports / Mihomo Alpha | be24159e5cc2 / 574c6db4a5db | 两个来源均无更新 |
| AnyKernel3 | master · 41f04bdb4ee3 | 刷机包来源无更新 |
| cgroup freezer / Binder freezer 参考来源 | Linux 5.10.274 · 3a323bc22b88 / android13-5.10 · 9536d991bb59 | 两个来源均无更新 |

Go 1.27.4 和 GitHub Actions 的四个构建依赖已核对。构建包括 WALT、V2 freezer、Binder freezer、蓝牙 UART 兼容修复及既有的 10 个安全修复和加固补丁。实际提交见 build-info.txt、source-revisions.json 和 vendored-upstreams.json。新镜像的真机开机和蓝牙连接仍待验证。
