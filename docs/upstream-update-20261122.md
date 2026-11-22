# OnePlus 6 / 6T 上游同步 · 2026-11-22

适用于 Android 15 / LineageOS 22.2 的 OnePlus 6（enchilada）与 6T（fajita）。刷机包为 Release 附件中以 AK3.zip 结尾的文件。SHA256SUMS 可核对刷机包与独立镜像。

| 部件 | 本次核对的上游提交 | 对本版本的影响 |
| --- | --- | --- |
| LineageOS SDM845 4.9.337 | lineage-22.2 · 228c16bfcd25 | 内核基线与上版相同 |
| BakaSU | main · 2734e0bc1557 | 同步 20 个上游提交。使用官方 UID 命令和软件包重扫，适配拆分后的驱动和 4.9 LSM 接口 |
| SUSFS 官方 | gki-android14-6.1 · f76b81f2a6bf | 版本仍为 v2.4.0 |
| SUSFS 4.9 移植来源 | mainline · ec069a4e34f9 | 上游修正了普通 inode 和 FUSE inode 的两处标志读取，本项目上一版已包含 |
| HybridMount | dev · b0fa65581aff | 内建 hm1 驱动拒绝递归代理源。恢复 superblock 后，在 RCU 宽限期结束时一起释放 xattr 表与包装结构 |
| WildKernels | main · 70c394f16d82 | 仓库有更新，本项目使用的 BBRv3 补丁内容相同 |
| Droidspaces / backports | v7.2.0 · cdadb9eb5d0f / be24159e5cc2 | 应用和系统调用回移来源均与上版相同，保留 WALT |
| Mihomo | Alpha · 574c6db4a5db | 测试目标相同。ARM64 eBPF 测试使用 Go 1.27.4 构建 |
| CAKE / Baseband Guard | 53ff94d4b580 / 028ff7fd509e | 两个来源均与上版相同 |
| ReKernel / RTL8812AU | ac08296174d7 / 734485506a30 | 所选分支与上版相同 |
| AnyKernel3 | master · 41f04bdb4ee3 | 刷机打包来源与上版相同 |
| cgroup freezer / Binder freezer 参考来源 | Linux 5.10.274 · 3a323bc22b88 / android13-5.10 · 9536d991bb59 | 保留现有 V2 与 Binder freezer 回移 |
| linux-firmware | a1ebb5ad7eae | 三份内建 USB Wi-Fi 固件与上版逐字节一致。构建按提交下载并校验各文件的 SHA-256 |

4.9 的安全钩子链没有模块名称。驱动按原回调地址识别 SELinux 项，保留链上其他安全模块的检查。关闭功能时，回调还原失败会保留重试状态，已被正在执行的回调引用的资源继续有效。保留蓝牙 UART ioctl 兼容修复与既有的 10 个安全修复和加固补丁。

构建使用 GitHub Actions 官方 checkout v7.0.1、cache v6.1.0、setup-go v7.1.0 和 upload-artifact v7.0.2，均按完整提交引用。发布流程执行手机镜像编译、主机回归和 ARM64 QEMU 测试。OnePlus 6/6T 真机开机与蓝牙连接仍待验证。实际源码提交和依赖版本见同页的 build-info.txt、source-revisions.json 和 vendored-upstreams.json。
