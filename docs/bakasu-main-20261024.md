# BakaSU main 的 Linux 4.9 适配记录

本轮审查并构建 `Baka-SU/BakaSU main @ c0c96a4087285ff82d71003d4186629de1c46b3c`。
`configs/enchilada.json` 继续跟踪 `main`；该 SHA 用于记录补丁来源和本轮验证，
不固定后续构建的 BakaSU 版本。原有 WALT、SUSFS、Hybridmount、Droidspaces、
Mihomo、V2 / Binder 冻结配置保留。

## 更新与适配

上游新增 UAPI v6、模块预初始化、模块热安装配套接口、模块黑名单、ADB 专用
shell root 和启动参数强制 feature 值。4.9 配套改动包括：

- 重新适配 SELinux hide 补丁，保留备份 policy/SID 转换、旧版 setprocattr 权限
  检查，以及回调恢复失败时保留备份并允许重试的处理。
- 补齐 SUSFS 的 preinit exec 前后调用，仅 PID 1 尝试替换 init。runner 无法执行
  且 exec 尚可恢复时，关闭其 fd 并重试原 init；有致命信号时不重试。
- preinit 使用 `getname_kernel()` 持有完整路径，避免较大 fd 路径的终止符问题；
  fd 0 也参与失败清理，成功 exec 后不再关闭可能被复用的 fd。
- 新模块检测同时识别 `kernel/module/main.c` 与 4.9 的 `kernel/module.c`。
  两个模块加载 syscall 在权限检查、输入读取和 `load_module()` 之后调用
  对应处理函数，原有权限及输入错误继续返回错误。
- 驱动私有黑名单指针改为 `ksu_module_blacklist_slot`，保留内核自身唯一的
  `module_blacklist` 符号，消除按名称查找的歧义。
- preinit runner 必须以目标 4.9 UAPI 头文件实际构建并嵌入内核，头文件安装
  失败时中止构建，避免悄悄禁用功能后仍生成刷机包。
- UAPI 安装显式使用手机输出目录；递归调用清空继承的 `KBUILD_SRC`，防止
  在源码目录生成文件。镜像检查同时验证源码目录未被污染，避免旧 Kbuild 的
  VPATH 使后续独立 QEMU 输出目录漏生成 `asm/types.h` 等文件。

对应补丁为 `bakasu-selinux-4.9.patch`、`bakasu-compat-4.9.patch`、
`bakasu-preinit-module-4.9.patch`。源代码检查保留原始上游文件指纹和补丁完整性
检查，新增 preinit、UAPI、模块及 feature 相关文件的审查指纹。

## 验证记录

| 检查 | 本地结果 |
| --- | --- |
| 完整手机 `Image.gz-dtb` | 通过，包含改名后的模块指针和 preinit ELF |
| ARM64 原生 / 32 位兼容寄存器、指针和 syscall 号 | 两种配置均通过 |
| SELinux 回调恢复失败、部分初始化回滚、重试清理 | 全通过 |
| preinit fd 0、长路径、分配失败、路径失败及执行失败清理 | 实际函数故障注入通过 |
| 两个模块 syscall 的权限、输入及黑名单处理边界 | 实际函数故障注入通过 |
| 最终镜像精确符号与 ELF | 唯一内核黑名单符号；所需 hook 已链接；嵌入字节与静态 AArch64 runner 完全一致 |
| 生产 runner 在 Linux 4.9 QEMU 8.2.2 中执行 | 六种情况全通过 |
| 从原始内核和上游重新应用补丁 | 两个内核文件、七个 BakaSU 文件均与实际构建源码逐字节一致 |
| 全新独立 QEMU 输出目录的 prepare / scripts | 通过，`asm/types.h` 和 modpost 均正常生成，源码目录保持干净 |
| GitHub CI | #129 手机镜像和 ELF 检查通过；后续 guest 构建暴露 UAPI 输出目录污染，已修正，待完整重跑 |
| OnePlus 6T / LOS 22.2 | 本轮待真机反馈 |

六个 QEMU 场景是：无配置、执行模块动作、不安全配置、启动计数限制、程序不存在、
执行超时。使用手机构建生成的真实 runner，逐项检查动作结果、参数/环境保留，
以及返回 `/system/bin/init` 的测试替身。测试 guest 无宿主磁盘或网络设备。
结果上传为 `bakasu-runtime-tests`；测试缺失、超时、内核 warning、BUG 或 panic
都会失败。

宿主函数测试模拟了 VFS、fd 与用户地址访问；QEMU 没有启动 Android 系统框架、
加载 Android SELinux policy，也没有运行真实模块安装。因此不能用这些结果
替代真机启动、root、SUSFS 隐藏、模块预初始化与热安装验证。
使用 UAPI v6 的新功能还需要匹配的新版 BakaSU 管理器及 ksud。

本地复现：

```sh
python3 tests/host/test-bakasu-integration.py --source kernel
python3 tests/host/check-bakasu-image.py \
  --source kernel \
  --vmlinux kernel/out/vmlinux \
  --runner kernel/out/drivers/kernelsu/preinit/runner.elf
python3 tests/host/run-bakasu-preinit-qemu.py \
  --kernel kernel/out-bpf-qemu/arch/arm64/boot/Image \
  --runner kernel/out/drivers/kernelsu/preinit/runner.elf \
  --busybox anykernel3/tools/busybox \
  --control artifacts/freezer-tests/freezer-backport.test \
  --log artifacts/bakasu-tests/preinit-qemu.log
```

来源：[BakaSU main](https://github.com/Baka-SU/BakaSU/tree/c0c96a4087285ff82d71003d4186629de1c46b3c)。
