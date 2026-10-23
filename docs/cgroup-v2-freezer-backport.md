# cgroup v2 冻结实验回移

分支：`work/cgroup-v2-freezer-4.9`。以用户已经验证的 Mihomo 主分支为基础，
增加 V2 冻结，保留 WALT、v1 freezer、BakaSU 跟踪 `main` 和现有网络功能。
用户反馈 NoActive 已支持 V2；后续 [Binder 冻结回移](binder-freezer-backport.md)
另有补丁和试用包，本轮 Binder 功能仍待真机验证。

## 验证记录

实现提交：`553d4dcfe7c447e971e4ad1386a649db91cc1698`。
验证工作流提交：`fafd6f93abffbe26996093ad8978053f8a196ab7`。
完整构建：[CI #125，2026-10-23，成功](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39970035191)。

| 检查 | 结果 |
| --- | --- |
| 10 个上游 + 8 个补充冻结用例 | 本地 QEMU 8.2.2 / 10.0.13 的双 CPU、四 CPU 均通过；CI #125 双 CPU 全通过 |
| Mihomo 原始程序及补充回归 | 最终源码在本地和 CI #125 的解释器、JIT、加固 JIT 三模式全通过 |
| `CGROUPS=n`、`DEBUG_ATOMIC_SLEEP=y` | fork、signal、scheduler 对象编译通过 |
| `CGROUPS=y`、`CGROUP_FREEZER=n`、`FREEZER=n`、`DEBUG_ATOMIC_SLEEP=y` | cgroup、fork、signal、scheduler 对象编译通过 |
| 从基线应用回移补丁 | 八个文件与实际构建源码逐字节一致 |
| 手机 `Image.gz-dtb` | 本地最终构建、CI #125 编译均通过 |
| CI #125 | FORTIFY 测试构建、BakaSU ABI / SELinux 清理、保留 ramdisk 的安装回归、手机编译、BPF / freezer 运行测试及 AK3 打包全部通过 |
| OnePlus 6T / LOS 22.2 / NoActive | 待真机反馈 |

CI #124 的手机编译和 Mihomo 三模式已经通过，但上游测试辅助函数缺少
`O_TMPFILE` 的 mode，被 FORTIFY 拒绝。该测试构建问题已修正，CI #125
也通过了原先未能执行的冻结运行测试。

试用包在 [CI #125 的 AK3 artifact](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39970035191/artifacts/12509602830)
中。先解压 artifact，再核对其中的 `SHA256SUMS`；实际刷入的内层 ZIP 为
`OnePlus6-6T-BakaSU-dac2d186-SUSFS-fcd842d8-DS7-b47b17db-TC-eBPF-FreezerV2-experimental-AK3.zip`。
CI 已通过该 ZIP 的完整性检查，输出的 SHA256 为：

```text
c91eaba08b2d8dec53a2942c126d4d1d40cc8700ea891c8718465bbd2b8b2bfa
```

## NoActive 的 V2 是什么

[NoActive 使用手册](https://app.myflv.cn/guide/app.html#冻结方式)中的 V2
对应内核 cgroup v2 freezer。它通过子分组的 `cgroup.freeze` 请求暂停进程，
通过 `cgroup.events` 中的 `frozen` 取得实际完成状态；解冻后继续执行。
`FreezeConfig.json` 的 `freezeMode: "v2"` 选择这种方式。
`MasterConfig.json` 中的 `freezeBinder` 是独立的 Binder 事务冻结开关。

Linux 原生 v2 freezer 在 5.2 引入，内核版本号本身不能证明旧内核是否已经回移。
本次之前，当前 4.9 树提供 cgroup v2 分组和 v1 `freezer.state`，但没有
`cgroup.freeze`，因此仅启用 `CONFIG_CGROUP_FREEZER` 无法提供 V2。

冻结按 cgroup 成员及其子分组生效。组内 fork/clone 出的新任务也需要冻结，
但已经被移到其他分组的进程不会因为“是某个应用的子进程”而自动冻结。
Linux v1 本身也有分组成员继承，不能把应用手册对 V1 的描述理解为内核完全
没有继承功能。应用如何选择和维护分组仍然影响结果。

V2 freezer 属于 cgroup 核心接口，无需在 `cgroup.subtree_control` 中开启
`freezer`，也不应要求 `cgroup.controllers` 必须列出 `freezer`。
`CONFIG_CGROUPS=y` 提供 V2；原来的 `CONFIG_CGROUP_FREEZER=y` 继续提供 V1。
该功能不依赖 CFS CPU 配额，WALT 保持启用。

## 回移来源及适配

- 实现来源：[Linux 5.10.272](https://github.com/gregkh/linux/tree/aca95a35f1bcc0626c4fa4d1252bf2d4c990a1a2)，
  包括该稳定版中的冻结、信号和 ptrace 修正。
- 原始特性：[76f969e8948d](https://github.com/torvalds/linux/commit/76f969e8948d82e78e1bc4beb6b9465908e74873)。
- 停止状态保护依赖：[b5bf9a90bbeb](https://github.com/torvalds/linux/commit/b5bf9a90bbebffba888c9144c5a8a10317b04064)，
  用任务的 `pi_lock` 保护 STOPPED/TRACED/DEAD，避免并发唤醒覆盖停止状态。
  保留 WALT 的调度算法。
- 接口语义：[Linux cgroup v2 文档](https://www.kernel.org/doc/html/v5.10/admin-guide/cgroup-v2.html)。
- 补丁：`patches/lineage-4.9/cgroup-v2-freezer-4.9.patch`，在 ReKernel 和三个
  Mihomo 补丁之后应用。

4.9 的 cgroup 核心仍是单个 `kernel/cgroup.c`，因此实现放在该文件，沿用
私有锁及旧版任务迭代 API。增加准确的 css_set 任务数和存活子分组数，覆盖
分组创建/删除、进程迁移、fork、vfork、退出，以及 SIGSTOP、SIGKILL 和 ptrace。
4.9 没有新任务返回路径的 `calculate_sigpending()`，所以为新任务设置冻结
trap 时显式设置 `TIF_SIGPENDING`，保证返回用户态前处理冻结。

保留 4.9 的任务工作通知路径，不引入 5.10 的 `TIF_NOTIFY_SIGNAL`，也不回移
仅用于跟踪的 freezer trace events。ReKernel 改为检查 `JOBCTL_TRAP_FREEZE`
是否存在，避免内核版本号仍为 4.9 时漏报 V2 冻结任务；V1 检测仍然保留。

## 自动验证

`configs/freezer-test.json` 固定上游测试来源，构建脚本核对实际提交后才提取文件。
原始 self-test 的二进制在 guest 中必须命名为 `test_freezer`，因为其 SIGSTOP
用例会检查 `/proc/PID/stat` 的进程名。

上游旧版测试在 PTRACE_DETACH 后立即读取 `frozen`，可能读到调试器分离过程中的
状态过渡。[上游 2026 年讨论](https://mail-archive.com/linux-kernel@vger.kernel.org/msg2642983.html)
已经记录这一 ARM64 竞态。`patches/tests/freezer-selftest-waits.patch` 为分离后的
检查增加有界等待，分离前的检查和最终 `frozen=1` 要求均保留。
它还消耗已读取的 inotify 通知、处理超时，避免重复轮询同一个旧通知；冻结和
迁移等待须等到实际目标状态，不能把更早的 populated 通知当作完成。
SIGSTOP 用例先以 `waitpid(WUNTRACED)` 确认任务确实已停止，避免只发送信号后
立即冻结/解冻，又在信号尚未处理时读取进程状态。各用例的最终断言均保留。

`freezer-selftest-fortify.patch` 为共享辅助函数的 `open(O_TMPFILE)` 补上
必需的 `0600` 创建模式。构建显式启用 `_FORTIFY_SOURCE=3`，本地与 Ubuntu
CI 使用相同校验。测试程序在手机内核编译前构建；后续测试失败时仍保存有效的
编译器缓存，但不会打包未通过全部检查的内核。

QEMU 执行 10 个上游用例：大量任务、分组树、fork、冻结期间创建/删除子组、
迁移、ptrace、已停止/已跟踪任务和 vfork。另执行 8 个补充行为测试：

1. 根分组不暴露冻结开关、空组冻结、非法参数拒绝；
2. 四线程整体暂停/恢复、非致命信号排队、SIGCONT 不能解冻、冻结时 SIGKILL；
3. 父组冻结与子组设置的优先关系、冻结期间创建子组；
4. 四线程在运行、冻结及两个冻结分组之间迁移；
5. 持续 fork/exit 期间进行 50 轮冻结，检查完成后计数器确实停止；
6. 20 轮调试器附加/中断/分离，检查重新冻结及用户态计数器不运行；
7. 四线程的 SIGSTOP 先完成，再进行 50 轮冻结/解冻；只有 SIGCONT 才能恢复；
8. V1/V2 同时存在及同时冻结，单独解冻其中一种不能恢复执行。

运行器要求所有用例实际通过；跳过、超时、内核 warning、BUG 或 panic 均失败。
补充测试要求专用 QEMU 启动标记，不可直接在手机上执行。
CI 复用 Mihomo 的 ARM64 guest 内核，在原有三种 BPF 执行模式回归之后执行
freezer 测试，上传 `freezer-runtime-tests`。V2 初版 CI #125 生成
`TC-eBPF-FreezerV2-experimental-AK3.zip`；后续含 Binder 的包另带
`FreezerV2-Binder-experimental` 标记，通过全部检查后才打包。

本地复现：

```sh
bash tests/host/build-freezer-tests.sh /path/to/linux-5.10.272 artifacts/freezer-tests
python3 tests/host/run-freezer-qemu.py \
  --kernel kernel/out-bpf-qemu/arch/arm64/boot/Image \
  --busybox anykernel3/tools/busybox \
  --upstream-test artifacts/freezer-tests/test_freezer \
  --backport-test artifacts/freezer-tests/freezer-backport.test \
  --log artifacts/freezer-tests/qemu.log
```

## 手机上验证 NoActive

本页记录的 CI #125 包只含进程冻结器，没有 `BINDER_FREEZE` /
`BINDER_GET_FROZEN_INFO`。后续实验包已经增加这两个 ioctl，详见
[Binder 冻结回移说明](binder-freezer-backport.md)，标准 Binder 冻结通知仍未回移。
先关闭 NoActive 的 `freezeBinder` 验证 V2，再按对应包的说明测试 Binder 选项；
不能据此宣称 Android 系统 API 冻结器或所有 NoActive 选项已经兼容。
`MasterConfig.json` 的修改需要重启生效。

刷入后先以 root 检查已有挂载及文件：

```sh
cat /proc/mounts | grep cgroup2
find /sys/fs/cgroup -name cgroup.freeze | head -20
```

`cgroup.freeze` 存在于子分组，根目录没有此文件是正常行为。
如果 ROM 没有挂载 cgroup2 或没有创建应用分组，还需要核对其 cgroups/task
profiles 和 NoActive 附加模块；内核补丁不会替 ROM 或模块修改目录及 SELinux
访问权限。NoActive 日志中的路径、权限和 ioctl 错误需要分别定位，不能仅通过
更改内核版本号解决。

按[官方安装说明](https://app.myflv.cn/guide/start.html)配置附加模块及 LSPosed。
本树已集成 ReKernel，避免另外叠加重复的 Binder hook。先用一个普通、无重要
后台任务的应用检查后台冻结、返回前台恢复、重复切换，再测试消息与网络解冻。
框架界面显示已冻结之外，还要检查实际进程暂停/恢复及是否有系统卡顿。
虚拟机测试不覆盖 SDM845 的休眠唤醒、Android Binder 通信或 NoActive 闭源实现，
这些仍需 OnePlus 6T / LOS 22.2 真机确认后再考虑合入主分支。
