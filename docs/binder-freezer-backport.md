# Binder 冻结实验回移

该回移已从 `work/cgroup-v2-freezer-4.9` 合入 `main`。本轮在 cgroup v2 freezer 上，
增加 Android 标准 Binder 事务冻结接口。WALT、BakaSU 跟踪 `main`、SUSFS、
Hybridmount、Droidspaces 和 Mihomo 配置继续保留。本轮 Binder 功能待真机验证。

## 实现及来源

来源为 [Android Common android13-5.10](https://github.com/aosp-mirror/kernel_common/tree/9536d991bb596a507f46aafe6b5f64fe9e599e78)，
固定提交 `9536d991bb596a507f46aafe6b5f64fe9e599e78`。
`configs/binder-freezer.json` 保存来源文件及 SHA256；补丁为
`patches/lineage-4.9/binder-freezer-4.9.patch`，在 ReKernel 和 V2 补丁之后应用。

本次增加：

- `BINDER_FREEZE`：按 PID 操作其所有 Binder 打开实例。冻结时阻止新同步请求，
  按指定超时等待已接收的事务完成；无法完成或被信号打断时返回错误。
- `BINDER_GET_FROZEN_INFO`：汇总该 PID 各实例的同步、异步接收标志，
  `sync_recv` 的 bit 1 同时报告未处理事务或等待回复的事务栈。
- `BR_FROZEN_REPLY`：向调用方报告目标已冻结，区别于目标死亡。
- 异步事务在缓冲区容量允许时继续排队，解冻后按原有 Binder 规则交付。
  Binder 标记本身不会暂停目标的 CPU 执行，仍须与 V2 冻结配合。

4.9 的进程、线程和事务结构都在 `binder.c` 内，进程临时引用为 `atomic_t`。
适配保留原来的事务自旋锁、进程引用及优先级路径，补齐正常请求、回复、
交付错误、线程退出、进程退出及 ReKernel 替换旧事务时的计数。
协议版本仍为 8，旧 ioctl 编号不变；新增两个 ioctl 的参数均为三个 `u32`，
ARM64 和 32 位兼容进程使用相同编号和布局。

本次未回移 `BC_REQUEST_FREEZE_NOTIFICATION` / `BR_FROZEN_BINDER` 等冻结
状态订阅接口，也不附带 oneway spam 检测等其他新版 Binder 功能。
现有 ReKernel 的事务事件上报继续保留；这种上报与标准冻结状态订阅不同。

## 验证

实现提交：`dcafe4ac8666f70d2d668e864ffbcda7e766c48d`。
完整构建：[CI #126，2026-10-23，成功](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39987204988)。

| 检查 | 结果 |
| --- | --- |
| 手机 `Image.gz-dtb` 完整构建 | 本地通过 |
| ARM64、ARM32 实际 Binder 事务 | 各 14 项通过，ReKernel 已启用；QEMU 10 四 CPU、CI 同版 QEMU 8.2.2 双 CPU 均通过 |
| cgroup V2 冻结和 Binder 配合 | 排队期间不执行，解除 Binder 标记仍保持 V2 冻结，V2 解冻后按序交付 |
| 原有 V2 冻结测试 | 最终 guest 内核四 CPU 下 10 个上游 + 8 个补充用例全通过 |
| Mihomo | 最终 guest 内核的解释器、JIT、加固 JIT 三模式全通过 |
| BakaSU ABI / SELinux 清理、SUSFS / Droidspaces 配置检查 | 全通过 |
| 从基线应用 Binder 补丁 | 两个文件与实际构建源码逐字节一致 |
| GitHub CI #126 | 手机完整编译、ARM64 / ARM32 各 14 项 Binder 测试、18 项 V2 测试、Mihomo 三模式及 AK3 打包全部通过 |
| OnePlus 6T / LOS 22.2 / NoActive Binder | 待真机反馈 |

测试使用真实 `/dev/binder`、`/dev/vndbinder`、`mmap`、`BINDER_WRITE_READ`
和父子进程收发，编译启用 `_FORTIFY_SOURCE=3`、`-Werror`。
14 项覆盖：参数/ABI、同步请求拒绝、异步与 V2 联合冻结、无等待失败回滚、
超时回滚、等待排空后成功、信号打断回滚、调用方等待回复、线程退出、进程退出、
交付时用户地址错误、等待期间目标退出、同 PID 多上下文，以及 50 轮冻结/恢复。
不接受跳过、缺失结果、内核 warning、BUG、panic 或超时。

运行器只在无宿主磁盘和网络接入的临时 ARM64 QEMU 中执行，包含测试 guest
重启；测试程序检查专用启动标记，不可直接在手机上执行。

```sh
bash tests/host/build-binder-freezer-tests.sh kernel artifacts/binder-freezer-tests
python3 tests/host/run-binder-freezer-qemu.py \
  --kernel kernel/out-bpf-qemu/arch/arm64/boot/Image \
  --busybox anykernel3/tools/busybox \
  --test artifacts/binder-freezer-tests/binder-freezer.test \
  --compat-test artifacts/binder-freezer-tests/binder-freezer-arm32.test \
  --log artifacts/binder-freezer-tests/qemu.log
```

## NoActive 真机试用

本轮 ZIP 带 `TC-eBPF-FreezerV2-Binder-experimental-AK3.zip` 标记，
`build-info.txt` 应记录两个已回移的 Binder ioctl 和本补丁校验值。
[下载 CI #126 的 AK3 artifact](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39987204988/artifacts/12516063827)，
先解压 artifact，核对其中的 `SHA256SUMS`，实际刷入内层 ZIP：

```text
OnePlus6-6T-BakaSU-dac2d186-SUSFS-fcd842d8-DS7-b47b17db-TC-eBPF-FreezerV2-Binder-experimental-AK3.zip
SHA256: aed8b21626f20a91a3af2f0fd60fd986351aebbfba062bdd295cad7d706fad81
```

该 ZIP 已通过 CI 中的完整性检查。原生及兼容事务执行结果另上传为
`binder-freezer-runtime-tests`。
[此前 CI #125](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39970035191)
的 `FreezerV2-experimental` 包只有 V2，没有本轮 Binder 接口。

先确认 V2 的后台冻结、前台恢复正常，再在 `MasterConfig.json` 中测试
`"freezeBinder": true`，按 NoActive 说明重启生效，冻结方式继续使用 V2。
优先选普通应用检查反复前后台切换、文件选择器或跨应用服务调用，并观察
NoActive 日志中有无 ioctl 错误、持续冻结失败或卡住。
出现问题可改回 `freezeBinder=false` 并重启，单独测试 V2。

两个 ioctl 的存在不能证明 NoActive 已利用所有接口，也不能替代 ROM 的
cgroup 分组、task profiles、访问权限与应用策略适配。
本轮不据此宣称 Android 系统 API 冻结器或新版本 Binder 通知全部兼容。
