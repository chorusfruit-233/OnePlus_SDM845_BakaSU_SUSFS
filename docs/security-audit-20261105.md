# 自定义补丁与近期安全公告审计（2026-11-05）

本轮检查了仓库原有的 36 个补丁（34 个生产补丁、2 个测试补丁），以及内联 hook、源码准备、版本提交和 AK3 安装脚本。修复以 10 个后置补丁集成，保留原始移植补丁和来源。BakaSU 继续跟踪 main，保留 WALT、实际 cgroup V2/Binder 冻结、Mihomo、Droidspaces、SUSFS 和 Hybrid Mount；手机默认不启用的 NFC/RFCOMM 没有被启用。

基线：LineageOS SDM845 `228c16bfcd256a546e3fde375215f6072135588f`；修复前完整集成源码 `4a0fe01b8d6a15954ddc9ba85ac75a6df363e821`，对应 builder `3ee30ca`。保留此前的 `TIOCGPTPEER` / Qualcomm `TIOCPMGET` 冲突修复。

审计是对集成边界、输入校验、引用生命周期和并发路径的人工检查与回归测试，不构成所有可能缺陷均不存在的证明。每个补丁的检查点、结果和 SHA-256 记录在 [完整补丁清单](custom-patch-audit-20261105.json)。后续改变补丁、受审计集成脚本或最终受修复源码时，CI 会要求更新审计记录，防止仍使用过期结论。

## 已修复的自定义代码问题

| 部件 | 确认的问题 | 修复与验证 |
| --- | --- | --- |
| SO_PEERGROUPS | UNIX `listen/connect` 可替换 `sk_peer_cred`；新增 getsockopt 路径没有锁或引用保护，在用户复制期间可能失效 | 在 `sk_peer_lock` 内取得 cred 引用，解锁后复制，所有出口释放引用。强制替换/复制失败测试及 ARM64/AArch32 各 10,000 次并发读写 |
| ReKernel 控制消息 | 没有验证声明长度；零长度匹配、越界比较；没有控制指令权限检查；重复删除 proc 目录仍使用旧指针 | `nlmsg_ok`、精确命令长度、初始用户命名空间的 `CAP_SYS_ADMIN` 校验；互斥删除并清空指针。保留命令有/无末尾 NUL 两种格式 |
| ReKernel 初始化 | 在 Binder/信号/网络报告路径懒初始化，可能在原子上下文执行睡眠操作；初始化状态在 socket 就绪前可见 | 改为一次 `late_initcall`，完整初始化后以 release/acquire 发布 ready；错误时释放资源 |
| ReKernel 网络 | `pskb_may_pull` 后沿用旧 IP 指针；IPv6 偏移处理不完整；只遍历初始化时已存在的 netns | 用本地 IP/TCP 头副本和边界检查，正确处理扩展头/分片；pernet 注册与退出。真实 TCP 流量及 12 次 netns 创建/销毁测试 |
| Hybrid Mount | 固定用户页并不阻止用户继续写入；长度检查与规则解析之间存在 double-fetch | 复制整份 hm1 请求后在内核快照上解析，再写回响应；测试在处理首条规则时篡改下一条记录以及 pin/分配失败的清理 |
| SUSFS 哈希查询 | 哈希桶候选只比较设备号，未比较 inode；同设备冲突可能选错规则 | 11 处 inode 索引读取补齐完整键比较；故意将同设备、错误 inode 放在桶首测试 |
| SUSFS 请求字符串 | 固定长用户数组未保证 NUL 终止，随后传给路径解析或字符串函数 | 对路径、uname、cmdline 请求检查数组范围内的终止符，拒绝不完整字符串 |
| SUSFS 规则/分配 | 并发首次 cmdline 配置可能重复分配；替换重定向时用新路径寻找旧反向记录 | 序列化初次分配和发布；使用旧记录的 inode、设备和目标路径删除旧反向规则 |
| SUSFS readlink | 小缓冲区或刚好等长的缓冲区错误返回 `ENAMETOOLONG` | 恢复 VFS 截断语义，不额外写 NUL；验证 1 字节及精确长度缓冲区 |
| Binder/ReKernel | 合并逻辑放在非 pending 队列分支，正常情况下不起作用；又缺少 `TF_UPDATE_TXN` 和发送者身份条件，不能安全移到有效分支 | 移除这段不适用的合并逻辑，保留标准 oneway 投递、报告与冻结功能；冻结后重复同 code 的事务必须全部送达 |
| BBRv3 | 分配状态失败时仅在 BBR `cong_control` 内调用 Reno 增长函数，仍跳过 TCP 核心的丢包减窗和 pacing 更新 | 切换为完整 Reno 回调，保留原模块引用；注入分配失败并执行实际 TCP 调度函数，检查丢包减窗、正常增长和 pacing 路径 |

上述接口中的 SUSFS/Hybrid Mount 配置原本就要求相应 root 管理权限；没有将这些自定义问题冒称为新的 CVE。

## 近期高危公告核对

核对范围为 Android 安全公告 **2026 年 9、10、11 月的 Kernel 和 Qualcomm 部分**，共 70 条：37 条内核、14 条 Qualcomm 开源部件、19 条 Qualcomm 闭源部件。10 月公告没有这两类条目。[逐条结果](security-advisories-20261105.json)包含公告地址、上游修复、实际代码证据与处置原因。

| 公告 | 本次处置 | 4.9 适配要点 |
| --- | --- | --- |
| CVE-2026-31629（Critical） | 修复 NFC LLCP 关闭后继续执行 | 补上关闭检查后的返回；手机 CONFIG_NFC 仍为 n |
| CVE-2026-64011（High） | 修复 LLCP 连接/关闭竞争 | 正确移除 connecting socket，连接完成时持锁并验证仍挂链；4.9 关闭路径也保持锁到 unlink 结束 |
| CVE-2026-53256（Critical） | 修复 RFCOMM listener 生命周期 | 链表锁内取得引用，锁内复查监听状态，最后释放；保留 4.9 BH 锁；手机 RFCOMM 仍为 n |
| CVE-2026-89774（Critical） | 回移等价 SCO 引用保护 | 持 connection/listener 锁取得 socket 引用；断连与接收也遵守同一规则，最终释放前清除指针；不引入自旋锁内睡眠 |
| CVE-2026-80604（Critical） | 对旧 HID API 加入等价保护 | `hid_report_raw_event` 在读取 report ID 前拒绝 numbered/零长度输入；4.9 没有新版单独的 bufsize 参数 |
| CVE-2026-43284（High） | 修复相同分片标记丢失，作为纵深加固 | 使用旧 `tx_flags/SKBTX_SHARED_FRAG`；覆盖 copy、shift、coalesce、GRO、GSO。原内核 ESP 无条件调用 `skb_cow_data`，因此不宣称复现了公告中的 ESP 利用路径；旧 TCP MTU probe 复制数据，无需套用新版 frag 克隆修改 |

其余 64 条中：

- 4 条已包含修复或已有等价保护：rtmutex、Logitech FF、Logitech DJ、旧 Sony DualShock4 报告数量边界。
- 34 条缺少受影响实现，例如 pKVM、内核 TLS、F2FS 压缩、Android 每进程 DMA-BUF 记账、新 epoll refcount 流程、FUSE passthrough、Gen7/Gen8 GPU 调度器。逐条检查了代码，未仅凭版本号排除。
- 26 条在这个内核仓库之外：19 条闭源部件、5 条 ABL/UEFI、2 条用户态 display-core。没有把它们标为已修复；适用时仍需设备厂商固件或 ROM 更新。

POSIX CPU timer 的 CVE-2026-64560 也作了单独语义检查：本树保留 task 引用与 `__exit_signal` 的旧 leader 清理 workaround，没有公告所依赖的 pid 引用改造。Binder CVE-2026-23184 的上游 Netlink API 也未导入，本树 ReKernel 报告发生在事务发布之前。

本轮没有修改 Android 安全补丁日期，也没有宣称覆盖 4.9 停止维护以来的所有历史漏洞、非上述公告中的全部 Linux CVE，或解决设备闭源固件的问题。

## 验证及复现

- `python3 scripts/check-security-audit.py --source kernel`：覆盖清单、补丁摘要与最终受修复源码一致性。
- `python3 tests/host/test-security-source.py --source kernel`：执行实际提取的生产函数；注入 cred 替换、复制/分配失败、恶意 Netlink 长度、同设备 inode 冲突及共享请求篡改，并验证 BBR 分配失败后走完整 Reno 路径。内核锁/VFS 原语在这些 host 测试中是模型。
- `tests/host/security-kernel.c`：仅临时链接进 QEMU 内核，实际调用 HID 和 skb 实现，验证空报告及共享分片 copy/shift/coalesce/GRO。构建后恢复源码，手机镜像不含测试对象。
- Droidspaces：13 组真实 syscall 测试，各在 ARM64/AArch32 执行，包括 UART ioctl、SO_PEERGROUPS 竞争与错误指针。
- Component QEMU：10 组实际 hm1/ext4/inotify/CAKE/memcg/ReKernel 控制/netns 测试，同时要求内核内部安全测试的完成标记。
- 保留 BakaSU ABI/SELinux 清理/preinit、SUSFS priority filter、Hybrid Mount 生命周期、Mihomo BPF/TC、cgroup V2 和 Binder 的完整现有 CI；Binder 加入相同 code 异步事务不能丢失的覆盖。
- 手机 defconfig 完整构建，以及 SUSFS priority filter 关闭的编译路径；QEMU 额外启用 NFC/RFCOMM 来编译手机未启用的修复路径。

本地故障测试以修复前 `4a0fe01b8d6a` 作负对照；旧实现失败，新实现通过。硬件蓝牙、GPU、USB 无线设备和 Android SELinux 行为不能由这些 QEMU/host 结果替代，刷入后仍需实机确认。

补丁顺序及来源由 [security-backports.json](../configs/security-backports.json) 管理，实际集成代码在构建时统一提交，版本字符串继续反映真实源码。
