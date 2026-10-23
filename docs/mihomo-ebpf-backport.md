# Mihomo eBPF 4.9 实验回移

目标是 `liuran001/mihomo` 的热点下联 **shared-network / packet_rewrite**，
以及本机 **cgroup socket-address** 和 **TC socket_assign** 接管。
三个阶段的回移及真机反馈已从 `work/mihomo-ebpf-4.9` 合入 `main`。
保留 WALT；BakaSU 继续跟踪 `main`。

## 回移内容

补丁为 `patches/lineage-4.9/mihomo-ebpf-4.9.patch`，基于固定的 LineageOS
4.9.337 / `228c16bfcd256a546e3fde375215f6072135588f`，在原有适配之后应用。
主要参考 Linux **v4.19.325 / `a67e7cdde7cc7984ae24c3c81a70dc1aa34424b1`**：

- LRU hash、per-CPU LRU hash 和 LPM trie；
- 新版标量跟踪校验器、BPF 子程序调用、解释执行器及 ARM64 JIT；
- 参考 Linux 5.2 `c04c0d2b968ac45d6ef020316808ef6c82325a82`，将 root
  加载的校验工作预算提高到 100 万；程序本身仍限制为 4096 条指令；
- program/map ID、信息查询，以及与 4.9 VFS 对接的 bpffs pin/get；
- skb 的 `BPF_PROG_TEST_RUN`，限制输出长度并按实际输入长度复制；
- 经典 BPF 的读包转换、栈深度记录和除零退出，以及 UDP 校验和
  `BPF_F_MARK_ENFORCE`；
- 保留 4.9 网络 helper、上下文转换、cgroup skb 和 perf 接口，适配新核心的回调。

第二阶段补丁为 `patches/lineage-4.9/mihomo-cgroup-4.9.patch`，在第一个补丁后
应用。socket-address 钩子、校验器上下文转换和 cgroup query 同样来自上述
4.19 稳定树，适配 4.9 的 socket 位域、协议回调、错误清理路径和 cgroup 锁。

- 注册 `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`，仅开放 IPv4/IPv6 connect、UDP
  sendmsg、UDP recvmsg 六个钩子；支持 socket cookie 和当前任务 UID/PID helper；
- TCP pre-connect 在传输层连接前执行，UDP connect/sendmsg/recvmsg 保留
  对应的 socket 锁，接收时可以还原对端地址与端口；
- 提供 `BPF_PROG_QUERY` 的本组/有效程序 ID、数量、挂载标志和短缓冲区行为；
  保留单程序、override、multi 及父子继承语义；
- 增加普通 hash 和 LRU hash 的原子 `BPF_MAP_LOOKUP_AND_DELETE_ELEM`。
  syscall 编号/属性布局参考 Linux v5.10
  `2c85ebc57b3e1817b6ce1a6b703928e113a90442`；实现沿用本树 bucket 锁和
  LRU 释放顺序，要求描述符同时可读可写。其他 map 类型和非零 flags 会拒绝；
- 修正固定 128 节点的 LRU 预取批量：按 `capacity / (2 * possible_cpus)`
  限制到 1～128，保留扫描预算。修复前，64 项 map 只存两个键也可在 CPU
  切换后丢键；新增确定性的双 CPU 用例，修复后该用例与 Mihomo 原始缓存
  重校验用例均通过。

第三阶段补丁为 `patches/lineage-4.9/mihomo-tc-4.9.patch`，在前两个补丁之后
应用。socket lookup/assign 和校验器引用跟踪主要参考 Linux **v5.10.272 /
`aca95a35f1bcc0626c4fa4d1252bf2d4c990a1a2`**，按 4.9 的网络栈与原有
4.19 校验器适配；`skb_change_head` 来自同一份 4.19.325 稳定树。

- 为 TC cls/act 开放 `skc_lookup_tcp`、`sk_lookup_tcp`、`sk_lookup_udp`、
  `sk_assign` 和 `sk_release`。检查 tuple 长度、flags、netns ID；通过现有
  IPv6 stub 对接 IPv6 栈，避免内建 BPF 对 IPv6 模块的直接符号依赖；
- 4.9 的 TCP/UDP 收包路径始终释放被传入的 socket 引用。因此查询结果统一
  持有实际引用，assign 再持有一个供 skb 使用的引用；保留现有收包引用语义，
  IPv4/IPv6 IP 入口识别预取 socket 并保留至传输层或 skb 析构；
- 校验器跟踪获取、判空、释放、跨子程序传递和所有寄存器/栈别名；拒绝泄漏、
  重复释放、释放后访问、带活动引用的 tail call/旧式读包。socket 指针禁止
  算术，只开放 `family`、`state` 的 32 位只读访问；
- 记录有界标量的完整 64 位栈保存/恢复，支持隔离 TC 程序中的 IPv6 头偏移。
  保留 4.19 对所有标量范围的精确比较，部分覆写仍清除保存的范围信息；
- 补回 `skb_change_head`，并为所有已提供、可能移动或改写报文存储的 helper
  标记旧报文指针失效。测试同时要求旧指针被拒绝、重新加载并检查的指针被接受；
- 使用 Mihomo 自带的 direct lookup 回退路径，`TCPListenerLookupMode()` 返回
  `direct`；不需要伪造 SOCKMAP 支持。当前调用方使用的隔离命名空间程序也纳入
  原始对象加载和完整收发测试。
- 修正 4.9 全局 dst GC 的 IPv6 设备清理：仅替换属于正在注销设备的
  `rt6i_idev`，避免把其他设备/命名空间的缓存路由转到当前 loopback。
  连续执行隔离收发测试发现了这一问题；修复前，下一轮创建命名空间会卡在
  `unregister_netdevice: waiting for lo`，修复后保留全部用例连续验证。

UAPI 的枚举定义不代表对应功能已实现。bind、socket-release、sockops、sockmap、
reuseport、devmap、AF_XDP、cgroup storage、map-in-map 和 ring buffer 等类型
不在本次注册范围内；未提供的 helper 继续由校验器拒绝。

手机配置启用 cgroup BPF、IPv6 和 BPF JIT，并默认关闭无特权 BPF；root 仍可
使用 `bpf()`。
运行时可查看 `/proc/sys/net/core/bpf_jit_enable`，设为 `1` 启用 JIT；
`bpf_jit_harden=2` 可启用常量混淆。
ARM64 LSE atomics 配置沿用手机原值。Qualcomm audio 的 Kbuild 增加平台条件，
使同一源码可编译 ARM64 virt 测试内核；SDM845 仍编译原有音频驱动。

## 可重复验证

测试对象固定为 [liuran001/mihomo](https://github.com/liuran001/mihomo)
`02581ff38100494f1d700612850b7611bdf2099e`，版本信息在
`configs/mihomo-ebpf-test.json`。测试直接编译并执行该提交的上游集成用例，
不修改 Mihomo 程序来绕过校验器。测试包使用相同版本的 Cilium eBPF 库。
构建脚本通过 Go overlay 加入本仓库 `tests/host/mihomo-cgroup-runtime_test.go`
和 `tests/host/mihomo-tc-runtime_test.go`，补充跨进程的真实 socket 收发测试，
不改动上游源码、BPF 对象或已有用例。另直接编译上游 `listener/sing_ebpf`
集成测试，覆盖实际 TC 运行时的隔离命名空间和回程。

CI 先构建手机 `Image.gz-dtb`，再用同一源码启动 ARM64 QEMU，在解释器、
JIT、启用常量混淆的 JIT 三种模式下运行：

- IPv4/IPv6、TCP/UDP 入站改写与回复还原，逐字节和校验和检查；
- 私有地址、FakeIP、主机地址和端口策略；
- veth + TC 实际 UDP 收包，包括禁用校验和与 CHECKSUM_PARTIAL 零种子；
- 控制 map 更新、LRU 淘汰、LPM 最长前缀和删除、bpffs 重开；
- BPF 子程序的调用栈和寄存器保存；
- 32/64 位原子加、旧式 eBPF 读包，以及经典 socket filter 的各宽度、
  间接读包、栈末端和除零行为；
- 无效栈、越界上下文、未检查的报文读取、递归和不支持的类型/helper；
- 测试 syscall 的用户缓冲区边界，以及旧版 seccomp 过滤的允许/拒绝行为。
- cgroup 六个钩子的合法访问与越界/只读字段拒绝、程序查询和父子继承；
- 普通/prealloc-disabled hash 与 LRU hash 的并发原子取出、flags 和描述符权限；
- Mihomo 原始 cgroup 程序矩阵、UDP 缓存重校验、策略回滚、超时控制和多实例；
- 实际 TCP4/TCP6/IPv4-mapped TCP，以及 UDP4/UDP6/IPv4-mapped UDP，覆盖
  未连接和已连接 UDP；父进程验证原目标和 socket cookie，子进程验证收包内容
  与 recvmsg 还原的对端地址/端口，并检查实际 Mihomo 程序的 JIT 长度。
- TC socket helper 的引用与只读字段检查、跨子程序返回/释放、失败 assign
  保留流状态、有界标量栈保存/部分覆写，以及 `skb_change_head` 参数和输出；
- veth 上原始 TCP SYN/SYNACK/ACK、双向数据和 FIN，覆盖共享/本机 delivery
  入口的 IPv4/IPv6；UDP 收包检查完整负载和未改写的原目标地址、端口；
- Mihomo 原始隔离 TC 对象、共享策略、IPv6 分流、分片、策略表与代次维护；
- Mihomo 原始隔离命名空间端到端用例，包含 TCP/UDP、L2/原始 IP、本机/共享
  路径、监听端口冲突、UDP 分片回复，以及基础设施损坏后的修复。

4.9 没有 batch-map 命令。上游的返回路由生命周期用例假定第一次 scan 即完成，
因此使用补充用例按有界 API 的 `Complete`/usage 状态执行后续 scan，验证实际
key-iterator 回退中的活跃引用保护、释放宽限期、容量压力和过期清理。
其他上游测试保持原样。QEMU 中先提升测试进程继承的 memlock 限额，避免上一轮
仍待 TCP/RCU 清理的命名空间对象影响下一轮特性探测。

netd 占位程序的接管、拒绝接管和卸载恢复用例在解释器和普通 JIT 下运行。
4.19 和 5.10 的 ARM64 加固 JIT 返回混淆后的 translated 指令，Mihomo 的
占位程序识别器无法将其识别为简单的 `return 1`；内核保留上游行为。
因此，**已在 harden=2 下加载的占位程序无法由当前 Mihomo 安全识别并接管**。
加固模式仍执行上述实际流量和 cgroup 回归，并验证拒绝接管时原占位程序仍被
保留；CI 分别核对每种模式的预期用例。

QEMU 中任何失败、跳过、内核 panic 或 warning 都会阻止该 CI 打包。
测试结果和 ARM64 测试程序保存在 `ebpf-runtime-tests` artifact。
测试内核配置为 `tests/host/bpf-qemu.config`，不启用 KernelSU。补充收发用例
要求 QEMU 的专用启动标记，只在可丢弃的 guest 中添加地址和路由；不在真机
直接运行该补充用例。

第一阶段已通过手机完整编译及双 CPU QEMU。第二阶段新增 cgroup 和 map
用例也已通过上述三种模式。第三阶段检查还覆盖 `CONFIG_INET=n` /
`CONFIG_CGROUP_BPF=n` 的相关对象编译，以及 `CONFIG_IPV6=m` 的内建/模块
符号边界；完整运行结果以对应提交 CI 的 `ebpf-runtime-tests` 为准。
第一阶段另已编译检查启用 BPF_EVENTS 时的 4.9 tracing 回调。

已有准备好的源码与交叉工具链时，可复现：

```sh
bash tests/host/build-ebpf-tests.sh /path/to/pinned-mihomo artifacts/ebpf-tests
mkdir -p kernel/out-bpf-qemu
cp tests/host/bpf-qemu.config kernel/out-bpf-qemu/.config
make -C kernel O=out-bpf-qemu ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make -C kernel O=out-bpf-qemu ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KCFLAGS=-Wno-error -j4 Image
python3 tests/host/run-ebpf-qemu.py \
  --kernel kernel/out-bpf-qemu/arch/arm64/boot/Image \
  --busybox anykernel3/tools/busybox \
  --mihomo-test artifacts/ebpf-tests/mihomo-ebpf.test \
  --inbound-test artifacts/ebpf-tests/mihomo-ebpf-inbound.test \
  --probe artifacts/ebpf-tests/ebpf-backport.test \
  --log artifacts/ebpf-tests/qemu.log
```

需要 Go 1.26、ARM64 GCC、Python 3 和 `qemu-system-aarch64`。可用 `GO_BINARY`
指定 Go 可执行文件。Linux/ARM64 测试程序也可复制到手机，在 root 下执行；
bpffs 需挂载到 `/sys/fs/bpf`，cgroup 用例需要可写的统一 cgroup v2 层级；
`ebpf-backport.test` 可用 `BACKPORT_CGROUP_ROOT` 指定其挂载点。真机测试应
保存完整输出和当前内核构建信息。

## 真机反馈（2026-10-23）

本轮提供的测试版本为 [CI #121](https://github.com/chorusfruit-233/OnePlus_SDM845_BakaSU_SUSFS/actions/runs/39941834264)，
构建器提交 `3ee4f40bc0a961001cb951bb40de86c10db3c099`。
用户在一加 **6T / LOS 22.2** 上反馈成功刷入并开机，随后对本轮提供的基础
BPF 回归、本机 TC 接管、热点 `socket_assign` / `packet_rewrite` 和启停测试
步骤反馈“全部正常”。本项记录为**用户反馈的真机冒烟通过**，原始逐项日志、
IPv6 网络条件及长时间运行记录未随反馈提交。

## 支持边界

本轮真机开机和冒烟状态以上述用户反馈为准。QEMU 与单台设备的反馈覆盖已
执行的场景，其他 ROM、硬件 WLAN、IPv6 路由和热点防火墙组合，以及长期
稳定性仍需分别验证。此前直接进入 fastboot 的具体根因尚无 boot/pstore
定位证据，本轮成功开机不用于推断该故障的具体原因。

第三阶段实验 CI 的 ZIP 文件名带 `TC-eBPF-experimental`。Mihomo 可使用
shared-network 的 `packet_rewrite`、本机 cgroup，以及 TC `socket_assign`
的 direct lookup 回退路径。cgroup socket-release 钩子、
ring buffer 和 coarse clock 未开放，Mihomo 使用自身的 LRU 清理与精确时钟
回退路径。socket map 和可选进程追踪组件不在本阶段回移范围内；隔离环境中的
既有 SNAT/conntrack 组合仍需另外验证，当前 QEMU 不安装 iptables。
