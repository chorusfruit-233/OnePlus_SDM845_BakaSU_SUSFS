# Mihomo eBPF 4.9 实验回移

目标是 `liuran001/mihomo` 的热点下联 **shared-network / packet_rewrite**，
以及本机 **cgroup socket-address** 接管。开发分支为 `work/mihomo-ebpf-4.9`，
尚未合入 `main`。保留 WALT；BakaSU 继续跟踪 `main`。`socket_assign` 未回移。

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
构建脚本通过 Go overlay 加入本仓库 `tests/host/mihomo-cgroup-runtime_test.go`，
补充跨进程的真实 socket 收发测试，不改动上游源码、BPF 对象或已有用例。

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
用例也已通过上述三种模式，完整手机编译和 CI 结果以对应实验分支 run 为准。
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
  --probe artifacts/ebpf-tests/ebpf-backport.test \
  --log artifacts/ebpf-tests/qemu.log
```

需要 Go 1.26、ARM64 GCC、Python 3 和 `qemu-system-aarch64`。可用 `GO_BINARY`
指定 Go 可执行文件。Linux/ARM64 测试程序也可复制到手机，在 root 下执行；
bpffs 需挂载到 `/sys/fs/bpf`，cgroup 用例需要可写的统一 cgroup v2 层级；
`ebpf-backport.test` 可用 `BACKPORT_CGROUP_ROOT` 指定其挂载点。真机测试应
保存完整输出和当前内核构建信息。

## 支持边界

QEMU 运行验证不能证明一加 6T 能开机，也不能覆盖 LOS 的 SELinux、netd、
硬件 WLAN、IPv6 路由和热点防火墙组合。此前直接进入 fastboot 的故障仍需
对应 boot/pstore 证据和真机复测，不能用 BPF 测试通过代替。

第二阶段实验 CI 的 ZIP 文件名带 `cgroup-eBPF-experimental`。Mihomo 可使用
shared-network 的 `packet_rewrite` 和本机 cgroup 数据面。socket-release、
ring buffer 和 coarse clock 未开放，Mihomo 使用自身的 LRU 清理与精确时钟
回退路径；`socket_assign`、TC socket lookup、socket map 和可选进程追踪组件
不在本阶段验证范围内。
