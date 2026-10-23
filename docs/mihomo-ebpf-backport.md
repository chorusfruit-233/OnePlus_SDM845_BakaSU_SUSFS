# Mihomo eBPF 4.9 实验回移

目标是 `liuran001/mihomo` 的热点下联 **shared-network / packet_rewrite**。
开发分支为 `work/mihomo-ebpf-4.9`，尚未合入 `main`。保留 WALT；BakaSU 继续
跟踪 `main`。本阶段不提供本机 cgroup socket-address 接管和 `socket_assign`。

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

UAPI 的枚举定义不代表对应功能已实现。socket-address、sockops、sockmap、
reuseport、devmap、AF_XDP、cgroup storage、map-in-map 和 ring buffer 等类型
不在本次注册范围内；未提供的 helper 继续由校验器拒绝。

手机配置增加 BPF JIT，并默认关闭无特权 BPF；root 仍可使用 `bpf()`。
运行时可查看 `/proc/sys/net/core/bpf_jit_enable`，设为 `1` 启用 JIT；
`bpf_jit_harden=2` 可启用常量混淆。
ARM64 LSE atomics 配置沿用手机原值。Qualcomm audio 的 Kbuild 增加平台条件，
使同一源码可编译 ARM64 virt 测试内核；SDM845 仍编译原有音频驱动。

## 可重复验证

测试对象固定为 [liuran001/mihomo](https://github.com/liuran001/mihomo)
`02581ff38100494f1d700612850b7611bdf2099e`，版本信息在
`configs/mihomo-ebpf-test.json`。测试直接编译并执行该提交的上游集成用例，
不修改 Mihomo 程序来绕过校验器。测试包使用相同版本的 Cilium eBPF 库。

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

QEMU 中任何失败、跳过、内核 panic 或 warning 都会阻止该 CI 打包。
测试结果和 ARM64 测试程序保存在 `ebpf-runtime-tests` artifact。
测试内核配置为 `tests/host/bpf-qemu.config`，不启用 KernelSU。

本地已通过手机完整编译及双 CPU QEMU 中上述三种模式的全部用例。
另已编译检查启用 BPF_EVENTS 时的 4.9 tracing 回调。

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
bpffs 需挂载到 `/sys/fs/bpf`。真机测试应保存完整输出和当前内核构建信息。

## 支持边界

QEMU 运行验证不能证明一加 6T 能开机，也不能覆盖 LOS 的 SELinux、netd、
硬件 WLAN、IPv6 路由和热点防火墙组合。此前直接进入 fastboot 的故障仍需
对应 boot/pstore 证据和真机复测，不能用 BPF 测试通过代替。

实验 CI 的 ZIP 文件名带 `eBPF-experimental`。本阶段成功后，Mihomo 应选择
shared-network 的 `packet_rewrite`；其他数据平面仍需后续独立回移和验证。
