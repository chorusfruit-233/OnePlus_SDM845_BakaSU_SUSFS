// SPDX-License-Identifier: GPL-3.0-or-later
// Run as root on the experimental ARM64 kernel, or in its QEMU test guest.
package backport

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("run these kernel regression tests as root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}

func newProgram(t *testing.T, insns asm.Instructions) *ebpf.Program {
	t.Helper()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, License: "GPL", Instructions: insns,
	})
	if err != nil {
		t.Fatalf("load: %+v", err)
	}
	t.Cleanup(func() { prog.Close() })
	return prog
}

func TestSubprogramExecution(t *testing.T) {
	requireRoot(t)
	// A call must preserve its caller's stack and callee-saved registers.
	p := newProgram(t, asm.Instructions{
		asm.Mov.Imm(asm.R6, 40),
		asm.Mov.Imm(asm.R1, 2),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.Call.Label("callee"),
		asm.LoadMem(asm.R1, asm.RFP, -8, asm.DWord),
		asm.Add.Reg(asm.R0, asm.R1),
		asm.Add.Reg(asm.R0, asm.R6),
		asm.Return(),
		asm.Mov.Imm(asm.R6, 99).WithSymbol("callee"),
		asm.Mov.Imm(asm.R1, 100),
		asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	})
	packet := make([]byte, 64)
	retval, out, err := p.Test(packet)
	if err != nil || retval != 42 || !bytes.Equal(packet, out) {
		t.Fatalf("call/return: retval=%d output=%x error=%v", retval, out, err)
	}
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	mode, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	if err != nil {
		t.Fatal(err)
	}
	size, err := info.JitedSize()
	if err != nil && !(bytes.TrimSpace(mode)[0] == '0' && errors.Is(err, ebpf.ErrNotSupported)) {
		t.Fatal(err)
	}
	if (bytes.TrimSpace(mode)[0] == '0') != (size == 0) {
		t.Fatalf("JIT mode %s produced %d machine-code bytes", mode, size)
	}
	t.Logf("JIT mode=%s machine-code bytes=%d", bytes.TrimSpace(mode), size)
}

func TestAtomicMapUpdates(t *testing.T) {
	requireRoot(t)
	for _, size := range []asm.Size{asm.Word, asm.DWord} {
		t.Run(size.String(), func(t *testing.T) {
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4,
				ValueSize: uint32(size.Sizeof()), MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			p := newProgram(t, asm.Instructions{
				asm.LoadMapPtr(asm.R1, m.FD()),
				asm.StoreImm(asm.RFP, -4, 0, asm.Word),
				asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4),
				asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "missing"),
				asm.Mov.Reg(asm.R1, asm.R0), asm.Mov.Imm(asm.R2, 1),
				asm.StoreXAdd(asm.R1, asm.R2, size),
				asm.LoadMem(asm.R0, asm.R1, 0, size), asm.Return(),
				asm.Mov.Imm(asm.R0, -1).WithSymbol("missing"), asm.Return(),
			})
			for want := uint32(1); want <= 2; want++ {
				got, _, err := p.Test(make([]byte, 64))
				if err != nil || got != want {
					t.Fatalf("atomic update: got=%d want=%d error=%v", got, want, err)
				}
			}
			// Exercise LL/SC retries when two guest CPUs share the counter.
			var workers sync.WaitGroup
			errorsOut := make(chan error, 2)
			for worker := 0; worker < 2; worker++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					for i := 0; i < 100; i++ {
						if _, _, err := p.Test(make([]byte, 64)); err != nil {
							errorsOut <- err
							return
						}
					}
				}()
			}
			workers.Wait()
			close(errorsOut)
			for err := range errorsOut {
				t.Fatal(err)
			}
			value := make([]byte, size.Sizeof())
			if err := m.Lookup(uint32(0), &value); err != nil {
				t.Fatal(err)
			}
			var got uint64
			for i := len(value) - 1; i >= 0; i-- {
				got = got<<8 | uint64(value[i])
			}
			if got != 202 {
				t.Fatalf("concurrent atomic updates lost: got=%d want=202", got)
			}
		})
	}
}

func TestLegacyEBPFPacketLoads(t *testing.T) {
	requireRoot(t)
	for name, tc := range map[string]struct {
		size asm.Size
		off  int32
		want uint32
	}{
		"byte": {asm.Byte, 0, 1}, "half": {asm.Half, 0, 0x0102},
		"word": {asm.Word, 0, 0x01020304}, "out_of_bounds": {asm.Word, 4096, 0},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProgram(t, asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1),
				asm.LoadAbs(tc.off, tc.size), asm.Return()})
			packet := make([]byte, 64)
			copy(packet, []byte{1, 2, 3, 4})
			got, out, err := p.Test(packet)
			if err != nil || got != tc.want || !bytes.Equal(out, packet) {
				t.Fatalf("legacy packet load: got=%d want=%d error=%v", got, tc.want, err)
			}
		})
	}
}

func TestLRUEviction(t *testing.T) {
	requireRoot(t)
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 4, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for i := uint32(0); i < 1024; i++ {
		if err := m.Update(i, i+1, ebpf.UpdateAny); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	var value uint32
	if err := m.Lookup(uint32(1023), &value); err != nil || value != 1024 {
		t.Fatalf("new entry lost: value=%d error=%v", value, err)
	}
	if err := m.Lookup(uint32(0), &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("old entry was not evicted: %v", err)
	}
	iter := m.Iterate()
	count := 0
	var key uint32
	for iter.Next(&key, &value) {
		count++
	}
	if err := iter.Err(); err != nil || count == 0 || count > 64 {
		t.Fatalf("LRU size=%d error=%v", count, err)
	}
}

func TestLPMUpdateDelete(t *testing.T) {
	requireRoot(t)
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: 8, ValueSize: 4,
		MaxEntries: 64, Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	type prefix struct {
		Bits uint32
		Addr [4]byte
	}
	defaultKey := prefix{0, [4]byte{}}
	subnet := prefix{24, [4]byte{192, 0, 2, 0}}
	for i, k := range []prefix{defaultKey, subnet} {
		if err := m.Update(k, uint32(i+1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	query := prefix{32, [4]byte{192, 0, 2, 123}}
	var value uint32
	if err := m.Lookup(query, &value); err != nil || value != 2 {
		t.Fatalf("longest prefix: value=%d error=%v", value, err)
	}
	if err := m.Delete(subnet); err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(query, &value); err != nil || value != 1 {
		t.Fatalf("default after delete: value=%d error=%v", value, err)
	}
}

func TestVerifierRejectsInvalidAccess(t *testing.T) {
	requireRoot(t)
	for name, insns := range map[string]asm.Instructions{
		"uninitialized_stack":   {asm.LoadMem(asm.R0, asm.RFP, -8, asm.DWord), asm.Return()},
		"stack_overflow":        {asm.StoreImm(asm.RFP, -520, 0, asm.Word), asm.Mov.Imm(asm.R0, 0), asm.Return()},
		"context_out_of_bounds": {asm.LoadMem(asm.R0, asm.R1, 4096, asm.Word), asm.Return()},
		"packet_without_bounds": {
			asm.LoadMem(asm.R2, asm.R1, 76, asm.Word), // __sk_buff.data
			asm.LoadMem(asm.R0, asm.R2, 0, asm.Word), asm.Return(),
		},
		"recursive_call":                {asm.Call.Label("again").WithSymbol("again"), asm.Return()},
		"unavailable_socket_assignment": {asm.FnSkAssign.Call(), asm.Return()},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
			if p != nil {
				p.Close()
				t.Fatal("invalid program was accepted")
			}
			var verifier *ebpf.VerifierError
			if !errors.As(err, &verifier) {
				t.Fatalf("expected verifier rejection, got %v", err)
			}
		})
	}
}

func TestUnsupportedTypesRejected(t *testing.T) {
	requireRoot(t)
	for _, typ := range []ebpf.ProgramType{ebpf.CGroupSock, ebpf.SockOps, ebpf.SkMsg, ebpf.SkReuseport} {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: typ, License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
		if p != nil {
			p.Close()
		}
		if err == nil {
			t.Fatalf("unsupported program type %s was accepted", typ)
		}
	}
	for _, typ := range []ebpf.MapType{ebpf.SockMap, ebpf.CGroupStorage, ebpf.DevMap, ebpf.RingBuf, ebpf.ArrayOfMaps, ebpf.HashOfMaps} {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: 4, ValueSize: 4, MaxEntries: 64})
		if m != nil {
			m.Close()
		}
		if err == nil {
			t.Fatalf("unsupported map type %s was accepted", typ)
		}
	}
}

func TestPinnedMapRoundTrip(t *testing.T) {
	requireRoot(t)
	path := filepath.Join("/sys/fs/bpf", "backport-test-map")
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Put(uint32(7), uint32(42)); err != nil {
		t.Fatal(err)
	}
	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}
	defer m.Unpin()
	reopened, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var value uint32
	if err := reopened.Lookup(uint32(7), &value); err != nil || value != 42 {
		t.Fatalf("pinned map lookup: value=%d error=%v", value, err)
	}
}

func TestRunUserBufferBounds(t *testing.T) {
	requireRoot(t)
	p := newProgram(t, asm.Instructions{asm.Mov.Imm(asm.R0, 42), asm.Return()})
	page := os.Getpagesize()
	mem, err := unix.Mmap(-1, 0, 2*page, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)
	if err := unix.Mprotect(mem[page:], unix.PROT_NONE); err != nil {
		t.Fatal(err)
	}
	// A non-aligned input ending at an inaccessible page must remain readable.
	input := mem[page-61 : page]
	output := bytes.Repeat([]byte{0xa5}, 128)
	type testAttr struct {
		FD, Retval, SizeIn, SizeOut uint32
		DataIn, DataOut             uint64
		Repeat, Duration            uint32
	}
	run := func(size uint32) (testAttr, unix.Errno) {
		attr := testAttr{FD: uint32(p.FD()), SizeIn: uint32(len(input)), SizeOut: size,
			DataIn:  uint64(uintptr(unsafe.Pointer(&input[0]))),
			DataOut: uint64(uintptr(unsafe.Pointer(&output[0]))), Repeat: 1}
		_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_TEST_RUN,
			uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
		return attr, errno
	}
	attr, errno := run(uint32(len(output)))
	if errno != 0 || attr.Retval != 42 || attr.SizeOut != 61 || !bytes.Equal(input, output[:61]) {
		t.Fatalf("input at page boundary: attr=%+v error=%v", attr, errno)
	}
	for i := range output {
		output[i] = 0xa5
	}
	attr, errno = run(1)
	if errno != unix.ENOSPC || attr.SizeOut != 61 || output[0] != input[0] ||
		!bytes.Equal(output[1:], bytes.Repeat([]byte{0xa5}, len(output)-1)) {
		t.Fatalf("output bound exceeded: attr=%+v error=%v output=%x", attr, errno, output)
	}
}

func TestSeccompCompatibility(t *testing.T) {
	requireRoot(t)
	if os.Getenv("BACKPORT_SECCOMP_CHILD") == "1" {
		// Restrict only the disposable child and keep its filter on this thread.
		runtime.LockOSThread()
		filters := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_GETPPID, Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)},
			{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		}
		fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
			uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0); errno != unix.EACCES {
			t.Fatalf("seccomp did not block getppid: %v", errno)
		}
		if _, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0); errno != 0 {
			t.Fatalf("seccomp blocked an allowed syscall: %v", errno)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestSeccompCompatibility$")
	cmd.Env = append(os.Environ(), "BACKPORT_SECCOMP_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seccomp child: %v\n%s", err, out)
	}
}

func TestClassicSocketFilters(t *testing.T) {
	requireRoot(t)
	compare := func(prefix []unix.SockFilter, expected uint32) []unix.SockFilter {
		return append(prefix,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: expected, Jf: 1},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0})
	}
	for name, tc := range map[string]struct {
		filter []unix.SockFilter
		drop   bool
	}{
		"byte": {filter: compare([]unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 0}}, 0x41)},
		"half": {filter: compare([]unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 2}}, 0x1234)},
		"word": {filter: compare([]unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}}, 0x01020304)},
		"last_stack_slot": {filter: compare([]unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_IMM, K: 0x1234}, {Code: unix.BPF_ST, K: 15},
			{Code: unix.BPF_LD | unix.BPF_IMM, K: 0}, {Code: unix.BPF_LD | unix.BPF_MEM, K: 15},
		}, 0x1234)},
		"msh_indirect": {filter: compare([]unix.SockFilter{
			{Code: unix.BPF_LDX | unix.BPF_MSH | unix.BPF_B, K: 0},
			{Code: unix.BPF_LD | unix.BPF_IND | unix.BPF_W, K: 0},
		}, 0x01020304)},
		"msh_preserves_accumulator": {filter: compare([]unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_IMM, K: 0x12345678},
			{Code: unix.BPF_LDX | unix.BPF_MSH | unix.BPF_B, K: 0},
		}, 0x12345678)},
		"load_out_of_bounds": {drop: true, filter: []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_ABS | unix.BPF_W, K: 4096},
			{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		}},
		"divide_by_zero": {drop: true, filter: []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_IMM, K: 10}, {Code: unix.BPF_LDX | unix.BPF_IMM, K: 0},
			{Code: unix.BPF_ALU | unix.BPF_DIV | unix.BPF_X}, {Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		}},
		"modulo_by_zero": {drop: true, filter: []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_IMM, K: 10}, {Code: unix.BPF_LDX | unix.BPF_IMM, K: 0},
			{Code: unix.BPF_ALU | unix.BPF_MOD | unix.BPF_X}, {Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			prog := unix.SockFprog{Len: uint16(len(tc.filter)), Filter: &tc.filter[0]}
			if err := unix.SetsockoptSockFprog(fds[1], unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
				t.Fatal(err)
			}
			packet := []byte{0x41, 0xab, 0x12, 0x34, 1, 2, 3, 4}
			if _, err := unix.Write(fds[0], packet); err != nil && !(tc.drop && errors.Is(err, unix.EPERM)) {
				t.Fatal(err)
			}
			out := make([]byte, 32)
			n, err := unix.Read(fds[1], out)
			if tc.drop {
				if !errors.Is(err, unix.EAGAIN) {
					t.Fatalf("filter failed to drop packet: len=%d error=%v", n, err)
				}
			} else if err != nil || n != len(packet) || !bytes.Equal(out[:n], packet) {
				t.Fatalf("filter did not accept packet: len=%d error=%v", n, err)
			}
		})
	}
}

// Used only after the disposable guest has printed its final result marker.
func TestQEMUShutdown(t *testing.T) {
	if os.Getenv("BACKPORT_QEMU_SHUTDOWN") != "1" {
		return
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("bpf_backport_qemu=1")) {
		t.Fatal("shutdown helper requires the regression guest command line")
	}
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		t.Fatal(err)
	}
}
