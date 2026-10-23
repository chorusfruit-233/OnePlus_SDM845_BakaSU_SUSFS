// SPDX-License-Identifier: GPL-3.0-or-later
package backport

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var socketAddressHooks = []ebpf.AttachType{
	ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupInet6Connect,
	ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP6Sendmsg,
	ebpf.AttachCGroupUDP4Recvmsg, ebpf.AttachCGroupUDP6Recvmsg,
}

// The isolated guest has no network manager to bring loopback up. This setup
// entry point does nothing on a device and can be run before the Mihomo tests.
func TestQEMUNetworkSetup(t *testing.T) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(cmdline), "bpf_backport_qemu=1") {
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	request, err := unix.NewIfreq("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		t.Fatal(err)
	}
	request.SetUint16(request.Uint16() | unix.IFF_UP)
	if err = unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, request); err != nil {
		t.Fatal(err)
	}
}

func socketAddressProgram(t *testing.T, hook ebpf.AttachType, insns asm.Instructions) *ebpf.Program {
	t.Helper()
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.CGroupSockAddr,
		AttachType: hook, License: "GPL", Instructions: insns})
	if err != nil {
		t.Fatalf("load %s: %+v", hook, err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestCgroupContextValidation(t *testing.T) {
	requireRoot(t)
	for _, hook := range socketAddressHooks {
		t.Run(hook.String(), func(t *testing.T) {
			ipv6 := hook == ebpf.AttachCGroupInet6Connect || hook == ebpf.AttachCGroupUDP6Sendmsg || hook == ebpf.AttachCGroupUDP6Recvmsg
			address, otherFamily := int16(4), int16(8)
			if ipv6 {
				address, otherFamily = 8, 4
			}
			insns := asm.Instructions{asm.LoadMem(asm.R2, asm.R1, address, asm.Word),
				asm.StoreMem(asm.R1, address, asm.R2, asm.Word),
				asm.LoadMem(asm.R2, asm.R1, 24, asm.Word),
				asm.StoreMem(asm.R1, 24, asm.R2, asm.Word),
				asm.LoadMem(asm.R2, asm.R1, 36, asm.Word),
				asm.Mov.Imm(asm.R0, 1), asm.Return()}
			socketAddressProgram(t, hook, insns)
			for name, bad := range map[string]asm.Instructions{
				"other_address_family": {asm.LoadMem(asm.R2, asm.R1, otherFamily, asm.Word)},
				"write_family":         {asm.StoreImm(asm.R1, 28, 0, asm.Word)},
				"write_type":           {asm.StoreImm(asm.R1, 32, 0, asm.Word)},
				"write_protocol":       {asm.StoreImm(asm.R1, 36, 0, asm.Word)},
				"narrow_write":         {asm.StoreImm(asm.R1, address, 0, asm.Byte)},
				"outside_context":      {asm.LoadMem(asm.R2, asm.R1, 4096, asm.Word)},
			} {
				t.Run(name, func(t *testing.T) {
					bad = append(bad, asm.Mov.Imm(asm.R0, 1), asm.Return())
					p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.CGroupSockAddr,
						AttachType: hook, License: "GPL", Instructions: bad})
					if p != nil {
						p.Close()
						t.Fatal("unsafe context access accepted")
					}
					var verifier *ebpf.VerifierError
					if !errors.As(err, &verifier) {
						t.Fatalf("expected verifier rejection, got %v", err)
					}
				})
			}
		})
	}
	for _, hook := range []ebpf.AttachType{ebpf.AttachCGroupInet4Bind, ebpf.AttachCGroupInet6Bind} {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.CGroupSockAddr,
			AttachType: hook, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}})
		if p != nil {
			p.Close()
		}
		if err == nil {
			t.Fatalf("unimplemented attach type %s accepted", hook)
		}
	}
}

func cgroupRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("BACKPORT_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(root, &stat); err != nil || uint64(stat.Type) != unix.CGROUP2_SUPER_MAGIC {
		t.Fatalf("BACKPORT_CGROUP_ROOT must be a cgroup v2 mount: %s, %v", root, err)
	}
	return root
}

func testCgroup(t *testing.T, parent string) *os.File {
	t.Helper()
	path, err := os.MkdirTemp(parent, "bpf-backport-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
	})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func attachCgroup(t *testing.T, f *os.File, p *ebpf.Program, flags uint32) {
	t.Helper()
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target: int(f.Fd()), Program: p, Attach: ebpf.AttachCGroupInet4Connect, Flags: flags,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target: int(f.Fd()), Program: p, Attach: ebpf.AttachCGroupInet4Connect,
		})
	})
}

func queryCgroup(f *os.File, queryFlags uint32, capacity int) ([]uint32, uint32, uint32, error) {
	ids := make([]uint32, capacity)
	attr := struct {
		TargetFD, AttachType, QueryFlags, AttachFlags uint32
		ProgIDs                                       uint64
		ProgCount, Padding                            uint32
	}{TargetFD: uint32(f.Fd()), AttachType: uint32(ebpf.AttachCGroupInet4Connect),
		QueryFlags: queryFlags, ProgCount: uint32(capacity)}
	if capacity > 0 {
		attr.ProgIDs = uint64(uintptr(unsafe.Pointer(&ids[0])))
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_QUERY, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(ids)
	runtime.KeepAlive(f)
	ids = ids[:min(len(ids), int(attr.ProgCount))]
	if errno != 0 {
		return ids, attr.AttachFlags, attr.ProgCount, errno
	}
	return ids, attr.AttachFlags, attr.ProgCount, nil
}

func programID(t *testing.T, p *ebpf.Program) uint32 {
	t.Helper()
	info, err := p.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("program ID unavailable")
	}
	return uint32(id)
}

func TestCgroupQueryAndInheritance(t *testing.T) {
	requireRoot(t)
	parent := testCgroup(t, cgroupRoot(t))
	child := testCgroup(t, filepath.Clean(parent.Name()))
	p := socketAddressProgram(t, ebpf.AttachCGroupInet4Connect, asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()})
	c := socketAddressProgram(t, ebpf.AttachCGroupInet4Connect, asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()})
	attachCgroup(t, parent, p, unix.BPF_F_ALLOW_MULTI)
	attachCgroup(t, child, c, unix.BPF_F_ALLOW_MULTI)
	parentID, childID := programID(t, p), programID(t, c)
	for _, flags := range []uint32{0, unix.BPF_F_QUERY_EFFECTIVE} {
		want := []uint32{childID}
		if flags != 0 {
			want = append(want, parentID)
		}
		ids, attachFlags, count, err := queryCgroup(child, flags, 8)
		if err != nil || !slices.Equal(ids, want) || int(count) != len(want) || attachFlags != unix.BPF_F_ALLOW_MULTI {
			t.Fatalf("query flags=%d: ids=%v count=%d attach=%d err=%v; want %v", flags, ids, count, attachFlags, err, want)
		}
	}
	_, flags, count, err := queryCgroup(child, unix.BPF_F_QUERY_EFFECTIVE, 0)
	if err != nil || count != 2 || flags != unix.BPF_F_ALLOW_MULTI {
		t.Fatalf("count-only query: count=%d flags=%d err=%v", count, flags, err)
	}
	ids, _, count, err := queryCgroup(child, unix.BPF_F_QUERY_EFFECTIVE, 1)
	if !errors.Is(err, unix.ENOSPC) || count != 2 || !slices.Equal(ids, []uint32{childID}) {
		t.Fatalf("short effective buffer: ids=%v count=%d err=%v", ids, count, err)
	}
	if _, _, _, err = queryCgroup(child, 2, 8); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("invalid query flags: %v", err)
	}
	if err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target: int(child.Fd()), Program: c, Attach: ebpf.AttachCGroupInet6Connect, Flags: unix.BPF_F_ALLOW_MULTI,
	}); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("mismatched attach type: %v", err)
	}
}

func TestCgroupExclusiveParent(t *testing.T) {
	requireRoot(t)
	parent := testCgroup(t, cgroupRoot(t))
	child := testCgroup(t, parent.Name())
	p := socketAddressProgram(t, ebpf.AttachCGroupInet4Connect, asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()})
	attachCgroup(t, parent, p, 0)
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target: int(child.Fd()), Program: p, Attach: ebpf.AttachCGroupInet4Connect, Flags: unix.BPF_F_ALLOW_MULTI,
	}); !errors.Is(err, unix.EPERM) {
		t.Fatalf("exclusive ancestor must reject child attachment: %v", err)
	}
	ids, flags, count, err := queryCgroup(parent, 0, 8)
	if err != nil || flags != 0 || count != 1 || !slices.Equal(ids, []uint32{programID(t, p)}) {
		t.Fatalf("ancestor owner changed: ids=%v flags=%d count=%d err=%v", ids, flags, count, err)
	}
}
