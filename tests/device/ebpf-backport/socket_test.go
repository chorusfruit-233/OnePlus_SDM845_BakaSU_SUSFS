// SPDX-License-Identifier: GPL-3.0-or-later
package backport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// A fully initialized IPv4 tuple, with an independently controllable helper.
// The caller's skb is saved in r6 and the lookup result is returned in r0.
func socketLookup(helper asm.BuiltinFunc, port uint16) asm.Instructions {
	var tuple [12]byte
	copy(tuple[4:8], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(tuple[8:10], 53299)
	binary.BigEndian.PutUint16(tuple[10:12], port)
	return asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.StoreImm(asm.RFP, -16, int64(binary.NativeEndian.Uint32(tuple[0:4])), asm.Word),
		asm.StoreImm(asm.RFP, -12, int64(binary.NativeEndian.Uint32(tuple[4:8])), asm.Word),
		asm.StoreImm(asm.RFP, -8, int64(binary.NativeEndian.Uint32(tuple[8:12])), asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -16),
		asm.Mov.Imm(asm.R3, 12), asm.Mov.Imm(asm.R4, -1), asm.Mov.Imm(asm.R5, 0),
		helper.Call(),
	}
}

func socketDone() asm.Instructions {
	return asm.Instructions{asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return()}
}

func TestSocketReferenceValidation(t *testing.T) {
	requireRoot(t)
	for _, tc := range []struct {
		name string
		body asm.Instructions
	}{
		{"leak", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}},
		{"unchecked_nullable_read", asm.Instructions{asm.LoadMem(asm.R1, asm.R0, 72, asm.Word)}},
		{"unchecked_nullable_release", asm.Instructions{asm.Mov.Reg(asm.R1, asm.R0), asm.FnSkRelease.Call()}},
		{"use_after_release", asm.Instructions{
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R7, asm.R0),
			asm.Mov.Reg(asm.R1, asm.R0), asm.FnSkRelease.Call(),
			asm.LoadMem(asm.R1, asm.R7, 72, asm.Word),
		}},
		{"spilled_use_after_release", asm.Instructions{
			asm.JEq.Imm(asm.R0, 0, "done"), asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord),
			asm.Mov.Reg(asm.R1, asm.R0), asm.FnSkRelease.Call(),
			asm.LoadMem(asm.R7, asm.RFP, -24, asm.DWord),
			asm.LoadMem(asm.R1, asm.R7, 72, asm.Word),
		}},
		{"double_release", asm.Instructions{
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R7, asm.R0),
			asm.Mov.Reg(asm.R1, asm.R0), asm.FnSkRelease.Call(),
			asm.Mov.Reg(asm.R1, asm.R7), asm.FnSkRelease.Call(),
		}},
		{"pointer_arithmetic", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.Add.Imm(asm.R0, 4)}},
		{"full_socket_only_field", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.LoadMem(asm.R1, asm.R0, 8, asm.Word)}},
		{"write_socket_state", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.StoreImm(asm.R0, 72, 1, asm.Word)}},
		{"short_state_read", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.LoadMem(asm.R1, asm.R0, 72, asm.Byte)}},
		{"out_of_bounds", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.LoadMem(asm.R1, asm.R0, 4096, asm.Word)}},
		{"release_in_only_one_branch", asm.Instructions{
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R7, asm.R0),
			asm.FnGetPrandomU32.Call(), asm.JEq.Imm(asm.R0, 0, "done"),
			asm.Mov.Reg(asm.R1, asm.R7), asm.FnSkRelease.Call(),
		}},
		{"legacy_packet_load_with_live_reference", asm.Instructions{asm.JEq.Imm(asm.R0, 0, "done"), asm.LoadAbs(0, asm.Word)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insns := append(socketLookup(asm.FnSkcLookupTcp, 59999), tc.body...)
			switch tc.name {
			case "full_socket_only_field", "write_socket_state", "short_state_read", "out_of_bounds":
				// Balance the non-NULL path so a missing access check cannot
				// accidentally pass this test through a reference-leak error.
				insns = append(insns, asm.Mov.Reg(asm.R1, asm.R0), asm.FnSkRelease.Call())
			}
			insns = append(insns, socketDone()...)
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
			if err == nil {
				p.Close()
				t.Fatal("unsafe socket lifetime/access was accepted")
			}
		})
	}
	// Callee release must invalidate copies in the caller, including spills.
	for _, spill := range []bool{false, true} {
		insns := append(socketLookup(asm.FnSkcLookupTcp, 59999),
			asm.JEq.Imm(asm.R0, 0, "done"), asm.Mov.Reg(asm.R7, asm.R0),
			asm.StoreMem(asm.RFP, -24, asm.R0, asm.DWord), asm.Mov.Reg(asm.R1, asm.R0),
			asm.Call.Label("release"))
		if spill {
			insns = append(insns, asm.LoadMem(asm.R7, asm.RFP, -24, asm.DWord))
		}
		insns = append(insns, asm.LoadMem(asm.R1, asm.R7, 72, asm.Word))
		insns = append(insns, socketDone()...)
		insns = append(insns, asm.FnSkRelease.Call().WithSymbol("release"), asm.Mov.Imm(asm.R0, 0), asm.Return())
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
		if err == nil {
			p.Close()
			t.Fatalf("callee release left caller alias usable (spill=%v)", spill)
		}
	}
}

func TestSocketLookupAndAssign(t *testing.T) {
	requireRoot(t)
	for _, helper := range []asm.BuiltinFunc{asm.FnSkcLookupTcp, asm.FnSkLookupTcp, asm.FnSkLookupUdp} {
		tcp := helper != asm.FnSkLookupUdp
		var closer interface{ Close() error }
		var port int
		var state int32
		if tcp {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			closer, port, state = listener, listener.Addr().(*net.TCPAddr).Port, 10
		} else {
			listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			closer, port, state = listener, listener.LocalAddr().(*net.UDPAddr).Port, 7
		}
		defer closer.Close()
		for _, kind := range []string{"context", "refused_assign", "invalid_flags", "callee_return", "callee_release"} {
			t.Run(kind+helper.String(), func(t *testing.T) {
				lookup := socketLookup(helper, uint16(port))
				if kind == "callee_return" {
					lookup = asm.Instructions{asm.Call.Label("lookup")}
				}
				insns := append(lookup, asm.JEq.Imm(asm.R0, 0, "missing"), asm.Mov.Reg(asm.R7, asm.R0))
				want := uint32(state | (2 << 8))
				if kind == "refused_assign" || kind == "invalid_flags" {
					flags := int32(0)
					want = uint32(95)
					if kind == "invalid_flags" {
						flags, want = 1, 22
					}
					insns = append(insns, asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Reg(asm.R2, asm.R7),
						asm.Mov.Imm(asm.R3, flags), asm.FnSkAssign.Call(), asm.Neg.Imm(asm.R0, 0), asm.Mov.Reg(asm.R8, asm.R0))
				} else {
					insns = append(insns, asm.LoadMem(asm.R8, asm.R7, 4, asm.Word), asm.LSh.Imm(asm.R8, 8),
						asm.LoadMem(asm.R9, asm.R7, 72, asm.Word), asm.Or.Reg(asm.R8, asm.R9))
				}
				insns = append(insns, asm.Mov.Reg(asm.R1, asm.R7))
				if kind == "callee_release" {
					insns = append(insns, asm.Call.Label("release"))
				} else {
					insns = append(insns, asm.FnSkRelease.Call())
				}
				insns = append(insns, asm.Mov.Reg(asm.R0, asm.R8), asm.Return(),
					asm.Mov.Imm(asm.R0, -1).WithSymbol("missing"), asm.Return())
				if kind == "callee_return" {
					body := socketLookup(helper, uint16(port))
					body[0] = body[0].WithSymbol("lookup")
					insns = append(insns, body...)
					insns = append(insns, asm.Return())
				} else if kind == "callee_release" {
					insns = append(insns, asm.FnSkRelease.Call().WithSymbol("release"), asm.Mov.Imm(asm.R0, 0), asm.Return())
				}
				p := newProgram(t, insns)
				for i := 0; i < 64; i++ {
					got, _, err := p.Test(make([]byte, 64))
					if err != nil || got != want {
						t.Fatalf("lookup/assign got=%d want=%d err=%v", got, want, err)
					}
				}
			})
		}
	}
}

func TestPacketPointersInvalidatedByHelpers(t *testing.T) {
	requireRoot(t)
	for _, tc := range []struct {
		helper asm.BuiltinFunc
		args   asm.Instructions
	}{
		{asm.FnSkbStoreBytes, asm.Instructions{
			asm.StoreImm(asm.RFP, -8, 0, asm.Word), asm.Mov.Imm(asm.R2, 0),
			asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -8), asm.Mov.Imm(asm.R4, 1), asm.Mov.Imm(asm.R5, 0)}},
		{asm.FnSkbPullData, asm.Instructions{asm.Mov.Imm(asm.R2, 0)}},
		{asm.FnSkbVlanPush, asm.Instructions{asm.Mov.Imm(asm.R2, 0x0081), asm.Mov.Imm(asm.R3, 1)}},
		{asm.FnSkbVlanPop, nil},
		{asm.FnSkbChangeProto, asm.Instructions{asm.Mov.Imm(asm.R2, 0xdd86), asm.Mov.Imm(asm.R3, 0)}},
		{asm.FnSkbChangeHead, asm.Instructions{asm.Mov.Imm(asm.R2, 14), asm.Mov.Imm(asm.R3, 0)}},
		{asm.FnSkbChangeTail, asm.Instructions{asm.Mov.Imm(asm.R2, 64), asm.Mov.Imm(asm.R3, 0)}},
		{asm.FnCloneRedirect, asm.Instructions{asm.Mov.Imm(asm.R2, 1), asm.Mov.Imm(asm.R3, 0)}},
		{asm.FnL3CsumReplace, asm.Instructions{asm.Mov.Imm(asm.R2, 24), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 2)}},
		{asm.FnL4CsumReplace, asm.Instructions{asm.Mov.Imm(asm.R2, 40), asm.Mov.Imm(asm.R3, 0), asm.Mov.Imm(asm.R4, 0), asm.Mov.Imm(asm.R5, 2)}},
	} {
		t.Run(tc.helper.String(), func(t *testing.T) {
			for _, reload := range []bool{false, true} {
				insns := asm.Instructions{
					asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, 76, asm.Word),
					asm.LoadMem(asm.R8, asm.R6, 80, asm.Word), asm.Mov.Reg(asm.R9, asm.R7),
					asm.Add.Imm(asm.R9, 1), asm.JGT.Reg(asm.R9, asm.R8, "done"),
				}
				insns = append(insns, tc.args...)
				insns = append(insns, tc.helper.Call())
				if reload {
					insns = append(insns, asm.LoadMem(asm.R7, asm.R6, 76, asm.Word),
						asm.LoadMem(asm.R8, asm.R6, 80, asm.Word), asm.Mov.Reg(asm.R9, asm.R7),
						asm.Add.Imm(asm.R9, 1), asm.JGT.Reg(asm.R9, asm.R8, "done"))
				}
				insns = append(insns, asm.LoadMem(asm.R0, asm.R7, 0, asm.Byte))
				insns = append(insns, socketDone()...)
				p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
				if p != nil {
					p.Close()
				}
				if reload && err != nil {
					t.Fatalf("reloaded/rechecked pointer rejected: %+v", err)
				}
				if !reload && err == nil {
					t.Fatal("stale direct packet pointer survived a modifying helper")
				}
			}
		})
	}
}

func TestSKBChangeHead(t *testing.T) {
	requireRoot(t)
	packet := bytes.Repeat([]byte{0x5a}, 64)
	for _, tc := range []struct {
		room, flags int32
		want        uint32
	}{
		{14, 0, 0}, {14, 1, 22}, {-1, 0, 22},
	} {
		p := newProgram(t, asm.Instructions{
			asm.Mov.Imm(asm.R2, tc.room), asm.Mov.Imm(asm.R3, tc.flags),
			asm.FnSkbChangeHead.Call(), asm.Neg.Imm(asm.R0, 0), asm.Return(),
		})
		got, output, err := p.Test(packet)
		want := packet
		if tc.want == 0 {
			want = append(make([]byte, 14), packet...)
		}
		if err != nil || got != tc.want || !bytes.Equal(output, want) {
			t.Fatalf("change_head room=%d flags=%d: retval=%d err=%v output=%x", tc.room, tc.flags, got, err, output)
		}
	}
}

func TestBoundedScalarSpills(t *testing.T) {
	requireRoot(t)
	for _, corrupt := range []bool{false, true} {
		insns := asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R2, asm.R6, 0, asm.Word),
			asm.And.Imm(asm.R2, 63), asm.Add.Imm(asm.R2, 1),
			asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		}
		if corrupt {
			insns = append(insns, asm.StoreImm(asm.RFP, -7, 0xff, asm.Byte))
		}
		insns = append(insns, asm.LoadMem(asm.R2, asm.RFP, -8, asm.DWord),
			asm.LSh.Imm(asm.R2, 32), asm.RSh.Imm(asm.R2, 32),
			asm.LoadMem(asm.R7, asm.R6, 76, asm.Word), asm.LoadMem(asm.R8, asm.R6, 80, asm.Word),
			asm.Add.Reg(asm.R7, asm.R2), asm.Mov.Reg(asm.R9, asm.R7), asm.Add.Imm(asm.R9, 1),
			asm.JGT.Reg(asm.R9, asm.R8, "done"), asm.LoadMem(asm.R0, asm.R7, 0, asm.Byte), asm.Return())
		insns = append(insns, socketDone()...)
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: "GPL", Instructions: insns})
		if corrupt {
			if err == nil {
				p.Close()
				t.Fatal("partial overwrite preserved stale scalar bounds")
			}
			continue
		}
		if err != nil {
			t.Fatalf("bounded scalar spill rejected: %+v", err)
		}
		got, _, err := p.Test(bytes.Repeat([]byte{0x5a}, 64))
		p.Close()
		if err != nil || got != 0x5a {
			t.Fatalf("bounded scalar execution: got=%d err=%v", got, err)
		}
	}
}
