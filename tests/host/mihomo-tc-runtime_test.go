//go:build with_ebpf && linux && ebpf_integration

// SPDX-License-Identifier: GPL-3.0-or-later
package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func backportTCFatal(t *testing.T, err error) {
	t.Helper()
	var verifier *CiliumEBPF.VerifierError
	if errors.As(err, &verifier) {
		t.Fatalf("%+v", verifier)
	}
	t.Fatal(err)
}

func backportTCGuest(t *testing.T) {
	t.Helper()
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(cmdline), "bpf_backport_qemu=1") {
		t.Fatal("this network test requires the disposable backport QEMU guest")
	}
}

func backportTCListener(t *testing.T, ipv6, tcp bool) (int, uint16) {
	t.Helper()
	family, kind := unix.AF_INET, unix.SOCK_DGRAM
	if ipv6 {
		family = unix.AF_INET6
	}
	if tcp {
		kind = unix.SOCK_STREAM
	}
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	level, transparent, original := unix.SOL_IP, unix.IP_TRANSPARENT, unix.IP_RECVORIGDSTADDR
	var address unix.Sockaddr = &unix.SockaddrInet4{}
	if ipv6 {
		level, transparent, original = unix.SOL_IPV6, unix.IPV6_TRANSPARENT, unix.IPV6_RECVORIGDSTADDR
		address = &unix.SockaddrInet6{}
		if err = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.SetsockoptInt(fd, level, transparent, 1); err != nil {
		t.Fatal(err)
	}
	if !tcp {
		if err = unix.SetsockoptInt(fd, level, original, 1); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Bind(fd, address); err != nil {
		t.Fatal(err)
	}
	if tcp {
		if err = unix.Listen(fd, 16); err != nil {
			t.Fatal(err)
		}
	}
	timeout := unix.NsecToTimeval((4 * time.Second).Nanoseconds())
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		t.Fatal(err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	if ipv6 {
		return fd, uint16(bound.(*unix.SockaddrInet6).Port)
	}
	return fd, uint16(bound.(*unix.SockaddrInet4).Port)
}

// A test-run call is outside TC ingress and must fail without deleting or
// replacing the existing assignment. The original upstream case uses SOCKMAP;
// this case exercises the unmodified object's direct-lookup fallback instead.
func TestBackportTCFailedAssignmentRetainsFlowIntegration(t *testing.T) {
	requireEBPFIntegration(t, "retain a flow when the direct lookup sk_assign fails")
	_, port := backportTCListener(t, false, true)
	b, err := prepareTC(TCConfig{ListenerPort: port, AssignmentCapacity: 64,
		EnableShared: true, EnableIPv4: true, EnableTCP: true}, true)
	if err != nil {
		backportTCFatal(t, err)
	}
	defer b.Close()
	if err = b.Enable(); err != nil {
		t.Fatal(err)
	}
	source, destination := netip.MustParseAddrPort("192.0.2.10:53100"), netip.MustParseAddrPort("203.0.113.10:443")
	key, _ := makeTCAssignKey(unix.IPPROTO_TCP, source, destination, 0)
	live := TCAssignment{SocketCookie: 0x5ab1e, InterfaceIndex: 7, Path: 1, Generation: 42}
	if err = updateMap(b.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&live)); err != nil {
		t.Fatal(err)
	}
	action, _ := runTCProgram(t, b.runtime.programs[tcProgramSharedIngressEthernet],
		testIPv4TCPPacket(source.Addr(), destination.Addr(), source.Port(), destination.Port()))
	stats, err := b.TCStats()
	if err != nil {
		t.Fatal(err)
	}
	if action != testTCActShot || stats.SKAssignFailed != 1 || stats.ListenerSocketMissing != 0 {
		t.Fatalf("packet did not reach refused assignment: action=%d stats=%+v", action, stats)
	}
	kept, err := b.LookupAssignment(unix.IPPROTO_TCP, source, destination, 0, false)
	if err != nil || kept != live {
		t.Fatalf("live assignment changed: got=%+v err=%v", kept, err)
	}
}

func backportTCPacket(source, destination netip.AddrPort, protocol uint8, flags byte,
	sequence, acknowledgement uint32, payload []byte, sourceMAC, destinationMAC net.HardwareAddr) []byte {
	ipv6 := source.Addr().Is6()
	ipSize, transportSize, ethertype := 20, 8, uint16(unix.ETH_P_IP)
	if ipv6 {
		ipSize, ethertype = 40, unix.ETH_P_IPV6
	}
	if protocol == unix.IPPROTO_TCP {
		transportSize = 20
	}
	packet := make([]byte, 14+ipSize+transportSize+len(payload))
	copy(packet[:6], destinationMAC)
	copy(packet[6:12], sourceMAC)
	binary.BigEndian.PutUint16(packet[12:14], ethertype)
	ip, segment := packet[14:], packet[14+ipSize:]
	if ipv6 {
		ip[0], ip[6], ip[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(segment)))
		copy(ip[8:24], source.Addr().AsSlice())
		copy(ip[24:40], destination.Addr().AsSlice())
	} else {
		ip[0], ip[8], ip[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		copy(ip[12:16], source.Addr().AsSlice())
		copy(ip[16:20], destination.Addr().AsSlice())
		binary.BigEndian.PutUint16(ip[10:12], sharedRewriteTestChecksum(ip[:20]))
	}
	binary.BigEndian.PutUint16(segment[:2], source.Port())
	binary.BigEndian.PutUint16(segment[2:4], destination.Port())
	checksumOffset := 6
	if protocol == unix.IPPROTO_TCP {
		checksumOffset = 16
		binary.BigEndian.PutUint32(segment[4:8], sequence)
		binary.BigEndian.PutUint32(segment[8:12], acknowledgement)
		segment[12], segment[13] = 0x50, flags
		binary.BigEndian.PutUint16(segment[14:16], 32768)
	} else {
		binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	}
	copy(segment[transportSize:], payload)
	pseudo := backportTCPseudo(source.Addr(), destination.Addr(), protocol, len(segment))
	checksum := sharedRewriteTestChecksum(append(pseudo, segment...))
	if checksum == 0 && protocol == unix.IPPROTO_UDP {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[checksumOffset:checksumOffset+2], checksum)
	return packet
}

func backportTCPseudo(source, destination netip.Addr, protocol uint8, size int) []byte {
	if source.Is6() {
		pseudo := make([]byte, 40)
		copy(pseudo[:16], source.AsSlice())
		copy(pseudo[16:32], destination.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(size))
		pseudo[39] = protocol
		return pseudo
	}
	pseudo := make([]byte, 12)
	copy(pseudo[:4], source.AsSlice())
	copy(pseudo[4:8], destination.AsSlice())
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(size))
	return pseudo
}

func backportTCReadTCP(t *testing.T, fd int, source, destination netip.AddrPort, payload bool) []byte {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(ready, 500); err != nil {
			t.Fatal(err)
		}
		if ready[0].Revents&unix.POLLIN == 0 {
			continue
		}
		packet := make([]byte, 2048)
		n, err := unix.Read(fd, packet)
		if err != nil {
			t.Fatal(err)
		}
		packet = packet[:n]
		offset := 34
		if source.Addr().Is6() {
			offset = 54
		}
		if len(packet) < offset+20 {
			continue
		}
		if source.Addr().Is6() {
			if binary.BigEndian.Uint16(packet[12:14]) != unix.ETH_P_IPV6 || packet[20] != unix.IPPROTO_TCP ||
				!bytes.Equal(packet[22:38], source.Addr().AsSlice()) {
				continue
			}
		} else if binary.BigEndian.Uint16(packet[12:14]) != unix.ETH_P_IP || packet[23] != unix.IPPROTO_TCP ||
			!bytes.Equal(packet[26:30], source.Addr().AsSlice()) {
			continue
		}
		segment := packet[offset:]
		if binary.BigEndian.Uint16(segment[:2]) != source.Port() || binary.BigEndian.Uint16(segment[2:4]) != destination.Port() {
			continue
		}
		header := int(segment[12]>>4) * 4
		if header < 20 || len(segment) < header {
			t.Fatal("invalid TCP response header")
		}
		if payload && len(segment) == header {
			continue
		}
		if !payload && segment[13]&0x12 != 0x12 {
			continue
		}
		if sharedRewriteTestChecksum(append(backportTCPseudo(source.Addr(), destination.Addr(), unix.IPPROTO_TCP, len(segment)), segment...)) != 0 {
			t.Fatal("invalid TCP response checksum")
		}
		return segment
	}
	t.Fatal("timed out waiting for TCP response through the assigned socket")
	return nil
}

func TestBackportTCSocketDeliveryIntegration(t *testing.T) {
	requireEBPFIntegration(t, "deliver unchanged TCP/UDP packets to Mihomo's assigned sockets")
	backportTCGuest(t)
	for _, delivery := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			for _, tcp := range []bool{false, true} {
				name := "shared/"
				if delivery {
					name = "delivery/"
				}
				if ipv6 {
					name += "ipv6/"
				} else {
					name += "ipv4/"
				}
				if tcp {
					name += "tcp"
				} else {
					name += "udp"
				}
				t.Run(name, func(t *testing.T) { backportTCDelivery(t, ipv6, tcp, delivery) })
			}
		}
	}
}

func backportTCDelivery(t *testing.T, ipv6, tcp, delivery bool) {
	// The 4.9 JIT sysctl is registered only in the initial network namespace.
	mode, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	if err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	previous, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	if err = unix.Unshare(unix.CLONE_NEWNET); err != nil {
		previous.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setns(int(previous.Fd()), unix.CLONE_NEWNET); err != nil {
			t.Errorf("restore network namespace: %v", err)
		}
		previous.Close()
		runtime.UnlockOSThread()
	}()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "bptc0"}, PeerName: "bptc1"}
	if err = netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	self, err := netlink.LinkByName("bptc0")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := netlink.LinkByName("bptc1")
	if err != nil {
		t.Fatal(err)
	}
	// AF_PACKET observes a veth's checksum seed before hardware offload.
	// Force software TX checksums so the captured replies are wire packets.
	ethtoolFD, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	value := struct{ Command, Data uint32 }{Command: 0x17} // ETHTOOL_STXCSUM
	ethtoolRequest := struct {
		Name    [16]byte
		Data    unsafe.Pointer
		Padding [16]byte
	}{Data: unsafe.Pointer(&value)}
	copy(ethtoolRequest.Name[:], self.Attrs().Name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(ethtoolFD), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ethtoolRequest)))
	unix.Close(ethtoolFD)
	if errno != 0 {
		t.Fatalf("disable veth TX checksum offload: %v", errno)
	}
	for _, name := range []string{"lo", "bptc0", "bptc1"} {
		device, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = netlink.LinkSetUp(device); err != nil {
			t.Fatal(err)
		}
	}
	local, source, destination := "192.0.2.1/24", netip.MustParseAddrPort("192.0.2.2:53100"), netip.MustParseAddrPort("203.0.113.10:443")
	if ipv6 {
		local, source, destination = "2001:db8:1::1/64", netip.MustParseAddrPort("[2001:db8:1::2]:53100"), netip.MustParseAddrPort("[2001:db8:2::10]:443")
	}
	addr, _ := netlink.ParseAddr(local)
	addr.Flags = unix.IFA_F_NODAD
	if err = netlink.AddrAdd(self, addr); err != nil {
		t.Fatal(err)
	}
	bits := 32
	if ipv6 {
		bits = 128
	}
	route := &netlink.Route{LinkIndex: self.Attrs().Index,
		Dst:   &net.IPNet{IP: net.IP(destination.Addr().AsSlice()), Mask: net.CIDRMask(bits, bits)},
		Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST}
	if err = netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	if err = netlink.NeighSet(&netlink.Neigh{LinkIndex: self.Attrs().Index, State: unix.NUD_PERMANENT,
		IP: net.IP(source.Addr().AsSlice()), HardwareAddr: peer.Attrs().HardwareAddr}); err != nil {
		t.Fatal(err)
	}
	listener, port := backportTCListener(t, ipv6, tcp)
	b, err := prepareTC(TCConfig{ListenerPort: port, AssignmentCapacity: 64,
		EnableLocal: true, EnableShared: true, EnableIPv4: true,
		EnableLocalIPv6: true, EnableSharedIPv6: true, EnableTCP: tcp, EnableUDP: !tcp}, true)
	if err != nil {
		backportTCFatal(t, err)
	}
	defer b.Close()
	program := b.runtime.programs[tcProgramSharedIngressEthernet]
	path := uint8(TCPathShared)
	if delivery {
		program, path = b.runtime.programs[tcProgramDeliveryIngress], TCPathDelivery
	}
	for _, p := range b.runtime.programs {
		if p == nil {
			continue
		}
		info, err := p.Info()
		if err != nil {
			t.Fatal(err)
		}
		size, _ := info.JitedSize()
		if (strings.TrimSpace(string(mode)) == "0") != (size == 0) {
			t.Fatalf("unexpected JIT size %d", size)
		}
	}
	if err = netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: self.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT}, QdiscType: "clsact"}); err != nil {
		t.Fatal(err)
	}
	if err = netlink.FilterAdd(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{
		LinkIndex: self.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Priority: 1, Protocol: unix.ETH_P_ALL},
		Fd: program.FD(), Name: "bptc_assign", DirectAction: true}); err != nil {
		t.Fatal(err)
	}
	if err = b.Enable(); err != nil {
		t.Fatal(err)
	}
	protocol := int(binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL}))
	sender, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sender)
	if err = unix.Bind(sender, &unix.SockaddrLinklayer{Ifindex: peer.Attrs().Index, Protocol: uint16(protocol)}); err != nil {
		t.Fatal(err)
	}
	transport := uint8(unix.IPPROTO_UDP)
	if tcp {
		transport = unix.IPPROTO_TCP
	}
	send := func(flags byte, seq, ack uint32, payload []byte) {
		t.Helper()
		packet := backportTCPacket(source, destination, transport, flags, seq, ack, payload,
			peer.Attrs().HardwareAddr, self.Attrs().HardwareAddr)
		if n, err := unix.Write(sender, packet); err != nil || n != len(packet) {
			t.Fatalf("send: n=%d err=%v", n, err)
		}
	}
	request := []byte("mihomo-socket-assign-request")
	if tcp {
		send(2, 1000, 0, nil)
		synack := backportTCReadTCP(t, sender, destination, source, false)
		serverSeq := binary.BigEndian.Uint32(synack[4:8]) + 1
		if binary.BigEndian.Uint32(synack[8:12]) != 1001 {
			t.Fatal("SYNACK acknowledged the wrong sequence")
		}
		send(0x10, 1001, serverSeq, nil)
		accepted, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
		if err != nil {
			t.Fatalf("accept assigned TCP: %v", err)
		}
		defer unix.Close(accepted)
		// The synthetic peer does not run a TCP close state machine. Avoid
		// leaving an orphan in LAST_ACK when the test's namespace is removed.
		if err = unix.SetsockoptLinger(accepted, unix.SOL_SOCKET, unix.SO_LINGER,
			&unix.Linger{Onoff: 1}); err != nil {
			t.Fatal(err)
		}
		timeout := unix.NsecToTimeval((4 * time.Second).Nanoseconds())
		if err = unix.SetsockoptTimeval(accepted, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			t.Fatal(err)
		}
		local, err := unix.Getsockname(accepted)
		if err != nil {
			t.Fatal(err)
		}
		if ipv6 {
			got := local.(*unix.SockaddrInet6)
			if got.Port != int(destination.Port()) || netip.AddrFrom16(got.Addr) != destination.Addr() {
				t.Fatalf("rewritten TCP destination: %+v", got)
			}
		} else {
			got := local.(*unix.SockaddrInet4)
			if got.Port != int(destination.Port()) || netip.AddrFrom4(got.Addr) != destination.Addr() {
				t.Fatalf("rewritten TCP destination: %+v", got)
			}
		}
		send(0x18, 1001, serverSeq, request)
		buffer := make([]byte, 512)
		n, err := unix.Read(accepted, buffer)
		if err != nil || !bytes.Equal(buffer[:n], request) {
			t.Fatalf("TCP receive: %q %v", buffer[:n], err)
		}
		reply := []byte("mihomo-socket-assign-reply")
		if _, err = unix.Write(accepted, reply); err != nil {
			t.Fatal(err)
		}
		segment := backportTCReadTCP(t, sender, destination, source, true)
		if !bytes.Equal(segment[int(segment[12]>>4)*4:], reply) {
			t.Fatalf("TCP reply: %x", segment)
		}
		send(0x11, 1001+uint32(len(request)), serverSeq+uint32(len(reply)), nil)
		if n, err = unix.Read(accepted, buffer); err != nil || n != 0 {
			t.Fatalf("TCP FIN: n=%d err=%v", n, err)
		}
	} else {
		send(0, 0, 0, request)
		buffer, control := make([]byte, 512), make([]byte, 256)
		n, controlSize, _, _, err := unix.Recvmsg(listener, buffer, control, 0)
		if err != nil || !bytes.Equal(buffer[:n], request) {
			t.Fatalf("UDP receive: %q %v", buffer[:n], err)
		}
		messages, err := unix.ParseSocketControlMessage(control[:controlSize])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, message := range messages {
			if (message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR) ||
				(message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR) {
				start := 4
				if ipv6 {
					start = 8
				}
				if len(message.Data) < start+len(destination.Addr().AsSlice()) {
					t.Fatal("short original destination control")
				}
				found = binary.BigEndian.Uint16(message.Data[2:4]) == destination.Port() &&
					bytes.Equal(message.Data[start:start+len(destination.Addr().AsSlice())], destination.Addr().AsSlice())
			}
		}
		if !found {
			t.Fatalf("original UDP destination lost: %x", control[:controlSize])
		}
	}
	index := uint32(0)
	if !tcp && !delivery {
		index = uint32(self.Attrs().Index)
	}
	assignment, err := b.LookupAssignment(transport, source, destination, index, false)
	if err != nil || assignment.Path != path || assignment.InterfaceIndex != uint32(self.Attrs().Index) || assignment.Generation == 0 {
		t.Fatalf("missing assignment: %+v err=%v", assignment, err)
	}
	stats, err := b.TCStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.SKAssignFailed != 0 || stats.ListenerSocketMissing != 0 || stats.AssignmentUpdateFailed != 0 {
		t.Fatalf("socket assignment errors: %+v", stats)
	}
}

func TestBackportTCLegacyLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load Mihomo's original legacy socket lookup objects")
	b, err := prepareTC(TCConfig{ListenerPort: 48500, AssignmentCapacity: 64,
		EnableLocal: true, EnableShared: true, EnableIPv4: true,
		EnableLocalIPv6: true, EnableSharedIPv6: true, EnableTCP: true, EnableUDP: true}, true)
	if err != nil {
		backportTCFatal(t, err)
	}
	defer b.Close()
	if b.TCPListenerLookupMode() != "direct" {
		t.Fatalf("unexpected lookup mode: %s", b.TCPListenerLookupMode())
	}
}

// The kernel deliberately has no batch-map ABI. Its first bounded scan detects
// that and requests another pass; honor that contract while testing live-route
// retention, grace after release, cleanup and capacity pressure.
func TestBackportTCReturnLifetimeIntegration(t *testing.T) {
	requireEBPFIntegration(t, "retain and retire TC return routes through the key-iterator fallback")
	b := newTestAssignmentBackend(t)
	m, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.Hash, KeySize: 44,
		ValueSize: uint32(unsafe.Sizeof(tcReturnValue{})), MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	b.runtime.maps["tc_return"] = m
	b.assignmentCapacity = 2
	source, destination := netip.MustParseAddrPort("192.0.2.2:41000"), netip.MustParseAddrPort("203.0.113.10:9681")
	key, _ := makeTCAssignKey(ProtocolUDP, destination, source, 0)
	value := tcReturnValue{LastSeenNS: 1, Generation: 42, InterfaceIndex: 7, Flags: 1}
	if err = m.Put(key, value); err != nil {
		t.Fatal(err)
	}
	first, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.AcquireReturnRoute(ProtocolUDP, source, destination)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := b.AcquireReplyRoute(first, netip.MustParseAddrPort("203.0.113.20:8567"))
	if err != nil {
		t.Fatal(err)
	}
	first.Release()
	if b.returnReferences[second.reference] != 1 {
		t.Fatal("wrong reference ownership/count")
	}
	third := key
	third.SourcePort++
	if err = m.Put(third, value); err == nil {
		t.Fatal("full return map admitted another flow")
	}
	sweep := func() TCAssignmentSweepResult {
		t.Helper()
		for i := 0; i < 8; i++ {
			result := TCAssignmentSweepResult{Complete: true, UsageKnown: true}
			if err := b.sweepReturnRoutesLocked(time.Nanosecond, 16, &result); err != nil {
				t.Fatal(err)
			}
			if result.ReturnUsageKnown {
				return result
			}
		}
		t.Fatal("bounded fallback scan did not finish")
		return TCAssignmentSweepResult{}
	}
	result := sweep()
	if result.ReturnRemoved != 0 || result.ReturnUsage.Entries != 2 || !result.Pressure {
		t.Fatalf("pinned sweep: %+v", result)
	}
	second.Release()
	alias.Release()
	if result = sweep(); result.ReturnRemoved != 0 {
		t.Fatalf("release skipped reply/FIN grace: %+v", result)
	}
	for ref := range b.returnReleased {
		b.returnReleased[ref] = 1
	}
	if result = sweep(); result.ReturnRemoved != 2 {
		t.Fatalf("released sweep: %+v", result)
	}
	if err = m.Lookup(key, &value); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("released route retained: %v", err)
	}
}
