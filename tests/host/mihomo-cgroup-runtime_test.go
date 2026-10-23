//go:build with_ebpf && linux && ebpf_integration

// SPDX-License-Identifier: GPL-3.0-or-later
// Supplemental tests compiled with the pinned, unmodified Mihomo package using
// Go's overlay. The production objects and upstream tests are unchanged.
package ebpf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

func backportIPv6Route(t *testing.T) {
	t.Helper()
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(cmdline), "bpf_backport_qemu=1") {
		t.Fatal("this network test requires the disposable backport QEMU guest")
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	addr, err := netlink.ParseAddr("fd53:696e:672d:626f::1/128")
	if err != nil {
		t.Fatal(err)
	}
	addr.Flags = unix.IFA_F_NODAD
	if err = netlink.AddrAdd(lo, addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(lo, addr) })
	_, prefix, _ := net.ParseCIDR("fd53:696e:672d:626f::/64")
	route := &netlink.Route{LinkIndex: lo.Attrs().Index, Dst: prefix,
		Table: unix.RT_TABLE_LOCAL, Type: unix.RTN_LOCAL, Scope: netlink.SCOPE_HOST}
	if err = netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
}

// A plain pass-through owner can be restored after takeover. A blinded one
// must remain attached when Mihomo cannot verify its behavior.
func TestBackportCgroupOwnerSafetyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "preserve the cgroup owner across all JIT modes")
	setting, err := os.ReadFile("/proc/sys/net/core/bpf_jit_harden")
	if err != nil {
		t.Fatal(err)
	}
	hardened := strings.TrimSpace(string(setting)) == "2"
	path, cgroup := dedicatedHookOwnerCgroup(t, 1400)
	owner := newHookOwnerTestProgram(t, "bp_old_owner")
	t.Cleanup(func() { owner.Close() })
	ownerID := attachLikeNetd(t, cgroup, owner)
	backend, err := prepareCgroupIntegrationBackend(path, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(41400); err != nil {
		t.Fatal(err)
	}
	err = backend.Attach()
	if hardened {
		if err == nil || !strings.Contains(err.Error(), "refusing to replace existing cgroup program owner") {
			t.Fatalf("unrecognizable blinded owner was not refused safely: %v", err)
		}
	} else if err != nil {
		t.Fatalf("plain pass-through owner takeover: %v", err)
	}
	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	if ids := connect4ProgramIDs(t, cgroup); len(ids) != 1 || ids[0] != ownerID {
		t.Fatalf("owner after close/refusal = %v, want original %v", ids, ownerID)
	}
}

func TestBackportCgroupSocketRoundTripIntegration(t *testing.T) {
	requireEBPFIntegration(t, "send real TCP and UDP through the 4.9 cgroup hooks")
	backportIPv6Route(t)
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	jitSetting, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	if err != nil {
		t.Fatal(err)
	}
	wantJIT := strings.TrimSpace(string(jitSetting)) != "0"
	for index, variant := range []string{"tcp4", "tcp6", "tcp6-mapped", "udp4", "udp6", "udp6-mapped", "udp4-connected", "udp6-connected", "udp6-mapped-connected"} {
		t.Run(variant, func(t *testing.T) {
			tcp := strings.HasPrefix(variant, "tcp")
			ipv6 := strings.Contains(variant, "6") && !strings.Contains(variant, "mapped")
			path, dedicated := createIntegrationCgroup(t, root, 1200+index)
			if !dedicated {
				t.Fatal("cannot create the socket test cgroup")
			}
			backend, err := prepareCgroupIntegrationBackend(path, tcp, !tcp, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			original := "203.0.113.10:9001"
			if ipv6 {
				original = "[2001:db8::10]:9001"
			} else if strings.Contains(variant, "mapped") {
				original = "[::ffff:203.0.113.10]:9001"
			}
			wantOriginal := netip.MustParseAddrPort(original)
			wantOriginal = netip.AddrPortFrom(wantOriginal.Addr().Unmap(), wantOriginal.Port())
			payload := []byte("cgroup-4.9-" + variant)
			var listener net.Listener
			var packet *net.UDPConn
			var port uint16
			if tcp {
				network, address := "tcp4", "0.0.0.0:0"
				if ipv6 {
					network, address = "tcp6", "[::]:0"
				}
				listener, err = net.Listen(network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
				port = uint16(listener.Addr().(*net.TCPAddr).Port)
			} else {
				network, address := "udp4", "0.0.0.0:0"
				if ipv6 {
					network, address = "udp6", "[::]:0"
				}
				config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
					var socketErr error
					err := raw.Control(func(fd uintptr) {
						level, transparent, info := unix.SOL_IP, unix.IP_TRANSPARENT, unix.IP_PKTINFO
						if ipv6 {
							level, transparent, info = unix.SOL_IPV6, unix.IPV6_TRANSPARENT, unix.IPV6_RECVPKTINFO
						}
						socketErr = unix.SetsockoptInt(int(fd), level, transparent, 1)
						if socketErr == nil {
							socketErr = unix.SetsockoptInt(int(fd), level, info, 1)
						}
					})
					if err != nil {
						return err
					}
					return socketErr
				}}
				connection, err := config.ListenPacket(context.Background(), network, address)
				if err != nil {
					t.Fatal(err)
				}
				packet = connection.(*net.UDPConn)
				defer packet.Close()
				_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
				port = uint16(packet.LocalAddr().(*net.UDPAddr).Port)
			}
			if err = backend.LoadPrograms(port); err != nil {
				t.Fatalf("load actual Mihomo object: %+v", err)
			}
			for _, program := range backend.runtime.programs {
				if program == nil {
					continue
				}
				info, err := program.Info()
				if err != nil {
					t.Fatal(err)
				}
				size, _ := info.JitedSize()
				if (size > 0) != wantJIT {
					t.Fatalf("Mihomo program JIT size=%d, requested JIT=%v", size, wantJIT)
				}
			}
			if err = backend.Attach(); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			command := exec.Command(os.Args[0], "-test.run=^TestBackportCgroupSocketHelper$")
			command.Env = append(os.Environ(), "BACKPORT_SOCKET_CGROUP="+path,
				"BACKPORT_SOCKET_VARIANT="+variant, "BACKPORT_SOCKET_DEST="+original)
			command.Stdout, command.Stderr = &output, &output
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = command.Process.Kill()
					_ = command.Wait()
				}
			}()
			var token netip.AddrPort
			if tcp {
				conn, err := listener.Accept()
				if err != nil {
					t.Fatalf("accept redirected connection: %v; helper: %s", err, &output)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				token = conn.LocalAddr().(*net.TCPAddr).AddrPort()
				buffer := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, buffer); err != nil || !bytes.Equal(buffer, payload) {
					t.Fatalf("TCP payload %q: %v", buffer, err)
				}
				if _, err = conn.Write(payload); err != nil {
					t.Fatal(err)
				}
			} else {
				buffer, oob := make([]byte, 128), make([]byte, 128)
				n, oobn, flags, peer, err := packet.ReadMsgUDP(buffer, oob)
				if err != nil {
					t.Fatalf("receive UDP: %v; helper: %s", err, &output)
				}
				if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("UDP payload %q flags=%d", buffer[:n], flags)
				}
				messages, err := unix.ParseSocketControlMessage(oob[:oobn])
				if err != nil {
					t.Fatal(err)
				}
				for _, message := range messages {
					if !ipv6 && message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_PKTINFO && len(message.Data) >= 12 {
						token = netip.AddrPortFrom(netip.AddrFrom4([4]byte(message.Data[8:12])), port)
					}
					if ipv6 && message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_PKTINFO && len(message.Data) >= 20 {
						token = netip.AddrPortFrom(netip.AddrFrom16([16]byte(message.Data[:16])), port)
					}
				}
				if !token.IsValid() {
					t.Fatal("missing redirected destination in packet info")
				}
				// Reuse packet-info as the reply source so recvmsg sees the token
				// and must restore the peer's original IP and port.
				if _, _, err = packet.WriteMsgUDP(payload, oob[:oobn], peer); err != nil {
					t.Fatal(err)
				}
			}
			protocol := uint8(ProtocolUDP)
			if tcp {
				protocol = ProtocolTCP
			}
			found, err := backend.LookupOriginal(protocol, token)
			if err != nil || found.Destination != wantOriginal || found.SocketCookie == 0 {
				t.Fatalf("original destination at %s = %+v, %v; want %s and nonzero cookie", token, found, err, wantOriginal)
			}
			if found.ConnectedUDP != strings.Contains(variant, "connected") {
				t.Fatalf("connected UDP metadata = %v", found.ConnectedUDP)
			}
			err = command.Wait()
			waited = true
			if err != nil {
				t.Fatalf("socket helper: %v\n%s", err, &output)
			}
		})
	}
}

func TestBackportCgroupSocketHelper(t *testing.T) {
	path := os.Getenv("BACKPORT_SOCKET_CGROUP")
	if path == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		t.Fatal(err)
	}
	variant := os.Getenv("BACKPORT_SOCKET_VARIANT")
	destination := netip.MustParseAddrPort(os.Getenv("BACKPORT_SOCKET_DEST"))
	tcp := strings.HasPrefix(variant, "tcp")
	family, socketType := unix.AF_INET, unix.SOCK_DGRAM
	if strings.Contains(variant, "6") {
		family = unix.AF_INET6
	}
	if tcp {
		socketType = unix.SOCK_STREAM
	}
	fd, err := unix.Socket(family, socketType|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	for _, option := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
		if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, option, &unix.Timeval{Sec: 4}); err != nil {
			t.Fatal(err)
		}
	}
	var address unix.Sockaddr
	if family == unix.AF_INET6 {
		if err = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
			t.Fatal(err)
		}
		address = &unix.SockaddrInet6{Port: int(destination.Port()), Addr: destination.Addr().As16()}
	} else {
		address = &unix.SockaddrInet4{Port: int(destination.Port()), Addr: destination.Addr().As4()}
	}
	payload := []byte("cgroup-4.9-" + variant)
	if tcp || strings.Contains(variant, "connected") {
		if err = unix.Connect(fd, address); err != nil {
			t.Fatal(err)
		}
		if n, err := unix.Write(fd, payload); err != nil || n != len(payload) {
			t.Fatalf("connected send: n=%d err=%v", n, err)
		}
	} else if err = unix.Sendto(fd, payload, 0, address); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	if tcp {
		for offset := 0; offset < len(payload); {
			n, err := unix.Read(fd, buffer[offset:len(payload)])
			if err == unix.EINTR {
				continue
			}
			if err != nil || n == 0 {
				t.Fatalf("TCP reply at byte %d: %v", offset, err)
			}
			offset += n
		}
		if !bytes.Equal(buffer[:len(payload)], payload) {
			t.Fatalf("TCP reply %q", buffer[:len(payload)])
		}
		return
	}
	n, peer, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		t.Fatalf("receive UDP reply: %v", err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("UDP reply %q", buffer[:n])
	}
	var restored netip.AddrPort
	switch peer := peer.(type) {
	case *unix.SockaddrInet4:
		restored = netip.AddrPortFrom(netip.AddrFrom4(peer.Addr), uint16(peer.Port))
	case *unix.SockaddrInet6:
		restored = netip.AddrPortFrom(netip.AddrFrom16(peer.Addr).Unmap(), uint16(peer.Port))
	default:
		t.Fatal(fmt.Errorf("unexpected reply address %T", peer))
	}
	want := netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if restored != want {
		t.Fatalf("recvmsg peer %s, want original %s", restored, want)
	}
}
