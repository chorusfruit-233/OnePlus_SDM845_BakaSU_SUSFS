// SPDX-License-Identifier: GPL-3.0-or-later
package backport

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestLRUSmallMapCPUHandoff(t *testing.T) {
	requireRoot(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var previous unix.CPUSet
	if err := unix.SchedGetaffinity(0, &previous); err != nil {
		t.Fatal(err)
	}
	defer unix.SchedSetaffinity(0, &previous)
	var cpus []int
	for cpu := range 1024 {
		if previous.IsSet(cpu) {
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) < 2 {
		t.Log("CPU handoff requires two online CPUs")
		return
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 4, ValueSize: 8, MaxEntries: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for index, cpu := range cpus[:2] {
		var affinity unix.CPUSet
		affinity.Set(cpu)
		if err = unix.SchedSetaffinity(0, &affinity); err != nil {
			t.Fatal(err)
		}
		if err = m.Update(uint32(index), uint64(index+10), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for key := range uint32(2) {
		var value uint64
		if err = m.Lookup(key, &value); err != nil || value != uint64(key+10) {
			t.Fatalf("CPU handoff evicted a key from a 2/64-full map: key=%d value=%d err=%v", key, value, err)
		}
		if err = m.Update(key, uint64(key+20), ebpf.UpdateExist); err != nil {
			t.Fatalf("updating an existing key caused premature eviction: %v", err)
		}
	}
}

func TestMapLookupAndDelete(t *testing.T) {
	requireRoot(t)
	for _, spec := range []ebpf.MapSpec{
		{Type: ebpf.Hash}, {Type: ebpf.Hash, Flags: unix.BPF_F_NO_PREALLOC}, {Type: ebpf.LRUHash},
	} {
		t.Run(fmt.Sprintf("%s-%d", spec.Type, spec.Flags), func(t *testing.T) {
			spec.KeySize, spec.ValueSize, spec.MaxEntries = 4, 8, 8
			m, err := ebpf.NewMap(&spec)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			key := uint32(1)
			for iteration := range 32 {
				want := uint64(0x100000001 + iteration)
				if err = m.Update(key, want, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				type result struct {
					value uint64
					err   error
				}
				start, done := make(chan struct{}), make(chan result, 2)
				for range 2 {
					go func() {
						<-start
						var value uint64
						err := m.LookupAndDelete(key, &value)
						done <- result{value, err}
					}()
				}
				close(start)
				a, b := <-done, <-done
				if a.err != nil {
					a, b = b, a
				}
				if a.err != nil || a.value != want || !errors.Is(b.err, unix.ENOENT) {
					t.Fatalf("atomic pop: got %+v and %+v, want one value %#x and one ENOENT", a, b, want)
				}
			}
			if err = m.Update(key, uint64(99), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			var value uint64
			if err = m.LookupAndDeleteWithFlags(key, &value, ebpf.LookupLock); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("unsupported flags: %v", err)
			}
			if err = m.Lookup(key, &value); err != nil || value != 99 {
				t.Fatalf("invalid flags consumed the entry: value=%d err=%v", value, err)
			}
			directory, err := os.MkdirTemp("/sys/fs/bpf", "bpf-pop-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(directory)
			pin := filepath.Join(directory, "map")
			if err = m.Pin(pin); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(pin)
			for _, flags := range []uint32{unix.BPF_F_RDONLY, unix.BPF_F_WRONLY} {
				restricted, err := ebpf.LoadPinnedMap(pin, &ebpf.LoadPinOptions{Flags: flags})
				if err != nil {
					t.Fatal(err)
				}
				err = restricted.LookupAndDelete(key, &value)
				restricted.Close()
				if !errors.Is(err, unix.EPERM) {
					t.Fatalf("read-only or write-only descriptor accepted pop: %v", err)
				}
			}
			if err = m.LookupAndDelete(key, &value); err != nil || value != 99 {
				t.Fatalf("permission failure consumed entry: value=%d err=%v", value, err)
			}
		})
	}
}
