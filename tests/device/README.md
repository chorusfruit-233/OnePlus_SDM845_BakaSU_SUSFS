# Device syscall regression test

Build the test as a static AArch64 binary and push it to a rooted device:

```sh
aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra \
  -o susfs_syscall_test susfs_syscall_test.c
adb push susfs_syscall_test /data/local/tmp/
adb push run-susfs-regression.sh /data/local/tmp/
adb shell su -c '/data/local/tmp/run-susfs-regression.sh'
```

The default fixture covers `stat`, `open/read`, `access`, `readlink`,
`getdents64`, `rename`, `unlink`, `O_PATH`, `O_TRUNC`, and readable
`/proc/self/mountinfo` and fdinfo fields. Run the same binary from a SUSFS
unmounted app/namespace with `--hidden /path/to/marked-entry` to assert
`ENOENT` for all of those path operations. `--mount-token` and
`--fdinfo-token` optionally assert that the supplied SUS_MOUNT-specific strings
are hidden.

The fixture also checks `statx` inode consistency and rejects the internal
SUSFS KSTAT discriminator bits in the exported `stx_mask`, and checks the
inode reported by inotify fdinfo. Hidden-path mode checks `statx` as well.

For a path already marked with a SUS_KSTAT rule, run this from the app UID
and namespace where spoofing should apply (a root shell may bypass spoofing):

```sh
susfs_syscall_test --kstat /path/to/marked-file 123456
```

Replace `123456` with the rule's spoofed inode (decimal or `0x` hexadecimal).
This mode checks `stat`, `fstat`, `statx`, ordinary fdinfo and inotify fdinfo
without creating the default fixture. The file must be readable and watchable
by that process. Use an ordinary marked file, without an OPEN_REDIRECT rule,
so this test measures KSTAT directly. Use `--root` to also run the fixture in
a directory writable by the test identity. These checks require a device
running the updated kernel; a host run tests the fixture plumbing only.

## SELinux hide regression probes

`selinux_hide_test.c` supplements the filesystem tests with fixed SELinux
probes. Compile the identical binary for baseline and candidate kernels:

```sh
source /workspace/build-env/activate.sh
aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror \
  -o /workspace/scratch/selinux_hide_test tests/device/selinux_hide_test.c
```

Run it from an ordinary application's own terminal/native process, such as
Termux. The UID and `u:r:untrusted_app...` domain must both be genuine. A root
shell with `setuid`, `adb shell`, and `run-as` are not substitutes. Copy the
binary into a location that the application is already allowed to execute;
Android execution restrictions may prevent running it from writable app data.
Use an application-owned executable location or a native test APK on such
systems. Do not add SELinux allow rules, relabel files, disable Enforcing, or
enable root access just to make these probes run.

```sh
# In the application's terminal, without su:
./selinux_hide_test --device --samples 256 --label baseline > baseline.jsonl
# Repeat with the candidate kernel, same app and test binary:
./selinux_hide_test --device --samples 256 --label candidate > candidate.jsonl
```

The program refuses root/shell UIDs, non-application SELinux domains, and
devices where it cannot confirm Enforcing. No arguments and `--help` only
print usage and are safe host checks. It never loads policies or writes
`enforce`, `load`, `checkreqprot`, or KernelSU feature settings.

The probes cover:

- `setprocattr/current` for the current context, a nonexistent context, and
  the fixed `u:r:ksu:s0` rejection probe. Each runs in a new child that exits
  immediately after reading its own context and returning the result. The
  parent never changes domain; unexpected success or a changed child domain
  is an invariant failure. There is no arbitrary target-context option.
- A child writing its original context to its parent's `attr/current`, which
  must fail even though the UID matches. On this 4.9 tree, the child and parent
  have different memory descriptors and the proc opener/mm check rejects the
  write with `EPERM` before SELinux runs. This verifies the VFS rejection only;
  it does not cover the four-argument SELinux hook's `current != p` check.
  Direct coverage of that hook requires a separate controlled same-mm fixture.
- SELinuxfs `context` and `access` query transactions with those same fixed
  contexts, using the device's actual `process` class index. These are queries,
  not permission grants. Canonical self-context, malformed output, and
  accepted nonexistent contexts are checked. A successful KSU query is
  reported; its meaning depends on whether hide is enabled for that run.
- SELinux status through read and a read-only mmap. The snapshots must report
  Enforcing and agree when their generation is stable; the test does not
  compare changing sequence or policy-load counters as semantic differences.
  Those counters are retained as diagnostics in the captures.

Ordinary app policies often deny context/access queries before the policy
parser runs. `stage=open`, `stage=prerequisite`, or a permission denial must
not be reported as evidence that backup policy/SID parsing works. If the
`process` class index is unreadable, access probes are skipped explicitly and
the other probes still run. This test does not manufacture coverage by
changing policy. Exercising bounded types and differing live/backup AV rules
requires separate controlled device fixtures and policy review.

Each probe performs eight warmup operations, then records repeated outcomes
and per-outcome min/median/p95/max monotonic-clock timings. For proc/context/
access, timings measure the write; if open fails, they measure the failed
open instead. The status timing measures its initial read, with mmap checked
separately. Forking, result transport, and opening successful query files are
outside write timings. Outcome groups are kept separate so a faster denied
open is not mistaken for a faster policy lookup.
Warmup invariant failures are retained even though their timings are discarded.

After copying both JSONL files to a workstation, compare them with:

```sh
python3 tests/device/compare-selinux-results.py baseline.jsonl candidate.jsonl
```

Keep device, app UID/domain, binary, ROM, modules, root grants, SUSFS rules,
feature state, thermal/load conditions, and sample count constant. Record
KernelSU's SELinux hide state separately; the test deliberately cannot toggle
it. Compare several runs and reboot cycles, and retain kernel init/hook error
logs. Compare hide off/on only as a separate, clearly labelled experiment.
Different contexts, status generations, and permission-denied paths need
separate interpretation. A distribution difference suggests further work;
equal coarse timings do not prove the absence of a timing side channel.

Exit `0` means the available invariant checks found no contradiction; it does
not certify hide effectiveness or complete hook coverage. Exit `1` means an
invariant failed or outcomes overflowed; exit `2` means invalid arguments or
missing prerequisites. The comparison script has the same distinction for
captured invariant failures and malformed/incomplete captures, and sets no
invented timing pass threshold. These checks require a device booted with the
candidate kernel; compilation and host help checks do not validate SELinux.
