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
