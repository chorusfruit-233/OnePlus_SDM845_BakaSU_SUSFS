# Hybrid Mount regression fixtures

Imported from [Hybrid-Mount/meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount/tree/b0fa65581aff1d4a49a11d0f0e66c69ade7e6fca/tests/kernel)
at `b0fa65581aff1d4a49a11d0f0e66c69ade7e6fca`. Each file retains its upstream
license. Python paths are adapted for this repository and the prepared 4.9 source;
the xattr fixture also models the equivalent 4.9 `IS_RDONLY(inode)` API.

Run `python3 tests/host/run-hybridmount-tests.py --source kernel` from the builder.
The fixtures extract production functions, inject allocation/ownership failures,
and check UID lookup, inode retirement, export encoder handling and reader
lifetimes. They use mocked kernel primitives and do not replace a kernel build,
device filesystem testing, SELinux testing, or KASAN/lockdep.
