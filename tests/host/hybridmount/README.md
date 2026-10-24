# Hybrid Mount regression fixtures

Imported from [Hybrid-Mount/meta-hybrid_mount](https://github.com/Hybrid-Mount/meta-hybrid_mount/tree/e5120adea50d917aa21fd5ab11a7823e48c937f0/tests/kernel)
at `e5120adea50d917aa21fd5ab11a7823e48c937f0`. Each file retains its upstream
license. Python paths are adapted for this repository and the prepared 4.9 source;
the C fixtures are unchanged.

Run `python3 tests/host/run-hybridmount-tests.py --source kernel` from the builder.
The fixtures extract production functions, inject allocation/ownership failures,
and check UID lookup, inode retirement, export encoder handling and reader
lifetimes. They use mocked kernel primitives and do not replace a kernel build,
device filesystem testing, SELinux testing, or KASAN/lockdep.
