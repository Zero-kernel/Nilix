# Nilix Fuzzing Executor

Phase 2 implementation: Multi-syscall executor with KCOV integration.

## Quick Start

### Build
```bash
cd tools/fuzz_executor
cargo build --release
```

### Run a Test Sequence
```bash
./target/release/fuzz_executor sequences/test1_simple.txt
```

### With Custom Timeout
```bash
./target/release/fuzz_executor sequences/test2_files.txt 10000
```

## Sequence Format

Sequences are text files with one syscall per line:

```
# Comments start with #
# Format: syscall_num arg0 arg1 arg2 arg3 arg4 arg5

# Example: getpid() - syscall 39
39 0 0 0 0 0 0

# Example: open("/foo", O_RDWR, 0644)
# syscall 2, path_ptr, flags, mode
2 0x10000000 2 420 0 0 0
```

**Arguments:**
- Decimal: `123`
- Hex: `0x1234`
- Negative: `-1`

## Execution Model

1. **Parent** loads sequence from file
2. **Forks** child process for isolation
3. **Child** initializes KCOV
4. **Child** enables coverage collection
5. **Child** executes all syscalls in sequence
6. **Child** dumps coverage and exits with edge count
7. **Parent** collects results and reports

## Results

Each execution produces one of four outcomes:

- **OK**: Completed successfully, reports edge count
- **CRASH**: Process died from signal (SIGSEGV, SIGILL, etc.)
- **TIMEOUT**: Exceeded time limit
- **KCOV_FAIL**: KCOV syscalls failed (kernel not built with `--features kcov`)

## Example Sequences

### test1_simple.txt
Basic syscalls to verify KCOV works: getpid, getppid, getuid, geteuid

### test2_files.txt
File operations: open, write, lseek, read, close, unlink

### test3_process.txt
Process operations: fork, getpid, wait4

### test4_memory.txt
Memory management: brk, mmap, munmap

### test5_stress.txt
Stress test with many syscalls to maximize coverage

## Limitations (Phase 2)

- **No smart argument generation**: Arguments are hardcoded in sequences
- **No return value tracking**: Can't use result of one syscall in the next
- **No memory allocation**: Pointer arguments use placeholder addresses
- **No resource cleanup**: Resources may leak between runs

These limitations will be addressed in Phase 3 (syscall descriptions) and Phase 5 (resource tracking).

## Architecture

```
┌────────────────────────────────┐
│    fuzz_executor (parent)      │
│  • Load sequence from file     │
│  • Fork child process          │
│  • Wait for child with timeout │
│  • Collect coverage data       │
│  • Report result               │
└────────────────────────────────┘
              │
              ▼ fork()
┌────────────────────────────────┐
│    Child Process               │
│  1. syscall(520, 4096)  [init] │
│  2. syscall(521)       [enable]│
│  3. Execute sequence           │
│  4. syscall(522)      [disable]│
│  5. syscall(523, buf) [dump]   │
│  6. exit(edge_count)           │
└────────────────────────────────┘
```

## Next Steps (Phase 3)

- Syscall description language (TOML)
- Smart argument generation
- Resource tracking (fd dependencies)
- Return value capture
- Corpus management
