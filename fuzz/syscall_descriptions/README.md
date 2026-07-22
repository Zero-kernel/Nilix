# Syscall Descriptions for Fuzzing

This directory contains TOML-based descriptions of Nilix syscalls for coverage-guided fuzzing.

## Purpose

Syscall descriptions define:
- Argument types and constraints
- Valid value ranges
- Flag bitmasks
- Resource dependencies (e.g., file descriptors)
- Return value patterns

These descriptions enable the fuzzer to generate valid syscall sequences that exercise kernel code paths effectively.

## Format

Each syscall is described in a TOML file with the following structure:

```toml
[syscall]
name = "open"
number = 2
description = "Open a file and return a file descriptor"

[[syscall.args]]
name = "pathname"
type = "const_ptr_u8"
constraints = [
    { type = "string", max_len = 256, charset = "printable" },
]

[[syscall.args]]
name = "flags"
type = "i32"
constraints = [
    { type = "bitmask", values = ["O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT"] },
]

[[syscall.args]]
name = "mode"
type = "u32"
constraints = [
    { type = "range", min = 0, max = 511 },  # 0o777
]
conditional = { depends_on = "flags", has_flag = "O_CREAT" }

[syscall.returns]
success = { type = "fd", range = [0, 65535] }
error = { type = "errno", values = ["ENOENT", "EACCES", "ENOMEM"] }
```

## Phase 3 Target Syscalls

The following 10 core syscalls are being described in Phase 3:

### File I/O (4 syscalls)
- `read` (0) - Read from file descriptor
- `write` (1) - Write to file descriptor
- `open` (2) - Open file and return fd
- `close` (3) - Close file descriptor

### Memory Management (3 syscalls)
- `brk` (12) - Change data segment size
- `mmap` (9) - Map memory region
- `munmap` (11) - Unmap memory region

### Process Management (3 syscalls)
- `fork` (57) - Create child process
- `execve` (59) - Execute program
- `exit` (60) - Terminate process

## Usage

The fuzzer will:
1. Parse TOML files to build syscall descriptors
2. Generate random but valid argument values
3. Execute syscall sequences while collecting coverage
4. Mutate successful sequences based on coverage feedback

## Next Steps

After Phase 3:
- Phase 4: Coverage-guided mutation
- Phase 5: Resource tracking (fd lifecycle)
- Phase 6: Stateful fuzzing with dependencies
