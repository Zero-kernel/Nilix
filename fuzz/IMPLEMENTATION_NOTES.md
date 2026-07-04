# Kernel Fuzz Testing - Implementation Notes

## Issue: no_std Kernel + cargo-fuzz Incompatibility

The fuzz targets as written cannot compile because:
1. The kernel is `no_std` bare-metal code
2. cargo-fuzz/libFuzzer requires a hosted environment (std)
3. Cannot directly link kernel modules into userspace fuzz harness

## Recommended Approaches

### Approach 1: Unit-Level Fuzzing (Immediate)
Extract pure algorithms into separate crates that can be tested in `std` environment:
- Path parsing logic
- ELF header validation
- Signal frame construction
- VFS operations (in-memory only)

### Approach 2: QEMU-based Fuzzing (Medium-term)
Use a kernel fuzzing framework like:
- **syzkaller** - Google's kernel fuzzer (most mature)
- **kAFL** - Hardware-assisted kernel fuzzing
- **TriforceAFL** - QEMU + AFL integration

### Approach 3: Syscall Fuzzing via Syscall Stub (Long-term)
Create a minimal userspace harness that:
1. Boots the kernel in QEMU
2. Makes syscalls with fuzzed inputs
3. Monitors for crashes/hangs
4. Uses AFL++ or libFuzzer as the fuzzing engine

## Immediate Action: syzkaller Integration

syzkaller is the industry-standard kernel fuzzer used by Linux, FreeBSD, and others.

### Setup Steps

1. **Install syzkaller**
   ```bash
   git clone https://github.com/google/syzkaller
   cd syzkaller
   make
   ```

2. **Create syscall descriptions** (`sys/nilix/nilix.txt`)
   ```
   # Nilix syscall descriptions for syzkaller
   read(fd fd, buf buffer[out], count len[buf])
   write(fd fd, buf buffer[in], count len[buf])
   open(path ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd
   close(fd fd)
   # ... add all syscalls
   ```

3. **Create kernel config** (`nilix.cfg`)
   ```json
   {
     "target": "linux/amd64",
     "http": "0.0.0.0:56741",
     "workdir": "./workdir",
     "kernel_obj": "./path/to/kernel.elf",
     "image": "./path/to/disk.img",
     "sshkey": "./ssh-key",
     "syzkaller": "./syzkaller",
     "procs": 8,
     "type": "qemu",
     "vm": {
       "count": 4,
       "cpu": 2,
       "mem": 2048,
       "kernel": "./kernel.elf",
       "cmdline": "console=ttyS0"
     }
   }
   ```

4. **Run syzkaller**
   ```bash
   ./bin/syz-manager -config=nilix.cfg
   ```

## Alternative: Targeted Unit Testing

Since full kernel fuzzing requires significant setup, the **best immediate approach** is:

### Create Fuzzable Unit Tests

Move complex parsing/validation logic into testable functions:

**Example: kernel/kernel_core/syscall_validation.rs**
```rust
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    
    // Can be fuzzed with cargo-fuzz in std environment
    pub fn validate_fcntl_args(fd: i32, cmd: i32, arg: u64) -> Result<(), SyscallError> {
        // Pure validation logic extracted from sys_fcntl
    }
    
    pub fn validate_mmap_args(addr: u64, len: u64, prot: i32, flags: i32) -> Result<(), SyscallError> {
        // Pure validation logic extracted from sys_mmap
    }
}
```

Then create std-compatible fuzz harness in `fuzz/`:
```rust
use kernel_validation::*; // Separate validation crate

fuzz_target!(|input: (i32, i32, u64)| {
    let _ = validate_fcntl_args(input.0, input.1, input.2);
});
```

## Status (updated)

The "cannot compile" premise above held only for the whole kernel. It turns out
the kernel's **pure validation/parsing layers do compile and link into a hosted
`std` cargo-fuzz harness** — the one true blocker was `mm`'s `#[global_allocator]`,
now compiled out under an `mm/host_harness` cargo feature (see
`kernel/mm/memory.rs`). With that gate, three targets drive real kernel code:

- ✅ `fuzz_elf_loader` → `kernel_core::validate_elf_image` (the execve/spawn_image
  ELF header + program-header-table pre-flight parse; guards the R172-02
  crafted-ELF `panic=abort` DoS fix).
- ✅ `fuzz_network_packet` → `net::parse_ethernet/ipv4/tcp/udp/icmp/arp` (the pure
  received-frame header decoders).
- ✅ `fuzz_vfs_path` → `vfs::normalize_path` / `split_path` (the R32-VFS-1
  `..`-escape guard + parent/basename split run before any mount/inode state).

- ⚠️ The other seven targets still exercise self-contained input-validation logic:
  the subsystems they model (syscall dispatch, signals, mm, ipc, scheduler,
  cgroup, futex) are hardware- and global-state-coupled and are not host-callable
  without a mock harness.
- ⏸️ syzkaller integration (whole-kernel syscall fuzzing) remains future work.

## Decision

Wire every kernel subsystem that exposes a **pure, host-safe** entry point to its
real code (done for ELF/net/path). For the stateful subsystems, either build a
host mock/shim or pursue syzkaller (QEMU-based) after 1.0-Preview; until then keep
their targets as input-validation guards so the CI job stays meaningful and green.

## References

- [syzkaller docs](https://github.com/google/syzkaller/tree/master/docs)
- [Linux kernel fuzzing](https://www.kernel.org/doc/html/latest/dev-tools/kunit/running_tips.html#fuzzing)
- [kAFL paper](https://github.com/IntelLabs/kAFL)
