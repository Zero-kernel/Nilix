#!/usr/bin/env python3
"""Generate AFL++ seed corpus for Nilix kernel"""

import struct
from pathlib import Path

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "fuzz" / "afl_seeds"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print(f"Generating AFL++ seed corpus for Nilix kernel...")
print(f"Output: {OUTPUT_DIR}")
print()


def write_syscall(f, nr, *args):
    """Write a single syscall to binary file (little-endian u64)"""
    f.write(struct.pack("<Q", nr))
    for arg in args:
        f.write(struct.pack("<Q", arg))


def generate_seed(name, *syscalls):
    """Generate a seed file with syscall sequence"""
    output = OUTPUT_DIR / name
    print(f"  Creating {name}...")
    with open(output, "wb") as f:
        for syscall_data in syscalls:
            write_syscall(f, *syscall_data)


# Seed 1: Simple read
# open("/dev/null", O_RDONLY) -> read(fd, buf, 64) -> close(fd)
generate_seed("01_simple_read",
    (2, 0, 0, 0, 0, 0, 0),   # open
    (0, 3, 0, 64, 0, 0, 0),  # read
    (3, 3, 0, 0, 0, 0, 0))   # close

# Seed 2: Fork and exec
# fork() -> execve("/bin/sh", args, env)
generate_seed("02_fork_exec",
    (57, 0, 0, 0, 0, 0, 0),  # fork
    (59, 0, 0, 0, 0, 0, 0))  # execve

# Seed 3: Memory mapping
# mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
# munmap
generate_seed("03_mmap_munmap",
    (9, 0, 4096, 3, 34, 0, 0),   # mmap
    (11, 0, 4096, 0, 0, 0, 0))   # munmap

# Seed 4: Signal delivery
# getpid() -> kill(pid, SIGTERM)
generate_seed("04_signal_delivery",
    (39, 0, 0, 0, 0, 0, 0),  # getpid
    (62, 0, 15, 0, 0, 0, 0)) # kill

# Seed 5: Multithreaded (clone + futex)
# clone(CLONE_VM|CLONE_FS|CLONE_FILES) -> futex(FUTEX_WAIT)
generate_seed("05_multithreaded",
    (56, 0x10000, 0, 0, 0, 0, 0),  # clone
    (202, 0, 0, 0, 0, 0, 0))       # futex

# Seed 6: Directory operations
# mkdir("/tmp/test") -> rmdir("/tmp/test")
generate_seed("06_dir_ops",
    (83, 0, 0o755, 0, 0, 0, 0),  # mkdir
    (84, 0, 0, 0, 0, 0, 0))      # rmdir

# Seed 7: Pipe operations
# pipe() -> write(pipe[1], data) -> read(pipe[0], buf) -> close both
generate_seed("07_pipe_ops",
    (22, 0, 0, 0, 0, 0, 0),      # pipe
    (1, 4, 0, 64, 0, 0, 0),      # write
    (0, 3, 0, 64, 0, 0, 0),      # read
    (3, 3, 0, 0, 0, 0, 0),       # close
    (3, 4, 0, 0, 0, 0, 0))       # close

# Seed 8: Socket operations
# socket(AF_INET, SOCK_STREAM) -> connect() -> send() -> recv() -> close()
generate_seed("08_socket_ops",
    (41, 2, 1, 0, 0, 0, 0),      # socket
    (42, 3, 0, 16, 0, 0, 0),     # connect
    (44, 3, 0, 64, 0, 0, 0),     # send
    (45, 3, 0, 64, 0, 0, 0),     # recv
    (3, 3, 0, 0, 0, 0, 0))       # close

# Seed 9: File descriptor manipulation
# dup() -> dup2() -> fcntl()
generate_seed("09_fd_ops",
    (32, 3, 0, 0, 0, 0, 0),      # dup
    (33, 3, 5, 0, 0, 0, 0),      # dup2
    (72, 5, 1, 0, 0, 0, 0))      # fcntl

# Seed 10: Time operations
# gettimeofday() -> nanosleep() -> clock_gettime()
generate_seed("10_time_ops",
    (96, 0, 0, 0, 0, 0, 0),      # gettimeofday
    (35, 0, 0, 0, 0, 0, 0),      # nanosleep
    (228, 0, 0, 0, 0, 0, 0))     # clock_gettime

print()
print(f"Generated {len(list(OUTPUT_DIR.glob('*')))} seed files")
print(f"Total size: {sum(f.stat().st_size for f in OUTPUT_DIR.glob('*'))} bytes")
print()
print("Use with:")
print(f"  ./scripts/afl_fuzz.sh --kernel kernel.elf --input {OUTPUT_DIR}")
