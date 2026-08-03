#!/bin/bash
# Generate AFL++ seed corpus for Nilix kernel
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/fuzz/afl_seeds"

mkdir -p "$OUTPUT_DIR"

echo "Generating AFL++ seed corpus for Nilix kernel..."
echo "Output: $OUTPUT_DIR"
echo ""

# Seed format: binary syscall trace
# Each seed is a sequence of:
#   [syscall_nr: u64][arg0: u64][arg1: u64][arg2: u64][arg3: u64][arg4: u64][arg5: u64]

generate_seed() {
    local name="$1"
    local output="$OUTPUT_DIR/$name"
    shift

    echo "  Creating $name..."

    # Write syscall sequence
    for syscall_data in "$@"; do
        # syscall_data format: "NR:ARG0:ARG1:ARG2:ARG3:ARG4:ARG5"
        IFS=':' read -ra PARTS <<< "$syscall_data"

        for part in "${PARTS[@]}"; do
            # Write as little-endian u64
            printf "\\x$(printf '%016x' "$part" | sed 's/../\\x&/g' | tac -s '\\')" >> "$output"
        done
    done
}

# Seed 1: Simple read
# open("/dev/null", O_RDONLY) -> read(fd, buf, 64) -> close(fd)
generate_seed "01_simple_read" \
    "2:0:0:0:0:0:0" \
    "0:3:0:64:0:0:0" \
    "3:3:0:0:0:0:0"

# Seed 2: Fork and exec
# fork() -> execve("/bin/sh", args, env)
generate_seed "02_fork_exec" \
    "57:0:0:0:0:0:0" \
    "59:0:0:0:0:0:0"

# Seed 3: Memory mapping
# mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
# write to it, then munmap
generate_seed "03_mmap_munmap" \
    "9:0:4096:3:34:0:0" \
    "11:0:4096:0:0:0:0"

# Seed 4: Signal delivery
# getpid() -> kill(pid, SIGTERM)
generate_seed "04_signal_delivery" \
    "39:0:0:0:0:0:0" \
    "62:0:15:0:0:0:0"

# Seed 5: Multithreaded (clone + futex)
# clone(CLONE_VM|CLONE_FS|CLONE_FILES) -> futex(FUTEX_WAIT)
generate_seed "05_multithreaded" \
    "56:0x10000:0:0:0:0:0" \
    "202:0:0:0:0:0:0"

# Seed 6: Directory operations
# mkdir("/tmp/test") -> rmdir("/tmp/test")
generate_seed "06_dir_ops" \
    "83:0:0755:0:0:0:0" \
    "84:0:0:0:0:0:0"

# Seed 7: Pipe operations
# pipe() -> write(pipe[1], data) -> read(pipe[0], buf) -> close both
generate_seed "07_pipe_ops" \
    "22:0:0:0:0:0:0" \
    "1:4:0:64:0:0:0" \
    "0:3:0:64:0:0:0" \
    "3:3:0:0:0:0:0" \
    "3:4:0:0:0:0:0"

# Seed 8: Socket operations
# socket(AF_INET, SOCK_STREAM) -> connect() -> send() -> recv() -> close()
generate_seed "08_socket_ops" \
    "41:2:1:0:0:0:0" \
    "42:3:0:16:0:0:0" \
    "44:3:0:64:0:0:0" \
    "45:3:0:64:0:0:0" \
    "3:3:0:0:0:0:0"

# Seed 9: File descriptor manipulation
# dup() -> dup2() -> fcntl()
generate_seed "09_fd_ops" \
    "32:3:0:0:0:0:0" \
    "33:3:5:0:0:0:0" \
    "72:5:1:0:0:0:0"

# Seed 10: Time operations
# gettimeofday() -> nanosleep() -> clock_gettime()
generate_seed "10_time_ops" \
    "96:0:0:0:0:0:0" \
    "35:0:0:0:0:0:0" \
    "228:0:0:0:0:0:0"

echo ""
echo "Generated $(ls -1 "$OUTPUT_DIR" | wc -l) seed files"
echo "Total size: $(du -sh "$OUTPUT_DIR" | cut -f1)"
echo ""
echo "Use with:"
echo "  ./scripts/afl_fuzz.sh --kernel kernel.elf --input $OUTPUT_DIR"
