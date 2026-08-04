#define _GNU_SOURCE

/*
 * Bounded Ring-3 workload used by the monthly QEMU stress gate.
 *
 * Nilix syscall 61 is wait(status), not Linux wait4(pid, status, ...), so the
 * parent deliberately invokes SYS_wait4 with only the status pointer. The
 * kernel writes the direct child exit code rather than an encoded wait status.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE_BYTES ((size_t)4096)
#define MEMORY_PAGES ((size_t)4)
#define COMBINED_MEMORY_PAGES ((size_t)2)
#define CPU_ITERATIONS ((uint64_t)500000)
#define CHILD_CPU_ITERATIONS ((uint64_t)150000)
#define COMBINED_CPU_ITERATIONS ((uint64_t)100000)
#define PROCESS_CHILDREN ((size_t)4)
#define COMBINED_CHILDREN ((size_t)4)
#define COMBINED_ROUNDS ((size_t)3)
#define FILE_BYTES ((size_t)8192)
#define FILE_ROUNDS ((size_t)3)

#define RAMFS_PATH "/nilix-stress-a.tmp"
#define RAMFS_RENAMED_PATH "/nilix-stress-b.tmp"
#define EXT3_PATH "/mnt/test/alloc.bin"

typedef struct {
    uint64_t operations;
    uint64_t checksum;
} PhaseResult;

static unsigned char file_write_buffer[FILE_BYTES];
static unsigned char file_read_buffer[FILE_BYTES];
static const char *failure_stage;
static long failure_code;
static int failure_emitted;

_Static_assert(MEMORY_PAGES <= SIZE_MAX / PAGE_BYTES, "memory phase size overflow");
_Static_assert(COMBINED_MEMORY_PAGES <= SIZE_MAX / PAGE_BYTES,
               "combined memory phase size overflow");
_Static_assert(PROCESS_CHILDREN <= 16, "process fanout must stay bounded");
_Static_assert(COMBINED_CHILDREN <= 16, "combined fanout must stay bounded");
_Static_assert(FILE_BYTES <= 64 * 1024, "file workload must stay bounded");

static void flush_output(void) {
    (void)fflush(stdout);
}

static long syscall_error(long result) {
    if (result == -1 && errno != 0) {
        return -errno;
    }
    return result;
}

static int record_failure(const char *stage, long code) {
    if (failure_stage == NULL) {
        failure_stage = stage;
        failure_code = code;
    }
    return -1;
}

static int emit_failure(void) {
    if (!failure_emitted) {
        printf("NILIX_STRESS_FAIL stage=%s code=%ld\n",
               failure_stage != NULL ? failure_stage : "unknown",
               failure_code);
        flush_output();
        failure_emitted = 1;
    }
    return 1;
}

static int checked_add_u64(uint64_t *value, uint64_t increment) {
    if (*value > UINT64_MAX - increment) {
        return record_failure("operation_count_overflow", -EOVERFLOW);
    }
    *value += increment;
    return 0;
}

static uint64_t hash_bytes(const unsigned char *bytes, size_t length) {
    uint64_t hash = UINT64_C(14695981039346656037);

    for (size_t i = 0; i < length; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t mix_checksum(uint64_t accumulator, uint64_t value) {
    accumulator ^= value + UINT64_C(0x9e3779b97f4a7c15) +
                   (accumulator << 6) + (accumulator >> 2);
    return accumulator;
}

static unsigned char pattern_byte(uint64_t seed, size_t offset) {
    uint64_t value = seed + (uint64_t)offset * UINT64_C(0x9e3779b1);
    value ^= value >> 17;
    value *= UINT64_C(0xed5ad4bb);
    value ^= value >> 11;
    return (unsigned char)value;
}

static uint64_t cpu_kernel(uint64_t seed, uint64_t iterations) {
    uint64_t state = seed | UINT64_C(1);

    for (uint64_t i = 0; i < iterations; ++i) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state += i ^ UINT64_C(0xa0761d6478bd642f);
    }
    return state;
}

static int run_memory_workload(size_t pages, uint64_t seed, PhaseResult *result) {
    if (pages == 0 || pages > SIZE_MAX / PAGE_BYTES) {
        return record_failure("memory_size", -EOVERFLOW);
    }
    const size_t length = pages * PAGE_BYTES;

    errno = 0;
    const long mapped = syscall(SYS_mmap, NULL, length, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapped == -1) {
        return record_failure("memory_mmap", syscall_error(mapped));
    }

    unsigned char *memory = (unsigned char *)(uintptr_t)mapped;
    for (size_t i = 0; i < length; ++i) {
        memory[i] = pattern_byte(seed, i);
    }
    for (size_t i = 0; i < length; ++i) {
        if (memory[i] != pattern_byte(seed, i)) {
            (void)syscall(SYS_munmap, memory, length);
            return record_failure("memory_verify", (long)i);
        }
    }

    result->operations = 0;
    if (checked_add_u64(&result->operations, (uint64_t)length) != 0 ||
        checked_add_u64(&result->operations, (uint64_t)length) != 0) {
        (void)syscall(SYS_munmap, memory, length);
        return -1;
    }
    result->checksum = hash_bytes(memory, length);

    errno = 0;
    const long unmapped = syscall(SYS_munmap, memory, length);
    if (unmapped != 0) {
        return record_failure("memory_munmap", syscall_error(unmapped));
    }
    return 0;
}

static int run_cpu_workload(uint64_t seed, uint64_t iterations, PhaseResult *result) {
    const uint64_t first = cpu_kernel(seed, iterations);
    const uint64_t second = cpu_kernel(seed, iterations);

    if (first != second) {
        return record_failure("cpu_verify", -EIO);
    }
    if (iterations > UINT64_MAX / 2) {
        return record_failure("cpu_operation_count", -EOVERFLOW);
    }
    result->operations = iterations * 2;
    result->checksum = first;
    return 0;
}

__attribute__((noreturn)) static void child_exit(int code) {
    (void)syscall(SYS_exit, code);
    __builtin_unreachable();
}

static long wait_one_child(int *status) {
    long result;

    do {
        errno = 0;
        result = syscall(SYS_wait4, status);
    } while (result == -1 && errno == EINTR);
    return result;
}

static int spawn_cpu_children(size_t child_count, uint64_t seed_base,
                              uint64_t iterations, PhaseResult *result) {
    if (child_count == 0 || child_count > PROCESS_CHILDREN) {
        return record_failure("process_child_count", -EINVAL);
    }

    long pids[PROCESS_CHILDREN] = {0};
    int seen[PROCESS_CHILDREN] = {0};
    size_t spawned = 0;

    for (size_t i = 0; i < child_count; ++i) {
        errno = 0;
        const long pid = syscall(SYS_fork);
        if (pid == 0) {
            const uint64_t seed = seed_base + (uint64_t)i;
            const uint64_t first = cpu_kernel(seed, iterations);
            const uint64_t second = cpu_kernel(seed, iterations);
            child_exit(first == second ? 0 : 10 + (int)i);
        }
        if (pid < 0) {
            const long code = syscall_error(pid);
            while (spawned > 0) {
                int ignored_status = 0;
                if (wait_one_child(&ignored_status) < 0) {
                    break;
                }
                --spawned;
            }
            return record_failure("process_fork", code);
        }
        pids[spawned++] = pid;
    }

    result->operations = 0;
    result->checksum = UINT64_C(0x6a09e667f3bcc909);
    for (size_t reaped = 0; reaped < child_count; ++reaped) {
        int status = -1;
        errno = 0;
        const long pid = wait_one_child(&status);
        if (pid < 0) {
            return record_failure("process_wait", syscall_error(pid));
        }

        size_t index = child_count;
        for (size_t i = 0; i < child_count; ++i) {
            if (pids[i] == pid) {
                index = i;
                break;
            }
        }
        if (index == child_count || seen[index]) {
            return record_failure("process_wait_pid", pid);
        }
        seen[index] = 1;
        if (status != 0) {
            return record_failure("process_child_status", status);
        }

        const uint64_t expected = cpu_kernel(seed_base + (uint64_t)index, iterations);
        result->checksum = mix_checksum(result->checksum, expected);
    }

    if (iterations > (UINT64_MAX - 2) / 3 ||
        (uint64_t)child_count > UINT64_MAX / (iterations * 3 + 2)) {
        return record_failure("process_operation_count", -EOVERFLOW);
    }
    result->operations = (uint64_t)child_count * (iterations * 3 + 2);
    return 0;
}

static int write_full(int fd, const unsigned char *buffer, size_t length,
                      const char *stage) {
    size_t offset = 0;

    while (offset < length) {
        errno = 0;
        const long written = syscall(SYS_write, fd, buffer + offset, length - offset);
        if (written <= 0) {
            return record_failure(stage, written == 0 ? -EIO : syscall_error(written));
        }
        if ((uint64_t)written > (uint64_t)(length - offset)) {
            return record_failure(stage, -EOVERFLOW);
        }
        offset += (size_t)written;
    }
    return 0;
}

static int read_full(int fd, unsigned char *buffer, size_t length,
                     const char *stage) {
    size_t offset = 0;

    while (offset < length) {
        errno = 0;
        const long count = syscall(SYS_read, fd, buffer + offset, length - offset);
        if (count <= 0) {
            return record_failure(stage, count == 0 ? -EIO : syscall_error(count));
        }
        if ((uint64_t)count > (uint64_t)(length - offset)) {
            return record_failure(stage, -EOVERFLOW);
        }
        offset += (size_t)count;
    }
    return 0;
}

static int close_fd(int fd, const char *stage) {
    errno = 0;
    const long result = syscall(SYS_close, fd);
    if (result != 0) {
        return record_failure(stage, syscall_error(result));
    }
    return 0;
}

static int unlink_if_present(const char *path) {
    errno = 0;
    const long result = syscall(SYS_unlink, path);
    if (result == 0 || (result == -1 && errno == ENOENT)) {
        return 0;
    }
    return record_failure("file_cleanup", syscall_error(result));
}

static int verify_open_file(const char *path, uint64_t expected_checksum,
                            uint64_t *operations) {
    errno = 0;
    const long opened = syscall(SYS_open, path, O_RDONLY, 0);
    if (opened < 0) {
        return record_failure("file_reopen", syscall_error(opened));
    }
    const int fd = (int)opened;

    memset(file_read_buffer, 0, sizeof(file_read_buffer));
    if (read_full(fd, file_read_buffer, FILE_BYTES, "file_read") != 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    unsigned char extra = 0;
    errno = 0;
    const long eof = syscall(SYS_read, fd, &extra, (size_t)1);
    if (eof != 0) {
        (void)syscall(SYS_close, fd);
        return record_failure("file_eof", eof < 0 ? syscall_error(eof) : eof);
    }
    if (hash_bytes(file_read_buffer, FILE_BYTES) != expected_checksum ||
        memcmp(file_write_buffer, file_read_buffer, FILE_BYTES) != 0) {
        (void)syscall(SYS_close, fd);
        return record_failure("file_verify", -EIO);
    }
    if (close_fd(fd, "file_read_close") != 0) {
        return -1;
    }
    return checked_add_u64(operations, (uint64_t)FILE_BYTES + 3);
}

static int exercise_ramfs(uint64_t seed, PhaseResult *result) {
    if (unlink_if_present(RAMFS_PATH) != 0 ||
        unlink_if_present(RAMFS_RENAMED_PATH) != 0) {
        return -1;
    }

    for (size_t i = 0; i < FILE_BYTES; ++i) {
        file_write_buffer[i] = pattern_byte(seed, i);
    }
    result->checksum = hash_bytes(file_write_buffer, FILE_BYTES);
    result->operations = 0;

    errno = 0;
    const long opened = syscall(SYS_open, RAMFS_PATH,
                                O_CREAT | O_EXCL | O_RDWR, 0600);
    if (opened < 0) {
        return record_failure("ramfs_create", syscall_error(opened));
    }
    const int fd = (int)opened;
    if (write_full(fd, file_write_buffer, FILE_BYTES, "ramfs_write") != 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    if (close_fd(fd, "ramfs_write_close") != 0 ||
        checked_add_u64(&result->operations, (uint64_t)FILE_BYTES + 2) != 0) {
        return -1;
    }

    /* Close + reopen is Nilix's supported synchronization boundary. */
    if (verify_open_file(RAMFS_PATH, result->checksum, &result->operations) != 0) {
        return -1;
    }
    errno = 0;
    const long renamed = syscall(SYS_rename, RAMFS_PATH, RAMFS_RENAMED_PATH);
    if (renamed != 0) {
        return record_failure("ramfs_rename", syscall_error(renamed));
    }
    if (checked_add_u64(&result->operations, 1) != 0 ||
        verify_open_file(RAMFS_RENAMED_PATH, result->checksum,
                         &result->operations) != 0) {
        return -1;
    }
    errno = 0;
    const long unlinked = syscall(SYS_unlink, RAMFS_RENAMED_PATH);
    if (unlinked != 0) {
        return record_failure("ramfs_unlink", syscall_error(unlinked));
    }
    return checked_add_u64(&result->operations, 1);
}

static int exercise_ext3(uint64_t seed, PhaseResult *result) {
    for (size_t i = 0; i < FILE_BYTES; ++i) {
        file_write_buffer[i] = pattern_byte(seed, i);
    }
    result->checksum = hash_bytes(file_write_buffer, FILE_BYTES);
    result->operations = 0;

    errno = 0;
    const long opened = syscall(SYS_open, EXT3_PATH, O_RDWR, 0);
    if (opened < 0) {
        return record_failure("ext3_open", syscall_error(opened));
    }
    const int fd = (int)opened;

    /*
     * Ext3 does not expose truncate/create yet. The reproducible image starts
     * with an empty inode and the boot probe writes one byte, so a complete
     * FILE_BYTES overwrite from offset zero establishes the exact final size.
     */
    if (write_full(fd, file_write_buffer, FILE_BYTES, "ext3_write") != 0) {
        (void)syscall(SYS_close, fd);
        return -1;
    }
    if (close_fd(fd, "ext3_write_close") != 0 ||
        checked_add_u64(&result->operations, (uint64_t)FILE_BYTES + 2) != 0) {
        return -1;
    }

    /* Ext3 writes synchronously; close + reopen exercises the durable boundary. */
    return verify_open_file(EXT3_PATH, result->checksum, &result->operations);
}

static int run_file_workload(uint64_t seed, PhaseResult *result) {
    PhaseResult ramfs;
    PhaseResult ext3;

    if (exercise_ramfs(seed, &ramfs) != 0 ||
        exercise_ext3(seed ^ UINT64_C(0xd1b54a32d192ed03), &ext3) != 0) {
        return -1;
    }
    result->operations = ramfs.operations;
    if (checked_add_u64(&result->operations, ext3.operations) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(ramfs.checksum, ext3.checksum);
    return 0;
}

static int run_combined_child(size_t child_index) {
    uint64_t aggregate = UINT64_C(0x510e527fade682d1);

    for (size_t round = 0; round < COMBINED_ROUNDS; ++round) {
        const uint64_t seed = UINT64_C(0x40000000) +
                              (uint64_t)child_index * UINT64_C(0x1000) +
                              (uint64_t)round;
        PhaseResult memory;
        PhaseResult cpu;
        if (run_memory_workload(COMBINED_MEMORY_PAGES, seed, &memory) != 0 ||
            run_cpu_workload(seed ^ UINT64_C(0xa5a5a5a5),
                             COMBINED_CPU_ITERATIONS, &cpu) != 0) {
            return -1;
        }
        aggregate = mix_checksum(aggregate, memory.checksum);
        aggregate = mix_checksum(aggregate, cpu.checksum);
    }
    return aggregate == 0 ? -1 : 0;
}

static int run_combined_workload(PhaseResult *result) {
    long pids[COMBINED_CHILDREN] = {0};
    int seen[COMBINED_CHILDREN] = {0};
    size_t spawned = 0;

    for (size_t i = 0; i < COMBINED_CHILDREN; ++i) {
        errno = 0;
        const long pid = syscall(SYS_fork);
        if (pid == 0) {
            child_exit(run_combined_child(i) == 0 ? 0 : 40 + (int)i);
        }
        if (pid < 0) {
            const long code = syscall_error(pid);
            while (spawned > 0) {
                int ignored_status = 0;
                if (wait_one_child(&ignored_status) < 0) {
                    break;
                }
                --spawned;
            }
            return record_failure("combined_fork", code);
        }
        pids[spawned++] = pid;
    }

    result->operations = 0;
    result->checksum = UINT64_C(0x1f83d9abfb41bd6b);
    for (size_t round = 0; round < FILE_ROUNDS; ++round) {
        PhaseResult file;
        if (run_file_workload(UINT64_C(0x50000000) + (uint64_t)round,
                              &file) != 0 ||
            checked_add_u64(&result->operations, file.operations) != 0) {
            return -1;
        }
        result->checksum = mix_checksum(result->checksum, file.checksum);
    }

    for (size_t reaped = 0; reaped < COMBINED_CHILDREN; ++reaped) {
        int status = -1;
        errno = 0;
        const long pid = wait_one_child(&status);
        if (pid < 0) {
            return record_failure("combined_wait", syscall_error(pid));
        }
        size_t index = COMBINED_CHILDREN;
        for (size_t i = 0; i < COMBINED_CHILDREN; ++i) {
            if (pids[i] == pid) {
                index = i;
                break;
            }
        }
        if (index == COMBINED_CHILDREN || seen[index]) {
            return record_failure("combined_wait_pid", pid);
        }
        seen[index] = 1;
        if (status != 0) {
            return record_failure("combined_child_status", status);
        }
        result->checksum = mix_checksum(result->checksum, (uint64_t)index + 1);
    }

    const uint64_t memory_ops =
        (uint64_t)COMBINED_MEMORY_PAGES * (uint64_t)PAGE_BYTES * 2;
    const uint64_t per_round = memory_ops + COMBINED_CPU_ITERATIONS * 2;
    const uint64_t child_ops = (uint64_t)COMBINED_CHILDREN *
                               (uint64_t)COMBINED_ROUNDS * per_round;
    if (checked_add_u64(&result->operations, child_ops) != 0 ||
        checked_add_u64(&result->operations,
                        (uint64_t)COMBINED_CHILDREN * 2) != 0) {
        return -1;
    }
    return 0;
}

static void emit_phase(const char *name, const PhaseResult *result) {
    printf("NILIX_STRESS_PHASE phase=%s ops=%" PRIu64 " checksum=%016" PRIx64 "\n",
           name, result->operations, result->checksum);
    flush_output();
}

static int accumulate_phase(PhaseResult *total, const PhaseResult *phase) {
    if (checked_add_u64(&total->operations, phase->operations) != 0) {
        return -1;
    }
    total->checksum = mix_checksum(total->checksum, phase->checksum);
    return 0;
}

int main(void) {
    PhaseResult memory;
    PhaseResult cpu;
    PhaseResult process;
    PhaseResult file;
    PhaseResult combined;
    PhaseResult total = {0, UINT64_C(0x5be0cd19137e2179)};

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    /* Separate the first marker from the interactive shell prompt. */
    printf("\nNILIX_STRESS_BEGIN version=1\n");

    if (run_memory_workload(MEMORY_PAGES, UINT64_C(0x10000000), &memory) != 0) {
        return emit_failure();
    }
    emit_phase("memory", &memory);

    if (run_cpu_workload(UINT64_C(0x20000000), CPU_ITERATIONS, &cpu) != 0) {
        return emit_failure();
    }
    emit_phase("cpu", &cpu);

    if (spawn_cpu_children(PROCESS_CHILDREN, UINT64_C(0x30000000),
                           CHILD_CPU_ITERATIONS, &process) != 0) {
        return emit_failure();
    }
    emit_phase("process", &process);

    if (run_file_workload(UINT64_C(0x60000000), &file) != 0) {
        return emit_failure();
    }
    emit_phase("file", &file);

    if (run_combined_workload(&combined) != 0) {
        return emit_failure();
    }
    emit_phase("combined", &combined);

    if (accumulate_phase(&total, &memory) != 0 ||
        accumulate_phase(&total, &cpu) != 0 ||
        accumulate_phase(&total, &process) != 0 ||
        accumulate_phase(&total, &file) != 0 ||
        accumulate_phase(&total, &combined) != 0) {
        return emit_failure();
    }

    printf("NILIX_STRESS_PASS phases=5 ops=%" PRIu64 " checksum=%016" PRIx64 "\n",
           total.operations, total.checksum);
    flush_output();

    /*
     * The host owns the soak duration and terminates QEMU at its deadline.
     * Keep executing complete, independently bounded combined rounds until
     * then. Resource fanout and allocation are fixed per iteration; counters
     * fail closed before wrapping.
     */
    uint64_t iteration = 0;
    for (;;) {
        PhaseResult sustained;
        if (run_combined_workload(&sustained) != 0 ||
            accumulate_phase(&total, &sustained) != 0) {
            return emit_failure();
        }
        if (iteration == UINT64_MAX) {
            (void)record_failure("heartbeat_iteration_overflow", -EOVERFLOW);
            return emit_failure();
        }
        ++iteration;
        printf("NILIX_STRESS_HEARTBEAT iteration=%" PRIu64
               " ops=%" PRIu64 " checksum=%016" PRIx64 "\n",
               iteration, total.operations, total.checksum);
        flush_output();
    }
}
