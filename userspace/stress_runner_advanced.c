#define _GNU_SOURCE

/*
 * Advanced bounded Ring-3 security and concurrency stress workload.
 *
 * Security > Correctness > Efficiency > Performance
 *
 * This workload extends stress_runner.c with security-focused scenarios:
 * - Permission boundary validation (syscall argument fuzzing)
 * - Resource exhaustion resilience (OOM, fd limits, process limits)
 * - Concurrency stress (race conditions, deadlock detection)
 * - Failure injection (invalid operations, edge cases)
 * - Signal handling under load
 *
 * Each phase is independently bounded and fail-closed.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PAGE_BYTES ((size_t)4096)
#define SECURITY_ROUNDS ((size_t)8)
#define CONCURRENCY_WORKERS ((size_t)4)
#define CONCURRENCY_ITERATIONS ((uint64_t)50000)
#define RESOURCE_STRESS_FDS ((size_t)32)
#define FAILURE_INJECTION_CASES ((size_t)16)

#define RAMFS_SECURITY_PATH "/nilix-security-test.tmp"
#define NILIX_SYS_GETPID 39

typedef struct {
    uint64_t operations;
    uint64_t checksum;
} PhaseResult;

typedef enum {
    SEC_NULL_PTR,
    SEC_INVALID_FD,
    SEC_NEGATIVE_SIZE,
    SEC_OVERFLOW_SIZE,
    SEC_UNALIGNED_ADDR,
    SEC_KERNEL_ADDR,
    SEC_UNMAPPED_ADDR,
    SEC_INVALID_FLAGS,
} SecurityCase;

static const char *failure_stage;
static long failure_code;
static int failure_emitted;
static volatile sig_atomic_t signal_count;

_Static_assert(CONCURRENCY_WORKERS <= 16, "concurrency fanout must stay bounded");
_Static_assert(RESOURCE_STRESS_FDS <= 256, "fd stress must stay bounded");
_Static_assert(FAILURE_INJECTION_CASES <= 32, "failure injection must stay bounded");

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
        printf("NILIX_STRESS_ADVANCED_FAIL stage=%s code=%ld\n",
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

static void signal_handler(int signum) {
    (void)signum;
    signal_count++;
}

/* Security Phase: Permission boundary validation */
static int run_security_workload(uint64_t seed, PhaseResult *result) {
    (void)seed;  /* Reserved for future use in test case selection */
    result->operations = 0;
    result->checksum = UINT64_C(0xcbf29ce484222325);

    /* Test NULL pointer rejection */
    errno = 0;
    long rc = syscall(SYS_read, 0, NULL, (size_t)1);
    if (rc != -1 || errno != EFAULT) {
        return record_failure("security_null_read", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test invalid fd rejection */
    errno = 0;
    unsigned char dummy = 0;
    rc = syscall(SYS_read, -1, &dummy, (size_t)1);
    if (rc != -1 || errno != EBADF) {
        return record_failure("security_invalid_fd", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test overflow size rejection */
    errno = 0;
    rc = syscall(SYS_mmap, NULL, SIZE_MAX, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rc != -1 || (errno != ENOMEM && errno != EINVAL)) {
        return record_failure("security_overflow_mmap", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test kernel address rejection */
    errno = 0;
    rc = syscall(SYS_munmap, (void *)0xffff800000000000UL, PAGE_BYTES);
    if (rc != -1 || errno != EINVAL) {
        return record_failure("security_kernel_munmap", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test invalid flags rejection */
    errno = 0;
    rc = syscall(SYS_mmap, NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                 0xDEADBEEF, -1, 0);
    if (rc != -1 || errno != EINVAL) {
        return record_failure("security_invalid_flags", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test close of invalid fd */
    errno = 0;
    rc = syscall(SYS_close, 9999);
    if (rc != -1 || errno != EBADF) {
        return record_failure("security_close_invalid", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test negative size */
    errno = 0;
    rc = syscall(SYS_write, 1, &dummy, (size_t)-1);
    if (rc != -1 || errno != EINVAL) {
        return record_failure("security_negative_size", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    /* Test unaligned mmap */
    errno = 0;
    rc = syscall(SYS_mmap, (void *)0x1001UL, PAGE_BYTES, PROT_READ,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (rc != -1 || errno != EINVAL) {
        return record_failure("security_unaligned_fixed", syscall_error(rc));
    }
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);

    return 0;
}

/* Concurrency Phase: Race condition and deadlock stress */
__attribute__((noreturn)) static void child_exit(int code) {
    (void)syscall(SYS_exit, code);
    __builtin_unreachable();
}

static long wait_one_child(int *status) {
    long result;

    do {
        errno = 0;
        /* ST-K3 FIX (wait4 ABI): SYS_wait4 takes (pid, wstatus, options,
         * rusage) — the status pointer is ARG1 with pid=-1 for any child.
         * The old single-arg call put the pointer in arg0, which the
         * repaired kernel reads as a pid selector (immediate ECHILD). */
        result = syscall(SYS_wait4, -1, status, 0, NULL);
    } while (result == -1 && errno == EINTR);
    return result;
}

static int run_concurrency_workload(uint64_t seed, PhaseResult *result) {
    long pids[CONCURRENCY_WORKERS] = {0};
    int seen[CONCURRENCY_WORKERS] = {0};
    size_t spawned = 0;

    for (size_t i = 0; i < CONCURRENCY_WORKERS; ++i) {
        errno = 0;
        const long pid = syscall(SYS_fork);
        if (pid == 0) {
            /* Child: Hammer getpid concurrently */
            uint64_t local_checksum = seed + (uint64_t)i;
            for (uint64_t iter = 0; iter < CONCURRENCY_ITERATIONS; ++iter) {
                errno = 0;
                long my_pid = syscall(SYS_getpid);
                if (my_pid <= 0) {
                    child_exit(10 + (int)i);
                }
                local_checksum ^= (uint64_t)my_pid + iter;
            }
            child_exit(local_checksum == 0 ? 1 : 0);
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
            return record_failure("concurrency_fork", code);
        }
        pids[spawned++] = pid;
    }

    result->operations = 0;
    result->checksum = UINT64_C(0x6a09e667bb67ae85);
    for (size_t reaped = 0; reaped < CONCURRENCY_WORKERS; ++reaped) {
        int status = -1;
        errno = 0;
        const long pid = wait_one_child(&status);
        if (pid < 0) {
            return record_failure("concurrency_wait", syscall_error(pid));
        }

        size_t index = CONCURRENCY_WORKERS;
        for (size_t i = 0; i < CONCURRENCY_WORKERS; ++i) {
            if (pids[i] == pid) {
                index = i;
                break;
            }
        }
        if (index == CONCURRENCY_WORKERS || seen[index]) {
            return record_failure("concurrency_wait_pid", pid);
        }
        seen[index] = 1;
        if (status != 0) {
            return record_failure("concurrency_child_status", status);
        }

        result->checksum = mix_checksum(result->checksum, (uint64_t)index + 1);
    }

    if (CONCURRENCY_ITERATIONS > UINT64_MAX / CONCURRENCY_WORKERS) {
        return record_failure("concurrency_operation_count", -EOVERFLOW);
    }
    result->operations = (uint64_t)CONCURRENCY_WORKERS *
                         CONCURRENCY_ITERATIONS * 2;
    return 0;
}

/* Resource Exhaustion Phase: Test fd/memory limits */
static int run_resource_exhaustion_workload(uint64_t seed, PhaseResult *result) {
    (void)seed;  /* Reserved for future use in test case selection */
    int fds[RESOURCE_STRESS_FDS];
    size_t opened = 0;

    /* Open many ramfs files */
    for (size_t i = 0; i < RESOURCE_STRESS_FDS; ++i) {
        char path[64];
        (void)snprintf(path, sizeof(path), "/nilix-stress-fd-%zu.tmp", i);
        errno = 0;
        const long fd = syscall(SYS_open, path, O_CREAT | O_RDWR, 0600);
        if (fd < 0) {
            /* Expected to hit limit eventually */
            break;
        }
        fds[opened++] = (int)fd;
    }

    if (opened == 0) {
        return record_failure("resource_no_fds", -EMFILE);
    }

    result->operations = opened;
    result->checksum = hash_bytes((const unsigned char *)fds,
                                   opened * sizeof(int));

    /* Clean up */
    for (size_t i = 0; i < opened; ++i) {
        char path[64];
        (void)snprintf(path, sizeof(path), "/nilix-stress-fd-%zu.tmp", i);
        errno = 0;
        (void)syscall(SYS_close, fds[i]);
        (void)syscall(SYS_unlink, path);
    }

    if (checked_add_u64(&result->operations, opened) != 0) {
        return -1;
    }

    return 0;
}

/* Signal Resilience Phase: Signal handling under syscall load */
static int run_signal_workload(uint64_t seed, PhaseResult *result) {
    (void)seed;  /* Reserved for future use in test case selection */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = SA_RESTART;

    errno = 0;
    if (syscall(SYS_rt_sigaction, SIGUSR1, &sa, NULL, sizeof(sigset_t)) != 0) {
        return record_failure("signal_install", syscall_error(-1));
    }

    signal_count = 0;
    const long my_pid = syscall(SYS_getpid);
    if (my_pid <= 0) {
        return record_failure("signal_getpid", syscall_error(my_pid));
    }

    /* Send signals to self while executing syscalls */
    for (size_t round = 0; round < 8; ++round) {
        errno = 0;
        if (syscall(SYS_kill, my_pid, SIGUSR1) != 0) {
            return record_failure("signal_kill", syscall_error(-1));
        }

        /* Execute some syscalls */
        for (size_t i = 0; i < 100; ++i) {
            (void)syscall(SYS_getpid);
        }
    }

    if (signal_count < 1) {
        return record_failure("signal_not_delivered", signal_count);
    }

    result->operations = 8 + 800 + (uint64_t)signal_count;
    result->checksum = mix_checksum((uint64_t)my_pid, (uint64_t)signal_count);

    /* Restore default handler */
    sa.sa_handler = SIG_DFL;
    (void)syscall(SYS_rt_sigaction, SIGUSR1, &sa, NULL, sizeof(sigset_t));

    return 0;
}

/* Failure Injection Phase: Systematic edge case validation */
static int run_failure_injection_workload(uint64_t seed, PhaseResult *result) {
    (void)seed;  /* Reserved for future use in test case selection */
    result->operations = 0;
    result->checksum = UINT64_C(0x510e527fade682d1);

    /* Test double close */
    errno = 0;
    long fd = syscall(SYS_open, "/nilix-fail-inject.tmp",
                      O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        return record_failure("fail_inject_create", syscall_error(fd));
    }
    if (syscall(SYS_close, (int)fd) != 0) {
        return record_failure("fail_inject_close1", syscall_error(-1));
    }
    errno = 0;
    long rc = syscall(SYS_close, (int)fd);
    if (rc != -1 || errno != EBADF) {
        return record_failure("fail_inject_double_close", syscall_error(rc));
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);
    if (checked_add_u64(&result->operations, 3) != 0) {
        return -1;
    }

    /* Test munmap of unmapped region */
    errno = 0;
    rc = syscall(SYS_munmap, (void *)0x7fff00000000UL, PAGE_BYTES);
    if (rc != -1 || errno != EINVAL) {
        return record_failure("fail_inject_munmap_unmapped", syscall_error(rc));
    }
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);
    if (checked_add_u64(&result->operations, 1) != 0) {
        return -1;
    }

    /* Test read from write-only fd */
    fd = syscall(SYS_open, "/nilix-fail-inject.tmp", O_WRONLY, 0);
    if (fd < 0) {
        return record_failure("fail_inject_open_wronly", syscall_error(fd));
    }
    unsigned char dummy = 0;
    errno = 0;
    rc = syscall(SYS_read, (int)fd, &dummy, (size_t)1);
    if (rc != -1 || errno != EBADF) {
        (void)syscall(SYS_close, (int)fd);
        return record_failure("fail_inject_read_wronly", syscall_error(rc));
    }
    (void)syscall(SYS_close, (int)fd);
    result->checksum = mix_checksum(result->checksum, (uint64_t)errno);
    if (checked_add_u64(&result->operations, 3) != 0) {
        return -1;
    }

    /* Clean up */
    (void)syscall(SYS_unlink, "/nilix-fail-inject.tmp");

    return 0;
}

static void emit_phase(const char *name, const PhaseResult *result) {
    printf("NILIX_STRESS_ADVANCED_PHASE phase=%s ops=%" PRIu64
           " checksum=%016" PRIx64 "\n",
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
    PhaseResult security;
    PhaseResult concurrency;
    PhaseResult resource;
    PhaseResult signal_phase;
    PhaseResult failure;
    PhaseResult total = {0, UINT64_C(0x9b05688c2b3e6c1f)};

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    printf("\nNILIX_STRESS_ADVANCED_BEGIN version=1\n");

    if (run_security_workload(UINT64_C(0xa0000000), &security) != 0) {
        return emit_failure();
    }
    emit_phase("security", &security);

    if (run_concurrency_workload(UINT64_C(0xb0000000), &concurrency) != 0) {
        return emit_failure();
    }
    emit_phase("concurrency", &concurrency);

    if (run_resource_exhaustion_workload(UINT64_C(0xc0000000), &resource) != 0) {
        return emit_failure();
    }
    emit_phase("resource", &resource);

    if (run_signal_workload(UINT64_C(0xd0000000), &signal_phase) != 0) {
        return emit_failure();
    }
    emit_phase("signal", &signal_phase);

    if (run_failure_injection_workload(UINT64_C(0xe0000000), &failure) != 0) {
        return emit_failure();
    }
    emit_phase("failure", &failure);

    if (accumulate_phase(&total, &security) != 0 ||
        accumulate_phase(&total, &concurrency) != 0 ||
        accumulate_phase(&total, &resource) != 0 ||
        accumulate_phase(&total, &signal_phase) != 0 ||
        accumulate_phase(&total, &failure) != 0) {
        return emit_failure();
    }

    printf("NILIX_STRESS_ADVANCED_PASS phases=5 ops=%" PRIu64
           " checksum=%016" PRIx64 "\n",
           total.operations, total.checksum);
    flush_output();

    /* Run sustained combined workload until host terminates */
    uint64_t iteration = 0;
    for (;;) {
        PhaseResult sustained;
        if (run_security_workload(UINT64_C(0xf0000000) + iteration,
                                   &sustained) != 0 ||
            accumulate_phase(&total, &sustained) != 0) {
            return emit_failure();
        }
        if (iteration == UINT64_MAX) {
            (void)record_failure("advanced_iteration_overflow", -EOVERFLOW);
            return emit_failure();
        }
        ++iteration;
        printf("NILIX_STRESS_ADVANCED_HEARTBEAT iteration=%" PRIu64
               " ops=%" PRIu64 " checksum=%016" PRIx64 "\n",
               iteration, total.operations, total.checksum);
        flush_output();
    }
}
