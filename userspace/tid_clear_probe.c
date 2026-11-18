/* The kernel clears the clear_child_tid word of an exiting task
 * (CLONE_CHILD_CLEARTID, set_tid_address). Linux does it with one 32-bit
 * store. Four separate byte stores let another task load a value that nobody
 * stored. musl takes a thread-list lock word equal to the caller's TID for a
 * lock the caller already holds, and a TID whose low byte is zero equals a
 * sibling's TID with only its low byte cleared (Nilix #90, #62).
 *
 * A CLONE_VM child fills the word with a pattern whose bytes are all non-zero
 * and waits until the parent has observed it on a different CPU. The parent
 * then loads the word until it is clear. Every load must be the pattern or zero.
 */
#include <sched.h>
#include <stdint.h>

#define TID_CLEAR_EXITS 200u
#define TID_CLEAR_PATTERN UINT32_C(0x01010101)
#define TID_CLEAR_STACK_BYTES (64u * 1024u)
#define TID_CLEAR_TIMEOUT_SECONDS 10

struct tid_clear_state {
    uint32_t word;
    int reader_ready;
    unsigned child_cpu;
    time_t deadline;
};

static int tid_clear_timeout(unsigned spin, time_t deadline) {
    if ((spin & 0xffff) != 0) return 0;
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec >= deadline;
}

static int tid_clear_child(void *opaque) {
    struct tid_clear_state *state = opaque;
    if (!exit_idle_pin(state->child_cpu) || !exit_idle_wait_cpu(state->child_cpu)) {
        __atomic_store_n(&state->reader_ready, -1, __ATOMIC_RELEASE);
        return 81;
    }
    __atomic_store_n(&state->word, TID_CLEAR_PATTERN, __ATOMIC_RELEASE);
    for (unsigned spin = 1; !__atomic_load_n(&state->reader_ready, __ATOMIC_ACQUIRE); ++spin) {
        if (tid_clear_timeout(spin, state->deadline)) return 82;
        __asm__ volatile("pause");
    }
    /* musl's clone trampoline issues SYS_exit with this return value. */
    return exit_idle_cpu() == state->child_cpu ? 0 : 83;
}

static const char *tid_clear_observe(struct tid_clear_state *state, unsigned reader_cpu,
                                     uint32_t *value) {
    int acknowledged = 0;
    for (unsigned spin = 1;; ++spin) {
        *value = __atomic_load_n(&state->word, __ATOMIC_ACQUIRE);
        if (*value == TID_CLEAR_PATTERN) {
            if (!acknowledged) {
                if (exit_idle_cpu() != reader_cpu) return "reader-affinity";
                __atomic_store_n(&state->reader_ready, 1, __ATOMIC_RELEASE);
                acknowledged = 1;
            }
        } else if (*value != 0) {
            return "torn";
        } else if (acknowledged) {
            return exit_idle_cpu() == reader_cpu ? NULL : "reader-affinity";
        } else if (__atomic_load_n(&state->reader_ready, __ATOMIC_ACQUIRE) < 0) {
            return "child-affinity";
        }
        if (tid_clear_timeout(spin, state->deadline)) return "timeout";
    }
}

static int tid_clear_reap(pid_t child, int *status) {
    for (unsigned attempt = 0; attempt < 1200; ++attempt) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return 1;
        if (result < 0 && errno != EINTR) break;
        if (attempt == 999) kill(child, SIGKILL);
        struct timespec delay = {.tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    return 0;
}

static int tid_clear_smoke(void) {
    static struct tid_clear_state state;
    uint64_t cpus = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(cpus), &cpus) != sizeof(cpus) || !cpus) {
        printf("MUSL-TID-CLEAR-FAIL stage=getaffinity errno=%d\n", errno);
        return 1;
    }
    uint64_t other_cpus = cpus & (cpus - 1);
    if (!other_cpus) {
        puts("MUSL-TID-CLEAR-SKIP reason=requires-multiple-cpus");
        return 0;
    }
    char *stack = mmap(NULL, TID_CLEAR_STACK_BYTES, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        printf("MUSL-TID-CLEAR-FAIL stage=mmap errno=%d\n", errno);
        return 1;
    }

    unsigned reader_cpu = (unsigned)__builtin_ctzll(cpus);
    state.child_cpu = (unsigned)__builtin_ctzll(other_cpus);
    const char *failure = NULL;
    unsigned completed = 0;
    uint32_t value = 0;
    int reaped = 1, status = -1;
    if (!exit_idle_pin(reader_cpu) || !exit_idle_wait_cpu(reader_cpu)) failure = "reader-affinity";
    while (!failure && completed < TID_CLEAR_EXITS) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) {
            failure = "clock";
            break;
        }
        state.deadline = now.tv_sec + TID_CLEAR_TIMEOUT_SECONDS;
        __atomic_store_n(&state.word, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&state.reader_ready, 0, __ATOMIC_RELAXED);
        /* Zero-OS accepts no CSIGNAL bits; wait4 selects this ordinary child. */
        pid_t child = clone(tid_clear_child, stack + TID_CLEAR_STACK_BYTES,
                            CLONE_VM | CLONE_CHILD_CLEARTID, &state, NULL, NULL, &state.word);
        if (child < 0) {
            failure = "clone";
            break;
        }
        /* The child inherits the reader's single-CPU affinity at clone. */
        syscall(SYS_sched_yield);
        failure = tid_clear_observe(&state, reader_cpu, &value);
        if (failure) kill(child, SIGKILL);
        status = -1;
        reaped = tid_clear_reap(child, &status);
        if (!failure && (!reaped || !WIFEXITED(status) || WEXITSTATUS(status) != 0))
            failure = "reap";
        if (!failure) ++completed;
    }
    if (syscall(SYS_sched_setaffinity, 0, sizeof(cpus), &cpus) && !failure) failure = "restore-affinity";
    /* An unreaped CLONE_VM child may still be using its stack. */
    if (reaped && munmap(stack, TID_CLEAR_STACK_BYTES) && !failure) failure = "unmap";
    if (failure) {
        printf("MUSL-TID-CLEAR-FAIL stage=%s exit=%u value=%08x status=%d reaped=%d\n",
               failure, completed, value, status, reaped);
        return 1;
    }
    printf("MUSL-TID-CLEAR-OK exits=%u concurrent=%u reader_cpu=%u child_cpu=%u\n",
           TID_CLEAR_EXITS, completed, reader_cpu, state.child_cpu);
    return 0;
}
