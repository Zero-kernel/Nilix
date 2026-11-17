/* The kernel clears the clear_child_tid word of an exiting task
 * (CLONE_CHILD_CLEARTID, set_tid_address). Linux does it with one 32-bit
 * store. Four separate byte stores let another task load a value that nobody
 * stored. musl takes a thread-list lock word equal to the caller's TID for a
 * lock the caller already holds, and a TID whose low byte is zero equals a
 * sibling's TID with only its low byte cleared (Nilix #90, #62).
 *
 * A CLONE_VM child fills the word with a pattern whose bytes are all non-zero
 * and exits. The parent, on another CPU, loads the word until it is clear.
 * Every value it loads must be the pattern or zero.
 */
#include <sched.h>
#include <stdint.h>

#define TID_CLEAR_EXITS 200u
#define TID_CLEAR_PATTERN UINT32_C(0x01010101)
#define TID_CLEAR_STACK_BYTES (64u * 1024u)
#define TID_CLEAR_TIMEOUT_SECONDS 10

struct tid_clear_state {
    /* The child's clear_child_tid word. */
    uint32_t word;
    /* Set by the child once the word holds the pattern. */
    uint32_t armed;
};

static int tid_clear_child(void *opaque) {
    struct tid_clear_state *state = opaque;
    __atomic_store_n(&state->word, TID_CLEAR_PATTERN, __ATOMIC_SEQ_CST);
    __atomic_store_n(&state->armed, 1, __ATOMIC_SEQ_CST);
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

static int tid_clear_smoke(void) {
    static struct tid_clear_state state;
    uint64_t cpus = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(cpus), &cpus) != sizeof(cpus)) {
        printf("MUSL-TID-CLEAR-FAIL stage=getaffinity errno=%d\n", errno);
        return 1;
    }
    if (!cpus || !(cpus & (cpus - 1))) {
        puts("MUSL-TID-CLEAR-SKIP reason=requires-multiple-cpus");
        return 0;
    }
    char *stack = mmap(NULL, TID_CLEAR_STACK_BYTES, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        printf("MUSL-TID-CLEAR-FAIL stage=mmap errno=%d\n", errno);
        return 1;
    }

    /* Exits during which the parent loaded the pattern, so it was reading
     * while the child was on its way out. */
    unsigned concurrent = 0;
    for (unsigned exit_index = 0; exit_index < TID_CLEAR_EXITS; ++exit_index) {
        __atomic_store_n(&state.word, 0, __ATOMIC_SEQ_CST);
        __atomic_store_n(&state.armed, 0, __ATOMIC_SEQ_CST);
        /* Zero-OS accepts no CSIGNAL bits; wait4 selects this ordinary child. */
        pid_t child = clone(tid_clear_child, stack + TID_CLEAR_STACK_BYTES,
                            CLONE_VM | CLONE_CHILD_CLEARTID, &state, NULL, NULL, &state.word);
        if (child < 0) {
            printf("MUSL-TID-CLEAR-FAIL stage=clone exit=%u errno=%d\n", exit_index, errno);
            return 1;
        }

        struct timespec started;
        clock_gettime(CLOCK_MONOTONIC, &started);
        int saw_pattern = 0, torn = 0, timed_out = 0;
        uint32_t value = 0;
        for (uint64_t spin = 1;; ++spin) {
            /* `armed` first: a clear word after it means the kernel cleared it. */
            uint32_t armed = __atomic_load_n(&state.armed, __ATOMIC_ACQUIRE);
            value = __atomic_load_n(&state.word, __ATOMIC_RELAXED);
            if (value == TID_CLEAR_PATTERN) {
                saw_pattern = 1;
            } else if (value != 0) {
                torn = 1;
                break;
            } else if (armed) {
                break;
            }
            if ((spin & 0xfffff) == 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (now.tv_sec - started.tv_sec > TID_CLEAR_TIMEOUT_SECONDS) {
                    timed_out = 1;
                    break;
                }
            }
        }

        int status = -1;
        if (timed_out) kill(child, SIGKILL);
        pid_t reaped;
        do {
            reaped = waitpid(child, &status, 0);
        } while (reaped < 0 && errno == EINTR);
        if (torn) {
            printf("MUSL-TID-CLEAR-FAIL stage=torn exit=%u value=%08x\n", exit_index, value);
            return 1;
        }
        if (timed_out) {
            printf("MUSL-TID-CLEAR-FAIL stage=timeout exit=%u value=%08x\n", exit_index, value);
            return 1;
        }
        if (reaped != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("MUSL-TID-CLEAR-FAIL stage=reap exit=%u status=%d errno=%d\n",
                   exit_index, status, errno);
            return 1;
        }
        concurrent += (unsigned)saw_pattern;
    }
    munmap(stack, TID_CLEAR_STACK_BYTES);
    if (concurrent == 0) {
        /* No exit was observed in progress, so the probe saw no store at all. */
        printf("MUSL-TID-CLEAR-FAIL stage=never-concurrent exits=%u\n", TID_CLEAR_EXITS);
        return 1;
    }
    printf("MUSL-TID-CLEAR-OK exits=%u concurrent=%u\n", TID_CLEAR_EXITS, concurrent);
    return 0;
}
