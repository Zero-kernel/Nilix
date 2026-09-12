/* KSA-011: a child on an otherwise idle CPU must leave its stack before reap.
 * The QEMU validation topology uses dense APIC IDs matching Zero-OS CPU IDs.
 */
#include <stdint.h>
#include <sched.h>
#include <signal.h>

static unsigned exit_idle_cpu(void) {
    unsigned eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "0"(1), "2"(0));
    return ebx >> 24;
}

static int exit_idle_pin(unsigned cpu) {
    uint64_t mask = UINT64_C(1) << cpu;
    return syscall(SYS_sched_setaffinity, 0, sizeof(mask), &mask) == 0;
}

static int exit_idle_wait_cpu(unsigned wanted) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (exit_idle_cpu() == wanted) return 1;
        syscall(SYS_sched_yield);
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return 0;
}

static void exit_idle_child_exit(int code) {
    syscall(SYS_exit, code);
    __builtin_unreachable();
}

static int exit_idle_reap(pid_t child, int expected) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        int status = -1;
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == expected) return 1;
            printf("MUSL-EXIT-IDLE-FAIL stage=status pid=%ld status=%d expected=%d\n",
                   (long)child, status, expected);
            return 0;
        }
        if (observed < 0 && errno != EINTR) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    printf("MUSL-EXIT-IDLE-FAIL stage=timeout pid=%ld\n", (long)child);
    kill(child, SIGKILL);
    for (int attempt = 0; attempt < 200; ++attempt) {
        pid_t observed = waitpid(child, NULL, WNOHANG);
        if (observed == child || (observed < 0 && errno == ECHILD)) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    printf("MUSL-EXIT-IDLE-UNREAPED pid=%ld\n", (long)child);
    return 0;
}

static int exit_idle_smoke(void) {
    uint64_t original = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(original), &original) != sizeof(original)) {
        printf("MUSL-EXIT-IDLE-FAIL stage=getaffinity errno=%d\n", errno);
        return 1;
    }
    if (!original || !(original & (original - 1))) {
        puts("MUSL-EXIT-IDLE-SKIP reason=requires-multiple-cpus");
        return 0;
    }
    unsigned parent_cpu = exit_idle_cpu();
    if (parent_cpu >= 64 || !(original & (UINT64_C(1) << parent_cpu)) ||
        !exit_idle_pin(parent_cpu)) {
        printf("MUSL-EXIT-IDLE-FAIL stage=parent-affinity cpu=%u errno=%d\n", parent_cpu, errno);
        return 1;
    }

    /* Keep one replacement on the parent's CPU while each child migrates.
     * It never runs on the child's target CPU and cannot serve as its exit
     * replacement. CPUID below verifies actual placement, not just a mask.
     */
    fflush(NULL);
    pid_t helper = (pid_t)syscall(SYS_fork);
    if (helper == 0) {
        for (;;) syscall(SYS_sched_yield);
    }
    int result = helper < 0;
    unsigned cases = 0;
    for (unsigned cpu = 0; !result && cpu < 64; ++cpu) {
        if (cpu == parent_cpu || !(original & (UINT64_C(1) << cpu))) continue;
        for (int fatal = 0; !result && fatal < 2; ++fatal) {
            int ready[2] = {-1, -1};
            if (exit_idle_cpu() != parent_cpu || (fatal && pipe(ready))) {
                result = 1;
                break;
            }
            fflush(NULL);
            pid_t child = (pid_t)syscall(SYS_fork);
            if (child == 0) {
                if (fatal) close(ready[0]);
                if (!exit_idle_pin(cpu) || !exit_idle_wait_cpu(cpu)) exit_idle_child_exit(81);
                if (!fatal) exit_idle_child_exit(40 + (int)cpu);
                if (write(ready[1], "r", 1) != 1) exit_idle_child_exit(82);
                /* No syscall safe point: the fatal IRQ handoff must leave this CPU. */
                for (;;) __asm__ volatile("pause");
            }
            if (fatal) close(ready[1]);
            if (child < 0) {
                result = 1;
            } else {
                int ready_ok = 1;
                if (fatal) {
                    struct pollfd event = {.fd = ready[0], .events = POLLIN};
                    char byte = 0;
                    ready_ok = poll(&event, 1, 3000) == 1 && (event.revents & POLLIN) &&
                               read(ready[0], &byte, 1) == 1 && byte == 'r';
                    if (kill(child, SIGKILL)) ready_ok = 0;
                }
                /* Zero-OS represents signal death using normal-exit 128+signal. */
                int reaped = exit_idle_reap(child, fatal ? 128 + SIGKILL : 40 + (int)cpu);
                result = !ready_ok || !reaped;
                if (!result) {
                    ++cases;
                    printf("MUSL-EXIT-IDLE-CASE-PASS parent_cpu=%u child_cpu=%u fatal=%d\n",
                           parent_cpu, cpu, fatal);
                }
            }
            if (fatal) close(ready[0]);
        }
    }
    if (helper > 0) {
        if (kill(helper, SIGKILL)) result = 1;
        if (!exit_idle_reap(helper, 128 + SIGKILL)) result = 1;
    }
    if (syscall(SYS_sched_setaffinity, 0, sizeof(original), &original)) result = 1;
    if (result || cases < 2) {
        printf("MUSL-EXIT-IDLE-FAIL stage=completion cases=%u errno=%d\n", cases, errno);
        return 1;
    }
    printf("MUSL-EXIT-IDLE-OK cases=%u\n", cases);
    return 0;
}
