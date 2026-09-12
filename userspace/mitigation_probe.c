/* Dedicated four-CPU workload for the debugger-observed dual-root proof.
 * CPU fields identify verified affinity targets. Actual execution CPU and CR3
 * observations come from the collector, not from these userspace markers.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { PROBE_CPUS = 4, PHASE_MS = 250, WAIT_POLLS = 4000, CLEANUP_POLLS = 400 };

static int emit(const char *format, ...) {
    char line[256];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(line)) return -1;
    return syscall(SYS_write, 1, line, (size_t)length) == length ? 0 : -1;
}

static int failure(const char *stage, int cpu, int code) {
    int saved_errno = errno;
    emit("MITIGATION-WORKLOAD FAIL stage=%s cpu=%d pid=%ld code=%d errno=%d\n",
         stage, cpu, (long)getpid(), code, saved_errno);
    return code;
}

static void child_exit(int code) {
    syscall(SYS_exit, code);
    __builtin_unreachable();
}

static uint64_t monotonic_ms(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0 || value.tv_nsec < 0)
        return UINT64_MAX;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}

static int read_affinity(uint64_t *mask) {
    *mask = 0;
    return syscall(SYS_sched_getaffinity, 0, sizeof(*mask), mask) == (long)sizeof(*mask);
}

static int worker_phase(int cpu, const char *phase) {
    const uint64_t target = UINT64_C(1) << cpu;
    uint64_t observed;
    if (!strcmp(phase, "exec") && (!read_affinity(&observed) || observed != target))
        return failure("exec-affinity-inheritance", cpu, 41);
    if (syscall(SYS_sched_setaffinity, 0, sizeof(target), &target) ||
        syscall(SYS_sched_yield) || !read_affinity(&observed) || observed != target)
        return failure("set-affinity", cpu, 42);
    pid_t pid = (pid_t)syscall(SYS_getpid);
    if (pid <= 1) return failure("worker-pid", cpu, 43);
    if (emit("MITIGATION-WORKER BEGIN phase=%s cpu=%d pid=%ld affinity=%llx\n",
             phase, cpu, (long)pid, (unsigned long long)observed)) return 44;

    uint64_t start = monotonic_ms();
    if (start == UINT64_MAX) return failure("clock-start", cpu, 45);
    volatile uint64_t accumulator = (uint64_t)pid ^ ((uint64_t)cpu << 32);
    unsigned long calls = 0;
    for (unsigned int batch = 0; batch < 4096; ++batch) {
        /* Stay in CPL3 between syscall bursts so timer-origin transitions run. */
        for (unsigned int work = 0; work < 65536; ++work)
            accumulator = accumulator * UINT64_C(6364136223846793005) + 1;
        for (unsigned int call = 0; call < 32; ++call) {
            if (syscall(SYS_getpid) != pid) return failure("getpid", cpu, 46);
            ++calls;
        }
        uint64_t now = monotonic_ms();
        if (now == UINT64_MAX || now < start) return failure("clock-progress", cpu, 47);
        if (now - start >= PHASE_MS) {
            if (emit("MITIGATION-WORKER PASS phase=%s cpu=%d pid=%ld calls=%lu elapsed_ms=%llu checksum=%llx\n",
                     phase, cpu, (long)pid, calls, (unsigned long long)(now - start),
                     (unsigned long long)accumulator)) return 48;
            return 0;
        }
    }
    return failure("timer-progress-bound", cpu, 49);
}

static void pause_poll(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
    nanosleep(&delay, NULL);
}

static int reap_workers(pid_t children[PROBE_CPUS], int error) {
    for (int poll = 0; poll < WAIT_POLLS; ++poll) {
        int pending = 0;
        for (int cpu = 0; cpu < PROBE_CPUS; ++cpu) {
            if (children[cpu] <= 0) continue;
            int status = -1;
            pid_t observed = waitpid(children[cpu], &status, WNOHANG);
            if (observed == children[cpu]) {
                int code = WIFEXITED(status) ? WEXITSTATUS(status) :
                           WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 50;
                if (emit("MITIGATION-WAIT %s cpu=%d pid=%ld raw_status=%d code=%d\n",
                         code ? "FAIL" : "PASS", cpu, (long)children[cpu], status, code) && !error)
                    error = 51;
                if (code && !error) error = code;
                children[cpu] = -1;
            } else if (observed < 0 && errno != EINTR) {
                if (!error) error = failure("waitpid", cpu, 52);
                children[cpu] = -1;
            } else {
                ++pending;
            }
        }
        if (!pending) return error;
        pause_poll();
    }
    if (!error) error = failure("worker-deadline", -1, 124);
    for (int cpu = 0; cpu < PROBE_CPUS; ++cpu)
        if (children[cpu] > 0) kill(children[cpu], SIGKILL);
    for (int poll = 0; poll < CLEANUP_POLLS; ++poll) {
        int pending = 0;
        for (int cpu = 0; cpu < PROBE_CPUS; ++cpu) {
            if (children[cpu] <= 0) continue;
            pid_t observed = waitpid(children[cpu], NULL, WNOHANG);
            if (observed == children[cpu] || (observed < 0 && errno == ECHILD))
                children[cpu] = -1;
            else
                ++pending;
        }
        if (!pending) return error;
        pause_poll();
    }
    for (int cpu = 0; cpu < PROBE_CPUS; ++cpu)
        if (children[cpu] > 0)
            emit("MITIGATION-WORKLOAD UNREAPED cpu=%d pid=%ld after=SIGKILL\n",
                 cpu, (long)children[cpu]);
    return error;
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "--exec-worker") &&
        argv[2][0] >= '0' && argv[2][0] < '0' + PROBE_CPUS && argv[2][1] == '\0')
        return worker_phase(argv[2][0] - '0', "exec");
    if (argc != 1) return failure("arguments", -1, 53);
    uint64_t available;
    if (!read_affinity(&available) || (available & 15) != 15)
        return failure("four-cpu-availability", -1, 54);
    /* The bootstrap shell can leave its prompt unterminated before PID1 runs. */
    if (emit("\nMITIGATION-WORKLOAD BEGIN pid=%ld cpus=4 forks=4 execs=4\n", (long)getpid())) return 55;
    pid_t children[PROBE_CPUS] = {-1, -1, -1, -1};
    int error = 0;
    for (int cpu = 0; cpu < PROBE_CPUS; ++cpu) {
        pid_t child = (pid_t)syscall(SYS_fork);
        if (child == 0) {
            int code = worker_phase(cpu, "fork");
            if (code) child_exit(code);
            char cpu_text[2] = {(char)('0' + cpu), '\0'};
            execl("/musl-test", "mitigation-probe", "--exec-worker", cpu_text, (char *)NULL);
            child_exit(failure("execve", cpu, 56));
        }
        if (child < 0) {
            error = failure("fork", cpu, 57);
            break;
        }
        children[cpu] = child;
    }
    error = reap_workers(children, error);
    if (error) return error;
    if (emit("MITIGATION-WORKLOAD PASS cpus=4 forks=4 execs=4\n")) return 58;
    return 0;
}
