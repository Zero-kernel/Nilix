/* KSA-011/012: real Ring-3 wait identity and masked default-action oracles. */
#include <sched.h>
#include <signal.h>

static void abi_child_exit(int code) {
    syscall(SYS_exit, code);
    __builtin_unreachable();
}

static int wait_exact_code(pid_t child, int code) {
    int status = -1;
    return child > 0 && waitpid(child, &status, 0) == child &&
           WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static int procfs_fd_lock_smoke(void) {
    char contents[128];
    int fd = open("/proc/self/stat", O_RDWR | O_CLOEXEC);
    if (fd < 0) goto fail;
    if (read(fd, contents, sizeof(contents)) <= 0) { close(fd); goto fail; }
    errno = 0;
    ssize_t result = write(fd, "x", 1);
    int saved_errno = errno;
    close(fd);
    /* The existing IPC errno adapter reports unsupported procfs writes as ENOSYS. */
    if (result != -1 || saved_errno != ENOSYS) goto fail;
    fd = open("/", O_RDONLY | O_DIRECTORY);
    if (fd < 0) goto fail;
    errno = 0;
    result = read(fd, contents, sizeof(contents));
    saved_errno = errno;
    close(fd);
    if (result != -1 || saved_errno != EISDIR) goto fail;
    puts("MUSL-PROCFS-FD-OK");
    return 0;
fail:
    puts("MUSL-PROCFS-FD-FAIL");
    return 1;
}

static int read_probe_byte(int fd, char expected, int timeout_ms) {
    struct pollfd event = {.fd = fd, .events = POLLIN};
    char byte = 0;
    return poll(&event, 1, timeout_ms) == 1 && (event.revents & POLLIN) &&
           read(fd, &byte, 1) == 1 && byte == expected;
}

static int wait_probe_stopped(pid_t child, int output_fd) {
    char path[64], contents[512];
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)child) >= (int)sizeof(path))
        return 0;
    for (int attempt = 0; attempt < 600; ++attempt) {
        struct pollfd event = {.fd = output_fd, .events = POLLIN};
        /* Silence alone cannot prove STOP: a slow child may not have sent it.
         * Observe its published stopped state before generating SIGCONT. */
        if (poll(&event, 1, 0) != 0) return 0;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        ssize_t count = read(fd, contents, sizeof(contents) - 1);
        close(fd);
        if (count <= 0) return 0;
        contents[count] = '\0';
        char *name_end = strrchr(contents, ')');
        if (name_end && strncmp(name_end, ") T ", 4) == 0)
            return poll(&event, 1, 100) == 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    return 0;
}

static int nested_wait_body(void) {
    int gate[2];
    if (pipe(gate)) return 11;
    pid_t worker = (pid_t)syscall(SYS_fork);
    if (worker == 0) {
        close(gate[1]);
        char byte;
        if (read(gate[0], &byte, 1) != 1) abi_child_exit(12);
        abi_child_exit(37);
    }
    close(gate[0]);
    int status = -1;
    if (worker <= 1 || waitpid(worker, &status, WNOHANG) != 0) return 13;
    if (write(gate[1], "x", 1) != 1) return 14;
    close(gate[1]);
    errno = 0;
    if (syscall(SYS_wait4, worker, (int *)1, 0, 0) != -1 || errno != EFAULT) return 15;
    if (!wait_exact_code(worker, 37)) return 16;
    worker = (pid_t)syscall(SYS_fork);
    if (worker == 0) abi_child_exit(38);
    if (worker <= 1 || waitpid(-1, &status, 0) != worker ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 38) return 17;
    return 0;
}

static int wait_namespace_smoke(void) {
    if (procfs_fd_lock_smoke()) return 1;
    pid_t supervisor = (pid_t)syscall(SYS_fork);
    if (supervisor == 0) {
        if (syscall(SYS_unshare, CLONE_NEWPID)) abi_child_exit(18);
        pid_t init = (pid_t)syscall(SYS_fork);
        if (init == 0) {
            if (getpid() != 1) abi_child_exit(19);
            abi_child_exit(nested_wait_body());
        }
        abi_child_exit(wait_exact_code(init, 0) ? 0 : 20);
    }
    if (!wait_exact_code(supervisor, 0)) {
        puts("MUSL-WAIT-NAMESPACE-FAIL");
        return 1;
    }
    puts("MUSL-WAIT-NAMESPACE-OK");
    return 0;
}

static int blocked_default_signal_smoke(void) {
    for (int mode = 0; mode < 5; ++mode) {
        int ready[2], release[2];
        if (pipe(ready) || pipe(release)) return 1;
        pid_t child = (pid_t)syscall(SYS_fork);
        if (child == 0) {
            close(ready[0]);
            close(release[1]);
            int sig = mode == 0 ? SIGTERM : (mode == 2 ? SIGSTOP : SIGTSTP);
            uint64_t mask = 1ULL << ((mode == 2 ? SIGCONT : sig) - 1);
            if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &mask, 0, 8)) abi_child_exit(21);
            if (mode == 2) {
                struct { uint64_t handler, flags, restorer, mask; } ignore = {1, 0, 0, 0};
                if (syscall(SYS_rt_sigaction, SIGCONT, &ignore, 0, 8)) abi_child_exit(22);
            } else if (kill(getpid(), sig)) {
                abi_child_exit(23);
            }
            /* This write proves blocked TERM/TSTP did not execute at generation. */
            if (write(ready[1], "a", 1) != 1) abi_child_exit(24);
            char byte;
            if (read(release[0], &byte, 1) != 1) abi_child_exit(25);
            if (mode == 2) {
                if (kill(getpid(), SIGSTOP)) abi_child_exit(26);
            } else if (mode == 3) {
                uint64_t temporary = 0, restored = 0;
                struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
                errno = 0;
                if (syscall(SYS_ppoll, 0, 0, &timeout, &temporary, 8) != -1 || errno != EINTR)
                    abi_child_exit(30);
                if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, 0, &restored, 8) || restored != mask)
                    abi_child_exit(31);
            } else if (syscall(SYS_rt_sigprocmask, SIG_UNBLOCK, &mask, 0, 8)) {
                abi_child_exit(27);
            }
            if (mode == 0) abi_child_exit(28); /* Unblocked SIGTERM must not return. */
            if (write(ready[1], "b", 1) != 1) abi_child_exit(29);
            abi_child_exit(0);
        }
        close(ready[1]);
        close(release[0]);
        const char *stage = "child-ready";
        int ok = child > 0 && read_probe_byte(ready[0], 'a', 3000);
        if (ok) {
            stage = "release";
            ok = write(release[1], "x", 1) == 1;
        }
        close(release[1]);
        if (ok && mode != 0) {
            stage = "observe-stopped-before-resume";
            ok = wait_probe_stopped(child, ready[0]);
            if (ok) {
                stage = mode == 4 ? "kill-stopped" : "continue-stopped";
                ok = kill(child, mode == 4 ? SIGKILL : SIGCONT) == 0;
            }
            if (ok && mode != 4) {
                stage = "resumed-byte";
                ok = read_probe_byte(ready[0], 'b', 3000);
            }
        }
        close(ready[0]);
        if (!ok && child > 0) kill(child, SIGKILL);
        /* Zero-OS currently exposes signal death using normal-exit 128+signal. */
        int expected = mode == 0 ? 128 + SIGTERM : (mode == 4 ? 128 + SIGKILL : 0);
        if (!wait_exact_code(child, expected)) {
            if (ok) stage = "reap-status";
            ok = 0;
        }
        if (!ok) {
            printf("MUSL-BLOCKED-SIGNAL-FAIL mode=%d stage=%s errno=%d\n", mode, stage, errno);
            return 1;
        }
        printf("MUSL-BLOCKED-SIGNAL-CASE-PASS mode=%d\n", mode);
    }
    puts("MUSL-BLOCKED-SIGNAL-OK");
    return 0;
}
