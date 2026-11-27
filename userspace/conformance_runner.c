#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Nilix N2.2 (#66) external conformance guest runner.
 *
 * Reads /mnt/test/conformance/list.txt (lines of "<suite> <name> <path>"),
 * forks + execve's each static binary with stdout/stderr redirected to
 * /dev/null (preventing raw child output from spoofing markers), polls
 * waitpid(WNOHANG) + nanosleep up to a per-case timeout (no alarm dependency),
 * SIGKILLs timed-out children, and emits structured CONF-CASE / CONF-SUMMARY
 * serial records for scripts/gates/conformance/conformance_gate.py.
 */

#define LIST_PATH "/mnt/test/conformance/list.txt"
#define WORK_DIR "/tmp"
#define DEFAULT_TIMEOUT_MS 5000
#define POLL_NS 10000000L /* 10 ms */
#define POLL_MS 10
#define MAX_LINE 512

static void write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (n == 0) {
            return;
        }
        off += (size_t)n;
    }
}

static void emit_line(const char *line) {
    write_all(STDOUT_FILENO, line, strlen(line));
    write_all(STDOUT_FILENO, "\n", 1);
}

static long elapsed_ms(const struct timespec *start, const struct timespec *now) {
    long sec = (long)(now->tv_sec - start->tv_sec);
    long nsec = (long)(now->tv_nsec - start->tv_nsec);
    return sec * 1000L + nsec / 1000000L;
}

static int run_one_case(
    const char *suite,
    const char *name,
    const char *path,
    long timeout_ms,
    int *out_exit_code
) {
    int err_pipe[2] = {-1, -1};
    if (pipe2(err_pipe, O_CLOEXEC) != 0) {
        *out_exit_code = errno;
        return 3; /* EXECFAIL */
    }

    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        close(err_pipe[0]);
        close(err_pipe[1]);
        *out_exit_code = e;
        return 3; /* EXECFAIL */
    }

    if (pid == 0) {
        close(err_pipe[0]);
        (void)chdir(WORK_DIR);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            (void)dup2(devnull, STDIN_FILENO);
            (void)dup2(devnull, STDOUT_FILENO);
            (void)dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) {
                close(devnull);
            }
        }

        char *const argv[] = {(char *)path, NULL};
        char *const envp[] = {"PATH=/mnt/test/conformance/bin:/bin", "TMPDIR=/tmp", NULL};
        execve(path, argv, envp);

        int e = errno;
        (void)write(err_pipe[1], &e, sizeof(e));
        close(err_pipe[1]);
        _exit(127);
    }

    close(err_pipe[1]);

    int status = 0;
    int reaped = 0;
    struct timespec start = {0, 0};
    struct timespec now = {0, 0};
    int have_clock = (clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    long waited_ms = 0;

    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            reaped = 1;
            break;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (have_clock && clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            if (elapsed_ms(&start, &now) >= timeout_ms) {
                break;
            }
        } else if (waited_ms >= timeout_ms) {
            break;
        }

        struct timespec req = {0, POLL_NS};
        (void)nanosleep(&req, NULL);
        waited_ms += POLL_MS;
    }

    if (!reaped) {
        (void)kill(pid, SIGKILL);
        for (int i = 0; i < 200; i++) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            if (r == pid || (r < 0 && errno == ECHILD)) {
                reaped = 1;
                break;
            }
            struct timespec req = {0, POLL_NS};
            (void)nanosleep(&req, NULL);
        }
        close(err_pipe[0]);
        *out_exit_code = 137;
        return 2; /* TIMEOUT */
    }

    int exec_err = 0;
    ssize_t n = read(err_pipe[0], &exec_err, sizeof(exec_err));
    close(err_pipe[0]);
    if (n == (ssize_t)sizeof(exec_err) && exec_err != 0) {
        *out_exit_code = exec_err;
        return 3; /* EXECFAIL */
    }

    int code = 1;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        code = 128 + WTERMSIG(status);
    }
    *out_exit_code = code;

    (void)suite;
    (void)name;
    return (code == 0) ? 0 : 1; /* 0=PASS, 1=FAIL */
}

int main(void) {
    (void)mkdir(WORK_DIR, 0755);

    FILE *fp = fopen(LIST_PATH, "r");
    if (!fp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "CONF-ERROR cannot open %s errno=%d", LIST_PATH, errno);
        emit_line(msg);
        return 1;
    }

    int total = 0;
    int passed = 0;
    int failed = 0;
    int timed_out = 0;
    int exec_failed = 0;
    char last_suite[64] = "unknown";
    char line[MAX_LINE];

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '#') {
            continue;
        }

        char suite[64];
        char name[128];
        char path[256];
        if (sscanf(p, "%63s %127s %255s", suite, name, path) != 3) {
            continue;
        }

        snprintf(last_suite, sizeof(last_suite), "%s", suite);
        int exit_code = 0;
        int rc = run_one_case(suite, name, path, DEFAULT_TIMEOUT_MS, &exit_code);
        const char *st = "FAIL";
        if (rc == 0) {
            st = "PASS";
            passed++;
        } else if (rc == 2) {
            st = "TIMEOUT";
            timed_out++;
        } else if (rc == 3) {
            st = "EXECFAIL";
            exec_failed++;
        } else {
            st = "FAIL";
            failed++;
        }
        total++;

        char out[512];
        snprintf(
            out,
            sizeof(out),
            "CONF-CASE suite=%s name=%s status=%s exit=%d",
            suite,
            name,
            st,
            exit_code
        );
        emit_line(out);

        /* Reap any grandchildren reparented to PID 1 by the finished test case. */
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
    }

    fclose(fp);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }

    char summary[256];
    snprintf(
        summary,
        sizeof(summary),
        "CONF-SUMMARY suite=%s total=%d pass=%d fail=%d timeout=%d execfail=%d",
        last_suite,
        total,
        passed,
        failed,
        timed_out,
        exec_failed
    );
    emit_line(summary);
    return 0;
}
