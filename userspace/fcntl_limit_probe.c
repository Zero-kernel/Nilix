/* KSA-013: real Ring-3 file-description status and numeric NOFILE oracles.
 * Each case runs in a child with a deadline, so a broken NONBLOCK path cannot
 * hang the entire musl program or leave its descriptor table/limits altered.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FDL_CHECK(condition) do { \
    if (!(condition)) { \
        printf("KSA-013-FAIL case=%s line=%d errno=%d\n", __func__, __LINE__, errno); \
        fflush(stdout); \
        return 1; \
    } \
} while (0)

#define FDL_ERR(expression, expected) do { \
    errno = 0; \
    long observed = (long)(expression); \
    int observed_errno = errno; \
    if (observed != -1 || observed_errno != (expected)) { \
        printf("KSA-013-FAIL case=%s line=%d result=%ld errno=%d expected=%d\n", \
               __func__, __LINE__, observed, observed_errno, (expected)); \
        fflush(stdout); \
        return 1; \
    } \
} while (0)

static void fdlimit_exit(int code) {
    syscall(SYS_exit, code);
    __builtin_unreachable();
}

static int fdlimit_reap(pid_t child) {
    if (child <= 0) return 0;
    for (int tick = 0; tick < 1000; ++tick) {
        int status = -1;
        pid_t observed = waitpid(child, &status, WNOHANG);
        if (observed == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (observed < 0 && errno != EINTR) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    printf("KSA-013-TIMEOUT pid=%ld\n", (long)child);
    fflush(stdout);
    kill(child, SIGKILL);
    for (int tick = 0; tick < 200; ++tick) {
        pid_t observed = waitpid(child, NULL, WNOHANG);
        if (observed == child || (observed < 0 && errno == ECHILD)) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    printf("KSA-013-UNREAPED pid=%ld after=SIGKILL\n", (long)child);
    fflush(stdout);
    return 0;
}

static int fdlimit_flags(int fd, int access, int status) {
    int flags = fcntl(fd, F_GETFL);
    const int mask = O_ACCMODE | O_APPEND | O_NONBLOCK;
    return flags >= 0 && (flags & mask) == (access | status) &&
           !(flags & (O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC));
}

static int fdlimit_regular(const char *path) {
    int file = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    FDL_CHECK(file >= 0 && fdlimit_flags(file, O_RDWR, 0));
    int duplicate = dup(file), independent = open(path, O_RDWR);
    FDL_CHECK(duplicate >= 0 && independent >= 0);
    FDL_CHECK(fcntl(file, F_GETFD) == FD_CLOEXEC && fcntl(duplicate, F_GETFD) == 0);
    FDL_CHECK(write(file, "abc", 3) == 3 && lseek(duplicate, 0, SEEK_SET) == 0);
    FDL_CHECK(fcntl(duplicate, F_SETFL, O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC) == 0);
    FDL_CHECK(fdlimit_flags(file, O_RDWR, O_APPEND | O_NONBLOCK));
    FDL_CHECK(fdlimit_flags(independent, O_RDWR, 0));
    FDL_CHECK(fcntl(file, F_GETFD) == FD_CLOEXEC && fcntl(duplicate, F_GETFD) == 0);
    FDL_CHECK(write(file, "D", 1) == 1 && lseek(file, 0, SEEK_CUR) == 4);
    FDL_CHECK(pwrite(duplicate, "E", 1, 0) == 1 && lseek(file, 0, SEEK_CUR) == 4);
    char bytes[5];
    FDL_CHECK(pread(file, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes) && !memcmp(bytes, "abcDE", 5));
    FDL_CHECK(write(independent, "Z", 1) == 1);

    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        int ok = fdlimit_flags(duplicate, O_RDWR, O_APPEND | O_NONBLOCK) &&
                 fcntl(duplicate, F_SETFL, O_NONBLOCK) == 0 &&
                 lseek(duplicate, 1, SEEK_SET) == 1 && write(duplicate, "Q", 1) == 1;
        fdlimit_exit(ok ? 0 : 61);
    }
    FDL_CHECK(fdlimit_reap(child));
    FDL_CHECK(fdlimit_flags(file, O_RDWR, O_NONBLOCK) && lseek(file, 0, SEEK_CUR) == 2);
    FDL_CHECK(fdlimit_flags(independent, O_RDWR, 0));
    FDL_CHECK(pread(file, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes) && !memcmp(bytes, "ZQcDE", 5));
    FDL_ERR(fcntl(file, F_SETFL, O_ASYNC), EOPNOTSUPP);
    FDL_CHECK(fdlimit_flags(duplicate, O_RDWR, O_NONBLOCK));
    int readonly = open(path, O_RDONLY), path_only = open(path, O_PATH | O_CLOEXEC);
    FDL_CHECK(readonly >= 0 && path_only >= 0);
    FDL_CHECK(fcntl(readonly, F_SETFL, O_WRONLY | O_APPEND) == 0);
    FDL_CHECK(fdlimit_flags(readonly, O_RDONLY, O_APPEND));
    FDL_ERR(write(readonly, "denied", 6), EBADF);
    FDL_CHECK(fcntl(path_only, F_GETFL) == O_PATH);
    FDL_ERR(fcntl(path_only, F_SETFL, 0), EBADF);
    FDL_ERR(fcntl(-1, F_GETFL), EBADF);
    FDL_ERR(fcntl(-1, F_SETFL, O_NONBLOCK), EBADF);
    return 0;
}

static int fdlimit_pipe(const char *unused) {
    (void)unused;
    int ends[2];
    FDL_CHECK(pipe2(ends, O_NONBLOCK | O_CLOEXEC) == 0);
    FDL_CHECK(fdlimit_flags(ends[0], O_RDONLY, O_NONBLOCK));
    FDL_CHECK(fdlimit_flags(ends[1], O_WRONLY, O_NONBLOCK));
    FDL_CHECK(fcntl(ends[0], F_GETFD) == FD_CLOEXEC && fcntl(ends[1], F_GETFD) == FD_CLOEXEC);
    char byte = 0;
    FDL_ERR(read(ends[0], &byte, 1), EAGAIN);
    int read_copy = dup(ends[0]), write_copy = dup(ends[1]);
    FDL_CHECK(read_copy >= 0 && write_copy >= 0 && fcntl(read_copy, F_GETFD) == 0);
    FDL_CHECK(fcntl(read_copy, F_SETFL, 0) == 0);
    FDL_CHECK(fdlimit_flags(ends[0], O_RDONLY, 0));
    FDL_CHECK(fdlimit_flags(ends[1], O_WRONLY, O_NONBLOCK));
    FDL_CHECK(fcntl(ends[0], F_SETFL, O_NONBLOCK | O_APPEND) == 0);
    FDL_CHECK(fdlimit_flags(read_copy, O_RDONLY, O_NONBLOCK | O_APPEND));

    char payload[256];
    memset(payload, 0x5a, sizeof(payload));
    size_t total = 0;
    while (total < 65536) {
        errno = 0;
        ssize_t count = write(ends[1], payload, sizeof(payload));
        if (count == -1 && errno == EAGAIN) break;
        FDL_CHECK(count == (ssize_t)sizeof(payload));
        total += (size_t)count;
    }
    FDL_CHECK(total > 0 && total < 65536);
    FDL_CHECK(fcntl(write_copy, F_SETFL, 0) == 0);
    FDL_CHECK(fdlimit_flags(ends[1], O_WRONLY, 0));
    FDL_CHECK(fdlimit_flags(ends[0], O_RDONLY, O_NONBLOCK | O_APPEND));
    FDL_CHECK(fcntl(ends[1], F_SETFL, O_NONBLOCK) == 0);
    FDL_ERR(write(write_copy, "x", 1), EAGAIN);

    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        int ok = fcntl(read_copy, F_SETFL, O_NONBLOCK) == 0 &&
                 fdlimit_flags(ends[1], O_WRONLY, O_NONBLOCK);
        fdlimit_exit(ok ? 0 : 62);
    }
    FDL_CHECK(fdlimit_reap(child));
    FDL_CHECK(fdlimit_flags(ends[0], O_RDONLY, O_NONBLOCK));
    size_t drained = 0;
    while (drained < total) {
        char received[256];
        ssize_t count = read(read_copy, received, sizeof(received));
        FDL_CHECK(count == (ssize_t)sizeof(received) && !memcmp(received, payload, sizeof(payload)));
        drained += (size_t)count;
    }
    FDL_ERR(read(ends[0], &byte, 1), EAGAIN);
    FDL_CHECK(close(ends[1]) == 0 && close(write_copy) == 0);
    FDL_CHECK(read(ends[0], &byte, 1) == 0);

    /* A pipe born blocking must also change actual I/O through F_SETFL. */
    int blocking[2];
    FDL_CHECK(pipe(blocking) == 0 && fdlimit_flags(blocking[0], O_RDONLY, 0));
    int changed = dup(blocking[0]);
    FDL_CHECK(changed >= 0 && fcntl(changed, F_SETFL, O_NONBLOCK) == 0);
    FDL_ERR(read(blocking[0], &byte, 1), EAGAIN);
    return 0;
}

static int fdlimit_socket(const char *unused) {
    (void)unused;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int independent = socket(AF_INET, SOCK_DGRAM, 0);
    int born_nonblock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    FDL_CHECK(socket_fd >= 0 && independent >= 0 && born_nonblock >= 0);
    FDL_CHECK(fdlimit_flags(born_nonblock, O_RDWR, O_NONBLOCK));
    FDL_CHECK(fcntl(born_nonblock, F_GETFD) == FD_CLOEXEC);
    int duplicate = dup(socket_fd);
    FDL_CHECK(duplicate >= 0 && fcntl(duplicate, F_SETFL, O_NONBLOCK) == 0);
    FDL_CHECK(fdlimit_flags(socket_fd, O_RDWR, O_NONBLOCK));
    FDL_CHECK(fdlimit_flags(independent, O_RDWR, 0));
    char byte;
    FDL_ERR(recvfrom(socket_fd, &byte, 1, 0, NULL, NULL), EAGAIN);
    FDL_ERR(recvfrom(born_nonblock, &byte, 1, 0, NULL, NULL), EAGAIN);
    FDL_ERR(recvfrom(independent, &byte, 1, MSG_DONTWAIT, NULL, NULL), EAGAIN);
    FDL_CHECK(fdlimit_flags(independent, O_RDWR, 0));

    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) fdlimit_exit(fcntl(duplicate, F_SETFL, 0) == 0 ? 0 : 63);
    FDL_CHECK(fdlimit_reap(child));
    FDL_CHECK(fdlimit_flags(socket_fd, O_RDWR, 0));
    FDL_CHECK(fcntl(socket_fd, F_SETFL, O_NONBLOCK) == 0);
    FDL_ERR(recvfrom(duplicate, &byte, 1, 0, NULL, NULL), EAGAIN);
    FDL_ERR(fcntl(duplicate, F_SETFL, O_ASYNC), EOPNOTSUPP);
    FDL_CHECK(fdlimit_flags(socket_fd, O_RDWR, O_NONBLOCK));
    return 0;
}

static int fdlimit_nofile(const char *path) {
    static const char contents[] = "preserve under NOFILE";
    int file = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    FDL_CHECK(file == 3 && write(file, contents, sizeof(contents)) == (ssize_t)sizeof(contents));
    int high = fcntl(file, F_DUPFD, 32);
    FDL_CHECK(high == 32 && dup2(1, 40) == 40);
    struct rlimit original, limited;
    FDL_CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur > 40);
    limited = original;
    limited.rlim_cur = 8;
    FDL_CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    FDL_CHECK(fdlimit_flags(high, O_RDWR, 0) && dup2(high, high) == high);
    FDL_ERR(dup3(high, high, 0), EINVAL);
    FDL_ERR(dup2(file, 8), EBADF);
    FDL_ERR(dup3(file, 8, O_CLOEXEC), EBADF);
    FDL_ERR(dup2(file, 40), EBADF);
    FDL_CHECK(fdlimit_flags(40, O_WRONLY, 0));
    FDL_ERR(fcntl(file, F_DUPFD, 8), EINVAL);
    FDL_ERR(fcntl(file, F_DUPFD_CLOEXEC, 8), EINVAL);
    FDL_ERR(fcntl(file, F_DUPFD, -1), EINVAL);

    int held[4];
    for (int i = 0; i < 4; ++i) {
        held[i] = fcntl(file, F_DUPFD_CLOEXEC, 0);
        FDL_CHECK(held[i] == 4 + i && fcntl(held[i], F_GETFD) == FD_CLOEXEC);
    }
    /* Ten live descriptors with soft limit eight prove a numeric, not count, cap. */
    FDL_ERR(dup(high), EMFILE);
    FDL_ERR(fcntl(high, F_DUPFD, 0), EMFILE);
    FDL_ERR(socket(AF_INET, SOCK_DGRAM, 0), EMFILE);
    FDL_ERR(open(path, O_WRONLY | O_TRUNC), EMFILE);
    char observed[sizeof(contents)];
    struct stat status;
    FDL_CHECK(fstat(high, &status) == 0 && status.st_size == (off_t)sizeof(contents));
    FDL_CHECK(pread(high, observed, sizeof(observed), 0) == (ssize_t)sizeof(observed) &&
              !memcmp(contents, observed, sizeof(contents)));

    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        errno = 0;
        int ok = fdlimit_flags(high, O_RDWR, 0) && dup2(high, high) == high &&
                 dup(1) == -1 && errno == EMFILE;
        fdlimit_exit(ok ? 0 : 64);
    }
    FDL_CHECK(fdlimit_reap(child));
    FDL_CHECK(close(held[1]) == 0 && fcntl(high, F_DUPFD_CLOEXEC, 4) == 5);
    FDL_CHECK(fcntl(5, F_GETFD) == FD_CLOEXEC);
    FDL_CHECK(dup3(high, 4, O_CLOEXEC) == 4 && fcntl(4, F_GETFD) == FD_CLOEXEC);
    FDL_CHECK(close(held[3]) == 0);
    for (int attempt = 0; attempt < 4; ++attempt) {
        int ends[2] = {-7, -9};
        FDL_ERR(pipe2(ends, O_NONBLOCK | O_CLOEXEC), EMFILE);
        FDL_CHECK(ends[0] == -7 && ends[1] == -9);
        int reused = dup(high);
        FDL_CHECK(reused == 7 && close(reused) == 0);
    }
    limited.rlim_cur = 0;
    FDL_CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0 && dup2(high, high) == high);
    FDL_ERR(dup(high), EMFILE);
    FDL_CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    return 0;
}

static int fcntl_limit_smoke(void) {
    static const struct {
        const char *name;
        int (*run)(const char *path);
    } cases[] = {
        {"regular", fdlimit_regular}, {"pipe", fdlimit_pipe},
        {"socket", fdlimit_socket}, {"nofile", fdlimit_nofile},
    };
    char directory[96], path[128];
    snprintf(directory, sizeof(directory), "/ksa-fcntl-probe-%ld", (long)getpid());
    if (mkdir(directory, 0700)) {
        printf("MUSL-FCNTL-LIMIT-FAIL mkdir errno=%d\n", errno);
        return 1;
    }
    int result = 0;
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        snprintf(path, sizeof(path), "%s/%s", directory, cases[c].name);
        printf("KSA-013-CASE BEGIN case=%s\n", cases[c].name);
        fflush(NULL);
        pid_t child = (pid_t)syscall(SYS_fork);
        if (child == 0) fdlimit_exit(cases[c].run(path));
        int ok = fdlimit_reap(child);
        unlink(path); /* Only our freshly created private directory is touched. */
        if (!ok) {
            printf("MUSL-FCNTL-LIMIT-FAIL case=%s errno=%d\n", cases[c].name, errno);
            result = 1;
            break;
        }
        printf("KSA-013-CASE PASS case=%s\n", cases[c].name);
    }
    if (rmdir(directory)) {
        printf("MUSL-FCNTL-LIMIT-FAIL cleanup errno=%d\n", errno);
        result = 1;
    }
    if (!result) puts("MUSL-FCNTL-LIMIT-OK");
    return result;
}

#undef FDL_CHECK
#undef FDL_ERR
