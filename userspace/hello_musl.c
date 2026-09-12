// Simple musl test program for Zero-OS
// This tests basic musl libc initialization and I/O
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "wait_signal_probe.c"
#include "fcntl_limit_probe.c"
#include "exit_idle_probe.c"
#include "vfs_context_probe.c"
#include "tls_context_probe.c"

#ifdef KSA_OPEN_FAULT_PROBE
#include "open_fault_probe.c"
#endif

static int fd_exec_check(void) {
    struct stat st;
    const int closed[] = {0, 2, 32};
    for (size_t i = 0; i < sizeof(closed) / sizeof(closed[0]); i++) {
        errno = 0;
        if (fcntl(closed[i], F_GETFD) != -1 || errno != EBADF) return 101;
    }
    if (fstat(1, &st) || !S_ISREG(st.st_mode)) return 102;
    if (fcntl(1, F_GETFD) != 0) return 103;
    return write(1, "ok", 2) == 2 ? 0 : 104;
}

static int standard_fd_smoke(void) {
    int saved[3] = {-1, -1, -1}, p[2] = {-1, -1}, file = -1;
    int held[256], held_count = 0, status = -1, result = 1;
    const char *stage = "save";
    char bytes[2];
    struct stat st;
    fflush(NULL);
    for (int i = 0; i < 3; i++) {
        if ((saved[i] = dup(i)) < 0) goto done;
    }
    stage = "close";
    if (close(0)) goto done;
    errno = 0;
    if (fcntl(0, F_GETFD) != -1 || errno != EBADF) goto done;
    struct pollfd probe = {.fd = 0, .events = POLLIN};
    if (poll(&probe, 1, 0) != 1 || !(probe.revents & POLLNVAL)) goto done;
    if (dup2(saved[0], 0) != 0) goto done;

    stage = "pipe redirection";
    if (pipe(p) || dup2(p[0], 0) != 0 || dup2(p[1], 1) != 1 ||
        dup2(p[1], 2) != 2) goto done;
    if (fstat(1, &st) || !S_ISFIFO(st.st_mode)) goto done;
    if (write(1, "A", 1) != 1 || write(2, "B", 1) != 1) goto done;
    probe.revents = 0;
    if (poll(&probe, 1, 0) != 1 || !(probe.revents & POLLIN)) goto done;
    if (read(0, bytes, 2) != 2 || memcmp(bytes, "AB", 2)) goto done;
    for (int i = 0; i < 3; i++) if (dup2(saved[i], i) != i) goto done;
    close(p[0]); close(p[1]); p[0] = p[1] = -1;

    stage = "fork/exec inheritance";
    file = open("/ksa-fd-file", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (file < 0 || dup3(file, 32, O_CLOEXEC) != 32 || dup2(32, 1) != 1 ||
        close(0) || fcntl(2, F_SETFD, FD_CLOEXEC)) goto done;
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        errno = 0;
        if (fcntl(0, F_GETFD) != -1 || errno != EBADF ||
            fcntl(2, F_GETFD) != FD_CLOEXEC) syscall(SYS_exit, 105);
        execl("/musl-test", "musl-test", "--fd-exec-check", (char *)NULL);
        syscall(SYS_exit, 106);
        __builtin_unreachable();
    }
    for (int i = 0; i < 3; i++) if (dup2(saved[i], i) != i) goto done;
    close(32);
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) goto done;
    if (pread(file, bytes, 2, 0) != 2 || memcmp(bytes, "ok", 2)) goto done;
    puts("MUSL-STANDARD-FD-OK");

    stage = "failed O_TRUNC";
    while (held_count < 256) {
        int next = dup(saved[1]);
        if (next < 0) break;
        held[held_count++] = next;
    }
    if (held_count == 256 || errno != EMFILE) goto done;
    errno = 0;
    int rejected = open("/ksa-fd-file", O_WRONLY | O_TRUNC);
    if (rejected >= 0) { close(rejected); goto done; }
    if (errno != EMFILE || pread(file, bytes, 2, 0) != 2 || memcmp(bytes, "ok", 2)) goto done;
    while (held_count) close(held[--held_count]);
    stage = "successful O_TRUNC";
    int truncated = open("/ksa-fd-file", O_WRONLY | O_TRUNC);
    if (truncated < 0) goto done;
    close(truncated);
    if (fstat(file, &st) || st.st_size != 0) goto done;
    puts("MUSL-OPEN-TRUNC-OK");
    result = 0;
done:
    while (held_count) close(held[--held_count]);
    for (int i = 0; i < 3; i++) {
        if (saved[i] >= 0) { dup2(saved[i], i); close(saved[i]); }
    }
    if (p[0] >= 0) close(p[0]);
    if (p[1] >= 0) close(p[1]);
    if (file >= 0) close(file);
    close(32);
    if (result) printf("MUSL-STANDARD-FD-FAIL stage=%s errno=%d child_status=%d\n", stage, errno, status);
    return result;
}

static int robust_usercopy_smoke(void) {
    for (int mode = 0; mode < 3; mode++) {
        pid_t child = (pid_t)syscall(SYS_fork);
        if (child == 0) {
            char *pages = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            uint32_t *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (pages == MAP_FAILED || word == MAP_FAILED) syscall(SYS_exit, 111);
            struct robust_head { void *next; long offset; void *pending; } head;
            head.next = pages;
            head.offset = (intptr_t)word - (intptr_t)pages;
            head.pending = NULL;
            *(void **)pages = &head;
            *word = (uint32_t)syscall(SYS_gettid);
            if (syscall(SYS_set_robust_list, &head, sizeof(head))) syscall(SYS_exit, 112);
            if (mode == 1 && mprotect(word, 4096, PROT_READ)) syscall(SYS_exit, 113);
            // A separate mapping removes the entire word region while the
            // list node stays readable, so cleanup must fault on the word.
            if (mode == 2 && munmap(word, 4096)) syscall(SYS_exit, 114);
            syscall(SYS_exit, 0);
            __builtin_unreachable();
        }
        int status = -1;
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("MUSL-ROBUST-USERCOPY-FAIL mode=%d status=%d errno=%d\n", mode, status, errno);
            return 1;
        }
    }
    puts("MUSL-ROBUST-USERCOPY-OK");
    return 0;
}

// M0-6 poll/select Ring-3 smoke: exercises the real syscall boundary (dispatch
// arms, PollFd / fd_set copy-in, revents / fd_set write-back, timeout casts) that
// the in-kernel self-tests cannot reach. Prints MUSL-POLL-OK only if every check
// passes; on failure prints a distinct diagnostic (so the musl gate fails loudly
// with the failing values). Every call here is non-blocking or a ~1ms sleep.
static void poll_smoke(void) {
    int pfd[2];
    if (pipe(pfd) != 0) {
        printf("MUSL-POLL-FAIL pipe errno=%d\n", errno);
        return;
    }

    // poll: the write end is writable now (timeout 0 => no block).
    struct pollfd pw = { .fd = pfd[1], .events = POLLOUT, .revents = 0 };
    int r1 = poll(&pw, 1, 0);

    // poll: the read end is NOT readable yet (empty pipe, writer alive).
    struct pollfd pr = { .fd = pfd[0], .events = POLLIN, .revents = 0 };
    int r2 = poll(&pr, 1, 0);

    // write one byte, then select must see the read end readable.
    write(pfd[1], "x", 1);
    fd_set rs;
    FD_ZERO(&rs);
    FD_SET(pfd[0], &rs);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
    int r3 = select(pfd[0] + 1, &rs, NULL, NULL, &tv);

    // ppoll with no fds and a 1ms timeout returns 0 (timed out).
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
    int r4 = ppoll(NULL, 0, &ts, NULL);

    // a bad fds pointer must fault with EFAULT.
    errno = 0;
    int r5 = poll((struct pollfd *)1, 1, 0);
    int e5 = errno;

    if (r1 == 1 && (pw.revents & POLLOUT) &&
        r2 == 0 &&
        r3 == 1 && FD_ISSET(pfd[0], &rs) &&
        r4 == 0 &&
        r5 == -1 && e5 == EFAULT) {
        puts("MUSL-POLL-OK");
    } else {
        printf("MUSL-POLL-FAIL r1=%d rev=%d r2=%d r3=%d r4=%d r5=%d e5=%d\n",
               r1, (int)pw.revents, r2, r3, r4, r5, e5);
    }

    close(pfd[0]);
    close(pfd[1]);
}

// RF180-27 Ring-3 socket ABI smoke. Zero-length I/O is not a blanket syscall
// no-op: validation must still run, and TCP's empty receive succeeds without a
// buffer while empty send still enforces connection state. Hosted socket tests
// prove UDP emits an eight-byte header; this Ring-3 probe proves the parseable
// datagram reaches production default-deny policy with the correct errno.
static void socket_zero_length_smoke(void) {
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    int tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (udp < 0 || tcp < 0) {
        printf("MUSL-SOCKET-ZERO-FAIL socket udp=%d tcp=%d errno=%d\n",
               udp, tcp, errno);
        if (udp >= 0) close(udp);
        if (tcp >= 0) close(tcp);
        return;
    }

    errno = 0;
    ssize_t bad_send_flags = sendto(udp, NULL, 0, MSG_OOB, NULL, 0);
    int bad_send_flags_errno = errno;

    errno = 0;
    ssize_t bad_recv_flags = recvfrom(udp, NULL, 0, MSG_OOB, NULL, NULL);
    int bad_recv_flags_errno = errno;

    errno = 0;
    ssize_t bad_send_fd = sendto(-1, NULL, 0, 0, NULL, 0);
    int bad_send_fd_errno = errno;

    errno = 0;
    ssize_t bad_recv_fd = recvfrom(-1, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    int bad_recv_fd_errno = errno;

    errno = 0;
    ssize_t missing_udp_dest = sendto(udp, NULL, 0, 0, NULL, 0);
    int missing_udp_dest_errno = errno;

    // A zero-byte stream receive is an immediate no-op, but send still checks
    // that the connection exists. NULL is valid because no payload byte is copied.
    errno = 0;
    ssize_t tcp_send_zero = send(tcp, NULL, 0, 0);
    int tcp_send_zero_errno = errno;

    errno = 0;
    ssize_t tcp_recv_zero = recv(tcp, NULL, 0, MSG_DONTWAIT);
    int tcp_recv_zero_errno = errno;

    // The production root namespace is default-deny. Requiring EPERM proves
    // the zero-length request passed fd/rights/sockaddr validation, serialized
    // a parseable eight-byte UDP header, and reached egress policy instead of
    // returning an incorrect early success or malformed-buffer EINVAL.
    struct sockaddr_in gateway;
    memset(&gateway, 0, sizeof(gateway));
    gateway.sin_family = AF_INET;
    gateway.sin_port = htons(9);
    gateway.sin_addr.s_addr = htonl(0x0a000202U); // 10.0.2.2
    errno = 0;
    ssize_t udp_send_zero = sendto(
        udp, NULL, 0, 0, (const struct sockaddr *)&gateway, sizeof(gateway));
    int udp_send_zero_errno = errno;

    if (bad_send_flags == -1 && bad_send_flags_errno == EINVAL &&
        bad_recv_flags == -1 && bad_recv_flags_errno == EINVAL &&
        bad_send_fd == -1 && bad_send_fd_errno == EBADF &&
        bad_recv_fd == -1 && bad_recv_fd_errno == EBADF &&
        missing_udp_dest == -1 && missing_udp_dest_errno == EDESTADDRREQ &&
        tcp_send_zero == -1 && tcp_send_zero_errno == ENOTCONN &&
        tcp_recv_zero == 0 &&
        udp_send_zero == -1 && udp_send_zero_errno == EPERM) {
        puts("MUSL-SOCKET-ZERO-OK");
    } else {
        printf("MUSL-SOCKET-ZERO-FAIL sf=%ld/%d rf=%ld/%d sfd=%ld/%d "
               "rfd=%ld/%d md=%ld/%d ts=%ld/%d tr=%ld/%d us=%ld/%d\n",
               (long)bad_send_flags, bad_send_flags_errno,
               (long)bad_recv_flags, bad_recv_flags_errno,
               (long)bad_send_fd, bad_send_fd_errno,
               (long)bad_recv_fd, bad_recv_fd_errno,
               (long)missing_udp_dest, missing_udp_dest_errno,
               (long)tcp_send_zero, tcp_send_zero_errno,
               (long)tcp_recv_zero, tcp_recv_zero_errno,
               (long)udp_send_zero, udp_send_zero_errno);
    }

    close(udp);
    close(tcp);
}

// D2-ABI-STAT-LAYOUT Ring-3 smoke: the kernel must emit the exact Linux x86-64
// struct stat (144B) wire layout musl compiles against (st_nlink u64@16,
// st_mode@24, st_rdev@40, ...). Buffers are prefilled with 0x5a so stale bytes
// cannot fake a pass; the explicit pad (@36) and reserved tail (@120..144)
// must come back zero, proving the kernel wrote the FULL record and no stale
// data leaks through the gaps. The fstat leg uses a pipe fd (deterministic
// S_IFIFO from the kernel's pipe FileOps) instead of fd 1, whose backing
// object is a harness detail.
static void stat_abi_smoke(void) {
    _Static_assert(sizeof(struct stat) == 144, "x86-64 struct stat must be 144 bytes");

    struct stat st;
    memset(&st, 0x5a, sizeof(st));
    errno = 0;
    int r = stat("/", &st);
    int st_errno = errno;
    const unsigned char *b = (const unsigned char *)&st;
    int pad_zero = (b[36] | b[37] | b[38] | b[39]) == 0;
    int tail_zero = 1;
    for (size_t i = 120; i < 144; i++) {
        if (b[i] != 0) tail_zero = 0;
    }

    int pfd[2];
    struct stat pst;
    memset(&pst, 0x5a, sizeof(pst));
    int rp = -1;
    if (pipe(pfd) == 0) {
        rp = fstat(pfd[0], &pst);
        close(pfd[0]);
        close(pfd[1]);
    }

    if (r == 0 && S_ISDIR(st.st_mode) && st.st_nlink >= 1 && st.st_size >= 0 &&
        pad_zero && tail_zero && rp == 0 && S_ISFIFO(pst.st_mode)) {
        puts("MUSL-STAT-OK");
    } else {
        printf("MUSL-STAT-FAIL r=%d errno=%d mode=%o nlink=%lu size=%lld pad=%d "
               "tail=%d rp=%d pmode=%o\n",
               r, st_errno, (unsigned)st.st_mode, (unsigned long)st.st_nlink,
               (long long)st.st_size, pad_zero, tail_zero, rp,
               (unsigned)pst.st_mode);
    }
}

// D2-ABI-STAT-LAYOUT (LOW leg): the kernel must write the full 390-byte Linux
// new_utsname INCLUDING domainname ("(none)" default). Before the fix the
// kernel wrote only 325 bytes, leaving domainname as stale caller memory —
// the 0x5a prefill would surface that as a mismatch here.
static void uname_abi_smoke(void) {
    _Static_assert(sizeof(struct utsname) == 390, "x86-64 new_utsname must be 390 bytes");

    struct utsname u;
    memset(&u, 0x5a, sizeof(u));
    if (uname(&u) == 0 && strcmp(u.sysname, "Zero-OS") == 0 &&
        strcmp(u.domainname, "(none)") == 0) {
        puts("MUSL-UNAME-OK");
    } else {
        printf("MUSL-UNAME-FAIL sys=%.8s dom=%.8s\n", u.sysname, u.domainname);
    }
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && strcmp(argv[1], "--vfs-cwd-exec-check") == 0) return vfs_context_exec_check(argc, argv);
    if (argc == 2 && strcmp(argv[1], "--fd-exec-check") == 0) return fd_exec_check();
    // Test 1: Simple write syscall
    const char *msg = "Hello from musl libc!\n";
    write(1, msg, 22);

    // Test 2: getpid
    pid_t pid = getpid();
    printf("My PID: %d\n", pid);

    // Test 3: Simple calculation
    int result = 42 * 2;
    printf("42 * 2 = %d\n", result);

    // Test 5 (M0-6): poll/select/ppoll end-to-end smoke.
    poll_smoke();

    // Test 6 (RF180-27): zero-length socket validation/semantics.
    socket_zero_length_smoke();

    // Test 7 (D2-ABI-STAT-LAYOUT): Linux stat wire-layout end-to-end.
    stat_abi_smoke();

    // Test 8 (D2-ABI-STAT-LAYOUT LOW leg): full new_utsname write.
    uname_abi_smoke();

    if (standard_fd_smoke() || robust_usercopy_smoke()) return 1;
    if (fcntl_limit_smoke()) return 1;
    if (exit_idle_smoke()) return 1;
    if (tls_context_smoke()) return 1;
    if (vfs_context_probe()) return 1;
    if (wait_namespace_smoke() || blocked_default_signal_smoke()) return 1;
#ifdef KSA_OPEN_FAULT_PROBE
    if (open_fault_smoke()) return 1;
#endif
    puts("musl libc test passed!");

    return 0;
}
