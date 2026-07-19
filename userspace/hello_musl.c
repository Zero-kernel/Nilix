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

int main(int argc, char *argv[]) {
    // Test 1: Simple write syscall
    const char *msg = "Hello from musl libc!\n";
    write(1, msg, 22);

    // Test 2: getpid
    pid_t pid = getpid();
    printf("My PID: %d\n", pid);

    // Test 3: Simple calculation
    int result = 42 * 2;
    printf("42 * 2 = %d\n", result);

    // Test 4: Success message
    puts("musl libc test passed!");

    // Test 5 (M0-6): poll/select/ppoll end-to-end smoke.
    poll_smoke();

    // Test 6 (RF180-27): zero-length socket validation/semantics.
    socket_zero_length_smoke();

    return 0;
}
