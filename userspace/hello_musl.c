// Simple musl test program for Zero-OS
// This tests basic musl libc initialization and I/O
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/select.h>
#include <errno.h>
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

    return 0;
}
