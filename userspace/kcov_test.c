/**
 * KCOV Test Program
 *
 * Tests the kernel coverage infrastructure by:
 * 1. Initializing coverage for this process
 * 2. Enabling collection
 * 3. Making several syscalls
 * 4. Dumping coverage data
 * 5. Verifying edge counts
 */

#include <stdint.h>

// Syscall numbers
#define SYS_KCOV_INIT    520
#define SYS_KCOV_ENABLE  521
#define SYS_KCOV_DISABLE 522
#define SYS_KCOV_DUMP    523
#define SYS_KCOV_RESET   524
#define SYS_WRITE        1
#define SYS_EXIT         60

// Syscall wrapper
static inline long syscall3(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile(
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall1(long n, long a1) {
    return syscall3(n, a1, 0, 0);
}

static inline long syscall2(long n, long a1, long a2) {
    return syscall3(n, a1, a2, 0);
}

// Print helper
static void print(const char *msg) {
    const char *p = msg;
    long len = 0;
    while (*p++) len++;
    syscall3(SYS_WRITE, 1, (long)msg, len);
}

static void print_num(long num) {
    char buf[32];
    int i = 0;

    if (num == 0) {
        buf[i++] = '0';
    } else {
        char tmp[32];
        int j = 0;
        long n = num;

        if (n < 0) {
            buf[i++] = '-';
            n = -n;
        }

        while (n > 0) {
            tmp[j++] = '0' + (n % 10);
            n /= 10;
        }

        while (j > 0) {
            buf[i++] = tmp[--j];
        }
    }

    buf[i] = '\0';
    print(buf);
}

void _start(void) {
    uint8_t coverage_buf[4096];
    long ret;

    print("\n=== KCOV Test Program ===\n\n");

    // Step 1: Initialize coverage (4KB buffer)
    print("[1/5] Initializing coverage (4KB buffer)...\n");
    ret = syscall1(SYS_KCOV_INIT, 4096);
    if (ret < 0) {
        print("ERROR: sys_kcov_init failed with code ");
        print_num(ret);
        print("\n");
        syscall1(SYS_EXIT, 1);
    }
    print("      Success! Coverage buffer allocated.\n\n");

    // Step 2: Enable coverage collection
    print("[2/5] Enabling coverage collection...\n");
    ret = syscall1(SYS_KCOV_ENABLE, 0);
    if (ret < 0) {
        print("ERROR: sys_kcov_enable failed with code ");
        print_num(ret);
        print("\n");
        syscall1(SYS_EXIT, 1);
    }
    print("      Success! Coverage is now recording.\n\n");

    // Step 3: Execute some syscalls to generate coverage
    print("[3/5] Executing syscalls to generate coverage...\n");
    print("      - Writing test string 1\n");
    syscall3(SYS_WRITE, 1, (long)"Test coverage path 1\n", 21);

    print("      - Writing test string 2\n");
    syscall3(SYS_WRITE, 1, (long)"Test coverage path 2\n", 21);

    print("      - Writing test string 3\n");
    syscall3(SYS_WRITE, 1, (long)"Test coverage path 3\n", 21);
    print("      Done executing test syscalls.\n\n");

    // Step 4: Disable coverage (optional, but good practice)
    print("[4/5] Disabling coverage...\n");
    ret = syscall1(SYS_KCOV_DISABLE, 0);
    if (ret < 0) {
        print("ERROR: sys_kcov_disable failed with code ");
        print_num(ret);
        print("\n");
        syscall1(SYS_EXIT, 1);
    }
    print("      Coverage collection stopped.\n\n");

    // Step 5: Dump coverage data
    print("[5/5] Dumping coverage data...\n");
    ret = syscall3(SYS_KCOV_DUMP, (long)coverage_buf, 4096, 0);
    if (ret < 0) {
        print("ERROR: sys_kcov_dump failed with code ");
        print_num(ret);
        print("\n");
        syscall1(SYS_EXIT, 1);
    }

    print("      Success! Collected ");
    print_num(ret);
    print(" unique edges.\n\n");

    // Verify we got some coverage
    if (ret > 0) {
        print("=== KCOV Test PASSED ===\n");
        print("Coverage infrastructure is working correctly!\n\n");

        // Show first few edges as a sample
        print("Sample coverage bitmap (first 32 bytes):\n");
        for (int i = 0; i < 32 && i < 4096; i++) {
            if (i > 0 && i % 16 == 0) print("\n");

            uint8_t byte = coverage_buf[i];
            char hex[4];
            hex[0] = "0123456789abcdef"[(byte >> 4) & 0xF];
            hex[1] = "0123456789abcdef"[byte & 0xF];
            hex[2] = ' ';
            hex[3] = '\0';
            print(hex);
        }
        print("\n\n");

        syscall1(SYS_EXIT, 0);
    } else {
        print("=== KCOV Test FAILED ===\n");
        print("Expected non-zero edge count, got 0.\n");
        print("This might indicate coverage recording is not working.\n\n");
        syscall1(SYS_EXIT, 1);
    }
}
