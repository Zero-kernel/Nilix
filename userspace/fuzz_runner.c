/*
 * Nilix KCOV Test Runner - Phase 2 Completion
 *
 * Minimal test harness that runs inside Nilix to verify KCOV integration.
 * This is a simpler version of the Rust executor designed to run natively
 * in the Nilix userspace environment.
 *
 * Tests:
 * 1. Initialize KCOV
 * 2. Enable coverage collection
 * 3. Execute a sequence of syscalls
 * 4. Dump coverage and verify edge count > 0
 * 5. Report results
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

// KCOV syscall numbers
#define SYS_KCOV_INIT    520
#define SYS_KCOV_ENABLE  521
#define SYS_KCOV_DISABLE 522
#define SYS_KCOV_DUMP    523
#define SYS_KCOV_RESET   524

#define KCOV_BUFFER_SIZE 4096

// Test results
typedef struct {
    int test_num;
    const char *name;
    int passed;
    long edge_count;
    const char *error;
    int errno_val;
} TestResult;

// Helper to execute a syscall sequence
static void execute_test_syscalls(void) {
    // Execute various syscalls to generate coverage
    syscall(39);  // getpid
    syscall(110); // getppid
    syscall(102); // getuid
    syscall(107); // geteuid
    syscall(104); // getgid
    syscall(108); // getegid
}

// Test 1: Basic KCOV initialization
TestResult test_kcov_init(void) {
    TestResult result = {1, "KCOV Initialization", 0, 0, NULL, 0};

    errno = 0;
    long ret = syscall(SYS_KCOV_INIT, KCOV_BUFFER_SIZE);
    if (ret < 0) {
        result.error = "kcov_init failed";
        result.errno_val = errno;
        return result;
    }

    result.passed = 1;
    return result;
}

// Test 2: Enable/disable coverage
TestResult test_kcov_enable_disable(void) {
    TestResult result = {2, "KCOV Enable/Disable", 0, 0, NULL, 0};

    // Enable
    errno = 0;
    long ret = syscall(SYS_KCOV_ENABLE);
    if (ret < 0) {
        result.error = "kcov_enable failed";
        result.errno_val = errno;
        return result;
    }

    // Disable
    errno = 0;
    ret = syscall(SYS_KCOV_DISABLE);
    if (ret < 0) {
        result.error = "kcov_disable failed";
        result.errno_val = errno;
        return result;
    }

    result.passed = 1;
    return result;
}

// Test 3: Coverage collection
TestResult test_kcov_collection(void) {
    TestResult result = {3, "KCOV Coverage Collection", 0, 0, NULL, 0};

    // Enable
    errno = 0;
    long ret = syscall(SYS_KCOV_ENABLE);
    if (ret < 0) {
        result.error = "kcov_enable failed";
        result.errno_val = errno;
        return result;
    }

    // Execute test syscalls
    execute_test_syscalls();

    // Disable
    errno = 0;
    ret = syscall(SYS_KCOV_DISABLE);
    if (ret < 0) {
        result.error = "kcov_disable failed";
        result.errno_val = errno;
        return result;
    }

    // Dump coverage
    unsigned char coverage_buf[KCOV_BUFFER_SIZE];
    errno = 0;
    ret = syscall(SYS_KCOV_DUMP, coverage_buf, KCOV_BUFFER_SIZE);
    if (ret < 0) {
        result.error = "kcov_dump failed";
        result.errno_val = errno;
        return result;
    }

    result.edge_count = ret;

    // Verify we got some coverage
    if (ret == 0) {
        result.error = "No edges collected (expected > 0)";
        return result;
    }

    result.passed = 1;
    return result;
}

// Test 4: Coverage reset
TestResult test_kcov_reset(void) {
    TestResult result = {4, "KCOV Reset", 0, 0, NULL, 0};

    // Enable and collect some coverage
    syscall(SYS_KCOV_ENABLE);
    execute_test_syscalls();
    syscall(SYS_KCOV_DISABLE);

    // Reset
    errno = 0;
    long ret = syscall(SYS_KCOV_RESET);
    if (ret < 0) {
        result.error = "kcov_reset failed";
        result.errno_val = errno;
        return result;
    }

    // Dump should now return 0 edges
    unsigned char coverage_buf[KCOV_BUFFER_SIZE];
    errno = 0;
    ret = syscall(SYS_KCOV_DUMP, coverage_buf, KCOV_BUFFER_SIZE);
    if (ret < 0) {
        result.error = "kcov_dump after reset failed";
        result.errno_val = errno;
        return result;
    }

    if (ret != 0) {
        result.error = "Expected 0 edges after reset";
        result.edge_count = ret;
        return result;
    }

    result.passed = 1;
    return result;
}

// Test 5: Multiple collection cycles
TestResult test_kcov_multi_cycle(void) {
    TestResult result = {5, "KCOV Multiple Cycles", 0, 0, NULL, 0};

    // Cycle 1
    syscall(SYS_KCOV_ENABLE);
    syscall(39); // getpid
    syscall(SYS_KCOV_DISABLE);

    unsigned char buf1[KCOV_BUFFER_SIZE];
    long edges1 = syscall(SYS_KCOV_DUMP, buf1, KCOV_BUFFER_SIZE);

    // Reset
    syscall(SYS_KCOV_RESET);

    // Cycle 2
    syscall(SYS_KCOV_ENABLE);
    syscall(110); // getppid (different syscall)
    syscall(SYS_KCOV_DISABLE);

    unsigned char buf2[KCOV_BUFFER_SIZE];
    long edges2 = syscall(SYS_KCOV_DUMP, buf2, KCOV_BUFFER_SIZE);

    if (edges1 <= 0 || edges2 <= 0) {
        result.error = "Expected positive edge count in both cycles";
        return result;
    }

    result.edge_count = edges1 + edges2;
    result.passed = 1;
    return result;
}

// Print test result
void print_result(TestResult result) {
    printf("[Test %d] %s: ", result.test_num, result.name);

    if (result.passed) {
        printf("✓ PASS");
        if (result.edge_count > 0) {
            printf(" (%ld edges)", result.edge_count);
        }
        printf("\n");
    } else {
        printf("✗ FAIL");
        if (result.error) {
            printf(" - %s", result.error);
        }
        if (result.errno_val != 0) {
            printf(" (errno=%d)", result.errno_val);
        }
        if (result.edge_count > 0) {
            printf(" (edges: %ld)", result.edge_count);
        }
        printf("\n");
    }
}

int main(void) {
    printf("=====================================\n");
    printf("  Nilix KCOV Test Runner - Phase 2\n");
    printf("=====================================\n\n");

    TestResult results[5];
    int total_tests = 5;
    int passed = 0;

    // Run tests
    results[0] = test_kcov_init();
    results[1] = test_kcov_enable_disable();
    results[2] = test_kcov_collection();
    results[3] = test_kcov_reset();
    results[4] = test_kcov_multi_cycle();

    // Print results
    for (int i = 0; i < total_tests; i++) {
        print_result(results[i]);
        if (results[i].passed) {
            passed++;
        }
    }

    printf("\n=====================================\n");
    printf("  Results: %d/%d tests passed\n", passed, total_tests);
    printf("=====================================\n");

    if (passed == total_tests) {
        printf("\n🎉 Phase 2 COMPLETE: KCOV integration verified!\n\n");
        return 0;
    } else {
        printf("\n❌ Phase 2 INCOMPLETE: %d tests failed\n\n", total_tests - passed);
        return 1;
    }
}
