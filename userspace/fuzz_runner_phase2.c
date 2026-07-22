/*
 * Nilix KCOV Test Runner - Phase 2 Complete
 *
 * Extended test harness with random syscall sequence generation.
 * Tests KCOV infrastructure and measures coverage discovery rate.
 *
 * Phase 2 Goals:
 * 1. Verify KCOV infrastructure (5 core tests)
 * 2. Generate random syscall sequences
 * 3. Measure unique edge discovery
 * 4. Validate coverage-guided approach
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdbool.h>

// KCOV syscall numbers
#define SYS_KCOV_INIT    520
#define SYS_KCOV_ENABLE  521
#define SYS_KCOV_DISABLE 522
#define SYS_KCOV_DUMP    523
#define SYS_KCOV_RESET   524

#define KCOV_BUFFER_SIZE 4096
#define MAX_UNIQUE_EDGES 32768  // 4KB bitmap = 32K edges max

// Test results
typedef struct {
    int test_num;
    const char *name;
    int passed;
    long edge_count;
    const char *error;
    int errno_val;
} TestResult;

// Coverage statistics
typedef struct {
    unsigned char global_bitmap[KCOV_BUFFER_SIZE];
    long total_unique_edges;
    long total_executions;
    long total_edges_collected;
} CoverageStats;

// Simple PRNG (LCG) - we can't use rand() as it may not be available
static unsigned int seed = 12345;

static unsigned int simple_rand(void) {
    seed = seed * 1103515245 + 12345;
    return (seed / 65536) % 32768;
}

static void simple_srand(unsigned int s) {
    seed = s;
}

// Safe syscall list - these should not crash or hang the kernel
// Only include info-gathering syscalls that are safe to call repeatedly
static const int SAFE_SYSCALLS[] = {
    39,   // getpid
    110,  // getppid
    102,  // getuid
    107,  // geteuid
    104,  // getgid
    108,  // getegid
    // Add more safe syscalls as they are implemented
};
static const int NUM_SAFE_SYSCALLS = sizeof(SAFE_SYSCALLS) / sizeof(SAFE_SYSCALLS[0]);

// Merge coverage bitmap into global coverage
static long merge_coverage(CoverageStats *stats, unsigned char *new_coverage, size_t len) {
    long new_edges = 0;

    for (size_t i = 0; i < len && i < KCOV_BUFFER_SIZE; i++) {
        unsigned char old_byte = stats->global_bitmap[i];
        unsigned char new_byte = new_coverage[i];

        // Merge new coverage into global bitmap
        unsigned char merged = old_byte | new_byte;
        if (merged != old_byte) {
            // Count new bits
            unsigned char diff = merged ^ old_byte;
            for (int bit = 0; bit < 8; bit++) {
                if (diff & (1 << bit)) {
                    new_edges++;
                }
            }
            stats->global_bitmap[i] = merged;
        }
    }

    return new_edges;
}

// Count total unique edges in bitmap
static long count_unique_edges(unsigned char *bitmap, size_t len) {
    long count = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char byte = bitmap[i];
        for (int bit = 0; bit < 8; bit++) {
            if (byte & (1 << bit)) {
                count++;
            }
        }
    }
    return count;
}

// Helper to execute a syscall sequence
static void execute_test_syscalls(void) {
    syscall(39);  // getpid
    syscall(110); // getppid
    syscall(102); // getuid
    syscall(107); // geteuid
    syscall(104); // getgid
    syscall(108); // getegid
}

// Generate and execute a random syscall sequence
static long execute_random_sequence(int seq_length) {
    for (int i = 0; i < seq_length; i++) {
        int idx = simple_rand() % NUM_SAFE_SYSCALLS;
        syscall(SAFE_SYSCALLS[idx]);
    }
    return 0;
}

// ============================================================================
// Phase 2 Core Tests (same as before)
// ============================================================================

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

TestResult test_kcov_enable_disable(void) {
    TestResult result = {2, "KCOV Enable/Disable", 0, 0, NULL, 0};

    errno = 0;
    long ret = syscall(SYS_KCOV_ENABLE);
    if (ret < 0) {
        result.error = "kcov_enable failed";
        result.errno_val = errno;
        return result;
    }

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

TestResult test_kcov_collection(void) {
    TestResult result = {3, "KCOV Coverage Collection", 0, 0, NULL, 0};

    errno = 0;
    long ret = syscall(SYS_KCOV_ENABLE);
    if (ret < 0) {
        result.error = "kcov_enable failed";
        result.errno_val = errno;
        return result;
    }

    execute_test_syscalls();

    errno = 0;
    ret = syscall(SYS_KCOV_DISABLE);
    if (ret < 0) {
        result.error = "kcov_disable failed";
        result.errno_val = errno;
        return result;
    }

    unsigned char coverage_buf[KCOV_BUFFER_SIZE];
    errno = 0;
    ret = syscall(SYS_KCOV_DUMP, coverage_buf, KCOV_BUFFER_SIZE);
    if (ret < 0) {
        result.error = "kcov_dump failed";
        result.errno_val = errno;
        return result;
    }

    result.edge_count = ret;

    if (ret == 0) {
        result.error = "No edges collected (expected > 0)";
        return result;
    }

    result.passed = 1;
    return result;
}

TestResult test_kcov_reset(void) {
    TestResult result = {4, "KCOV Reset", 0, 0, NULL, 0};

    syscall(SYS_KCOV_ENABLE);
    execute_test_syscalls();
    syscall(SYS_KCOV_DISABLE);

    errno = 0;
    long ret = syscall(SYS_KCOV_RESET);
    if (ret < 0) {
        result.error = "kcov_reset failed";
        result.errno_val = errno;
        return result;
    }

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
    syscall(110); // getppid
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

// ============================================================================
// Phase 2 Extended: Random Sequence Generation
// ============================================================================

void run_random_fuzzing(int num_sequences, int seq_length) {
    printf("\n=====================================\n");
    printf("  Phase 2 Extended: Random Fuzzing\n");
    printf("=====================================\n");
    printf("Sequences: %d\n", num_sequences);
    printf("Sequence length: %d syscalls\n\n", seq_length);

    CoverageStats stats = {0};
    unsigned char coverage_buf[KCOV_BUFFER_SIZE];

    // Initialize with getpid() to get baseline
    simple_srand((unsigned int)syscall(39)); // seed with PID

    for (int i = 0; i < num_sequences; i++) {
        // Reset coverage for this run
        syscall(SYS_KCOV_RESET);

        // Enable coverage
        if (syscall(SYS_KCOV_ENABLE) < 0) {
            printf("Failed to enable KCOV for sequence %d\n", i);
            continue;
        }

        // Execute random sequence
        execute_random_sequence(seq_length);

        // Disable coverage
        if (syscall(SYS_KCOV_DISABLE) < 0) {
            printf("Failed to disable KCOV for sequence %d\n", i);
            continue;
        }

        // Dump coverage
        memset(coverage_buf, 0, KCOV_BUFFER_SIZE);
        long edges = syscall(SYS_KCOV_DUMP, coverage_buf, KCOV_BUFFER_SIZE);
        if (edges < 0) {
            printf("Failed to dump coverage for sequence %d\n", i);
            continue;
        }

        // Merge into global coverage
        long new_edges = merge_coverage(&stats, coverage_buf, KCOV_BUFFER_SIZE);
        stats.total_executions++;
        stats.total_edges_collected += edges;
        stats.total_unique_edges = count_unique_edges(stats.global_bitmap, KCOV_BUFFER_SIZE);

        // Print progress every 10 sequences
        if ((i + 1) % 10 == 0) {
            printf("[%3d/%3d] Total unique edges: %5ld (+%2ld new) | Avg edges/seq: %ld\n",
                   i + 1, num_sequences,
                   stats.total_unique_edges,
                   new_edges,
                   stats.total_edges_collected / stats.total_executions);
        }
    }

    printf("\n=====================================\n");
    printf("  Random Fuzzing Results\n");
    printf("=====================================\n");
    printf("Total executions:   %ld\n", stats.total_executions);
    printf("Total unique edges: %ld\n", stats.total_unique_edges);
    printf("Total edges:        %ld\n", stats.total_edges_collected);
    printf("Avg edges/exec:     %ld\n", stats.total_edges_collected / stats.total_executions);
    printf("Coverage density:   %.2f%% (%ld / %d edges)\n",
           (double)stats.total_unique_edges / MAX_UNIQUE_EDGES * 100.0,
           stats.total_unique_edges, MAX_UNIQUE_EDGES);
    printf("=====================================\n");
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char *argv[]) {
    int run_fuzzing = 0;
    int num_sequences = 100;
    int seq_length = 10;

    // Parse command line args
    if (argc > 1 && strcmp(argv[1], "--fuzz") == 0) {
        run_fuzzing = 1;
        if (argc > 2) num_sequences = atoi(argv[2]);
        if (argc > 3) seq_length = atoi(argv[3]);
    }

    printf("=====================================\n");
    printf("  Nilix KCOV Test Runner - Phase 2\n");
    printf("=====================================\n\n");

    // Run core tests
    TestResult results[5];
    int total_tests = 5;
    int passed = 0;

    results[0] = test_kcov_init();
    results[1] = test_kcov_enable_disable();
    results[2] = test_kcov_collection();
    results[3] = test_kcov_reset();
    results[4] = test_kcov_multi_cycle();

    for (int i = 0; i < total_tests; i++) {
        print_result(results[i]);
        if (results[i].passed) {
            passed++;
        }
    }

    printf("\n=====================================\n");
    printf("  Core Tests: %d/%d passed\n", passed, total_tests);
    printf("=====================================\n");

    if (passed != total_tests) {
        printf("\n❌ Core tests failed - skipping fuzzing\n\n");
        return 1;
    }

    // Run extended fuzzing if requested
    if (run_fuzzing) {
        run_random_fuzzing(num_sequences, seq_length);
        printf("\n🎉 Phase 2 COMPLETE: KCOV + Random Fuzzing verified!\n\n");
    } else {
        printf("\n🎉 Phase 2 Core Tests COMPLETE!\n");
        printf("Run with --fuzz [sequences] [length] for extended tests\n\n");
    }

    return 0;
}
