#define _GNU_SOURCE

/*
 * Deterministic Nilix KCOV guest executor test.
 *
 * This is an integration gate for the syscall executor and KCOV data path. It
 * is deliberately not a fuzz campaign: two fixed syscall programs exercise
 * coverage collection, reset, disabled collection, and repeatability inside a
 * real QEMU guest.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NILIX_SYS_WRITE 1
#define NILIX_SYS_BRK 12
#define NILIX_SYS_GETPID 39
#define NILIX_SYS_GETPPID 110

#define NILIX_SYS_KCOV_INIT 520
#define NILIX_SYS_KCOV_ENABLE 521
#define NILIX_SYS_KCOV_DISABLE 522
#define NILIX_SYS_KCOV_DUMP 523
#define NILIX_SYS_KCOV_RESET 524

#define KCOV_BUFFER_SIZE 4096

typedef enum {
    OP_GETPID,
    OP_GETPPID,
    OP_WRITE,
    OP_BRK_QUERY,
} Operation;

typedef struct {
    const Operation *operations;
    size_t operation_count;
} Program;

typedef struct {
    long count;
    size_t popcount;
    uint64_t hash;
} Snapshot;

typedef struct {
    const char *phase;
    long code;
    size_t operation_index;
    int has_operation;
} RunError;

static const Operation PROGRAM_A_OPERATIONS[] = {OP_GETPID, OP_GETPPID};
static const Operation PROGRAM_B_OPERATIONS[] = {OP_WRITE, OP_BRK_QUERY};

static const Program PROGRAM_A = {
    PROGRAM_A_OPERATIONS,
    sizeof(PROGRAM_A_OPERATIONS) / sizeof(PROGRAM_A_OPERATIONS[0]),
};

static const Program PROGRAM_B = {
    PROGRAM_B_OPERATIONS,
    sizeof(PROGRAM_B_OPERATIONS) / sizeof(PROGRAM_B_OPERATIONS[0]),
};

static unsigned char bitmap_a[KCOV_BUFFER_SIZE];
static unsigned char bitmap_b[KCOV_BUFFER_SIZE];
static unsigned char bitmap_a_repeat[KCOV_BUFFER_SIZE];
static unsigned char bitmap_scratch[KCOV_BUFFER_SIZE];

static void flush_output(void) {
    (void)fflush(stdout);
}

static long error_code(long result) {
    if (result < 0 && errno != 0) {
        return -errno;
    }
    return result;
}

static int fail(const char *stage, long code) {
    printf("NILIX_KCOV_E2E_FAIL stage=%s code=%ld\n", stage, code);
    flush_output();
    return 1;
}

static int fail_run(const char *program_name, const RunError *error) {
    if (error->has_operation) {
        printf(
            "NILIX_KCOV_E2E_FAIL stage=%s_%s code=%ld op=%zu\n",
            program_name,
            error->phase,
            error->code,
            error->operation_index
        );
    } else {
        printf(
            "NILIX_KCOV_E2E_FAIL stage=%s_%s code=%ld\n",
            program_name,
            error->phase,
            error->code
        );
    }
    flush_output();
    return 1;
}

static size_t bitmap_popcount(const unsigned char *bitmap) {
    size_t count = 0;

    for (size_t i = 0; i < KCOV_BUFFER_SIZE; ++i) {
        unsigned char value = bitmap[i];
        while (value != 0) {
            count += value & 1U;
            value >>= 1;
        }
    }

    return count;
}

static uint64_t bitmap_hash(const unsigned char *bitmap) {
    uint64_t hash = UINT64_C(14695981039346656037);

    for (size_t i = 0; i < KCOV_BUFFER_SIZE; ++i) {
        hash ^= bitmap[i];
        hash *= UINT64_C(1099511628211);
    }

    return hash;
}

static int bitmap_is_zero(const unsigned char *bitmap) {
    for (size_t i = 0; i < KCOV_BUFFER_SIZE; ++i) {
        if (bitmap[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static int kcov_control(long syscall_number, long *failure_code) {
    errno = 0;
    const long result = syscall(syscall_number);
    if (result != 0) {
        *failure_code = error_code(result);
        return -1;
    }
    return 0;
}

static int dump_snapshot(
    unsigned char *bitmap,
    Snapshot *snapshot,
    const char **failure_phase,
    long *failure_code
) {
    memset(bitmap, 0xa5, KCOV_BUFFER_SIZE);
    errno = 0;
    const long result = syscall(
        NILIX_SYS_KCOV_DUMP,
        bitmap,
        (size_t)KCOV_BUFFER_SIZE
    );
    if (result < 0) {
        *failure_phase = "dump";
        *failure_code = error_code(result);
        return -1;
    }

    snapshot->count = result;
    snapshot->popcount = bitmap_popcount(bitmap);
    snapshot->hash = bitmap_hash(bitmap);

    if ((size_t)result != snapshot->popcount) {
        *failure_phase = "count_popcount";
        *failure_code = result;
        return -1;
    }

    return 0;
}

static int execute_operation(Operation operation, long *failure_code) {
    long result;

    errno = 0;
    switch (operation) {
        case OP_GETPID:
            result = syscall(NILIX_SYS_GETPID);
            if (result <= 0) {
                *failure_code = error_code(result);
                return -1;
            }
            return 0;
        case OP_GETPPID:
            result = syscall(NILIX_SYS_GETPPID);
            if (result < 0) {
                *failure_code = error_code(result);
                return -1;
            }
            return 0;
        case OP_WRITE: {
            static const char payload = '\n';
            result = syscall(NILIX_SYS_WRITE, 1, &payload, (size_t)1);
            if (result != 1) {
                *failure_code = error_code(result);
                return -1;
            }
            return 0;
        }
        case OP_BRK_QUERY:
            result = syscall(NILIX_SYS_BRK, 0);
            if (result < 0) {
                *failure_code = error_code(result);
                return -1;
            }
            return 0;
    }

    *failure_code = -EINVAL;
    return -1;
}

static int execute_program(
    const Program *program,
    size_t *failed_operation,
    long *failure_code
) {
    for (size_t i = 0; i < program->operation_count; ++i) {
        if (execute_operation(program->operations[i], failure_code) != 0) {
            *failed_operation = i;
            return -1;
        }
    }
    return 0;
}

static int collect_program(
    const Program *program,
    unsigned char *bitmap,
    Snapshot *snapshot,
    RunError *error
) {
    long code = 0;

    if (kcov_control(NILIX_SYS_KCOV_ENABLE, &code) != 0) {
        *error = (RunError){"enable", code, 0, 0};
        return -1;
    }

    size_t failed_operation = 0;
    if (execute_program(program, &failed_operation, &code) != 0) {
        long disable_code = 0;
        if (kcov_control(NILIX_SYS_KCOV_DISABLE, &disable_code) != 0) {
            *error = (RunError){"disable_after_execute", disable_code, 0, 0};
            return -1;
        }
        *error = (RunError){"execute", code, failed_operation, 1};
        return -1;
    }

    if (kcov_control(NILIX_SYS_KCOV_DISABLE, &code) != 0) {
        *error = (RunError){"disable", code, 0, 0};
        return -1;
    }

    const char *dump_phase = NULL;
    if (dump_snapshot(bitmap, snapshot, &dump_phase, &code) != 0) {
        *error = (RunError){dump_phase, code, 0, 0};
        return -1;
    }
    if (snapshot->count <= 0) {
        *error = (RunError){"zero_coverage", snapshot->count, 0, 0};
        return -1;
    }

    return 0;
}

static int reset_and_verify_zero(
    unsigned char *bitmap,
    Snapshot *snapshot,
    const char **failure_phase,
    long *failure_code
) {
    if (kcov_control(NILIX_SYS_KCOV_RESET, failure_code) != 0) {
        *failure_phase = "reset";
        return -1;
    }
    if (dump_snapshot(
            bitmap,
            snapshot,
            failure_phase,
            failure_code
        ) != 0) {
        return -1;
    }
    if (snapshot->count != 0 || snapshot->popcount != 0 || !bitmap_is_zero(bitmap)) {
        *failure_phase = "reset_not_zero";
        *failure_code = snapshot->count;
        return -1;
    }
    return 0;
}

static void print_snapshot(
    const char *name,
    unsigned int iteration,
    size_t operation_count,
    const Snapshot *snapshot
) {
    printf(
        "NILIX_KCOV_E2E_SEQ name=%s iteration=%u ops=%zu count=%ld "
        "popcount=%zu hash=%016" PRIx64 "\n",
        name,
        iteration,
        operation_count,
        snapshot->count,
        snapshot->popcount,
        snapshot->hash
    );
    flush_output();
}

int main(void) {
    Snapshot snapshot_a;
    Snapshot snapshot_b;
    Snapshot snapshot_a_repeat;
    Snapshot snapshot_disabled;
    Snapshot snapshot_zero;
    RunError run_error;
    const char *failure_phase = NULL;
    long code = 0;
    size_t failed_operation = 0;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    printf("NILIX_KCOV_E2E_BEGIN version=1\n");

    errno = 0;
    const long init_result = syscall(NILIX_SYS_KCOV_INIT, (size_t)KCOV_BUFFER_SIZE);
    if (init_result != 0) {
        return fail("init", error_code(init_result));
    }

    if (reset_and_verify_zero(
            bitmap_scratch,
            &snapshot_zero,
            &failure_phase,
            &code
        ) != 0) {
        return fail(failure_phase, code);
    }

    if (collect_program(
            &PROGRAM_A,
            bitmap_a,
            &snapshot_a,
            &run_error
        ) != 0) {
        return fail_run("a1", &run_error);
    }
    print_snapshot("A", 1, PROGRAM_A.operation_count, &snapshot_a);

    if (execute_program(&PROGRAM_B, &failed_operation, &code) != 0) {
        printf(
            "NILIX_KCOV_E2E_FAIL stage=disabled_execute code=%ld op=%zu\n",
            code,
            failed_operation
        );
        flush_output();
        return 1;
    }
    if (dump_snapshot(
            bitmap_scratch,
            &snapshot_disabled,
            &failure_phase,
            &code
        ) != 0) {
        return fail(failure_phase, code);
    }
    if (snapshot_disabled.count != snapshot_a.count ||
        snapshot_disabled.popcount != snapshot_a.popcount ||
        memcmp(bitmap_scratch, bitmap_a, KCOV_BUFFER_SIZE) != 0) {
        return fail("disabled_changed_coverage", snapshot_disabled.count);
    }
    printf(
        "NILIX_KCOV_E2E_DISABLED count=%ld popcount=%zu hash=%016" PRIx64
        " stable=1\n",
        snapshot_disabled.count,
        snapshot_disabled.popcount,
        snapshot_disabled.hash
    );

    if (reset_and_verify_zero(
            bitmap_scratch,
            &snapshot_zero,
            &failure_phase,
            &code
        ) != 0) {
        return fail(failure_phase, code);
    }
    printf("NILIX_KCOV_E2E_RESET count=0 popcount=0\n");

    if (collect_program(
            &PROGRAM_B,
            bitmap_b,
            &snapshot_b,
            &run_error
        ) != 0) {
        return fail_run("b1", &run_error);
    }
    print_snapshot("B", 1, PROGRAM_B.operation_count, &snapshot_b);

    if (memcmp(bitmap_a, bitmap_b, KCOV_BUFFER_SIZE) == 0) {
        return fail("a_b_not_distinct", snapshot_a.count);
    }
    printf("NILIX_KCOV_E2E_DIFF value=1\n");

    if (reset_and_verify_zero(
            bitmap_scratch,
            &snapshot_zero,
            &failure_phase,
            &code
        ) != 0) {
        return fail(failure_phase, code);
    }

    if (collect_program(
            &PROGRAM_A,
            bitmap_a_repeat,
            &snapshot_a_repeat,
            &run_error
        ) != 0) {
        return fail_run("a2", &run_error);
    }
    print_snapshot("A", 2, PROGRAM_A.operation_count, &snapshot_a_repeat);

    if (snapshot_a_repeat.count != snapshot_a.count ||
        snapshot_a_repeat.popcount != snapshot_a.popcount ||
        memcmp(bitmap_a_repeat, bitmap_a, KCOV_BUFFER_SIZE) != 0) {
        return fail("a_repeat_unstable", snapshot_a_repeat.count);
    }
    printf("NILIX_KCOV_E2E_REPEAT name=A stable=1\n");

    if (reset_and_verify_zero(
            bitmap_scratch,
            &snapshot_zero,
            &failure_phase,
            &code
        ) != 0) {
        return fail(failure_phase, code);
    }
    printf("NILIX_KCOV_E2E_FINAL_RESET count=0 popcount=0\n");
    printf("NILIX_KCOV_E2E_PASS\n");
    flush_output();
    return 0;
}
