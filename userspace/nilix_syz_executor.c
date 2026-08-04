#define _GNU_SOURCE

/*
 * Nilix syzkaller-style guest executor.
 *
 * This program runs inside a QEMU guest and executes serialized syscall
 * programs under KCOV coverage collection. Results are written back to
 * the host via virtio-serial.
 *
 * Binary program format:
 * - Header: magic (0x4E494C58), version (1), syscall_count
 * - For each syscall:
 *   - syscall_number (u64)
 *   - arg_count (u64)
 *   - For each arg:
 *     - type (u8): 0=immediate, 1=buffer, 2=null
 *     - length (u64)
 *     - data (variable)
 *
 * Security > Correctness > Efficiency > Performance
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NILIX_SYS_KCOV_INIT 520
#define NILIX_SYS_KCOV_ENABLE 521
#define NILIX_SYS_KCOV_DISABLE 522
#define NILIX_SYS_KCOV_DUMP 523
#define NILIX_SYS_KCOV_RESET 524

#define KCOV_BUFFER_SIZE 32768
#define MAX_PROGRAM_SIZE (256 * 1024)  /* 256 KB */
#define MAX_SYSCALLS 100
#define MAX_ARGS 6
#define MAX_BUFFER_SIZE (64 * 1024)  /* 64 KB */

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t syscall_count;
} __attribute__((packed)) ProgramHeader;

typedef struct {
    uint64_t syscall_number;
    uint64_t arg_count;
} __attribute__((packed)) SyscallHeader;

typedef enum {
    ARG_TYPE_IMMEDIATE = 0,
    ARG_TYPE_BUFFER = 1,
    ARG_TYPE_NULL = 2,
} ArgumentType;

static uint8_t coverage_bitmap[KCOV_BUFFER_SIZE];
static uint8_t program_buffer[MAX_PROGRAM_SIZE];

static int fail(const char *stage) {
    printf("NILIX_SYZ_EXECUTOR_FAIL stage=%s\n", stage);
    fflush(stdout);
    return 1;
}

static uint64_t parse_argument(const uint8_t **ptr, const uint8_t *end) {
    if (*ptr + 9 > end) {
        return 0;
    }

    uint8_t type = **ptr;
    (*ptr)++;

    uint64_t length;
    memcpy(&length, *ptr, 8);
    (*ptr) += 8;

    if (length > MAX_BUFFER_SIZE || *ptr + length > end) {
        return 0;
    }

    switch (type) {
        case ARG_TYPE_IMMEDIATE: {
            if (length != 8) {
                return 0;
            }
            uint64_t value;
            memcpy(&value, *ptr, 8);
            (*ptr) += 8;
            return value;
        }

        case ARG_TYPE_BUFFER: {
            /* Return pointer to buffer data */
            uint64_t result = (uint64_t)(uintptr_t)(*ptr);
            (*ptr) += length;
            return result;
        }

        case ARG_TYPE_NULL:
            return 0;

        default:
            return 0;
    }
}

static int execute_program(const uint8_t *data, size_t length) {
    if (length < sizeof(ProgramHeader)) {
        return fail("program_too_small");
    }

    const uint8_t *ptr = data;
    const uint8_t *end = data + length;

    ProgramHeader header;
    memcpy(&header, ptr, sizeof(header));
    ptr += sizeof(header);

    if (header.magic != 0x4E494C58) {
        return fail("invalid_magic");
    }

    if (header.version != 1) {
        return fail("unsupported_version");
    }

    if (header.syscall_count > MAX_SYSCALLS) {
        return fail("too_many_syscalls");
    }

    /* Initialize KCOV */
    errno = 0;
    if (syscall(NILIX_SYS_KCOV_INIT, KCOV_BUFFER_SIZE) != 0) {
        return fail("kcov_init");
    }

    /* Enable coverage collection */
    errno = 0;
    if (syscall(NILIX_SYS_KCOV_ENABLE) != 0) {
        return fail("kcov_enable");
    }

    /* Execute each syscall */
    for (uint64_t i = 0; i < header.syscall_count; ++i) {
        if (ptr + sizeof(SyscallHeader) > end) {
            break;
        }

        SyscallHeader syscall_hdr;
        memcpy(&syscall_hdr, ptr, sizeof(syscall_hdr));
        ptr += sizeof(syscall_hdr);

        if (syscall_hdr.arg_count > MAX_ARGS) {
            continue;
        }

        /* Parse arguments */
        uint64_t args[MAX_ARGS] = {0};
        for (uint64_t j = 0; j < syscall_hdr.arg_count && j < MAX_ARGS; ++j) {
            args[j] = parse_argument(&ptr, end);
        }

        /* Execute syscall - ignore errors to continue program */
        errno = 0;
        (void)syscall(syscall_hdr.syscall_number,
                      args[0], args[1], args[2],
                      args[3], args[4], args[5]);
    }

    /* Disable coverage */
    errno = 0;
    if (syscall(NILIX_SYS_KCOV_DISABLE) != 0) {
        return fail("kcov_disable");
    }

    /* Dump coverage */
    errno = 0;
    long edge_count = syscall(NILIX_SYS_KCOV_DUMP, coverage_bitmap, KCOV_BUFFER_SIZE);
    if (edge_count < 0) {
        return fail("kcov_dump");
    }

    /* For now, just report success */
    printf("NILIX_SYZ_EXECUTOR_PASS edges=%ld\n", edge_count);
    fflush(stdout);

    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("NILIX_SYZ_EXECUTOR_BEGIN version=1\n");
    fflush(stdout);

    /* Read program from stdin (for now - virtio-serial comes later) */
    size_t total_read = 0;
    ssize_t n;

    while (total_read < MAX_PROGRAM_SIZE) {
        n = read(STDIN_FILENO, program_buffer + total_read,
                 MAX_PROGRAM_SIZE - total_read);
        if (n <= 0) {
            break;
        }
        total_read += n;
    }

    if (total_read == 0) {
        return fail("no_program_data");
    }

    printf("NILIX_SYZ_EXECUTOR_READ_PROGRAM bytes=%zu\n", total_read);
    fflush(stdout);

    return execute_program(program_buffer, total_read);
}
