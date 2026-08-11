#define _GNU_SOURCE

/*
 * Nilix syzkaller-style guest executor.
 *
 * The host places one authenticated, strictly bounded program at
 * /mnt/test/syz-program.bin.  This process validates the complete program,
 * executes only a small non-destructive syscall allowlist under per-task KCOV,
 * and atomically publishes an authenticated result at
 * /mnt/test/syz-result.bin.
 *
 * Security > Correctness > Efficiency > Performance
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0x80000
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0x20000
#endif

#define NILIX_SYS_KCOV_INIT 520
#define NILIX_SYS_KCOV_ENABLE 521
#define NILIX_SYS_KCOV_DISABLE 522
#define NILIX_SYS_KCOV_DUMP 523
#define NILIX_SYS_KCOV_RESET 524

#define NILIX_SYS_RENAMEAT2 316
#define NILIX_SYS_UNLINK 87
#define NILIX_AT_FDCWD (-100)
#define NILIX_RENAME_NOREPLACE 1U

#define PROTOCOL_VERSION 2U
#define PROGRAM_HEADER_SIZE 128U
#define CALL_HEADER_SIZE 16U
#define ARG_HEADER_SIZE 24U
#define RESULT_HEADER_SIZE 128U
#define RESULT_TAG_SIZE 32U
#define RESULT_OCCUPIED_SLOT_COUNT_OFFSET 36U

#define KCOV_BUFFER_SIZE 4096U
#define MAX_PROGRAM_SIZE (256U * 1024U)
#define MAX_SYSCALLS 100U
#define MAX_ARGS 6U
#define MAX_ARG_CAPACITY 4096U
#define ARG_ARENA_SIZE (128U * 1024U)
#define RESULT_MAX_SIZE \
    (RESULT_HEADER_SIZE + MAX_SYSCALLS * 8U + KCOV_BUFFER_SIZE + RESULT_TAG_SIZE)
#define KCOV_BUSY_RETRIES 4U

#define PROGRAM_PATH "/mnt/test/syz-program.bin"
#define RESULT_TEMP_PATH "/mnt/test/.syz-result.bin.tmp"
#define RESULT_PATH "/mnt/test/syz-result.bin"

enum {
    ARG_IMMEDIATE = 0,
    ARG_NULL = 1,
    ARG_INPUT = 2,
    ARG_OUTPUT = 3,
    ARG_INOUT = 4,
};

typedef struct {
    uint32_t state[8];
    uint64_t total_length;
    uint8_t block[64];
    size_t block_length;
} Sha256Context;

typedef struct {
    uint8_t kind;
    uint32_t data_length;
    uint32_t capacity;
    uint64_t value;
    size_t arena_offset;
} ParsedArgument;

typedef struct {
    uint32_t number;
    uint16_t argument_count;
    ParsedArgument arguments[MAX_ARGS];
} ParsedCall;

typedef struct {
    uint32_t syscall_count;
    uint32_t kcov_length;
    uint64_t sequence;
    uint8_t run_id[16];
    uint8_t auth_key[32];
    uint8_t program_digest[32];
    ParsedCall calls[MAX_SYSCALLS];
    size_t arena_used;
} ParsedProgram;

typedef struct {
    const char *stage;
    int64_t code;
} ExecutorError;

typedef union {
    max_align_t alignment;
    uint8_t bytes[ARG_ARENA_SIZE];
} AlignedArgumentArena;

static const uint8_t PROGRAM_MAGIC[8] = {
    'N', 'L', 'S', 'Y', 'Z', 'P', 'G', 0,
};
static const uint8_t RESULT_MAGIC[8] = {
    'N', 'L', 'S', 'Y', 'Z', 'R', 'S', 0,
};
static const uint8_t PROGRAM_DOMAIN[] = "NILIX-SYZ-PROGRAM-V2";
static const uint8_t RESULT_DOMAIN[] = "NILIX-SYZ-RESULT-V2";

static uint8_t program_buffer[MAX_PROGRAM_SIZE + 1U];
static uint8_t coverage_bitmap[KCOV_BUFFER_SIZE];
static uint8_t result_buffer[RESULT_MAX_SIZE];
static int64_t syscall_returns[MAX_SYSCALLS];
static AlignedArgumentArena argument_arena;
static bool terminal_marker_emitted;

static const uint32_t SHA256_CONSTANTS[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
    UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
    UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
    UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
    UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
    UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
    UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
    UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
    UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
    UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
    UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
    UINT32_C(0xc67178f2),
};

static uint16_t read_le16(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t read_le32(const uint8_t *data) {
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_le64(const uint8_t *data) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8U; ++i) {
        value |= (uint64_t)data[i] << (i * 8U);
    }
    return value;
}

static void write_le16(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8);
}

static void write_le32(uint8_t *data, uint32_t value) {
    for (unsigned int i = 0; i < 4U; ++i) {
        data[i] = (uint8_t)(value >> (i * 8U));
    }
}

static void write_le64(uint8_t *data, uint64_t value) {
    for (unsigned int i = 0; i < 8U; ++i) {
        data[i] = (uint8_t)(value >> (i * 8U));
    }
}

static bool bytes_are_zero(const uint8_t *data, size_t length) {
    uint8_t combined = 0;
    for (size_t i = 0; i < length; ++i) {
        combined |= data[i];
    }
    return combined == 0;
}

static bool range_is_valid(size_t offset, size_t length, size_t limit) {
    return offset <= limit && length <= limit - offset;
}

static bool checked_add_size(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) {
        return false;
    }
    *result = left + right;
    return true;
}

static bool checked_align8(size_t value, size_t *result) {
    size_t adjusted;
    if (!checked_add_size(value, 7U, &adjusted)) {
        return false;
    }
    *result = adjusted & ~(size_t)7U;
    return true;
}

static uint32_t rotate_right32(uint32_t value, unsigned int shift) {
    return (value >> shift) | (value << (32U - shift));
}

static uint32_t read_be32(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static void write_be32(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static void write_be64(uint8_t *data, uint64_t value) {
    for (unsigned int i = 0; i < 8U; ++i) {
        data[i] = (uint8_t)(value >> ((7U - i) * 8U));
    }
}

static void sha256_transform(Sha256Context *context, const uint8_t block[64]) {
    uint32_t schedule[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;

    for (unsigned int i = 0; i < 16U; ++i) {
        schedule[i] = read_be32(block + i * 4U);
    }
    for (unsigned int i = 16U; i < 64U; ++i) {
        const uint32_t s0 = rotate_right32(schedule[i - 15U], 7U) ^
                            rotate_right32(schedule[i - 15U], 18U) ^
                            (schedule[i - 15U] >> 3);
        const uint32_t s1 = rotate_right32(schedule[i - 2U], 17U) ^
                            rotate_right32(schedule[i - 2U], 19U) ^
                            (schedule[i - 2U] >> 10);
        schedule[i] = schedule[i - 16U] + s0 + schedule[i - 7U] + s1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (unsigned int i = 0; i < 64U; ++i) {
        const uint32_t sum1 = rotate_right32(e, 6U) ^
                              rotate_right32(e, 11U) ^
                              rotate_right32(e, 25U);
        const uint32_t choose = (e & f) ^ ((~e) & g);
        const uint32_t temporary1 = h + sum1 + choose +
                                    SHA256_CONSTANTS[i] + schedule[i];
        const uint32_t sum0 = rotate_right32(a, 2U) ^
                              rotate_right32(a, 13U) ^
                              rotate_right32(a, 22U);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temporary2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(Sha256Context *context) {
    static const uint32_t initial_state[8] = {
        UINT32_C(0x6a09e667), UINT32_C(0xbb67ae85),
        UINT32_C(0x3c6ef372), UINT32_C(0xa54ff53a),
        UINT32_C(0x510e527f), UINT32_C(0x9b05688c),
        UINT32_C(0x1f83d9ab), UINT32_C(0x5be0cd19),
    };

    memcpy(context->state, initial_state, sizeof(initial_state));
    context->total_length = 0;
    context->block_length = 0;
    memset(context->block, 0, sizeof(context->block));
}

static void sha256_update(Sha256Context *context, const uint8_t *data, size_t length) {
    context->total_length += (uint64_t)length;

    while (length > 0U) {
        const size_t available = sizeof(context->block) - context->block_length;
        const size_t take = length < available ? length : available;

        memcpy(context->block + context->block_length, data, take);
        context->block_length += take;
        data += take;
        length -= take;

        if (context->block_length == sizeof(context->block)) {
            sha256_transform(context, context->block);
            context->block_length = 0;
        }
    }
}

static void sha256_final(Sha256Context *context, uint8_t digest[32]) {
    const uint64_t bit_length = context->total_length * UINT64_C(8);
    size_t cursor = context->block_length;

    context->block[cursor++] = UINT8_C(0x80);
    if (cursor > 56U) {
        memset(context->block + cursor, 0, sizeof(context->block) - cursor);
        sha256_transform(context, context->block);
        cursor = 0;
    }

    memset(context->block + cursor, 0, 56U - cursor);
    write_be64(context->block + 56U, bit_length);
    sha256_transform(context, context->block);

    for (unsigned int i = 0; i < 8U; ++i) {
        write_be32(digest + i * 4U, context->state[i]);
    }

    memset(context, 0, sizeof(*context));
}

static void sha256_digest(const uint8_t *data, size_t length, uint8_t digest[32]) {
    Sha256Context context;
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, digest);
}

static void hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *domain,
    size_t domain_length,
    const uint8_t *data,
    size_t data_length,
    uint8_t digest[32]
) {
    uint8_t key_block[64];
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    uint8_t inner_digest[32];
    Sha256Context context;

    memset(key_block, 0, sizeof(key_block));
    if (key_length > sizeof(key_block)) {
        sha256_digest(key, key_length, key_block);
    } else if (key_length > 0U) {
        memcpy(key_block, key, key_length);
    }

    for (size_t i = 0; i < sizeof(key_block); ++i) {
        inner_pad[i] = key_block[i] ^ UINT8_C(0x36);
        outer_pad[i] = key_block[i] ^ UINT8_C(0x5c);
    }

    sha256_init(&context);
    sha256_update(&context, inner_pad, sizeof(inner_pad));
    sha256_update(&context, domain, domain_length);
    sha256_update(&context, data, data_length);
    sha256_final(&context, inner_digest);

    sha256_init(&context);
    sha256_update(&context, outer_pad, sizeof(outer_pad));
    sha256_update(&context, inner_digest, sizeof(inner_digest));
    sha256_final(&context, digest);

    memset(key_block, 0, sizeof(key_block));
    memset(inner_pad, 0, sizeof(inner_pad));
    memset(outer_pad, 0, sizeof(outer_pad));
    memset(inner_digest, 0, sizeof(inner_digest));
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

static void encode_hex(const uint8_t *data, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        output[i * 2U] = digits[data[i] >> 4];
        output[i * 2U + 1U] = digits[data[i] & UINT8_C(0x0f)];
    }
    output[length * 2U] = '\0';
}

static int write_all(int fd, const uint8_t *data, size_t length, int64_t *error_code) {
    size_t offset = 0;
    while (offset < length) {
        const ssize_t written = write(fd, data + offset, length - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        *error_code = written < 0 && errno != 0 ? -(int64_t)errno : -(int64_t)EIO;
        return -1;
    }
    return 0;
}

static int write_marker(const char *marker, size_t length) {
    int64_t ignored_code = 0;
    return write_all(STDOUT_FILENO, (const uint8_t *)marker, length, &ignored_code);
}

static int emit_begin(const ParsedProgram *program) {
    char run_hex[33];
    char program_hex[65];
    char marker[256];
    int length;

    encode_hex(program->run_id, sizeof(program->run_id), run_hex);
    encode_hex(program->program_digest, sizeof(program->program_digest), program_hex);
    length = snprintf(
        marker,
        sizeof(marker),
        "NILIX_SYZ_V2_BEGIN seq=%016" PRIx64 " run=%s program=%s\n",
        program->sequence,
        run_hex,
        program_hex
    );
    if (length < 0 || (size_t)length >= sizeof(marker)) {
        return -1;
    }
    return write_marker(marker, (size_t)length);
}

static int emit_pass(
    const ParsedProgram *program,
    uint32_t occupied_slot_count,
    const uint8_t tag[32]
) {
    char run_hex[33];
    char program_hex[65];
    char tag_hex[65];
    char marker[384];
    int length;

    terminal_marker_emitted = true;
    encode_hex(program->run_id, sizeof(program->run_id), run_hex);
    encode_hex(program->program_digest, sizeof(program->program_digest), program_hex);
    encode_hex(tag, 32U, tag_hex);
    length = snprintf(
        marker,
        sizeof(marker),
        "NILIX_SYZ_V2_PASS seq=%016" PRIx64
        " run=%s program=%s slots=%" PRIu32 " tag=%s\n",
        program->sequence,
        run_hex,
        program_hex,
        occupied_slot_count,
        tag_hex
    );
    if (length < 0 || (size_t)length >= sizeof(marker)) {
        return -1;
    }
    return write_marker(marker, (size_t)length);
}

static int emit_fail(
    const ParsedProgram *program,
    bool identity_available,
    const ExecutorError *error
) {
    char marker[384];
    int length;

    if (terminal_marker_emitted) {
        return -1;
    }
    terminal_marker_emitted = true;

    if (identity_available) {
        char run_hex[33];
        char program_hex[65];
        encode_hex(program->run_id, sizeof(program->run_id), run_hex);
        encode_hex(program->program_digest, sizeof(program->program_digest), program_hex);
        length = snprintf(
            marker,
            sizeof(marker),
            "NILIX_SYZ_V2_FAIL seq=%016" PRIx64
            " run=%s program=%s stage=%s code=%" PRId64 "\n",
            program->sequence,
            run_hex,
            program_hex,
            error->stage,
            error->code
        );
    } else {
        length = snprintf(
            marker,
            sizeof(marker),
            "NILIX_SYZ_V2_FAIL seq=none run=none program=none"
            " stage=%s code=%" PRId64 "\n",
            error->stage,
            error->code
        );
    }

    if (length < 0 || (size_t)length >= sizeof(marker)) {
        return -1;
    }
    return write_marker(marker, (size_t)length);
}

static int set_error(ExecutorError *error, const char *stage, int64_t code) {
    error->stage = stage;
    error->code = code;
    return -1;
}

static int read_program_file(size_t *program_length, ExecutorError *error) {
    int fd = open(PROGRAM_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return set_error(error, "input_open", errno != 0 ? -(int64_t)errno : -(int64_t)EIO);
    }

    size_t total = 0;
    for (;;) {
        if (total == sizeof(program_buffer)) {
            (void)close(fd);
            return set_error(error, "input_oversize", -(int64_t)E2BIG);
        }

        const ssize_t count = read(fd, program_buffer + total, sizeof(program_buffer) - total);
        if (count > 0) {
            total += (size_t)count;
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }

        const int saved_errno = errno;
        (void)close(fd);
        return set_error(
            error,
            "input_read",
            saved_errno != 0 ? -(int64_t)saved_errno : -(int64_t)EIO
        );
    }

    if (close(fd) != 0) {
        return set_error(error, "input_close", errno != 0 ? -(int64_t)errno : -(int64_t)EIO);
    }
    if (total == 0U) {
        return set_error(error, "input_empty", -(int64_t)EINVAL);
    }
    if (total > MAX_PROGRAM_SIZE) {
        return set_error(error, "input_oversize", -(int64_t)E2BIG);
    }

    *program_length = total;
    return 0;
}

static void compute_program_digest(
    const uint8_t *data,
    size_t length,
    uint8_t digest[32]
) {
    static const uint8_t zero_digest[32] = {0};
    Sha256Context context;

    sha256_init(&context);
    sha256_update(&context, PROGRAM_DOMAIN, sizeof(PROGRAM_DOMAIN) - 1U);
    sha256_update(&context, data, 88U);
    sha256_update(&context, zero_digest, sizeof(zero_digest));
    sha256_update(&context, data + 120U, length - 120U);
    sha256_final(&context, digest);
}

static bool is_canonical_path(const ParsedArgument *argument) {
    if (argument->kind != ARG_INPUT || argument->data_length == 0U) {
        return false;
    }

    const uint8_t *path = argument_arena.bytes + argument->arena_offset;
    if (path[argument->data_length - 1U] != 0U) {
        return false;
    }
    for (uint32_t i = 0; i + 1U < argument->data_length; ++i) {
        if (path[i] == 0U) {
            return false;
        }
    }
    return true;
}

static bool is_immediate(const ParsedArgument *argument) {
    return argument->kind == ARG_IMMEDIATE;
}

static bool is_null_argument(const ParsedArgument *argument) {
    return argument->kind == ARG_NULL;
}

static bool is_output_exact(const ParsedArgument *argument, uint32_t minimum_capacity) {
    return argument->kind == ARG_OUTPUT && argument->capacity >= minimum_capacity;
}

static bool is_output_or_inout(const ParsedArgument *argument, uint32_t minimum_capacity) {
    return (argument->kind == ARG_OUTPUT || argument->kind == ARG_INOUT) &&
           argument->capacity >= minimum_capacity;
}

static bool validate_call_policy(const ParsedCall *call) {
    const ParsedArgument *args = call->arguments;

    switch (call->number) {
        case 24U:
        case 39U:
        case 102U:
        case 104U:
        case 107U:
        case 108U:
        case 110U:
        case 186U:
            return call->argument_count == 0U;

        case 12U:
            return call->argument_count == 1U &&
                   is_immediate(&args[0]) && args[0].value == 0U;

        case 21U:
            return call->argument_count == 2U &&
                   is_canonical_path(&args[0]) &&
                   is_immediate(&args[1]) && args[1].value <= 7U;

        case 4U:
        case 6U:
            return call->argument_count == 2U &&
                   is_canonical_path(&args[0]) &&
                   is_output_or_inout(&args[1], 144U);

        case 63U:
            return call->argument_count == 1U &&
                   is_output_or_inout(&args[0], 390U);

        case 96U:
            return call->argument_count == 2U &&
                   is_output_or_inout(&args[0], 16U) &&
                   is_null_argument(&args[1]);

        case 228U:
            if (call->argument_count != 2U ||
                !is_immediate(&args[0]) ||
                !is_output_or_inout(&args[1], 16U)) {
                return false;
            }
            return args[0].value == 0U || args[0].value == 1U ||
                   args[0].value == 4U || args[0].value == 5U ||
                   args[0].value == 6U || args[0].value == 7U;

        case 318U:
            return call->argument_count == 3U &&
                   is_output_exact(&args[0], 1U) &&
                   is_immediate(&args[1]) && args[1].value >= 1U &&
                   args[1].value <= args[0].capacity &&
                   is_immediate(&args[2]) && args[2].value == 1U;

        case 79U:
            return call->argument_count == 2U &&
                   is_output_exact(&args[0], 1U) &&
                   is_immediate(&args[1]) && args[1].value >= 1U &&
                   args[1].value <= args[0].capacity;

        case 89U:
            return call->argument_count == 3U &&
                   is_canonical_path(&args[0]) &&
                   is_output_exact(&args[1], 1U) &&
                   is_immediate(&args[2]) && args[2].value >= 1U &&
                   args[2].value <= args[1].capacity;

        case 204U:
            return call->argument_count == 3U &&
                   is_immediate(&args[0]) && args[0].value == 0U &&
                   is_immediate(&args[1]) && args[1].value >= 1U &&
                   is_output_exact(&args[2], 1U) &&
                   args[1].value <= args[2].capacity;

        case 97U:
            return call->argument_count == 2U &&
                   is_immediate(&args[0]) && args[0].value <= 15U &&
                   is_output_exact(&args[1], 16U);

        default:
            return false;
    }
}

static int parse_program(
    const uint8_t *data,
    size_t length,
    ParsedProgram *program,
    bool *identity_available,
    ExecutorError *error
) {
    uint8_t computed_digest[32];
    size_t cursor;

    memset(program, 0, sizeof(*program));
    memset(argument_arena.bytes, 0, sizeof(argument_arena.bytes));
    *identity_available = false;

    if (length < PROGRAM_HEADER_SIZE) {
        return set_error(error, "header_truncated", -(int64_t)EINVAL);
    }
    if (memcmp(data, PROGRAM_MAGIC, sizeof(PROGRAM_MAGIC)) != 0) {
        return set_error(error, "header_magic", -(int64_t)EINVAL);
    }
    if (read_le16(data + 8U) != PROTOCOL_VERSION) {
        return set_error(error, "header_version", -(int64_t)EINVAL);
    }
    if (read_le16(data + 10U) != PROGRAM_HEADER_SIZE) {
        return set_error(error, "header_length", -(int64_t)EINVAL);
    }
    if (read_le32(data + 12U) != length) {
        return set_error(error, "total_length", -(int64_t)EINVAL);
    }
    if (read_le32(data + 16U) != 0U) {
        return set_error(error, "header_flags", -(int64_t)EINVAL);
    }

    program->syscall_count = read_le32(data + 20U);
    if (program->syscall_count == 0U || program->syscall_count > MAX_SYSCALLS) {
        return set_error(error, "syscall_count", -(int64_t)EINVAL);
    }
    program->kcov_length = read_le32(data + 24U);
    if (program->kcov_length != KCOV_BUFFER_SIZE) {
        return set_error(error, "kcov_length", -(int64_t)EINVAL);
    }
    if (read_le32(data + 28U) != 0U || !bytes_are_zero(data + 120U, 8U)) {
        return set_error(error, "header_reserved", -(int64_t)EINVAL);
    }

    program->sequence = read_le64(data + 32U);
    memcpy(program->run_id, data + 40U, sizeof(program->run_id));
    memcpy(program->auth_key, data + 56U, sizeof(program->auth_key));
    memcpy(program->program_digest, data + 88U, sizeof(program->program_digest));

    compute_program_digest(data, length, computed_digest);
    if (!constant_time_equal(
            computed_digest,
            program->program_digest,
            sizeof(computed_digest)
        )) {
        memset(computed_digest, 0, sizeof(computed_digest));
        return set_error(error, "program_digest", -(int64_t)EBADMSG);
    }
    memset(computed_digest, 0, sizeof(computed_digest));
    *identity_available = true;

    cursor = PROGRAM_HEADER_SIZE;
    for (uint32_t call_index = 0; call_index < program->syscall_count; ++call_index) {
        ParsedCall *call = &program->calls[call_index];
        const size_t record_start = cursor;
        size_t record_end;
        size_t argument_cursor;

        if (!range_is_valid(record_start, CALL_HEADER_SIZE, length)) {
            return set_error(error, "call_header", -(int64_t)EINVAL);
        }

        call->number = read_le32(data + record_start);
        const uint32_t record_length_u32 = read_le32(data + record_start + 4U);
        call->argument_count = read_le16(data + record_start + 8U);

        if (record_length_u32 < CALL_HEADER_SIZE ||
            (record_length_u32 & 7U) != 0U ||
            !checked_add_size(record_start, (size_t)record_length_u32, &record_end) ||
            record_end > length) {
            return set_error(error, "call_record_length", -(int64_t)EINVAL);
        }
        if (call->argument_count > MAX_ARGS) {
            return set_error(error, "argument_count", -(int64_t)EINVAL);
        }
        if (read_le16(data + record_start + 10U) != 0U ||
            read_le32(data + record_start + 12U) != 0U) {
            return set_error(error, "call_reserved", -(int64_t)EINVAL);
        }

        argument_cursor = record_start + CALL_HEADER_SIZE;
        for (uint16_t argument_index = 0;
             argument_index < call->argument_count;
             ++argument_index) {
            ParsedArgument *argument = &call->arguments[argument_index];
            size_t data_start;
            size_t data_end;
            size_t padded_end;

            if (!range_is_valid(argument_cursor, ARG_HEADER_SIZE, record_end)) {
                return set_error(error, "argument_header", -(int64_t)EINVAL);
            }

            argument->kind = data[argument_cursor];
            argument->data_length = read_le32(data + argument_cursor + 4U);
            argument->capacity = read_le32(data + argument_cursor + 8U);
            argument->value = read_le64(data + argument_cursor + 16U);

            if (argument->kind > ARG_INOUT) {
                return set_error(error, "argument_kind", -(int64_t)EINVAL);
            }
            if (data[argument_cursor + 1U] != 0U ||
                read_le16(data + argument_cursor + 2U) != 0U ||
                read_le32(data + argument_cursor + 12U) != 0U) {
                return set_error(error, "argument_reserved", -(int64_t)EINVAL);
            }
            if (argument->capacity > MAX_ARG_CAPACITY ||
                argument->data_length > argument->capacity) {
                return set_error(error, "argument_capacity", -(int64_t)E2BIG);
            }

            switch (argument->kind) {
                case ARG_IMMEDIATE:
                    if (argument->data_length != 0U || argument->capacity != 0U) {
                        return set_error(error, "argument_canonical", -(int64_t)EINVAL);
                    }
                    break;
                case ARG_NULL:
                    if (argument->data_length != 0U || argument->capacity != 0U ||
                        argument->value != 0U) {
                        return set_error(error, "argument_canonical", -(int64_t)EINVAL);
                    }
                    break;
                case ARG_INPUT:
                    if (argument->data_length != argument->capacity || argument->value != 0U) {
                        return set_error(error, "argument_canonical", -(int64_t)EINVAL);
                    }
                    break;
                case ARG_OUTPUT:
                    if (argument->data_length != 0U || argument->capacity == 0U ||
                        argument->value != 0U) {
                        return set_error(error, "argument_canonical", -(int64_t)EINVAL);
                    }
                    break;
                case ARG_INOUT:
                    if (argument->value != 0U) {
                        return set_error(error, "argument_canonical", -(int64_t)EINVAL);
                    }
                    break;
                default:
                    return set_error(error, "argument_kind", -(int64_t)EINVAL);
            }

            if (!checked_add_size(argument_cursor, ARG_HEADER_SIZE, &data_start) ||
                !range_is_valid(data_start, argument->data_length, record_end)) {
                return set_error(error, "argument_data", -(int64_t)EINVAL);
            }
            data_end = data_start + argument->data_length;
            if (!checked_align8(data_end, &padded_end) || padded_end > record_end) {
                return set_error(error, "argument_padding", -(int64_t)EINVAL);
            }
            if (!bytes_are_zero(data + data_end, padded_end - data_end)) {
                return set_error(error, "argument_padding", -(int64_t)EINVAL);
            }

            argument->arena_offset = 0U;
            if (argument->capacity > 0U) {
                size_t arena_offset;
                size_t arena_end;
                if (!checked_align8(program->arena_used, &arena_offset) ||
                    !checked_add_size(arena_offset, argument->capacity, &arena_end) ||
                    arena_end > ARG_ARENA_SIZE) {
                    return set_error(error, "arena_capacity", -(int64_t)E2BIG);
                }
                argument->arena_offset = arena_offset;
                if (argument->data_length > 0U) {
                    memcpy(
                        argument_arena.bytes + arena_offset,
                        data + data_start,
                        argument->data_length
                    );
                }
                if (argument->capacity > argument->data_length) {
                    memset(
                        argument_arena.bytes + arena_offset + argument->data_length,
                        0,
                        argument->capacity - argument->data_length
                    );
                }
                program->arena_used = arena_end;
            }

            argument_cursor = padded_end;
        }

        if (argument_cursor != record_end) {
            return set_error(error, "record_boundary", -(int64_t)EINVAL);
        }
        if (!validate_call_policy(call)) {
            return set_error(error, "syscall_policy", -(int64_t)EPERM);
        }
        cursor = record_end;
    }

    if (cursor != length) {
        return set_error(error, "trailing_data", -(int64_t)EINVAL);
    }
    return 0;
}

static int64_t invoke_syscall(uint32_t number, const uint64_t arguments[6]) {
    errno = 0;
    const long result = syscall(
        (long)number,
        arguments[0],
        arguments[1],
        arguments[2],
        arguments[3],
        arguments[4],
        arguments[5]
    );
    if (result == -1L && errno != 0) {
        return -(int64_t)errno;
    }
    return (int64_t)result;
}

static int64_t invoke_kcov_retry(uint32_t number, uint64_t first, uint64_t second) {
    const uint64_t arguments[6] = {first, second, 0, 0, 0, 0};
    int64_t result = -(int64_t)EBUSY;

    for (unsigned int attempt = 0; attempt < KCOV_BUSY_RETRIES; ++attempt) {
        result = invoke_syscall(number, arguments);
        if (result != -(int64_t)EBUSY) {
            break;
        }
    }
    return result;
}

static void best_effort_kcov_disable(void) {
    (void)invoke_kcov_retry(NILIX_SYS_KCOV_DISABLE, 0U, 0U);
}

static uint32_t bitmap_popcount(const uint8_t *bitmap, size_t length) {
    uint32_t count = 0;
    for (size_t i = 0; i < length; ++i) {
        uint8_t value = bitmap[i];
        while (value != 0U) {
            count += value & 1U;
            value >>= 1;
        }
    }
    return count;
}

static void materialize_arguments(const ParsedCall *call, uint64_t arguments[6]) {
    memset(arguments, 0, 6U * sizeof(arguments[0]));
    for (uint16_t i = 0; i < call->argument_count; ++i) {
        const ParsedArgument *argument = &call->arguments[i];
        switch (argument->kind) {
            case ARG_IMMEDIATE:
                arguments[i] = argument->value;
                break;
            case ARG_NULL:
                arguments[i] = 0U;
                break;
            case ARG_INPUT:
            case ARG_OUTPUT:
            case ARG_INOUT:
                arguments[i] = (uint64_t)(uintptr_t)(
                    argument_arena.bytes + argument->arena_offset
                );
                break;
            default:
                arguments[i] = 0U;
                break;
        }
    }
}

static int collect_coverage(
    const ParsedProgram *program,
    uint32_t *executed_count,
    uint32_t *occupied_slot_count,
    ExecutorError *error
) {
    bool enabled = false;
    int64_t result;

    result = invoke_kcov_retry(NILIX_SYS_KCOV_INIT, KCOV_BUFFER_SIZE, 0U);
    if (result != 0) {
        return set_error(error, "kcov_init", result);
    }

    result = invoke_kcov_retry(NILIX_SYS_KCOV_RESET, 0U, 0U);
    if (result != 0) {
        return set_error(error, "kcov_reset_before", result);
    }

    result = invoke_kcov_retry(NILIX_SYS_KCOV_ENABLE, 0U, 0U);
    if (result != 0) {
        return set_error(error, "kcov_enable", result);
    }
    enabled = true;

    *executed_count = 0U;
    for (uint32_t i = 0; i < program->syscall_count; ++i) {
        uint64_t arguments[6];
        materialize_arguments(&program->calls[i], arguments);
        syscall_returns[i] = invoke_syscall(program->calls[i].number, arguments);
        *executed_count = i + 1U;
    }

    result = invoke_kcov_retry(NILIX_SYS_KCOV_DISABLE, 0U, 0U);
    if (result != 0) {
        best_effort_kcov_disable();
        return set_error(error, "kcov_disable", result);
    }
    enabled = false;

    memset(coverage_bitmap, 0, sizeof(coverage_bitmap));
    result = invoke_kcov_retry(
        NILIX_SYS_KCOV_DUMP,
        (uint64_t)(uintptr_t)coverage_bitmap,
        KCOV_BUFFER_SIZE
    );
    if (result < 0) {
        return set_error(error, "kcov_dump", result);
    }
    if ((uint64_t)result > (uint64_t)KCOV_BUFFER_SIZE * 8U) {
        return set_error(error, "kcov_slot_range", result);
    }

    const uint32_t counted_slots = bitmap_popcount(coverage_bitmap, sizeof(coverage_bitmap));
    if ((uint32_t)result != counted_slots) {
        return set_error(error, "kcov_popcount", result);
    }
    if (counted_slots == 0U) {
        return set_error(error, "kcov_zero", 0);
    }

    result = invoke_kcov_retry(NILIX_SYS_KCOV_RESET, 0U, 0U);
    if (result != 0) {
        return set_error(error, "kcov_reset_after", result);
    }

    *occupied_slot_count = counted_slots;
    return 0;

    if (enabled) {
        best_effort_kcov_disable();
    }
}

static int build_result(
    const ParsedProgram *program,
    uint32_t executed_count,
    uint32_t occupied_slot_count,
    size_t *result_length,
    uint8_t tag[32],
    ExecutorError *error
) {
    size_t returns_length;
    size_t bitmap_offset;
    size_t tag_offset;
    size_t total_length;

    if (executed_count != program->syscall_count) {
        return set_error(error, "result_executed_count", -(int64_t)EINVAL);
    }
    if (!checked_add_size(0U, (size_t)program->syscall_count * 8U, &returns_length) ||
        !checked_add_size(RESULT_HEADER_SIZE, returns_length, &bitmap_offset) ||
        !checked_add_size(bitmap_offset, KCOV_BUFFER_SIZE, &tag_offset) ||
        !checked_add_size(tag_offset, RESULT_TAG_SIZE, &total_length) ||
        total_length > sizeof(result_buffer) ||
        total_length > UINT32_MAX) {
        return set_error(error, "result_size", -(int64_t)EOVERFLOW);
    }

    memset(result_buffer, 0, total_length);
    memcpy(result_buffer, RESULT_MAGIC, sizeof(RESULT_MAGIC));
    write_le16(result_buffer + 8U, PROTOCOL_VERSION);
    write_le16(result_buffer + 10U, RESULT_HEADER_SIZE);
    write_le32(result_buffer + 12U, (uint32_t)total_length);
    write_le32(result_buffer + 16U, 0U);
    write_le32(result_buffer + 20U, 0U);
    write_le32(result_buffer + 24U, program->syscall_count);
    write_le32(result_buffer + 28U, executed_count);
    write_le32(result_buffer + 32U, KCOV_BUFFER_SIZE);
    write_le32(result_buffer + RESULT_OCCUPIED_SLOT_COUNT_OFFSET, occupied_slot_count);
    write_le32(result_buffer + 40U, RESULT_HEADER_SIZE);
    write_le32(result_buffer + 44U, (uint32_t)bitmap_offset);
    write_le32(result_buffer + 48U, (uint32_t)tag_offset);
    write_le32(result_buffer + 52U, 0U);
    write_le64(result_buffer + 56U, program->sequence);
    memcpy(result_buffer + 64U, program->run_id, sizeof(program->run_id));
    memcpy(result_buffer + 80U, program->program_digest, sizeof(program->program_digest));

    for (uint32_t i = 0; i < program->syscall_count; ++i) {
        write_le64(
            result_buffer + RESULT_HEADER_SIZE + (size_t)i * 8U,
            (uint64_t)syscall_returns[i]
        );
    }
    memcpy(result_buffer + bitmap_offset, coverage_bitmap, KCOV_BUFFER_SIZE);

    hmac_sha256(
        program->auth_key,
        sizeof(program->auth_key),
        RESULT_DOMAIN,
        sizeof(RESULT_DOMAIN) - 1U,
        result_buffer,
        tag_offset,
        tag
    );
    memcpy(result_buffer + tag_offset, tag, RESULT_TAG_SIZE);
    *result_length = total_length;
    return 0;
}

static void best_effort_unlink_temp(void) {
    const uint64_t arguments[6] = {
        (uint64_t)(uintptr_t)RESULT_TEMP_PATH, 0, 0, 0, 0, 0,
    };
    (void)invoke_syscall(NILIX_SYS_UNLINK, arguments);
}

static int write_result_file(size_t result_length, ExecutorError *error) {
    int fd = open(
        RESULT_TEMP_PATH,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    if (fd < 0) {
        return set_error(error, "result_open", errno != 0 ? -(int64_t)errno : -(int64_t)EIO);
    }

    int64_t write_error = 0;
    if (write_all(fd, result_buffer, result_length, &write_error) != 0) {
        (void)close(fd);
        best_effort_unlink_temp();
        return set_error(error, "result_write", write_error);
    }
    if (close(fd) != 0) {
        const int saved_errno = errno;
        best_effort_unlink_temp();
        return set_error(
            error,
            "result_close",
            saved_errno != 0 ? -(int64_t)saved_errno : -(int64_t)EIO
        );
    }

    const uint64_t rename_arguments[6] = {
        (uint64_t)(int64_t)NILIX_AT_FDCWD,
        (uint64_t)(uintptr_t)RESULT_TEMP_PATH,
        (uint64_t)(int64_t)NILIX_AT_FDCWD,
        (uint64_t)(uintptr_t)RESULT_PATH,
        NILIX_RENAME_NOREPLACE,
        0,
    };
    const int64_t rename_result = invoke_syscall(NILIX_SYS_RENAMEAT2, rename_arguments);
    if (rename_result != 0) {
        best_effort_unlink_temp();
        return set_error(error, "result_rename", rename_result);
    }
    return 0;
}

static int decode_hex(const char *input, uint8_t *output, size_t output_length) {
    for (size_t i = 0; i < output_length; ++i) {
        unsigned int high;
        unsigned int low;
        const char high_char = input[i * 2U];
        const char low_char = input[i * 2U + 1U];

        if (high_char >= '0' && high_char <= '9') {
            high = (unsigned int)(high_char - '0');
        } else if (high_char >= 'a' && high_char <= 'f') {
            high = (unsigned int)(high_char - 'a') + 10U;
        } else {
            return -1;
        }
        if (low_char >= '0' && low_char <= '9') {
            low = (unsigned int)(low_char - '0');
        } else if (low_char >= 'a' && low_char <= 'f') {
            low = (unsigned int)(low_char - 'a') + 10U;
        } else {
            return -1;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return input[output_length * 2U] == '\0' ? 0 : -1;
}

static int run_self_test(void) {
    static const uint8_t abc[] = {'a', 'b', 'c'};
    static const uint8_t hmac_message[] = "Hi There";
    static const char sha_expected_hex[] =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";
    static const char hmac_expected_hex[] =
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7";
    uint8_t hmac_key[20];
    uint8_t digest[32];
    uint8_t expected[32];

    memset(hmac_key, UINT8_C(0x0b), sizeof(hmac_key));
    sha256_digest(abc, sizeof(abc), digest);
    if (decode_hex(sha_expected_hex, expected, sizeof(expected)) != 0 ||
        !constant_time_equal(digest, expected, sizeof(expected))) {
        return 1;
    }

    hmac_sha256(
        hmac_key,
        sizeof(hmac_key),
        NULL,
        0U,
        hmac_message,
        sizeof(hmac_message) - 1U,
        digest
    );
    if (decode_hex(hmac_expected_hex, expected, sizeof(expected)) != 0 ||
        !constant_time_equal(digest, expected, sizeof(expected))) {
        return 1;
    }

    static const char pass_marker[] = "NILIX_SYZ_V2_SELF_TEST_PASS\n";
    return write_marker(pass_marker, sizeof(pass_marker) - 1U) == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    // RF187-5 FIX: the pre-parse argument failure path still passes the
    // identity container to emit_fail. Zero-initialize it so strict compilers
    // and any future diagnostic refactor cannot observe indeterminate fields.
    ParsedProgram program = {0};
    ExecutorError error = {"internal", -(int64_t)EIO};
    bool identity_available = false;
    size_t program_length = 0;
    size_t result_length = 0;
    uint32_t executed_count = 0;
    uint32_t occupied_slot_count = 0;
    uint8_t result_tag[32];

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return run_self_test();
    }
    if (argc != 1) {
        (void)emit_fail(&program, false, &(ExecutorError){"arguments", -(int64_t)EINVAL});
        return 1;
    }

    if (read_program_file(&program_length, &error) != 0) {
        (void)emit_fail(&program, false, &error);
        return 1;
    }
    if (parse_program(
            program_buffer,
            program_length,
            &program,
            &identity_available,
            &error
        ) != 0) {
        (void)emit_fail(&program, identity_available, &error);
        return 1;
    }
    if (emit_begin(&program) != 0) {
        return 1;
    }

    if (collect_coverage(&program, &executed_count, &occupied_slot_count, &error) != 0) {
        (void)emit_fail(&program, true, &error);
        return 1;
    }
    if (build_result(
            &program,
            executed_count,
            occupied_slot_count,
            &result_length,
            result_tag,
            &error
        ) != 0) {
        (void)emit_fail(&program, true, &error);
        return 1;
    }
    if (write_result_file(result_length, &error) != 0) {
        (void)emit_fail(&program, true, &error);
        return 1;
    }
    if (emit_pass(&program, occupied_slot_count, result_tag) != 0) {
        return 1;
    }
    return 0;
}
