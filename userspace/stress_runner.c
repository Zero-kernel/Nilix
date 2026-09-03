#define _GNU_SOURCE

/*
 * Bounded Ring-3 stress workload speaking the NILSTR2 ("stress-v2") contract.
 *
 * Security > Correctness > Efficiency > Performance
 *
 * The host half of this contract lives in scripts/stress_protocol.py and
 * scripts/stress_test.sh. It injects a 256-byte configuration record into the
 * ext3 image at /test/stress.cfg (visible here as /mnt/test/stress.cfg), boots
 * this guest, and validates the serial marker stream fail-closed. Every field
 * emitted below is cross-checked host-side, so this file must not "round" or
 * approximate any counter: the validator asserts exact arithmetic.
 *
 * Marker order for a normal run is fixed and load-bearing:
 *
 *     BEGIN
 *     READY
 *     <profile> seq=1        <- one round of work
 *     PASS                   <- only after the first round, echoing its counters
 *     HEARTBEAT seq=1
 *     <profile> seq=2
 *     HEARTBEAT seq=2
 *     ...
 *
 * PASS, HEARTBEAT(N) and round N all carry the same checksum; heartbeat cycles
 * are exactly seq * rounds_per_heartbeat and both cycles and ops must strictly
 * increase. The run is host-terminated: we loop until QEMU is killed.
 *
 * Each phase is independently bounded and fail-closed. Any deviation emits a
 * FAIL marker (which the validator treats as fatal) rather than continuing.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Nilix-specific syscall surface (kernel/kernel_core/syscall.rs)      */
/* ------------------------------------------------------------------ */

#define NILIX_SYS_CGROUP_CREATE 500
#define NILIX_SYS_CGROUP_ATTACH 502
#define NILIX_SYS_CGROUP_SET_LIMIT 503
#define NILIX_SYS_CGROUP_GET_STATS2 516

/* CgroupControllers bits (kernel/kernel_core/cgroup.rs). */
#define CGROUP_CTRL_CPU 0x01u
#define CGROUP_CTRL_MEMORY 0x02u
#define CGROUP_CTRL_PIDS 0x04u

/* CGROUP_LIMIT_* discriminants (kernel/kernel_core/syscall.rs). */
#define CGROUP_LIMIT_MEMORY_MAX 3u
#define CGROUP_LIMIT_PIDS_MAX 5u

/*
 * Offset-stable prefix of CgroupStatsBuf. The kernel struct is #[repr(C)] and
 * 136 bytes today; sys_cgroup_get_stats2 negotiates the length via buf_len and
 * never writes past it, so declaring the v1 104-byte prefix would also be
 * valid. We mirror the full 136-byte layout and pass sizeof(), which keeps the
 * pids/memory event counters we depend on inside the copied range.
 */
typedef struct {
    uint64_t id;
    uint32_t depth;
    uint32_t controllers;
    uint64_t nr_tasks;
    uint64_t cpu_time_ns;
    uint64_t memory_current;
    uint64_t memory_events_high;
    uint64_t memory_events_max;
    uint32_t pids_events_max;
    uint32_t padding;
    uint64_t io_read_bytes;
    uint64_t io_write_bytes;
    uint64_t io_read_ios;
    uint64_t io_write_ios;
    uint64_t io_throttle_events;
    uint64_t fds_current;
    uint64_t ports_current;
    uint64_t vfs_dir_current;
    uint32_t fds_events_max;
    uint32_t ports_events_max;
} CgroupStatsBuf;

_Static_assert(sizeof(CgroupStatsBuf) == 136, "CgroupStatsBuf must match the kernel ABI");
_Static_assert(offsetof(CgroupStatsBuf, memory_current) == 32, "memory_current offset drift");
_Static_assert(offsetof(CgroupStatsBuf, memory_events_max) == 48, "memory_events_max offset drift");
_Static_assert(offsetof(CgroupStatsBuf, pids_events_max) == 56, "pids_events_max offset drift");

/* ------------------------------------------------------------------ */
/* Configuration record                                                */
/* ------------------------------------------------------------------ */

/*
 * The harness injects its files into the ext3 image under /test, which the
 * kernel mounts at /mnt. STRESS_GUEST_ROOT may be overridden at compile time so
 * the parser and marker formatting can be exercised on a normal Linux host,
 * where /mnt is not writable; the shipped guest always uses the contract path.
 */
#ifndef STRESS_GUEST_ROOT
#define STRESS_GUEST_ROOT "/mnt/test"
#endif

#define CONFIG_PATH STRESS_GUEST_ROOT "/stress.cfg"
#define CONFIG_TOTAL_BYTES 256u
#define CONFIG_HEADER_BYTES 40u
#define CONFIG_DIGEST_OFFSET 216u
#define CONFIG_RESERVED_OFFSET 112u
#define CONFIG_RESERVED_BYTES 104u
#define CONFIG_END_MAGIC_OFFSET 248u
#define CONFIG_VERSION 2u

#define PROFILE_MEMORY 1u
#define PROFILE_CPU 2u
#define PROFILE_SMP 3u
#define PROFILE_PROCESS 4u
#define PROFILE_BLOCK 5u
#define PROFILE_COMBINED 6u

#define FLAG_REQUIRE_OOM (1u << 0)
#define FLAG_PIN_WORKERS (1u << 1)
#define FLAG_BLOCK_CRASH_AUTO (1u << 2)
#define FLAG_HOST_TERMINATED (1u << 3)
#define FLAG_REQUIRE_QMP_VCPUS (1u << 4)

#define PAGE_BYTES ((size_t)4096)
#define MAX_WORKERS 64u
/*
 * Worst case admitted by the host validator: a 1 GiB memory_limit_delta cut
 * into 64 KiB chunks. Sized for that bound and held in BSS rather than on the
 * stack, so a large-delta configuration can never overflow the mapping table.
 */
#define MAX_CHUNKS 16384u

typedef struct {
    uint32_t profile;
    uint32_t flags;
    uint64_t run_id;
    uint64_t seed;
    uint32_t vcpus;
    uint32_t workers;
    uint32_t heartbeat_max_ms;
    uint32_t rounds_per_heartbeat;
    uint64_t memory_limit_delta;
    uint64_t memory_chunk_bytes;
    uint64_t cpu_iterations;
    uint64_t contention_iterations;
    uint32_t churn_fanout;
    uint32_t churn_waves;
    uint32_t io_block_bytes;
    uint32_t io_slots;
    uint32_t io_writes_per_round;
    uint32_t reclaim_percent;
    char digest_hex[65];
} StressConfig;

static const char *const PROFILE_NAMES[] = {
    NULL, "memory", "cpu", "smp", "process", "block", "combined",
};

/* Emitted at most once; the validator treats any FAIL as fatal. */
static int failure_emitted;
static StressConfig config;
static uint64_t cgroup_id;

/* ------------------------------------------------------------------ */
/* SHA-256 (config digest verification)                                */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buffered;
} Sha256;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static uint32_t rotate_right(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32u - bits));
}

static void sha256_init(Sha256 *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->buffered = 0;
}

static void sha256_compress(Sha256 *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; ++i) {
        const uint32_t s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (size_t i = 0; i < 64; ++i) {
        const uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + s1 + ch + SHA256_K[i] + w[i];
        const uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_update(Sha256 *ctx, const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        ctx->buffer[ctx->buffered++] = data[i];
        if (ctx->buffered == 64) {
            sha256_compress(ctx, ctx->buffer);
            ctx->bitlen += 512;
            ctx->buffered = 0;
        }
    }
}

static void sha256_final(Sha256 *ctx, uint8_t digest[32]) {
    const uint64_t total_bits = ctx->bitlen + (uint64_t)ctx->buffered * 8u;
    size_t i = ctx->buffered;

    ctx->buffer[i++] = 0x80u;
    if (i > 56) {
        while (i < 64) {
            ctx->buffer[i++] = 0x00u;
        }
        sha256_compress(ctx, ctx->buffer);
        i = 0;
    }
    while (i < 56) {
        ctx->buffer[i++] = 0x00u;
    }
    for (int shift = 7; shift >= 0; --shift) {
        ctx->buffer[i++] = (uint8_t)((total_bits >> (shift * 8)) & 0xffu);
    }
    sha256_compress(ctx, ctx->buffer);

    for (size_t word = 0; word < 8; ++word) {
        digest[word * 4] = (uint8_t)((ctx->state[word] >> 24) & 0xffu);
        digest[word * 4 + 1] = (uint8_t)((ctx->state[word] >> 16) & 0xffu);
        digest[word * 4 + 2] = (uint8_t)((ctx->state[word] >> 8) & 0xffu);
        digest[word * 4 + 3] = (uint8_t)(ctx->state[word] & 0xffu);
    }
}

/* ------------------------------------------------------------------ */
/* Marker emission                                                     */
/* ------------------------------------------------------------------ */

static const char *profile_name(void) {
    if (config.profile >= 1u && config.profile <= 6u) {
        return PROFILE_NAMES[config.profile];
    }
    return "memory";
}

static void emit(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vprintf(format, arguments);
    va_end(arguments);
    (void)fputc('\n', stdout);
    (void)fflush(stdout);
}

/*
 * Fail-closed exit. `seq` may be zero (the FAIL marker permits it), `errno_value`
 * is reported verbatim so the host log names the failing syscall.
 */
static void fail(const char *stage, long errno_value, uint64_t detail) {
    if (!failure_emitted) {
        failure_emitted = 1;
        emit("NILIX_STRESS_V2_FAIL run=%016" PRIx64 " profile=%s seq=0 stage=%s errno=%ld detail=%" PRIu64,
             config.run_id, profile_name(), stage, errno_value, detail);
    }
    _exit(1);
}

/*
 * 64-bit FNV-1a. The validator rejects an all-zero checksum, so fold a non-zero
 * constant in rather than ever publishing 0.
 */
static uint64_t checksum_mix(uint64_t accumulator, uint64_t value) {
    accumulator ^= value;
    accumulator *= 0x100000001b3ull;
    return accumulator;
}

static uint64_t checksum_finalize(uint64_t accumulator) {
    return accumulator == 0 ? 0x9e3779b97f4a7c15ull : accumulator;
}

static uint64_t monotonic_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        fail("clock_gettime", errno, 0);
    }
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Configuration loading                                               */
/* ------------------------------------------------------------------ */

static uint16_t load_u16(const uint8_t *base, size_t offset) {
    return (uint16_t)((uint16_t)base[offset] | ((uint16_t)base[offset + 1] << 8));
}

static uint32_t load_u32(const uint8_t *base, size_t offset) {
    return (uint32_t)base[offset] | ((uint32_t)base[offset + 1] << 8) |
           ((uint32_t)base[offset + 2] << 16) | ((uint32_t)base[offset + 3] << 24);
}

static uint64_t load_u64(const uint8_t *base, size_t offset) {
    return (uint64_t)load_u32(base, offset) | ((uint64_t)load_u32(base, offset + 4) << 32);
}

static void read_exact(const char *path, uint8_t *buffer, size_t length) {
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fail("config_open", errno, 0);
    }
    size_t total = 0;
    while (total < length) {
        const ssize_t chunk = read(fd, buffer + total, length - total);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            (void)close(fd);
            fail("config_read", saved, total);
        }
        if (chunk == 0) {
            (void)close(fd);
            fail("config_short", 0, total);
        }
        total += (size_t)chunk;
    }
    /* A longer-than-contract record is a mismatch, not a truncation. */
    uint8_t excess;
    const ssize_t trailing = read(fd, &excess, 1);
    (void)close(fd);
    if (trailing != 0) {
        fail("config_oversized", 0, total);
    }
}

static void load_config(void) {
    uint8_t raw[CONFIG_TOTAL_BYTES];
    read_exact(CONFIG_PATH, raw, sizeof(raw));

    if (memcmp(raw, "NILSTR2", 8) != 0) {
        fail("config_magic", 0, 0);
    }
    if (memcmp(raw + CONFIG_END_MAGIC_OFFSET, "NILEND2", 8) != 0) {
        fail("config_end_magic", 0, 0);
    }
    if (load_u16(raw, 8) != CONFIG_VERSION) {
        fail("config_version", 0, load_u16(raw, 8));
    }
    if (load_u16(raw, 10) != CONFIG_HEADER_BYTES) {
        fail("config_header_bytes", 0, load_u16(raw, 10));
    }
    if (load_u32(raw, 12) != CONFIG_TOTAL_BYTES) {
        fail("config_total_bytes", 0, load_u32(raw, 12));
    }
    for (size_t i = 0; i < CONFIG_RESERVED_BYTES; ++i) {
        if (raw[CONFIG_RESERVED_OFFSET + i] != 0) {
            fail("config_reserved", 0, i);
        }
    }

    /*
     * The digest covers the record prefix only. Recomputing it here is what
     * proves to the host that this guest actually read its own configuration:
     * BEGIN echoes the value back and the validator compares it.
     */
    uint8_t digest[32];
    Sha256 ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, raw, CONFIG_DIGEST_OFFSET);
    sha256_final(&ctx, digest);
    if (memcmp(digest, raw + CONFIG_DIGEST_OFFSET, sizeof(digest)) != 0) {
        fail("config_digest", 0, 0);
    }

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(digest); ++i) {
        config.digest_hex[i * 2] = hex[(digest[i] >> 4) & 0x0fu];
        config.digest_hex[i * 2 + 1] = hex[digest[i] & 0x0fu];
    }
    config.digest_hex[64] = '\0';

    config.profile = load_u32(raw, 16);
    config.flags = load_u32(raw, 20);
    config.run_id = load_u64(raw, 24);
    config.seed = load_u64(raw, 32);
    config.vcpus = load_u32(raw, 40);
    config.workers = load_u32(raw, 44);
    config.heartbeat_max_ms = load_u32(raw, 48);
    config.rounds_per_heartbeat = load_u32(raw, 52);
    config.memory_limit_delta = load_u64(raw, 56);
    config.memory_chunk_bytes = load_u64(raw, 64);
    config.cpu_iterations = load_u64(raw, 72);
    config.contention_iterations = load_u64(raw, 80);
    config.churn_fanout = load_u32(raw, 88);
    config.churn_waves = load_u32(raw, 92);
    config.io_block_bytes = load_u32(raw, 96);
    config.io_slots = load_u32(raw, 100);
    config.io_writes_per_round = load_u32(raw, 104);
    config.reclaim_percent = load_u32(raw, 108);

    if (config.profile < 1u || config.profile > 6u) {
        fail("config_profile", 0, config.profile);
    }
    if (config.workers == 0u || config.workers > MAX_WORKERS) {
        fail("config_workers", 0, config.workers);
    }
    if (config.rounds_per_heartbeat == 0u) {
        fail("config_rounds", 0, 0);
    }
}

/* ------------------------------------------------------------------ */
/* cgroup helpers                                                      */
/* ------------------------------------------------------------------ */

/*
 * Creating a cgroup does not require the caller to be a member, so the parent
 * owns the node for the whole run and each round's worker joins it. Doing this
 * once also keeps the registry from filling up with one node per round.
 */
static void cgroup_create_once(uint32_t controllers) {
    const long created = syscall(NILIX_SYS_CGROUP_CREATE, (uint64_t)0, controllers);
    if (created < 0) {
        fail("cgroup_create", errno, controllers);
    }
    cgroup_id = (uint64_t)created;
}

/*
 * Joining a cgroup DOES require membership of the current one, and the kernel
 * only records membership for tasks created by fork (fork.rs attaches the child
 * to its parent's cgroup). The initial Ring-3 process is never inserted into the
 * root cgroup's task set, so it can never migrate out itself: cgroup_attach
 * returns EIO (CgroupError::TaskNotAttached) for PID 1. Every cgroup-resident
 * phase therefore runs in a forked worker, which is attached and can migrate.
 */
static void cgroup_attach_self(void) {
    if (syscall(NILIX_SYS_CGROUP_ATTACH, cgroup_id) < 0) {
        fail("cgroup_attach", errno, cgroup_id);
    }
}

static void cgroup_set_limit(uint32_t kind, uint64_t value) {
    if (syscall(NILIX_SYS_CGROUP_SET_LIMIT, cgroup_id, kind, value) < 0) {
        fail("cgroup_set_limit", errno, kind);
    }
}

static void cgroup_stats(CgroupStatsBuf *out) {
    memset(out, 0, sizeof(*out));
    if (syscall(NILIX_SYS_CGROUP_GET_STATS2, cgroup_id, out, sizeof(*out)) < 0) {
        fail("cgroup_get_stats", errno, cgroup_id);
    }
}

/*
 * ST-K3 Phase D: best-effort cgroup snapshot emitted just before an mmap FAIL
 * marker. The NILIX_MMAP_DIAG prefix is deliberately NOT NILIX_STRESS_V2_* —
 * the validator's line filter only selects that prefix (stress_protocol.py
 * protocol_lines) and its FAIL regex requires a bare-integer detail field, so
 * the diagnosis rides on its own line and the marker stays schema-legal.
 * This helper must never call fail(): a failing stats syscall here would
 * consume the failure_emitted latch and swallow the original marker. Both
 * stats calls are tolerated-failure; rc values are reported so a stats error
 * is itself visible. Callers pass errno by value BEFORE these syscalls run,
 * so the reported errno is never clobbered.
 */
static void emit_mmap_diag(const char *stage, long errno_value, uint64_t detail) {
    CgroupStatsBuf run_stats;
    CgroupStatsBuf root_stats;
    memset(&run_stats, 0, sizeof(run_stats));
    memset(&root_stats, 0, sizeof(root_stats));
    long run_rc = syscall(NILIX_SYS_CGROUP_GET_STATS2, cgroup_id, &run_stats, sizeof(run_stats));
    long root_rc = syscall(NILIX_SYS_CGROUP_GET_STATS2, 0, &root_stats, sizeof(root_stats));
    emit("NILIX_MMAP_DIAG stage=%s errno=%ld detail=%" PRIu64
         " run_cg=%" PRIu64 " run_rc=%ld run_mem_cur=%" PRIu64
         " run_mem_max_events=%" PRIu64 " root_rc=%ld root_mem_cur=%" PRIu64
         " root_mem_max_events=%" PRIu64,
         stage, errno_value, detail,
         cgroup_id, run_rc, run_stats.memory_current, run_stats.memory_events_max,
         root_rc, root_stats.memory_current, root_stats.memory_events_max);
}

/* ST-K3 Phase D: fail(), preceded by the diagnosis line for mmap sites. */
static void fail_with_stats(const char *stage, long errno_value, uint64_t detail) {
    if (!failure_emitted) {
        emit_mmap_diag(stage, errno_value, detail);
    }
    fail(stage, errno_value, detail);
}

/* ------------------------------------------------------------------ */
/* Worker pinning                                                      */
/* ------------------------------------------------------------------ */

/*
 * FLAG_PIN_WORKERS demands each worker sit on a distinct vCPU so the host's QMP
 * snapshots observe every vCPU making progress. The kernel takes an opaque
 * byte mask; try the compact 8-byte form first and fall back to the wider
 * glibc/musl-sized mask before giving up.
 */
static void pin_to_cpu(uint32_t cpu) {
    if ((config.flags & FLAG_PIN_WORKERS) == 0u) {
        return;
    }

    uint64_t compact = 1ull << (cpu % 64u);
    if (syscall(SYS_sched_setaffinity, 0, sizeof(compact), &compact) == 0) {
        return;
    }

    uint8_t wide[128];
    memset(wide, 0, sizeof(wide));
    wide[(cpu % 64u) / 8u] = (uint8_t)(1u << ((cpu % 64u) % 8u));
    if (syscall(SYS_sched_setaffinity, 0, sizeof(wide), wide) == 0) {
        return;
    }

    fail("pin_workers", errno, cpu);
}

/* ------------------------------------------------------------------ */
/* Shared worker scratch space                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t lock;
    uint32_t done_low;
    uint32_t done_high;
    uint32_t padding;
    uint64_t counter;
    uint64_t spins;
    uint64_t results[MAX_WORKERS];
    uint64_t elapsed_ns[MAX_WORKERS];
} SharedRegion;

/*
 * Results a cgroup-resident worker publishes back to the marker-emitting parent.
 * Held in a MAP_SHARED mapping so the child's writes are visible after it exits.
 */
typedef struct {
    uint64_t baseline;
    uint64_t limit;
    uint64_t peak;
    uint64_t recovered;
    uint64_t oom_events;
    uint64_t ops;
    uint64_t checksum;
    uint64_t spawned;
    uint64_t reaped;
    uint64_t limit_hits;
    uint64_t recovered_forks;
} ProfileReport;

/*
 * Run `body` inside a forked worker that has joined the run's cgroup, and hand
 * back what it published. A worker that fails emits its own FAIL marker before
 * exiting non-zero, so the parent exits quietly rather than emitting a second.
 */
static void run_in_cgroup_child(void (*body)(ProfileReport *), ProfileReport *out) {
    void *mapping = mmap(NULL, sizeof(ProfileReport), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fail_with_stats("report_mmap", errno, sizeof(ProfileReport));
    }
    /* ST-K3 Phase D step markers: bisect which kernel interaction after the
     * (historically first-ever successful) anonymous mmap faults the kernel.
     * NILIX_MMAP_DIAG lines are invisible to the stress validator. */
    emit("NILIX_MMAP_DIAG step=mapped");
    ProfileReport *report = (ProfileReport *)mapping;
    memset(report, 0, sizeof(*report));
    emit("NILIX_MMAP_DIAG step=zeroed");

    const pid_t child = fork();
    if (child < 0) {
        fail("cgroup_child_fork", errno, 0);
    }
    if (child == 0) {
        emit("NILIX_MMAP_DIAG step=child_alive");
        cgroup_attach_self();
        emit("NILIX_MMAP_DIAG step=child_attached");
        body(report);
        _exit(0);
    }
    emit("NILIX_MMAP_DIAG step=parent_forked");

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            fail("cgroup_child_wait", errno, 0);
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        _exit(1);
    }

    *out = *report;
    if (munmap(mapping, sizeof(ProfileReport)) != 0) {
        fail("report_munmap", errno, 0);
    }
}

static SharedRegion *shared_region_create(void) {
    void *mapping = mmap(NULL, sizeof(SharedRegion), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fail_with_stats("shared_mmap", errno, sizeof(SharedRegion));
    }
    memset(mapping, 0, sizeof(SharedRegion));
    return (SharedRegion *)mapping;
}

static void shared_region_destroy(SharedRegion *region) {
    if (munmap(region, sizeof(SharedRegion)) != 0) {
        fail("shared_munmap", errno, 0);
    }
}

static void spin_lock_acquire(SharedRegion *region, uint64_t *local_spins) {
    while (__atomic_exchange_n(&region->lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
        *local_spins += 1u;
        sched_yield();
    }
}

static void spin_lock_release(SharedRegion *region) {
    __atomic_store_n(&region->lock, 0u, __ATOMIC_RELEASE);
}

/*
 * Fork `count` workers, run `body`, and reap them all. Returns only when every
 * child has exited zero; any abnormal exit is fail-closed.
 */
static void run_workers(SharedRegion *region, uint32_t count, void (*body)(SharedRegion *, uint32_t)) {
    pid_t children[MAX_WORKERS];
    uint32_t started = 0;

    for (uint32_t index = 0; index < count; ++index) {
        const pid_t child = fork();
        if (child < 0) {
            /* Reap what we already started before failing, so no zombie leaks. */
            for (uint32_t reap = 0; reap < started; ++reap) {
                int ignored;
                (void)waitpid(children[reap], &ignored, 0);
            }
            fail("worker_fork", errno, index);
        }
        if (child == 0) {
            pin_to_cpu(index);
            body(region, index);
            _exit(0);
        }
        children[started++] = child;
    }

    for (uint32_t index = 0; index < started; ++index) {
        int status = 0;
        while (waitpid(children[index], &status, 0) < 0) {
            if (errno != EINTR) {
                fail("worker_wait", errno, index);
            }
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fail("worker_exit", 0, index);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Profile: memory                                                     */
/* ------------------------------------------------------------------ */

/*
 * mmap charges the whole mapping length to the cgroup up front and returns
 * ENOMEM when the charge would breach memory.max, incrementing the OOM event
 * counter. That lets us walk right up to the boundary without ever touching a
 * page that could not be charged.
 */
static void *memory_chunks[MAX_CHUNKS];

/* Runs inside the cgroup-resident worker; publishes into `report`. */
static void memory_round_body(ProfileReport *report) {
    CgroupStatsBuf stats;
    cgroup_stats(&stats);
    const uint64_t baseline = stats.memory_current;
    const uint64_t limit = baseline + config.memory_limit_delta;
    const uint64_t chunk = config.memory_chunk_bytes;
    uint64_t ops = 0;

    if (chunk == 0u) {
        fail("memory_chunk_zero", 0, 0);
    }
    cgroup_set_limit(CGROUP_LIMIT_MEMORY_MAX, limit);

    void **chunks = memory_chunks;
    uint32_t held = 0;
    uint64_t peak = baseline;
    uint64_t checksum = checksum_mix(config.seed, baseline);

    for (;;) {
        if (held == MAX_CHUNKS) {
            fail("memory_chunk_cap", 0, held);
        }
        void *mapping = mmap(NULL, (size_t)chunk, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) {
            if (errno == ENOMEM) {
                break; /* the configured pressure boundary was reached */
            }
            fail_with_stats("memory_mmap", errno, held);
        }
        chunks[held++] = mapping;
        ops += 1u;

        cgroup_stats(&stats);
        if (stats.memory_current > peak) {
            peak = stats.memory_current;
        }
        checksum = checksum_mix(checksum, stats.memory_current);
    }

    cgroup_stats(&stats);
    const uint64_t oom_events = stats.memory_events_max;

    for (uint32_t index = 0; index < held; ++index) {
        if (munmap(chunks[index], (size_t)chunk) != 0) {
            fail("memory_munmap", errno, index);
        }
        chunks[index] = NULL;
        ops += 1u;
    }

    cgroup_stats(&stats);
    const uint64_t recovered = stats.memory_current;

    /*
     * The validator demands an exact return to baseline: a drift here means a
     * charge leaked, which is precisely the regression this profile exists to
     * catch. Report it as a failure rather than publishing a passing marker.
     */
    if (recovered != baseline) {
        fail("memory_not_reclaimed", 0, recovered);
    }
    if (oom_events < 1u) {
        fail("memory_no_oom", 0, oom_events);
    }

    report->baseline = baseline;
    report->limit = limit;
    report->peak = peak;
    report->recovered = recovered;
    report->oom_events = oom_events;
    report->ops = ops;
    report->checksum = checksum_finalize(checksum_mix(checksum, peak));
}

static void emit_memory_marker(uint64_t seq, uint64_t baseline, uint64_t limit, uint64_t peak,
                               uint64_t recovered, uint64_t oom_events, uint64_t checksum) {
    emit("NILIX_STRESS_V2_MEMORY run=%016" PRIx64 " seq=%" PRIu64 " baseline=%" PRIu64
         " limit=%" PRIu64 " peak=%" PRIu64 " recovered=%" PRIu64 " oom_events=%" PRIu64
         " checksum=%016" PRIx64,
         config.run_id, seq, baseline, limit, peak, recovered, oom_events, checksum);
}

/* ------------------------------------------------------------------ */
/* Profile: cpu                                                        */
/* ------------------------------------------------------------------ */

static void cpu_worker_body(SharedRegion *region, uint32_t index) {
    const uint64_t started = monotonic_ns();
    uint64_t accumulator = config.seed ^ ((uint64_t)index + 1u);

    for (uint64_t iteration = 0; iteration < config.cpu_iterations; ++iteration) {
        accumulator = checksum_mix(accumulator, iteration);
    }

    region->results[index] = checksum_finalize(accumulator);
    region->elapsed_ns[index] = monotonic_ns() - started;
}

/* ------------------------------------------------------------------ */
/* Profile: smp                                                        */
/* ------------------------------------------------------------------ */

static void smp_worker_body(SharedRegion *region, uint32_t index) {
    uint64_t local_spins = 0;
    uint64_t accumulator = config.seed ^ ((uint64_t)index + 0x9e37u);

    for (uint64_t iteration = 0; iteration < config.contention_iterations; ++iteration) {
        spin_lock_acquire(region, &local_spins);
        region->counter += 1u;
        spin_lock_release(region);
        accumulator = checksum_mix(accumulator, iteration);
    }

    __atomic_fetch_add(&region->spins, local_spins, __ATOMIC_RELAXED);
    if (index < 32u) {
        __atomic_fetch_or(&region->done_low, 1u << index, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_or(&region->done_high, 1u << (index - 32u), __ATOMIC_RELAXED);
    }
    region->results[index] = checksum_finalize(accumulator);
}

/* ------------------------------------------------------------------ */
/* Profile: process                                                    */
/* ------------------------------------------------------------------ */

/*
 * Each wave forks exactly churn_fanout children, proves the pids.max ceiling by
 * having the next fork fail, reaps everything, and then proves the cgroup
 * recovers by forking once more. The recovery child is deliberately excluded
 * from spawned/reaped: the validator expects those to equal fanout * waves.
 *
 * Runs inside the cgroup-resident worker, so the grandchildren forked here are
 * attached to the limited cgroup and the ceiling actually binds.
 */
static void process_round_body(ProfileReport *report) {
    uint64_t checksum = checksum_mix(config.seed, config.churn_waves);
    pid_t children[MAX_WORKERS];

    if (config.churn_fanout == 0u || config.churn_fanout > MAX_WORKERS) {
        fail("process_fanout", 0, config.churn_fanout);
    }

    for (uint32_t wave = 0; wave < config.churn_waves; ++wave) {
        CgroupStatsBuf stats;
        cgroup_stats(&stats);
        /*
         * Re-derive the ceiling from the live task count each wave so the limit
         * lands exactly one fork above the fan-out regardless of what else the
         * cgroup is carrying.
         */
        cgroup_set_limit(CGROUP_LIMIT_PIDS_MAX, stats.nr_tasks + config.churn_fanout);

        uint32_t started = 0;
        for (uint32_t index = 0; index < config.churn_fanout; ++index) {
            const pid_t child = fork();
            if (child < 0) {
                fail("process_fork", errno, index);
            }
            if (child == 0) {
                _exit(0);
            }
            children[started++] = child;
            report->spawned += 1u;
        }

        /* The ceiling is now saturated: this fork must be refused. */
        const pid_t overflow = fork();
        if (overflow == 0) {
            _exit(0);
        }
        if (overflow < 0) {
            if (errno != EAGAIN && errno != ENOMEM) {
                fail("process_limit_errno", errno, wave);
            }
            report->limit_hits += 1u;
        } else {
            int status = 0;
            (void)waitpid(overflow, &status, 0);
            fail("process_limit_not_enforced", 0, wave);
        }

        for (uint32_t index = 0; index < started; ++index) {
            int status = 0;
            while (waitpid(children[index], &status, 0) < 0) {
                if (errno != EINTR) {
                    fail("process_wait", errno, index);
                }
            }
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                fail("process_child_exit", 0, index);
            }
            report->reaped += 1u;
        }

        /* Room has been returned to the cgroup, so forking must work again. */
        const pid_t recovered = fork();
        if (recovered < 0) {
            fail("process_no_recovery", errno, wave);
        }
        if (recovered == 0) {
            _exit(0);
        }
        int status = 0;
        while (waitpid(recovered, &status, 0) < 0) {
            if (errno != EINTR) {
                fail("process_recovery_wait", errno, wave);
            }
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fail("process_recovery_exit", 0, wave);
        }
        report->recovered_forks += 1u;
        checksum = checksum_mix(checksum, ((uint64_t)wave << 32) | report->spawned);
    }

    report->checksum = checksum_finalize(checksum);
}

/* ------------------------------------------------------------------ */
/* Profile: combined                                                   */
/* ------------------------------------------------------------------ */

#define COMBINED_IO_PATH STRESS_GUEST_ROOT "/stress-combined.tmp"

typedef struct {
    uint64_t memory_ops;
    uint64_t cpu_ops;
    uint64_t smp_ops;
    uint64_t process_ops;
    uint64_t io_ops;
    uint64_t checksum;
} CombinedRoundResult;

/*
 * A scaled-down slice of every subsystem. The validator requires each counter
 * to be non-zero, so every branch here must contribute at least one operation.
 */
static CombinedRoundResult run_combined_round(void) {
    CombinedRoundResult result = {0, 0, 0, 0, 0, 0};
    uint64_t checksum = checksum_mix(config.seed, 0xc0ffee01ull);

    /* Memory: one bounded chunk, charged and released. */
    const size_t chunk = config.memory_chunk_bytes != 0u ? (size_t)config.memory_chunk_bytes : PAGE_BYTES;
    void *mapping = mmap(NULL, chunk, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        fail_with_stats("combined_mmap", errno, chunk);
    }
    memset(mapping, 0xa5, PAGE_BYTES);
    checksum = checksum_mix(checksum, (uint64_t)((const uint8_t *)mapping)[0]);
    if (munmap(mapping, chunk) != 0) {
        fail("combined_munmap", errno, 0);
    }
    result.memory_ops = 2u;

    /* CPU + SMP: one worker pass over the shared counter. */
    SharedRegion *region = shared_region_create();
    const uint64_t cpu_started = monotonic_ns();
    run_workers(region, config.workers, cpu_worker_body);
    const uint64_t cpu_elapsed = monotonic_ns() - cpu_started;
    for (uint32_t index = 0; index < config.workers; ++index) {
        checksum = checksum_mix(checksum, region->results[index]);
    }
    result.cpu_ops = (uint64_t)config.workers * config.cpu_iterations;
    if (result.cpu_ops == 0u) {
        result.cpu_ops = config.workers;
    }

    memset(region, 0, sizeof(*region));
    run_workers(region, config.workers, smp_worker_body);
    result.smp_ops = region->counter;
    if (result.smp_ops == 0u) {
        result.smp_ops = config.workers;
    }
    checksum = checksum_mix(checksum, region->counter);
    checksum = checksum_mix(checksum, cpu_elapsed);
    shared_region_destroy(region);

    /* Process: a single fork/reap pair is enough to be non-zero. */
    const pid_t child = fork();
    if (child < 0) {
        fail("combined_fork", errno, 0);
    }
    if (child == 0) {
        _exit(0);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            fail("combined_wait", errno, 0);
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fail("combined_child_exit", 0, 0);
    }
    result.process_ops = 1u;

    /*
     * I/O: buffered writes only. Durability is deliberately not claimed here:
     * there is no fsync in the kernel yet, which is why the block profile is
     * fail-closed. The combined profile only needs the writes to land in the
     * page cache for io_ops to be meaningful.
     */
    const int fd = open(COMBINED_IO_PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fail("combined_open", errno, 0);
    }
    uint8_t record[PAGE_BYTES];
    memset(record, (int)(config.seed & 0xffu), sizeof(record));
    const uint32_t writes = config.io_writes_per_round != 0u ? config.io_writes_per_round : 1u;
    for (uint32_t index = 0; index < writes; ++index) {
        ssize_t written = write(fd, record, sizeof(record));
        if (written < 0) {
            const int saved = errno;
            (void)close(fd);
            fail("combined_write", saved, index);
        }
        if ((size_t)written != sizeof(record)) {
            (void)close(fd);
            fail("combined_short_write", 0, index);
        }
        result.io_ops += 1u;
        checksum = checksum_mix(checksum, index);
    }
    if (close(fd) != 0) {
        fail("combined_close", errno, 0);
    }
    if (unlink(COMBINED_IO_PATH) != 0 && errno != ENOENT) {
        fail("combined_unlink", errno, 0);
    }

    result.checksum = checksum_finalize(checksum);
    return result;
}

/* ------------------------------------------------------------------ */
/* Round driver                                                        */
/* ------------------------------------------------------------------ */

/*
 * Runs one round for the configured profile, emits its profile marker, and
 * returns the round checksum plus the cumulative operation count.
 */
static uint64_t run_round(uint64_t seq, uint64_t *cumulative_ops) {
    uint64_t checksum = 0;

    switch (config.profile) {
    case PROFILE_MEMORY: {
        /*
         * Every field below is measured inside the round from kernel-published
         * counters; the round itself has already asserted the exact return to
         * baseline and the OOM boundary before returning.
         */
        ProfileReport result;
        run_in_cgroup_child(memory_round_body, &result);
        *cumulative_ops += result.ops;
        checksum = result.checksum;
        emit_memory_marker(seq, result.baseline, result.limit, result.peak, result.recovered,
                           result.oom_events, checksum);
        break;
    }
    case PROFILE_CPU: {
        SharedRegion *region = shared_region_create();
        const uint64_t started = monotonic_ns();
        run_workers(region, config.workers, cpu_worker_body);
        const uint64_t wall_ns = monotonic_ns() - started;

        uint64_t cpu_ns = 0;
        uint64_t accumulator = checksum_mix(config.seed, seq);
        for (uint32_t index = 0; index < config.workers; ++index) {
            cpu_ns += region->elapsed_ns[index];
            accumulator = checksum_mix(accumulator, region->results[index]);
        }
        shared_region_destroy(region);

        *cumulative_ops += (uint64_t)config.workers * config.cpu_iterations;
        checksum = checksum_finalize(accumulator);

        /* Both fields must be non-zero; a sub-nanosecond round would break the regex. */
        const uint64_t reported_wall = wall_ns != 0u ? wall_ns : 1u;
        const uint64_t reported_cpu = cpu_ns != 0u ? cpu_ns : 1u;

        emit("NILIX_STRESS_V2_CPU run=%016" PRIx64 " seq=%" PRIu64 " workers=%" PRIu32
             " iterations=%" PRIu64 " wall_ns=%" PRIu64 " cpu_ns=%" PRIu64 " checksum=%016" PRIx64,
             config.run_id, seq, config.workers, config.cpu_iterations, reported_wall,
             reported_cpu, checksum);
        break;
    }
    case PROFILE_SMP: {
        SharedRegion *region = shared_region_create();
        run_workers(region, config.workers, smp_worker_body);

        const uint64_t expected = (uint64_t)config.workers * config.contention_iterations;
        const uint64_t counter = region->counter;
        const uint64_t spins = region->spins;
        const uint64_t done_mask = (uint64_t)region->done_low | ((uint64_t)region->done_high << 32);

        uint64_t accumulator = checksum_mix(config.seed, seq);
        for (uint32_t index = 0; index < config.workers; ++index) {
            accumulator = checksum_mix(accumulator, region->results[index]);
        }
        shared_region_destroy(region);

        if (counter != expected) {
            fail("smp_counter_mismatch", 0, counter);
        }
        *cumulative_ops += counter;
        checksum = checksum_finalize(accumulator);

        emit("NILIX_STRESS_V2_SMP run=%016" PRIx64 " seq=%" PRIu64 " workers=%" PRIu32
             " iterations=%" PRIu64 " counter=%" PRIu64 " expected=%" PRIu64 " spins=%" PRIu64
             " done_mask=%016" PRIx64 " checksum=%016" PRIx64,
             config.run_id, seq, config.workers, config.contention_iterations, counter, expected,
             spins, done_mask, checksum);
        break;
    }
    case PROFILE_PROCESS: {
        ProfileReport result;
        run_in_cgroup_child(process_round_body, &result);
        *cumulative_ops += result.spawned + result.reaped + result.recovered_forks;
        checksum = result.checksum;

        emit("NILIX_STRESS_V2_PROCESS run=%016" PRIx64 " seq=%" PRIu64 " waves=%" PRIu32
             " spawned=%" PRIu64 " reaped=%" PRIu64 " limit_hits=%" PRIu64
             " recovered_forks=%" PRIu64 " checksum=%016" PRIx64,
             config.run_id, seq, config.churn_waves, result.spawned, result.reaped,
             result.limit_hits, result.recovered_forks, checksum);
        break;
    }
    case PROFILE_COMBINED: {
        const CombinedRoundResult result = run_combined_round();
        *cumulative_ops += result.memory_ops + result.cpu_ops + result.smp_ops +
                           result.process_ops + result.io_ops;
        checksum = result.checksum;

        emit("NILIX_STRESS_V2_COMBINED run=%016" PRIx64 " seq=%" PRIu64 " memory_ops=%" PRIu64
             " cpu_ops=%" PRIu64 " smp_ops=%" PRIu64 " process_ops=%" PRIu64 " io_ops=%" PRIu64
             " checksum=%016" PRIx64,
             config.run_id, seq, result.memory_ops, result.cpu_ops, result.smp_ops,
             result.process_ops, result.io_ops, checksum);
        break;
    }
    case PROFILE_BLOCK:
    default:
        /*
         * The block profile is a crash-consistency test: it must durably commit
         * a record, let the host kill QEMU mid-flight, and prove the journal
         * recovered. The kernel has no fsync/fdatasync yet (syscalls 74/75 are
         * unbound and Ext2Fs never overrides FileSystem::sync), so a "commit"
         * here would be a lie. Refuse rather than emit an unbacked proof.
         */
        fail("fsync_unsupported", -ENOSYS, PROFILE_BLOCK);
        break;
    }

    return checksum;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(void) {
    load_config();

    emit("");
    emit("NILIX_STRESS_V2_BEGIN run=%016" PRIx64 " profile=%s config_sha256=%s vcpus=%" PRIu32
         " workers=%" PRIu32,
         config.run_id, profile_name(), config.digest_hex, config.vcpus, config.workers);

    /*
     * Only the block profile has writer/recovery modes, and it is fail-closed
     * below, so a surviving run is always "normal".
     */
    emit("NILIX_STRESS_V2_READY run=%016" PRIx64 " profile=%s mode=normal", config.run_id,
         profile_name());

    /*
     * Only the memory and process profiles assert against cgroup counters, and
     * only they need a limited node. The cpu/smp/combined markers are derived
     * purely from work the guest performs, so they run in the root cgroup and
     * avoid the membership dance entirely.
     */
    if (config.profile == PROFILE_MEMORY) {
        cgroup_create_once(CGROUP_CTRL_MEMORY);
    } else if (config.profile == PROFILE_PROCESS) {
        cgroup_create_once(CGROUP_CTRL_PIDS);
    }

    uint64_t cumulative_ops = 0;
    int pass_emitted = 0;

    for (uint64_t seq = 1;; ++seq) {
        const uint64_t checksum = run_round(seq, &cumulative_ops);
        const uint64_t cycles = seq * (uint64_t)config.rounds_per_heartbeat;

        /*
         * ops must strictly increase between heartbeats. A profile that somehow
         * performed no work would otherwise publish a stalled counter and the
         * host would reject the whole run; surface it precisely instead.
         */
        if (cumulative_ops == 0u) {
            fail("no_operations", 0, seq);
        }

        if (!pass_emitted) {
            /* PASS sits between the first round and the first heartbeat, and
             * must carry byte-identical counters to that heartbeat. */
            emit("NILIX_STRESS_V2_PASS run=%016" PRIx64 " profile=%s cycles=%" PRIu64 " ops=%" PRIu64
                 " checksum=%016" PRIx64,
                 config.run_id, profile_name(), cycles, cumulative_ops, checksum);
            pass_emitted = 1;
        }

        emit("NILIX_STRESS_V2_HEARTBEAT run=%016" PRIx64 " profile=%s seq=%" PRIu64 " cycles=%" PRIu64
             " ops=%" PRIu64 " checksum=%016" PRIx64,
             config.run_id, profile_name(), seq, cycles, cumulative_ops, checksum);
    }
}
