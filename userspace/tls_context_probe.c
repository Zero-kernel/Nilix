/* KSA SMP TLS: measure hardware FS/GS after IRQ-only migration, before SYSRET
 * could hide a missing scheduler restore. Dense QEMU APIC IDs match CPU masks.
 * Custom-TLS workers use only inline assembly/syscalls and never call libc.
 */
struct tls_context_record {
    uint64_t fs_cookie, gs_cookie;
    uint64_t observed_fs, observed_gs, checks;
    uint64_t startup_arch_result, startup_affinity_result;
    unsigned startup_attempts;
    int wanted_cpu, phase, seen_phase, observed_cpu, startup_cpu, stop, failed;
};

static __attribute__((always_inline, no_stack_protector)) inline
long tls_context_raw(long number, long first, long second, long third) {
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "0"(number), "D"(first), "S"(second), "d"(third)
                     : "rcx", "r11", "memory");
    return result;
}

static __attribute__((always_inline, no_stack_protector)) inline
unsigned tls_context_cpu(void) {
    unsigned eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "0"(1), "2"(0) : "memory");
    return ebx >> 24;
}

static __attribute__((always_inline, no_stack_protector)) inline
int tls_context_start(struct tls_context_record *record) {
    uint64_t mask = UINT64_C(1) << record->wanted_cpu;
    /* Capture the CPU even when the first startup syscall fails. */
    __atomic_store_n(&record->startup_cpu, (int)tls_context_cpu(), __ATOMIC_RELAXED);
    /* ARCH_SET_GS programs user GS; the kernel's active GS must stay private. */
    long arch_result = tls_context_raw(SYS_arch_prctl, 0x1001, (long)&record->gs_cookie, 0);
    __atomic_store_n(&record->startup_arch_result, (uint64_t)arch_result, __ATOMIC_RELEASE);
    if (arch_result) {
        __atomic_store_n(&record->failed, 1, __ATOMIC_RELEASE);
        return 61;
    }
    long affinity_result = tls_context_raw(SYS_sched_setaffinity, 0, sizeof(mask), (long)&mask);
    __atomic_store_n(&record->startup_affinity_result, (uint64_t)affinity_result, __ATOMIC_RELEASE);
    if (affinity_result) {
        __atomic_store_n(&record->failed, 1, __ATOMIC_RELEASE);
        return 61;
    }
    /* Startup may use syscalls. The primary's measured loop starts only after
     * it reaches the requested CPU, and never issues a syscall thereafter. */
    for (unsigned attempt = 0;; ++attempt) {
        unsigned cpu = tls_context_cpu();
        __atomic_store_n(&record->startup_cpu, (int)cpu, __ATOMIC_RELAXED);
        __atomic_store_n(&record->startup_attempts, attempt + 1, __ATOMIC_RELAXED);
        if (cpu == (unsigned)record->wanted_cpu) break;
        if (attempt == 2000) {
            __atomic_store_n(&record->failed, 2, __ATOMIC_RELEASE);
            return 62;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        tls_context_raw(SYS_sched_yield, 0, 0, 0);
        tls_context_raw(SYS_nanosleep, (long)&delay, 0, 0);
    }

    return 0;
}

static __attribute__((always_inline, no_stack_protector)) inline
int tls_context_measure(struct tls_context_record *record, uint64_t *checks) {
    int cpu = (int)tls_context_cpu();
    uint64_t fs, gs;
    __asm__ volatile("movq %%fs:0, %0" : "=r"(fs) : : "memory");
    __asm__ volatile("movq %%gs:0, %0" : "=r"(gs) : : "memory");
    if (fs != record->fs_cookie || gs != record->gs_cookie) {
        __atomic_store_n(&record->observed_fs, fs, __ATOMIC_RELAXED);
        __atomic_store_n(&record->observed_gs, gs, __ATOMIC_RELAXED);
        __atomic_store_n(&record->failed, 3, __ATOMIC_RELEASE);
        return 63;
    }
    ++*checks;
    int phase = __atomic_load_n(&record->phase, __ATOMIC_ACQUIRE);
    if (cpu == (int)tls_context_cpu() &&
        cpu == __atomic_load_n(&record->wanted_cpu, __ATOMIC_RELAXED) &&
        phase != __atomic_load_n(&record->seen_phase, __ATOMIC_RELAXED)) {
        __atomic_store_n(&record->observed_fs, fs, __ATOMIC_RELAXED);
        __atomic_store_n(&record->observed_gs, gs, __ATOMIC_RELAXED);
        record->observed_cpu = cpu;
        record->checks = *checks;
        __atomic_store_n(&record->seen_phase, phase, __ATOMIC_RELEASE);
    }
    return 0;
}

static __attribute__((no_stack_protector)) int tls_context_worker(void *argument) {
    struct tls_context_record *record = argument;
    int result = tls_context_start(record);
    if (result) return result;
    uint64_t checks = 0;
    while (!__atomic_load_n(&record->stop, __ATOMIC_ACQUIRE)) {
        result = tls_context_measure(record, &checks);
        if (result) return result;
        /* The primary must observe each migration before any SYSRET repairs TLS. */
        __asm__ volatile("pause");
    }
    return 0; /* musl's clone assembly issues raw SYS_exit after this return. */
}

static __attribute__((no_stack_protector)) int tls_context_helper(void *argument) {
    struct tls_context_record *record = argument;
    int result = tls_context_start(record);
    if (result) return result;
    uint64_t checks = 0;
    while (!__atomic_load_n(&record->stop, __ATOMIC_ACQUIRE)) {
        result = tls_context_measure(record, &checks);
        if (result) return result;
        /* Stealing runs in process context. Helpers drive destination queue
         * progress while the primary measures its IRQ-only continuation. */
        tls_context_raw(SYS_sched_yield, 0, 0, 0);
    }
    return 0;
}

static int tls_context_wait_phase(struct tls_context_record *record, pid_t *pid,
                                  int *status_out, int phase) {
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (__atomic_load_n(&record->failed, __ATOMIC_ACQUIRE)) return 0;
        if (__atomic_load_n(&record->seen_phase, __ATOMIC_ACQUIRE) == phase) {
            return record->observed_cpu == record->wanted_cpu && record->checks != 0 &&
                   __atomic_load_n(&record->observed_fs, __ATOMIC_RELAXED) == record->fs_cookie &&
                   __atomic_load_n(&record->observed_gs, __ATOMIC_RELAXED) == record->gs_cookie;
        }
        int status = -1;
        pid_t result = waitpid(*pid, &status, WNOHANG);
        if (result == *pid) {
            printf("MUSL-TLS-IRQ-WORKER-EXIT pid=%ld status=%d phase=%d\n", (long)*pid, status, phase);
            *status_out = status;
            *pid = -1;
            return 0;
        }
        if (result < 0 && errno != EINTR) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    return 0;
}

static int tls_context_smoke(void) {
    enum { WORKERS = 3, RECORD_BYTES = 4096, STACK_BYTES = 64 * 1024,
           STRIDE = RECORD_BYTES + STACK_BYTES, MIGRATIONS = 4 };
    uint64_t original = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(original), &original) != sizeof(original)) {
        puts("MUSL-TLS-IRQ-FAIL stage=getaffinity");
        return 1;
    }
    unsigned parent_cpu = tls_context_cpu(), targets[2], count = 0;
    if (parent_cpu >= 64 || !(original & (UINT64_C(1) << parent_cpu))) {
        puts("MUSL-TLS-IRQ-FAIL stage=actual-parent-cpu");
        return 1;
    }
    for (unsigned cpu = 0; cpu < 64 && count < 2; ++cpu)
        if (cpu != parent_cpu && (original & (UINT64_C(1) << cpu))) targets[count++] = cpu;
    if (count != 2) {
        puts("MUSL-TLS-IRQ-SKIP reason=requires-three-cpus");
        return 0;
    }
    uint64_t parent_mask = UINT64_C(1) << parent_cpu;
    if (syscall(SYS_sched_setaffinity, 0, sizeof(parent_mask), &parent_mask)) return 1;

    char *storage = mmap(NULL, WORKERS * STRIDE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    pid_t children[WORKERS] = {-1, -1, -1};
    pid_t reported_pids[WORKERS] = {-1, -1, -1};
    int child_status[WORKERS] = {-1, -1, -1};
    struct tls_context_record *records[WORKERS] = {NULL, NULL, NULL};
    const char *stage = "mapping";
    int failed = storage == MAP_FAILED, unreaped = 0, parent_errno = -1;
    unsigned completed = 0;
    if (failed) goto cleanup;
    /* Start the helpers before the syscall-free primary.  Worker 0 spins on
     * its destination CPU by design; launching it first can starve the helper
     * pinned to that same destination before the bounded startup handshake
     * observes phase 1.  The helpers still retain exact affinity and provide
     * the runnable destination work needed for the later IRQ-only migrations.
     */
    static const unsigned launch_order[WORKERS] = {1, 2, 0};
    for (unsigned launch = 0; launch < WORKERS; ++launch) {
        unsigned index = launch_order[launch];
        struct tls_context_record *record = (void *)(storage + index * STRIDE);
        records[index] = record;
        record->fs_cookie = UINT64_C(0x4653544c53000000) + index + 1;
        record->gs_cookie = UINT64_C(0x4753544c53000000) + index + 1;
        record->wanted_cpu = (int)targets[index == 2 ? 1 : 0];
        record->phase = 1;
        stage = "clone raw TLS worker";
        /* Zero-OS accepts no CSIGNAL bits; its wait4 selects these ordinary
         * children without Linux's __WCLONE filter, as in the VFS probe. */
        children[index] = clone(index == 0 ? tls_context_worker : tls_context_helper,
                                storage + (index + 1) * STRIDE,
                                CLONE_VM | CLONE_SETTLS, record, NULL, &record->fs_cookie, NULL);
        if (children[index] < 0) { failed = 1; goto cleanup; }
        reported_pids[index] = children[index];
        printf("MUSL-TLS-IRQ-BASE worker=%u pid=%ld fs_base=%llx gs_base=%llx\n",
               index, (long)children[index], (unsigned long long)(uintptr_t)&record->fs_cookie,
               (unsigned long long)(uintptr_t)&record->gs_cookie);
    }
    for (unsigned index = 0; index < WORKERS; ++index) {
        stage = "worker startup";
        if (!tls_context_wait_phase(records[index], &children[index], &child_status[index], 1)) {
            failed = 1;
            goto cleanup;
        }
    }
    for (unsigned migration = 0; migration < MIGRATIONS; ++migration) {
        struct tls_context_record *record = records[0];
        unsigned target = targets[(migration + 1) % 2];
        uint64_t mask = UINT64_C(1) << target;
        int phase = (int)migration + 2;
        __atomic_store_n(&record->wanted_cpu, (int)target, __ATOMIC_RELAXED);
        __atomic_store_n(&record->phase, phase, __ATOMIC_RELEASE);
        stage = "parent changes child affinity";
        if (syscall(SYS_sched_setaffinity, children[0], sizeof(mask), &mask)) {
            parent_errno = errno;
            failed = 1;
            goto cleanup;
        }
        stage = "IRQ-only migration and exact TLS";
        if (!tls_context_wait_phase(record, &children[0], &child_status[0], phase) ||
            __atomic_load_n(&records[1]->failed, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&records[2]->failed, __ATOMIC_ACQUIRE)) {
            failed = 1;
            goto cleanup;
        }
        ++completed;
        printf("MUSL-TLS-IRQ-CASE-PASS phase=%d cpu=%u fs_cookie=%llx gs_cookie=%llx checks=%llu\n",
               phase, target, (unsigned long long)__atomic_load_n(&record->observed_fs, __ATOMIC_RELAXED),
               (unsigned long long)__atomic_load_n(&record->observed_gs, __ATOMIC_RELAXED),
               (unsigned long long)record->checks);
    }

cleanup:
    for (unsigned index = 0; index < WORKERS; ++index) {
        if (records[index]) __atomic_store_n(&records[index]->stop, 1, __ATOMIC_RELEASE);
    }
    /* Let a failed worker publish its exit status and diagnostics first. A
     * bounded reap below still SIGKILLs a child that ignores stop or is stuck
     * in the kernel; killing immediately races away the raw startup result. */
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        unsigned pending = 0;
        for (unsigned index = 0; index < WORKERS; ++index) {
            if (children[index] <= 0) continue;
            int status = -1;
            pid_t result = waitpid(children[index], &status, WNOHANG);
            if (result == children[index]) {
                child_status[index] = status;
                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failed = 1;
                children[index] = -1;
            } else {
                ++pending;
                if (result < 0 && errno != EINTR) {
                    parent_errno = errno;
                    failed = 1;
                }
                if (attempt == 399) kill(children[index], SIGKILL);
            }
        }
        if (!pending) break;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
        nanosleep(&delay, NULL);
    }
    for (unsigned index = 0; index < WORKERS; ++index)
        if (children[index] > 0) { unreaped = 1; failed = 1; }
    if (syscall(SYS_sched_setaffinity, 0, sizeof(original), &original)) {
        parent_errno = errno;
        failed = 1;
    }
    if (failed || completed != MIGRATIONS) {
        printf("MUSL-TLS-IRQ-FAIL stage=%s migrations=%u unreaped=%d parent_errno=%d\n",
               stage, completed, unreaped, parent_errno);
        for (unsigned index = 0; index < WORKERS; ++index) {
            struct tls_context_record *record = records[index];
            if (!record) continue;
            printf("MUSL-TLS-IRQ-DIAG worker=%u pid=%ld wait_status=%d failed=%d wanted_cpu=%d startup_cpu=%d "
                   "startup_attempts=%u arch_result=%lld affinity_result=%lld "
                   "phase=%d seen_phase=%d observed_cpu=%d observed_fs=%llx observed_gs=%llx checks=%llu\n",
                   index, (long)reported_pids[index], child_status[index],
                   __atomic_load_n(&record->failed, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&record->wanted_cpu, __ATOMIC_RELAXED),
                   __atomic_load_n(&record->startup_cpu, __ATOMIC_RELAXED),
                   __atomic_load_n(&record->startup_attempts, __ATOMIC_RELAXED),
                   (long long)__atomic_load_n(&record->startup_arch_result, __ATOMIC_ACQUIRE),
                   (long long)__atomic_load_n(&record->startup_affinity_result, __ATOMIC_ACQUIRE),
                   __atomic_load_n(&record->phase, __ATOMIC_RELAXED),
                   __atomic_load_n(&record->seen_phase, __ATOMIC_RELAXED),
                   __atomic_load_n(&record->observed_cpu, __ATOMIC_RELAXED),
                   (unsigned long long)__atomic_load_n(&record->observed_fs, __ATOMIC_RELAXED),
                   (unsigned long long)__atomic_load_n(&record->observed_gs, __ATOMIC_RELAXED),
                   (unsigned long long)__atomic_load_n(&record->checks, __ATOMIC_RELAXED));
        }
        /* Diagnostics above consume the shared records while their mapping is
         * still valid. Only then is it safe to release the shared stacks. */
        if (storage != MAP_FAILED && !unreaped && munmap(storage, WORKERS * STRIDE))
            failed = 1;
        return 1;
    }
    /* Success has no record dereferences left; release the mapping before the
     * final marker and report an unmap error as a failure. */
    if (storage != MAP_FAILED && munmap(storage, WORKERS * STRIDE)) {
        stage = "unmap";
        failed = 1;
    }
    if (failed) {
        printf("MUSL-TLS-IRQ-FAIL stage=%s migrations=%u unreaped=%d parent_errno=%d\n",
               stage, completed, unreaped, parent_errno);
        return 1;
    }
    puts("MUSL-TLS-IRQ-OK migrations=4");
    return 0;
}
