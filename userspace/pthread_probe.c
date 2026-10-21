// GAP-5 slice 4: a pthread-like static workload on musl's real pthread code.
// pthread_create issues CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|
// CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|
// CLONE_CHILD_CLEARTID|CLONE_DETACHED, and pthread_join sleeps on the
// CLONE_CHILD_CLEARTID word with a private FUTEX_WAIT until the exiting
// thread's clear-and-wake. pthread_cond_broadcast wakes the first parked
// worker and each worker requeues the next one to the mutex with
// FUTEX_REQUEUE, so the broadcast leg hangs if that op is missing.
// Included by hello_musl.c.
#include <pthread.h>

#define PTHREAD_PROBE_THREADS 4
#define PTHREAD_PROBE_ROUNDS 2000

static pthread_mutex_t pthread_probe_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pthread_probe_cond = PTHREAD_COND_INITIALIZER;
static long pthread_probe_counter;
static int pthread_probe_parked;
static int pthread_probe_go;
static __thread long pthread_probe_tls = -1;

struct pthread_probe_slot {
    long index;
    pid_t pid;
    pid_t tid;
    int fd;
    int tls_ok;
};

static void *pthread_probe_worker(void *arg) {
    struct pthread_probe_slot *slot = arg;
    pthread_probe_tls = slot->index; // per-thread TLS (CLONE_SETTLS)
    slot->pid = getpid();
    slot->tid = (pid_t)syscall(SYS_gettid);
    for (int round = 0; round < PTHREAD_PROBE_ROUNDS; ++round) {
        pthread_mutex_lock(&pthread_probe_lock);
        ++pthread_probe_counter;
        pthread_mutex_unlock(&pthread_probe_lock);
        if ((round & 63) == 0) sched_yield();
    }
    // Park until the main thread broadcasts.
    pthread_mutex_lock(&pthread_probe_lock);
    ++pthread_probe_parked;
    while (!pthread_probe_go) pthread_cond_wait(&pthread_probe_cond, &pthread_probe_lock);
    pthread_mutex_unlock(&pthread_probe_lock);
    // A descriptor opened here lands in the shared table (CLONE_FILES).
    slot->fd = dup(1);
    slot->tls_ok = pthread_probe_tls == slot->index;
    return (void *)(slot->index + 100);
}

static int pthread_smoke(void) {
    pthread_t threads[PTHREAD_PROBE_THREADS];
    struct pthread_probe_slot slots[PTHREAD_PROBE_THREADS];
    const char *stage = "create";
    pid_t self = getpid();
    pid_t self_tid = (pid_t)syscall(SYS_gettid);
    int created = 0;
    int ok = 0;

    pthread_probe_tls = 42;
    for (int i = 0; i < PTHREAD_PROBE_THREADS; ++i) {
        slots[i] = (struct pthread_probe_slot){.index = i, .fd = -1};
        int error = pthread_create(&threads[i], NULL, pthread_probe_worker, &slots[i]);
        if (error) {
            printf("MUSL-PTHREAD-FAIL stage=%s error=%d\n", stage, error);
            goto join;
        }
        ++created;
    }

join:
    // Broadcast once every created worker is parked (all of them are
    // condition waiters by then: musl enqueues before releasing the mutex).
    for (;;) {
        pthread_mutex_lock(&pthread_probe_lock);
        int parked = pthread_probe_parked == created;
        if (parked) {
            pthread_probe_go = 1;
            pthread_cond_broadcast(&pthread_probe_cond);
        }
        pthread_mutex_unlock(&pthread_probe_lock);
        if (parked) break;
        sched_yield();
    }
    stage = "join";
    for (int i = 0; i < created; ++i) {
        void *value = NULL;
        int error = pthread_join(threads[i], &value);
        if (error || value != (void *)(long)(i + 100)) {
            printf("MUSL-PTHREAD-FAIL stage=%s thread=%d error=%d\n", stage, i, error);
            created = -1;
            break;
        }
    }
    if (created != PTHREAD_PROBE_THREADS) return 1;

    stage = "identity";
    for (int i = 0; i < PTHREAD_PROBE_THREADS; ++i) {
        if (slots[i].pid != self || slots[i].tid == self_tid || slots[i].tid <= 0) goto fail;
        for (int j = 0; j < i; ++j)
            if (slots[j].tid == slots[i].tid) goto fail;
    }
    stage = "tls";
    if (pthread_probe_tls != 42) goto fail;
    for (int i = 0; i < PTHREAD_PROBE_THREADS; ++i)
        if (!slots[i].tls_ok) goto fail;
    stage = "mutex";
    if (pthread_probe_counter != (long)PTHREAD_PROBE_THREADS * PTHREAD_PROBE_ROUNDS) goto fail;
    stage = "timedwait";
    {
        // A 5 ms deadline that nothing signals: musl turns it into a relative
        // FUTEX_WAIT timeout, which must expire as ETIMEDOUT.
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline)) goto fail;
        deadline.tv_nsec += 5 * 1000 * 1000;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&pthread_probe_lock);
        int error = pthread_cond_timedwait(&pthread_probe_cond, &pthread_probe_lock, &deadline);
        pthread_mutex_unlock(&pthread_probe_lock);
        if (error != ETIMEDOUT) goto fail;
    }
    stage = "shared files";
    for (int i = 0; i < PTHREAD_PROBE_THREADS; ++i) {
        if (slots[i].fd < 0 || fcntl(slots[i].fd, F_GETFD) < 0) goto fail;
        if (close(slots[i].fd)) goto fail;
    }
    ok = 1;

fail:
    if (!ok) {
        printf("MUSL-PTHREAD-FAIL stage=%s counter=%ld errno=%d\n", stage, pthread_probe_counter,
               errno);
        return 1;
    }
    puts("MUSL-PTHREAD-OK");
    return 0;
}

// GAP-5 G7: process-directed signals in a thread group. kill(2) queues in the
// group's shared set; the member chosen for the signal must be woken from a
// blocking wait (leg A), and a member whose pselect6 mask opens for a signal
// queued while every member blocked it must return EINTR at once (leg B,
// Linux set_user_sigmask). Each signal is delivered exactly once, to the
// worker. Prints MUSL-PTHREAD-SIGNAL-OK.
#include <signal.h>

static volatile sig_atomic_t pthread_sig_hits;
static volatile pid_t pthread_sig_tid;
static volatile pid_t pthread_sig_worker_tid;
static volatile int pthread_sig_ready;
static volatile int pthread_sig_go;
static volatile int pthread_sig_result;
static volatile long pthread_sig_elapsed_ms;

static void pthread_sig_handler(int sig) {
    (void)sig;
    pthread_sig_tid = (pid_t)syscall(SYS_gettid);
    ++pthread_sig_hits;
}

static long pthread_sig_now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

// Leg A: the only member that does not block the signal sleeps.
static void *pthread_sig_sleeper(void *arg) {
    (void)arg;
    pthread_sig_worker_tid = (pid_t)syscall(SYS_gettid);
    long start = pthread_sig_now_ms();
    pthread_sig_ready = 1;
    for (int i = 0; i < 2 && !pthread_sig_hits; ++i) {
        struct timespec nap = {3, 0};
        nanosleep(&nap, NULL);
    }
    pthread_sig_elapsed_ms = pthread_sig_now_ms() - start;
    return NULL;
}

// Leg B: this member inherits the blocked signal, then opens its mask.
static void *pthread_sig_pselector(void *arg) {
    (void)arg;
    pthread_sig_worker_tid = (pid_t)syscall(SYS_gettid);
    pthread_sig_ready = 1;
    while (!pthread_sig_go) sched_yield();
    sigset_t open;
    sigemptyset(&open);
    struct timespec limit = {3, 0};
    long start = pthread_sig_now_ms();
    int r = pselect(0, NULL, NULL, NULL, &limit, &open);
    int error = errno;
    pthread_sig_elapsed_ms = pthread_sig_now_ms() - start;
    pthread_sig_result = (r == -1 && error == EINTR) ? 1 : 2;
    return NULL;
}

static void pthread_sig_reset(void) {
    pthread_sig_hits = 0;
    pthread_sig_tid = 0;
    pthread_sig_worker_tid = -1;
    pthread_sig_ready = 0;
    pthread_sig_go = 0;
    pthread_sig_result = 0;
    pthread_sig_elapsed_ms = -1;
}

static int pthread_signal_smoke(void) {
    const char *stage = "sigaction";
    struct sigaction sa;
    sigset_t old, one;
    pthread_t thread;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = pthread_sig_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) || sigaction(SIGUSR2, &sa, NULL)) goto fail;
    if (pthread_sigmask(SIG_SETMASK, NULL, &old)) goto fail;

    stage = "wake";
    pthread_sig_reset();
    if (pthread_create(&thread, NULL, pthread_sig_sleeper, NULL)) goto fail;
    sigemptyset(&one);
    sigaddset(&one, SIGUSR2);
    pthread_sigmask(SIG_BLOCK, &one, NULL);
    while (!pthread_sig_ready) sched_yield();
    kill(getpid(), SIGUSR2);
    pthread_join(thread, NULL);
    // Unblocking here must not deliver the signal a second time.
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (pthread_sig_hits != 1 || pthread_sig_tid != pthread_sig_worker_tid ||
        pthread_sig_elapsed_ms < 0 || pthread_sig_elapsed_ms > 2000)
        goto fail;

    stage = "pselect";
    pthread_sig_reset();
    sigemptyset(&one);
    sigaddset(&one, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &one, NULL); // inherited by the worker
    if (pthread_create(&thread, NULL, pthread_sig_pselector, NULL)) {
        pthread_sigmask(SIG_SETMASK, &old, NULL);
        goto fail;
    }
    while (!pthread_sig_ready) sched_yield();
    kill(getpid(), SIGUSR1); // every member blocks it: it waits in the group set
    pthread_sig_go = 1;
    pthread_join(thread, NULL);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (pthread_sig_result != 1 || pthread_sig_hits != 1 ||
        pthread_sig_tid != pthread_sig_worker_tid || pthread_sig_elapsed_ms < 0 ||
        pthread_sig_elapsed_ms > 2000)
        goto fail;

    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    puts("MUSL-PTHREAD-SIGNAL-OK");
    return 0;

fail:
    printf("MUSL-PTHREAD-SIGNAL-FAIL stage=%s hits=%d tid=%d worker=%d result=%d elapsed=%ld "
           "errno=%d\n",
           stage, (int)pthread_sig_hits, (int)pthread_sig_tid, (int)pthread_sig_worker_tid,
           (int)pthread_sig_result, (long)pthread_sig_elapsed_ms, errno);
    return 1;
}
