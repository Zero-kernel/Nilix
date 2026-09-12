/* KSA-010/014/016: include from hello_musl.c and call vfs_context_probe().
 * Route --vfs-cwd-exec-check to vfs_context_exec_check(argc, argv) before the
 * normal test sequence. Run only in the disposable Zero-OS test guest.
 * Functional pivot_root runs in a copied mount namespace using its /sys mount.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_chroot
#define SYS_chroot 161
#endif
#ifndef SYS_pivot_root
#define SYS_pivot_root 155
#endif

struct vctx_open_how {
    uint64_t flags, mode, resolve;
};

static int vctx_open(const char *path, uint64_t resolve) {
    struct vctx_open_how how = {O_RDONLY, 0, resolve};
    return (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
}

static int vctx_cwd_is(const char *expected) {
    char buffer[256];
    memset(buffer, 0xa5, sizeof(buffer));
    long count = syscall(SYS_getcwd, buffer, sizeof(buffer));
    return count == (long)strlen(expected) + 1 && !strcmp(buffer, expected);
}

static int vctx_put(const char *path, char value, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) return -1;
    int ok = write(fd, &value, 1) == 1;
    int saved = errno;
    if (close(fd)) ok = 0;
    errno = saved;
    return ok ? 0 : -1;
}

static int vctx_read_is(int fd, char expected) {
    if (fd < 0) return 0;
    char value = 0;
    int ok = read(fd, &value, 1) == 1 && value == expected;
    if (close(fd)) ok = 0;
    return ok;
}

static int vctx_wait(pid_t child) {
    int status = -1;
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("MUSL-VFS-CHILD-FAIL pid=%ld status=%d errno=%d\n",
               (long)child, status, errno);
        return -1;
    }
    return 0;
}

static int vfs_context_exec_check(int argc, char **argv) {
    if (argc != 3 || !vctx_cwd_is(argv[2])) return 81;
    return vctx_read_is(open("public", O_RDONLY), 'P') ? 0 : 82;
}

static void vctx_exit(int code) {
    fflush(NULL);
    syscall(SYS_exit, code);
    __builtin_unreachable();
}

/* Each observer establishes its own cwd/root/namespace before the parent pivots.
 * Pipes make that ordering explicit on both one-CPU and SMP guests. */
static int vctx_pivot_observe(int which, const char *base, const char *old_leaf,
                              const char *marker, int ready, int gate) {
    char expected[256], old_marker[128], byte = 0;
    int setup = 0;
    if (which == 0) setup = chdir("/");
    if (which == 1) setup = chdir(base);
    if (which == 2) setup = chdir(base) || syscall(SYS_chroot, "jail");
    if (which == 3) setup = syscall(SYS_unshare, CLONE_NEWNS) || chdir("/");
    if (write(ready, setup ? "E" : "R", 1) != 1) return 91;
    close(ready);
    if (setup || read(gate, &byte, 1) != 1 || byte != 'G') return 92;
    close(gate);
    snprintf(expected, sizeof(expected), "/%s%s", old_leaf, base);
    snprintf(old_marker, sizeof(old_marker), "/sys/%s", marker);
    char new_marker[128];
    snprintf(new_marker, sizeof(new_marker), "/%s", marker);
    if (which == 0)
        return vctx_cwd_is("/") && vctx_read_is(open(new_marker, O_RDONLY), 'N') ? 0 : 93;
    if (which == 1)
        return vctx_cwd_is(expected) && vctx_read_is(open("public", O_RDONLY), 'P') ? 0 : 94;
    if (which == 2)
        return vctx_cwd_is("/") && vctx_read_is(open("/public", O_RDONLY), 'J') ? 0 : 95;
    struct stat status;
    errno = 0;
    if (stat(new_marker, &status) != -1 || errno != ENOENT) return 96;
    return vctx_cwd_is("/") && vctx_read_is(open(old_marker, O_RDONLY), 'N') &&
           !stat("/musl-test", &status) ? 0 : 97;
}

static int vctx_pivot_run(const char *base) {
    char old_leaf[64], marker[64], put_old[128], marker_path[128];
    char link_path[128], marker_root[96], old_root[96], expected[256], put_back[192];
    pid_t children[4] = {-1, -1, -1, -1};
    int gates[4] = {-1, -1, -1, -1};
    int ready[2] = {-1, -1}, gate[2] = {-1, -1};
    const char *stage = "setup copied namespace";
    int failed = 1, held = -1;
    struct stat before, after;
    snprintf(old_leaf, sizeof(old_leaf), "ksa-pivot-old-%ld", (long)getpid());
    snprintf(marker, sizeof(marker), "ksa-pivot-new-%ld", (long)getpid());
    snprintf(put_old, sizeof(put_old), "/sys/%s", old_leaf);
    snprintf(marker_path, sizeof(marker_path), "/sys/%s", marker);
    snprintf(marker_root, sizeof(marker_root), "/%s", marker);
    snprintf(old_root, sizeof(old_root), "/%s", old_leaf);
    snprintf(link_path, sizeof(link_path), "/sys/ksa-pivot-link-%ld", (long)getpid());
    if (syscall(SYS_unshare, CLONE_NEWNS) || mkdir(put_old, 0755) ||
        vctx_put(marker_path, 'N', 0644) || symlink(marker_root, link_path) ||
        (held = open("public", O_RDONLY)) < 0 || fstat(held, &before)) goto done;

    stage = "invalid transaction rollback";
    errno = 0;
    if (syscall(SYS_pivot_root, "jail", "jail/deep") != -1 ||
        errno != EINVAL || !vctx_cwd_is(base)) goto done;
    errno = 0;
    if (syscall(SYS_pivot_root, "/sys", "/sys") != -1 ||
        errno != EINVAL || !vctx_cwd_is(base)) goto done;

    stage = "prepare concurrent observers";
    for (int which = 0; which < 4; ++which) {
        if (pipe(ready) || pipe(gate)) goto done;
        fflush(NULL);
        children[which] = (pid_t)syscall(SYS_fork);
        if (children[which] == 0) {
            for (int previous = 0; previous < which; ++previous) close(gates[previous]);
            close(ready[0]);
            close(gate[1]);
            close(held);
            vctx_exit(vctx_pivot_observe(which, base, old_leaf, marker, ready[1], gate[0]));
        }
        close(ready[1]); ready[1] = -1;
        close(gate[0]); gate[0] = -1;
        gates[which] = gate[1]; gate[1] = -1;
        char byte = 0;
        if (children[which] < 0 || read(ready[0], &byte, 1) != 1 || byte != 'R') goto done;
        close(ready[0]); ready[0] = -1;
    }

    stage = "publish pivot";
    if (syscall(SYS_pivot_root, "/sys", put_old)) goto done;
    snprintf(expected, sizeof(expected), "/%s%s", old_leaf, base);
    snprintf(link_path, sizeof(link_path), "/ksa-pivot-link-%ld", (long)getpid());
    if (!vctx_cwd_is(expected) || !vctx_read_is(open(marker_root, O_RDONLY), 'N') ||
        !vctx_read_is(open(link_path, O_RDONLY), 'N') ||
        stat("/fs/cgroup", &after) || !S_ISDIR(after.st_mode) ||
        fstat(held, &after) || after.st_ino != before.st_ino ||
        after.st_dev != before.st_dev) goto done;
    if (!vctx_read_is(held, 'P')) { held = -1; goto done; }
    held = -1;
    for (int which = 0; which < 4; ++which) {
        if (write(gates[which], "G", 1) != 1) goto done;
        close(gates[which]); gates[which] = -1;
    }
    for (int which = 0; which < 4; ++which) {
        pid_t child = children[which]; children[which] = -1;
        if (vctx_wait(child)) goto done;
    }

    stage = "intentional old-root selection and later namespace copy";
    if (chdir(old_root) || !vctx_cwd_is(old_root) || chdir("..") || !vctx_cwd_is("/")) goto done;
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        if (syscall(SYS_unshare, CLONE_NEWNS) || !vctx_cwd_is("/") ||
            !vctx_read_is(open(marker_root, O_RDONLY), 'N')) vctx_exit(98);
        vctx_exit(0);
    }
    if (vctx_wait(child)) goto done;

    stage = "reverse pivot and inherited current root";
    snprintf(put_back, sizeof(put_back), "/%s/sys/ksa-put-back-%ld", old_leaf, (long)getpid());
    if (mkdir(put_back, 0755) || syscall(SYS_pivot_root, old_root, put_back) ||
        !vctx_cwd_is("/") || stat("/musl-test", &after) || chdir(base) ||
        !vctx_cwd_is(base) || !vctx_read_is(open("public", O_RDONLY), 'P')) goto done;
    snprintf(marker_path, sizeof(marker_path), "/sys/ksa-put-back-%ld/%s", (long)getpid(), marker);
    if (!vctx_read_is(open(marker_path, O_RDONLY), 'N')) goto done;
    failed = 0;
done:
    if (held >= 0) close(held);
    for (int which = 0; which < 4; ++which) if (gates[which] >= 0) close(gates[which]);
    for (int index = 0; index < 2; ++index) {
        if (ready[index] >= 0) close(ready[index]);
        if (gate[index] >= 0) close(gate[index]);
    }
    for (int which = 0; which < 4; ++which) if (children[which] > 0) vctx_wait(children[which]);
    if (failed) printf("MUSL-VFS-PIVOT-FAIL stage=%s errno=%d\n", stage, errno);
    return failed;
}

/* CLONE_NEWUSER is supported on the CLONE_VM path. The child inherits local
 * UID/GID zero; the parent publishes their nonroot host mappings before it runs
 * any syscall. There is no setuid/setgid/setgroups ABI in this kernel.
 * Zero-OS rejects all low CSIGNAL flag bits. Its wait4 selects regular children
 * without Linux's __WCLONE filter, and termination always notifies the parent;
 * use exactly CLONE_VM | CLONE_NEWUSER with ordinary waitpid(child, ..., 0).
 *
 * No CLONE_SETTLS means libc TLS (including errno) is shared. Only the parent
 * uses libc before release, only the child uses it until completion. The child
 * then returns through musl's raw-exit clone trampoline; the parent reaps it
 * before releasing the shared record and its separate 64 KiB stack. A stuck or
 * faulting child cannot emit success and remains bounded by the outer gate.
 */
struct vctx_mapped_child {
    int released, completed, result, error, primary_group;
    const char *stage;
    char base[112];
};

static int vctx_mapped_checks(struct vctx_mapped_child *child) {
    struct stat status;
    child->stage = "mapped local identity and inherited cwd";
    errno = 0;
    if (syscall(SYS_getuid) != 0 || syscall(SYS_getgid) != 0 ||
        !vctx_cwd_is(child->base)) return 29;

    child->stage = "primary group overrides more permissive other bits";
    errno = 0;
    if (child->primary_group) {
        if (syscall(SYS_access, "access-group", R_OK) != -1 || errno != EACCES)
            return 51;
        errno = 0;
        return syscall(SYS_access, "access-group", F_OK) ? 52 : 0;
    }

    child->stage = "unrelated identity receives other permissions";
    errno = 0;
    if (syscall(SYS_access, "access-group", R_OK) ||
        syscall(SYS_access, "access-group", F_OK) ||
        !vctx_read_is(open("public", O_RDONLY), 'P')) return 30;
    child->stage = "component search denial before dotdot";
    errno = 0;
    int fd = open("blocked/../public", O_RDONLY);
    if (fd >= 0) { close(fd); return 31; }
    if (errno != EACCES) return 32;
    child->stage = "chdir search denial preserves cwd";
    errno = 0;
    if (chdir("blocked") != -1 || errno != EACCES || !vctx_cwd_is(child->base))
        return 33;
    child->stage = "mapped nonroot chroot rejection";
    errno = 0;
    if (syscall(SYS_chroot, "jail") != -1 || errno != EPERM ||
        !vctx_cwd_is(child->base)) return 34;
    child->stage = "mapped nonroot pivot rejection";
    errno = 0;
    if (syscall(SYS_pivot_root, "/sys", "/sys/fs") != -1 || errno != EPERM ||
        !vctx_cwd_is(child->base)) return 45;

    child->stage = "created file displays namespace ownership";
    errno = 0;
    fd = open("owned", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return 35;
    int ok = !fstat(fd, &status) && status.st_uid == 0 && status.st_gid == 0;
    int saved = errno;
    if (close(fd)) return 36;
    errno = saved;
    if (!ok || stat("owned", &status) || status.st_uid != 0 || status.st_gid != 0)
        return 36;
    child->stage = "created symlink displays namespace ownership";
    errno = 0;
    if (symlink("owned", "owned-link") || lstat("owned-link", &status) ||
        !S_ISLNK(status.st_mode) || status.st_uid != 0 || status.st_gid != 0)
        return 37;
    return 0;
}

static int vctx_mapped_worker(void *argument) {
    struct vctx_mapped_child *child = argument;
    while (!__atomic_load_n(&child->released, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause");
    child->result = vctx_mapped_checks(child);
    child->error = errno;
    __atomic_store_n(&child->completed, 1, __ATOMIC_RELEASE);
    return child->result;
}

static int vctx_publish_map(pid_t child, const char *name, const char *mapping) {
    char path[96];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t length = (ssize_t)strlen(mapping);
    ssize_t written = write(fd, mapping, (size_t)length);
    int saved = written < 0 ? errno : EIO;
    int closed = close(fd);
    if (written != length) { errno = saved; return -1; }
    return closed;
}

static int vctx_mapped_run(const char *base, int primary_group) {
    enum { RECORD_BYTES = 4096, STACK_BYTES = 64 * 1024 };
    const size_t allocation_bytes = RECORD_BYTES + STACK_BYTES;
    const char *stage = "allocate mapped child record and stack";
    int failed = 1, saved = 0, status = -1, reaped = 0;
    pid_t child = -1;
    struct vctx_mapped_child *record = mmap(NULL, allocation_bytes,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (record == MAP_FAILED) {
        printf("MUSL-VFS-MAPPED-FAIL stage=%s errno=%d\n", stage, errno);
        return -1;
    }
    record->primary_group = primary_group;
    record->result = -1;
    record->stage = "await parent mappings";
    snprintf(record->base, sizeof(record->base), "%s", base);
    stage = "clone new user namespace";
    child = clone(vctx_mapped_worker, (char *)record + allocation_bytes,
                  CLONE_VM | CLONE_NEWUSER, record, NULL, NULL, NULL);
    if (child < 0) { saved = errno; goto done; }
    stage = "publish uid_map";
    if (vctx_publish_map(child, "uid_map", primary_group ? "0 70003 1\n" : "0 70001 1\n")) {
        saved = errno; goto done;
    }
    stage = "publish gid_map";
    if (vctx_publish_map(child, "gid_map", primary_group ? "0 0 1\n" : "0 70002 1\n")) {
        saved = errno; goto done;
    }
    __atomic_store_n(&record->released, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&record->completed, __ATOMIC_ACQUIRE))
        __asm__ volatile("pause");
    stage = record->stage;
    saved = record->error;
    pid_t observed;
    do { observed = waitpid(child, &status, 0); } while (observed < 0 && errno == EINTR);
    if (observed != child) { stage = "reap mapped child"; saved = errno; goto done; }
    reaped = 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || record->result != 0)
        goto done;

    stage = "root parent observes full host ownership";
    errno = 0;
    if (!primary_group) {
        struct stat host_status;
        if (stat("owned", &host_status) || !S_ISREG(host_status.st_mode) ||
            host_status.st_uid != 70001 || host_status.st_gid != 70002 ||
            lstat("owned-link", &host_status) || !S_ISLNK(host_status.st_mode) ||
            host_status.st_uid != 70001 || host_status.st_gid != 70002) {
            saved = errno; goto done;
        }
    }
    failed = 0;
done:
    /* Before release the child only spins; after completion it no longer uses
     * libc. Both cleanup paths may therefore use the inherited TLS safely. */
    if (child > 0 && !reaped) {
        int killed = kill(child, SIGKILL);
        if (!killed || errno == ESRCH) {
            pid_t observed;
            do { observed = waitpid(child, &status, 0); } while (observed < 0 && errno == EINTR);
            reaped = observed == child;
        }
        if (!reaped)
            printf("MUSL-VFS-MAPPED-UNREAPED pid=%ld errno=%d\n", (long)child, errno);
    }
    if (failed)
        printf("MUSL-VFS-MAPPED-FAIL case=%s stage=%s code=%d errno=%d status=%d\n",
               primary_group ? "primary-group" : "ownership-dac", stage,
               record->result, saved, status);
    /* A failed reap retains the entire allocation, including the copied path;
     * an active child must never touch an unmapped stack or dead local record. */
    if (child < 0 || reaped) {
        if (munmap(record, allocation_bytes)) {
            printf("MUSL-VFS-MAPPED-FAIL stage=unmap errno=%d\n", errno);
            failed = 1;
        }
    }
    errno = saved;
    return failed ? -1 : 0;
}

static int vctx_child_checks(const char *base, int which) {
    if (!vctx_cwd_is(base)) return 20;
    if (which == 0) {
        if (chdir("/")) return 21;
        return vctx_cwd_is("/") ? 0 : 22;
    }
    if (which == 1) {
        if (mkdir("gone", 0777) || chdir("gone") ||
            rmdir("../gone") || mkdir("../gone", 0777) ||
            vctx_put("../gone/replacement", 'R', 0644)) return 23;
        char buffer[256];
        errno = 0;
        if (syscall(SYS_getcwd, buffer, sizeof(buffer)) != -1 || errno != ENOENT)
            return 24;
        errno = 0;
        int fd = open("replacement", O_RDONLY);
        if (fd >= 0) { close(fd); return 25; }
        if (errno != ENOENT) return 26;
        errno = 0;
        fd = open("new", O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) { close(fd); return 27; }
        if (errno != ENOENT || chdir("..") || !vctx_cwd_is(base)) return 28;
        return 0;
    }
    if (which == 3) {
        if (chdir("jail/deep") || syscall(SYS_chroot, "..") ||
            !vctx_cwd_is("/deep")) return 38;
        if (!vctx_read_is(open("/absolute", O_RDONLY), 'J') ||
            chdir("../../..") || !vctx_cwd_is("/") ||
            !vctx_read_is(open("/../public", O_RDONLY), 'J')) return 39;
        errno = 0;
        int fd = open("/outside", O_RDONLY);
        if (fd >= 0) { close(fd); return 40; }
        return errno == ENOENT ? 0 : 41;
    }
    if (which == 4) {
        /* Zero-OS deliberately resets an outside cwd during chroot. */
        if (syscall(SYS_chroot, "jail") || !vctx_cwd_is("/") ||
            !vctx_read_is(open("public", O_RDONLY), 'J')) return 42;
        errno = 0;
        if (syscall(SYS_chroot, "public") != -1 || errno != ENOTDIR ||
            !vctx_cwd_is("/")) return 43;
        return 0;
    }
    if (which == 5) {
        char target[160], link[64];
        snprintf(target, sizeof(target), "%s/public", base);
        snprintf(link, sizeof(link), "ksa-vfs-return-%ld", (long)getpid());
        if (chdir("/sys") || symlink(target, link)) return 46;
        errno = 0;
        int fd = vctx_open(link, 0x01);
        if (fd >= 0) { close(fd); return 47; }
        if (errno != EXDEV || !vctx_read_is(open(link, O_RDONLY), 'P')) return 48;
        return unlink(link) ? 49 : 0;
    }
    return 44;
}

static int vctx_run(void) {
    char base[96], moved[112], expected[144];
    const char *stage = "setup";
    int failed = 1;
    snprintf(base, sizeof(base), "/ksa-vfs-context-%ld", (long)getpid());
    snprintf(moved, sizeof(moved), "%s-moved", base);
    umask(0);
    if (mkdir(base, 0777) || chdir(base) || !vctx_cwd_is(base) ||
        mkdir("inner", 0755) || mkdir("blocked", 0000) ||
        mkdir("target", 0755) || mkdir("target/sub", 0755) ||
        mkdir("jail", 0755) || mkdir("jail/deep", 0755) ||
        vctx_put("public", 'P', 0644) || vctx_put("outside", 'O', 0644) ||
        vctx_put("access-group", 'G', 0004) ||
        vctx_put("target/public", 'T', 0644) ||
        vctx_put("jail/public", 'J', 0644) ||
        symlink("/public", "jail/absolute") ||
        symlink("target/sub", "link")) goto done;

    stage = "cwd and relative callers";
    char tiny[1] = {(char)0xa5};
    errno = 0;
    if (syscall(SYS_getcwd, tiny, sizeof(tiny)) != -1 || errno != ERANGE ||
        tiny[0] != (char)0xa5) goto done;
    if (!vctx_read_is(openat(AT_FDCWD, "public", O_RDONLY), 'P') ||
        !vctx_read_is(open("link/../public", O_RDONLY), 'T')) goto done;
    errno = 0;
    int fd = open("public/../public", O_RDONLY);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != ENOTDIR) goto done;
    if (vctx_put("rename-source", 'N', 0600) ||
        renameat(AT_FDCWD, "rename-source", AT_FDCWD, "renamed") ||
        !vctx_read_is(open("renamed", O_RDONLY), 'N')) goto done;

    stage = "component length before lookup and creation";
    char overlong[257];
    memset(overlong, 'x', sizeof(overlong) - 1);
    overlong[sizeof(overlong) - 1] = '\0';
    errno = 0;
    fd = open(overlong, O_RDONLY);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != ENAMETOOLONG) goto done;

    stage = "access requested-mask validation";
    errno = 0;
    if (syscall(SYS_access, "public", 8) != -1 || errno != EINVAL) goto done;
    errno = 0;
    fd = open(overlong, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != ENAMETOOLONG) goto done;

    stage = "openat2 confinement";
    if (!vctx_read_is(vctx_open("/public", 0x10), 'P')) goto done;
    errno = 0;
    fd = vctx_open("../musl-test", 0x08);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != EXDEV) goto done;
    errno = 0;
    fd = vctx_open("/public", 0x08);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != EXDEV) goto done;
    errno = 0;
    fd = vctx_open("../dev/null", 0x01);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != EXDEV) goto done;
    errno = 0;
    fd = vctx_open("link/../public", 0x04);
    if (fd >= 0) { close(fd); goto done; }
    if (errno != ELOOP) goto done;

    stage = "fork and relative exec";
    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        execl("../musl-test", "musl-test", "--vfs-cwd-exec-check", base,
              (char *)NULL);
        syscall(SYS_exit, 83);
        __builtin_unreachable();
    }
    if (vctx_wait(child) || !vctx_cwd_is(base)) goto done;
    child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        syscall(SYS_exit, vctx_child_checks(base, 0));
        __builtin_unreachable();
    }
    if (vctx_wait(child) || !vctx_cwd_is(base)) goto done;

    stage = "rename cwd ancestor";
    if (chdir("inner") || rename(base, moved)) goto done;
    snprintf(expected, sizeof(expected), "%s/inner", moved);
    if (!vctx_cwd_is(expected) || chdir("..") || !vctx_cwd_is(moved) ||
        !vctx_read_is(open("public", O_RDONLY), 'P')) goto done;

    stage = "deletion DAC IDs and root transitions";
    for (int which = 1; which <= 6; ++which) {
        if (which == 2 || which == 6) {
            if (vctx_mapped_run(moved, which == 6) || !vctx_cwd_is(moved)) goto done;
            continue;
        }
        fflush(NULL);
        child = (pid_t)syscall(SYS_fork);
        if (child == 0) {
            syscall(SYS_exit, vctx_child_checks(moved, which));
            __builtin_unreachable();
        }
        if (vctx_wait(child) || !vctx_cwd_is(moved)) goto done;
    }

    stage = "functional mount-root transaction";
    child = (pid_t)syscall(SYS_fork);
    if (child == 0) vctx_exit(vctx_pivot_run(moved));
    if (vctx_wait(child) || !vctx_cwd_is(moved) ||
        !vctx_read_is(open("public", O_RDONLY), 'P')) goto done;
    puts("MUSL-VFS-PIVOT-OK scope=transaction-fork-namespaces-descriptors-repeat");
    failed = 0;
done:
    if (failed) printf("MUSL-VFS-CONTEXT-FAIL stage=%s errno=%d\n", stage, errno);
    return failed;
}

static int vfs_context_probe(void) {
    fflush(NULL);
    pid_t child = (pid_t)syscall(SYS_fork);
    if (child == 0) {
        int result = vctx_run();
        fflush(NULL);
        syscall(SYS_exit, result);
        __builtin_unreachable();
    }
    if (vctx_wait(child)) return 1;
    puts("MUSL-VFS-CONTEXT-OK scope=cwd-components-dac-ids-chroot");
    return 0;
}
