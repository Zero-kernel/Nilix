#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Nilix #66 BusyBox boot gate PID 1 init wrapper.
 *
 * BusyBox (GPL-2.0) is never embedded or committed to the repository; it is
 * staged onto the disposable Ext3 test disk at /mnt/test/bin/busybox.
 *
 * Boot 1 (no /mnt/test/boot2.flag):
 *   1. Executes /mnt/test/bin/busybox sh /mnt/test/gate_script.sh
 *      (scripted pipelines, redirection, background jobs, file ops on /mnt/test).
 *   2. Emits BB-SCRIPTED OK and BB-INTERACTIVE-READY.
 *   3. Replaces PID 1 via execve() with interactive `/mnt/test/bin/busybox sh -i`
 *      so ash inherits session 1's controlling terminal for real serial job
 *      control (^Z, bg, fg, ^C).
 *
 * Boot 2 (/mnt/test/boot2.flag present after reboot):
 *   1. Executes /mnt/test/bin/busybox sh /mnt/test/verify_persist.sh to prove
 *      Ext3 writes persisted across reboot.
 *   2. Emits BB-BOOT2-DONE and exits 0.
 */

#define BUSYBOX_PATH "/mnt/test/bin/busybox"
#define SCRIPT_BOOT1 "/mnt/test/gate_script.sh"
#define SCRIPT_BOOT2 "/mnt/test/verify_persist.sh"
#define BOOT2_FLAG   "/mnt/test/boot2.flag"

static void write_line(const char *s) {
    size_t n = strlen(s);
    while (n > 0) {
        ssize_t r = write(STDOUT_FILENO, s, n);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (r == 0) {
            return;
        }
        s += r;
        n -= (size_t)r;
    }
    (void)write(STDOUT_FILENO, "\n", 1);
}

static int run_busybox_script(const char *script_path, char *const envp[]) {
    pid_t pid = fork();
    if (pid < 0) {
        char msg[128];
        snprintf(msg, sizeof(msg), "BB-ERROR fork failed errno=%d", errno);
        write_line(msg);
        return 1;
    }
    if (pid == 0) {
        char *const argv[] = {"sh", (char *)script_path, NULL};
        execve(BUSYBOX_PATH, argv, envp);
        char msg[160];
        snprintf(msg, sizeof(msg), "BB-ERROR execve(%s) failed errno=%d", script_path, errno);
        write_line(msg);
        _exit(127);
    }

    int status = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, 0);
        if (r == pid) {
            break;
        }
        if (r < 0 && errno == EINTR) {
            continue;
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "BB-ERROR waitpid failed errno=%d", errno);
        write_line(msg);
        return 1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    char msg[160];
    snprintf(
        msg,
        sizeof(msg),
        "BB-ERROR script %s failed status=0x%x",
        script_path,
        (unsigned int)status
    );
    write_line(msg);
    return 1;
}

static void populate_bin_symlinks(void) {
    static const char *const applets[] = {
        "sh", "ash", "cat", "chmod", "chown", "cp", "cut", "echo", "env",
        "expr", "false", "grep", "head", "id", "kill", "ln", "ls", "mkdir",
        "mkfifo", "mknod", "mv", "printf", "ps", "pwd", "readlink", "rm",
        "rmdir", "sed", "seq", "sleep", "sort", "stat", "sync", "tail",
        "test", "[", "[[", "touch", "tr", "true", "uname", "uniq", "wc", "yes",
        NULL,
    };
    (void)mkdir("/bin", 0755);
    for (size_t i = 0; applets[i] != NULL; i++) {
        char link_path[64];
        int n = snprintf(link_path, sizeof(link_path), "/bin/%s", applets[i]);
        if (n > 0 && (size_t)n < sizeof(link_path)) {
            (void)symlink(BUSYBOX_PATH, link_path);
        }
    }
}

int main(void) {
    (void)mkdir("/tmp", 0755);

    if (access(BUSYBOX_PATH, X_OK) != 0) {
        char msg[160];
        snprintf(msg, sizeof(msg), "BB-ERROR missing %s errno=%d", BUSYBOX_PATH, errno);
        write_line(msg);
        return 1;
    }

    populate_bin_symlinks();

    char *const envp[] = {
        "PATH=/bin:/mnt/test/bin",
        "HOME=/tmp",
        "TMPDIR=/tmp",
        "TERM=vt100",
        "PS1=BB-PROMPT> ",
        NULL,
    };

    if (access(BOOT2_FLAG, F_OK) == 0) {
        if (run_busybox_script(SCRIPT_BOOT2, envp) != 0) {
            return 1;
        }
        write_line("BB-BOOT2-DONE");
        return 0;
    }

    if (run_busybox_script(SCRIPT_BOOT1, envp) != 0) {
        return 1;
    }
    write_line("BB-SCRIPTED OK");
    write_line("BB-INTERACTIVE-READY");

    /* Replace PID 1 with interactive BusyBox ash on the controlling console. */
    char *const sh_argv[] = {"sh", "-i", NULL};
    execve(BUSYBOX_PATH, sh_argv, envp);

    char msg[160];
    snprintf(msg, sizeof(msg), "BB-ERROR execve(sh -i) failed errno=%d", errno);
    write_line(msg);
    return 127;
}
