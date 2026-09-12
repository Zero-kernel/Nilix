/* Included only by the dedicated KSA_OPEN_FAULT_PROBE musl build. */
static int open_fault_smoke(void) {
    static const struct {
        const char *name;
        const char *path;
        int expected_errno;
    } cases[] = {
        {"allocation", "/ksa-open-allocation", ENOMEM},
        {"capability", "/ksa-open-capability", ENOMEM},
        {"lsm", "/ksa-open-lsm", EACCES},
        {"credential", "/ksa-open-credential", EAGAIN},
        {"success", "/ksa-open-success", 0},
    };
    static const char original[] = "keep these bytes";
    for (int family = 0; family < 2; family++) {
        const char *family_name = family ? "openat2" : "open";
        for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            for (int attempt = 0; attempt < (cases[c].expected_errno ? 4 : 1); attempt++) {
                struct stat st;
                char bytes[sizeof(original)];
                int fd = open(cases[c].path, O_CREAT | O_WRONLY, 0600);
                if (fd < 0) goto fail;
                if (write(fd, original, sizeof(original)) != sizeof(original) || close(fd)) goto fail;
                int next_fd = dup(1);
                if (next_fd < 0 || close(next_fd)) goto fail;
                printf("KSA-004-CASE BEGIN family=%s case=%s attempt=%d\n",
                       family_name, cases[c].name, attempt);
                fflush(stdout);
                errno = 0;
                if (family) {
                    struct { uint64_t flags, mode, resolve; } how = {
                        .flags = O_WRONLY | O_TRUNC,
                    };
                    fd = syscall(437 /* openat2 */, AT_FDCWD, cases[c].path, &how, sizeof(how));
                } else {
                    fd = syscall(SYS_open, cases[c].path, O_WRONLY | O_TRUNC, 0);
                }
                int observed_errno = errno;
                if (cases[c].expected_errno) {
                    if (fd != -1 || observed_errno != cases[c].expected_errno) goto fail;
                } else {
                    if (fd != next_fd || fstat(fd, &st) || st.st_size != 0 ||
                        write(fd, "x", 1) != 1 || close(fd)) goto fail;
                }
                fd = open(cases[c].path, O_RDONLY);
                if (fd != next_fd || fstat(fd, &st)) goto fail;
                if (cases[c].expected_errno) {
                    if (st.st_size != sizeof(original) ||
                        read(fd, bytes, sizeof(bytes)) != sizeof(original) ||
                        memcmp(bytes, original, sizeof(original))) goto fail;
                } else {
                    if (st.st_size != 1 || read(fd, bytes, sizeof(bytes)) != 1 || bytes[0] != 'x') goto fail;
                }
                if (close(fd)) goto fail;
                printf("KSA-004-CASE PASS family=%s case=%s attempt=%d errno=%d data=%s fd=reused\n",
                       family_name, cases[c].name, attempt, cases[c].expected_errno,
                       cases[c].expected_errno ? "preserved" : "truncated");
                fflush(stdout);
                continue;
            fail:
                printf("KSA-004-CASE FAIL family=%s case=%s attempt=%d errno=%d\n",
                       family_name, cases[c].name, attempt, errno);
                return 1;
            }
        }
    }
    puts("KSA-004-PROBES PASS families=2 negative=32 success=2");
    return 0;
}
