"""Run the production C input reader against a bounded-I/O host shim."""

import errno
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fixture_open(const char *path, int flags, ...);
static ssize_t quota_read(int fd, void *buffer, size_t count);
static int observed_close(int fd);
#define main guest_executor_main
#define open fixture_open
#define read quota_read
#define close observed_close
#include "nilix_syz_executor.c"
#undef main
#undef open
#undef read
#undef close

static const char *fixture;
static const char *mode;
static unsigned int reads;
static unsigned int closes;

static int fixture_open(const char *path, int flags, ...) {
    (void)path;
    return open(fixture, flags, 0600);
}

static ssize_t quota_read(int fd, void *buffer, size_t count) {
    ++reads;
    /* Model the kernel's owner budget including allocator overhead. */
    if (count > 128U * 1024U - 32U) {
        errno = ENOMEM;
        return -1;
    }
    if (strcmp(mode, "read_error") == 0) {
        errno = EIO;
        return -1;
    }
    if (strcmp(mode, "partial") == 0) {
        if (reads == 1U) {
            errno = EINTR;
            return -1;
        }
        if (count > 997U) {
            count = 997U;
        }
    }
    return read(fd, buffer, count);
}

static int observed_close(int fd) {
    ++closes;
    const int result = close(fd);
    if (strcmp(mode, "close_error") == 0) {
        errno = EIO;
        return -1;
    }
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }
    fixture = argv[1];
    mode = argv[2];
    size_t length = 0;
    ExecutorError error = {"none", 0};
    const int result = read_program_file(&length, &error);
    if (result == 0) {
        for (size_t i = 0; i < length; ++i) {
            if (program_buffer[i] != (uint8_t)(i % 251U)) {
                return 3;
            }
        }
    }
    printf("%d %zu %s %" PRId64 " %u %u\n",
           result, length, error.stage, error.code, closes, reads);
    return 0;
}
'''


class ExecutorInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("the executor input regression requires a C compiler")
        cls.directory = tempfile.TemporaryDirectory(prefix="nilix-executor-input-")
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        source = root / "reader.c"
        cls.binary = root / "reader"
        source.write_text(HARNESS)
        compiled = subprocess.run(
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(ROOT / "userspace"), str(source), "-o", str(cls.binary)],
            capture_output=True, text=True,
        )
        if compiled.returncode:
            raise RuntimeError(f"executor reader harness compilation failed:\n{compiled.stderr}")

    def read_fixture(self, length, mode="normal"):
        path = Path(self.directory.name) / "input.bin"
        path.write_bytes(bytes(i % 251 for i in range(length)))
        result = subprocess.run(
            [str(self.binary), str(path), mode],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        status, size, stage, code, closes, reads = result
        self.assertEqual(int(closes), 1, "every opened input must be closed exactly once")
        return int(status), int(size), stage, int(code), int(reads)

    def test_maximum_program_fits_the_io_budget_without_losing_bytes(self):
        status, size, stage, code, reads = self.read_fixture(256 * 1024)
        self.assertEqual((status, size, stage, code), (0, 256 * 1024, "none", 0))
        self.assertGreater(reads, 1)

    def test_short_reads_and_eintr_preserve_the_complete_input(self):
        status, size, stage, code, reads = self.read_fixture(128 * 1024 + 1, "partial")
        self.assertEqual((status, size, stage, code), (0, 128 * 1024 + 1, "none", 0))
        self.assertGreater(reads, 2)

    def test_one_byte_over_the_program_limit_is_still_rejected(self):
        status, _, stage, code, _ = self.read_fixture(256 * 1024 + 1)
        self.assertEqual((status, stage, code), (-1, "input_oversize", -errno.E2BIG))

    def test_empty_input_is_still_rejected(self):
        status, _, stage, code, _ = self.read_fixture(0)
        self.assertEqual((status, stage, code), (-1, "input_empty", -errno.EINVAL))

    def test_read_error_is_preserved_and_closes_the_input(self):
        status, _, stage, code, _ = self.read_fixture(32, "read_error")
        self.assertEqual((status, stage, code), (-1, "input_read", -errno.EIO))

    def test_close_error_is_preserved(self):
        status, _, stage, code, _ = self.read_fixture(32, "close_error")
        self.assertEqual((status, stage, code), (-1, "input_close", -errno.EIO))


if __name__ == "__main__":
    unittest.main()
