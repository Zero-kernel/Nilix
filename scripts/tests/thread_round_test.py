"""Exercise the real thread parent against successful and broken child reports."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform == "linux", "the guest native harness requires Linux")
class ThreadRoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("cc is required for the thread report regression tests")
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        cls.binary = directory / "thread-rounds"
        harness = directory / "harness.c"
        harness.write_text(
            '#define main stress_guest_main\n'
            f'#include "{ROOT / "userspace/stress_runner.c"}"\n'
            '#undef main\n' + r'''
#include <signal.h>

static void seed_report_child(const char *mode) {
    int fds[2];
    if (pipe(fds) != 0) abort();
    pid_t child = fork();
    if (child < 0) abort();
    if (child == 0) {
        close(fds[0]);
        ThreadRoundReport report = {2, 2, 10, 0x0123456789abcdefull, 12345};
        for (unsigned i = 0; i < 2; i++)
            write_all_fd(fds[1], &report, sizeof(report), "injected_write");
        if (!strcmp(mode, "exit7")) _exit(7);
        if (!strcmp(mode, "signal")) { kill(getpid(), SIGKILL); _exit(9); }
        if (!strcmp(mode, "short")) {
            write_all_fd(fds[1], &report, 7, "injected_write");
            _exit(0);
        }
        if (!strcmp(mode, "oversize")) {
            write_all_fd(fds[1], &report, sizeof(report), "injected_write");
            write_all_fd(fds[1], "x", 1, "injected_write");
            _exit(0);
        }
        fail("unknown_test_mode", 0, 0);
    }
    close(fds[1]);
    thread_group_child = child;
    thread_group_fd = fds[0];
    thread_group_wave = 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    config.profile = PROFILE_THREAD;
    config.seed = 123;
    config.run_id = 0x1020304050607080ull;
    config.workers = 2;
    config.contention_iterations = 5;
    config.churn_waves = 3;
    if (strcmp(argv[1], "ok")) seed_report_child(argv[1]);
    uint64_t ops = 0;
    for (uint64_t seq = 1; seq <= 6; seq++) run_round(seq, &ops);
    int status;
    errno = 0;
    pid_t child = waitpid(-1, &status, WNOHANG);
    if (child != -1 || errno != ECHILD) fail("leaked_child", errno, child);
    if (thread_group_child != -1 || thread_group_fd != -1) fail("leaked_group", 0, 0);
    if (ops != 72) fail("bad_total", 0, ops);
    return 0;
}
''', encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
             str(harness), "-o", str(cls.binary)],
            check=True, capture_output=True, text=True,
        )

    def run_case(self, mode):
        return subprocess.run([str(self.binary), mode], capture_output=True,
                              text=True, timeout=10)

    def test_two_groups_report_each_wave_and_release_children(self):
        result = self.run_case("ok")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rounds = [line for line in result.stdout.splitlines()
                  if line.startswith("NILIX_STRESS_V2_THREAD ")]
        self.assertEqual(len(rounds), 6, result.stdout)
        for seq, line in enumerate(rounds, 1):
            self.assertIn(f"seq={seq} ", line)
            self.assertIn(f"wave={(seq - 1) % 3} ", line)
            self.assertIn("created=2 joined=2", line)

    def test_abnormal_exit_after_partial_progress_emits_fail(self):
        for mode in ("exit7", "signal"):
            with self.subTest(mode=mode):
                result = self.run_case(mode)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("seq=2 workers=2 waves=3 wave=1", result.stdout)
                self.assertIn("NILIX_STRESS_V2_FAIL ", result.stdout)
                self.assertIn("stage=thread_child_exit", result.stdout)

    def test_short_report_is_rejected(self):
        result = self.run_case("short")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stage=thread_report_short", result.stdout)

    def test_extra_report_bytes_are_rejected(self):
        result = self.run_case("oversize")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stage=thread_report_oversized", result.stdout)


if __name__ == "__main__":
    unittest.main()
