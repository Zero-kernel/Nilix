"""Exercise the real guest's recovery checks against stale and torn disk slots."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BlockRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc")
        if compiler is None:
            raise RuntimeError("cc is required for the block recovery regression tests")
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        cls.binary = cls.directory / "block-records"
        harness = cls.directory / "harness.c"
        harness.write_text(
            '#define main stress_guest_main\n'
            f'#include "{ROOT / "userspace/stress_runner.c"}"\n'
            '#undef main\n' + r'''
static void replace_slot(uint64_t generation, int torn) {
    uint8_t record[PAGE_BYTES];
    block_build_record(record, generation);
    if (torn) record[100] ^= 1;
    const off_t offset = (generation % config.io_slots) * PAGE_BYTES;
    if (pwrite(block_fd, record, PAGE_BYTES, offset) != PAGE_BYTES) exit(2);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    config.run_id = 0x12345678;
    config.seed = 17;
    config.io_slots = 12;
    block_fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (block_fd < 0) return 2;
    for (uint64_t g = 1; g <= 25; ++g) block_commit(g);
    if (strcmp(argv[2], "stale") == 0) replace_slot(3, 0);
    if (strcmp(argv[2], "stale-next") == 0) replace_slot(2, 0);
    if (strcmp(argv[2], "torn-next") == 0) replace_slot(26, 1);
    if (strcmp(argv[2], "torn-older") == 0) replace_slot(15, 1);
    block_recover();
    if (strcmp(argv[2], "stale-after-recovery") == 0) replace_slot(3, 0);
    uint64_t ops = 0;
    block_recovery_round(1, &ops);
    return close(block_fd) == 0 ? 0 : 2;
}
''', encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
             str(harness), "-o", str(cls.binary)],
            check=True, capture_output=True, text=True,
        )

    def run_case(self, mode, failure=None):
        result = subprocess.run(
            [str(self.binary), str(self.directory / "records.bin"), mode],
            capture_output=True, text=True, timeout=10,
        )
        if failure is None:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("generation=26 valid_slots=12", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn(f"stage={failure}", result.stdout)

    def test_complete_rotation_survives_recovery(self):
        self.run_case("clean")

    def test_stale_sealed_slot_is_not_a_durable_commit(self):
        self.run_case("stale", "block_stale_record")

    def test_successor_write_must_not_hide_a_stale_slot(self):
        self.run_case("stale-next", "block_stale_record")

    def test_single_inflight_torn_slot_can_be_repaired(self):
        self.run_case("torn-next")

    def test_torn_committed_slot_is_rejected_before_repair(self):
        self.run_case("torn-older", "block_lost_record")

    def test_soak_detects_stale_data_after_recovery(self):
        self.run_case("stale-after-recovery", "block_stale_record")


if __name__ == "__main__":
    unittest.main()
