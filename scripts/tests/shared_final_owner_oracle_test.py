"""Host gate regression: old serial receipts cannot qualify the new SMP race."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "shared_final_owner_oracle",
    Path(__file__).resolve().parents[1] / "gates/boot/shared_final_owner_oracle.py",
)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class FinalOwnerOracleTest(unittest.TestCase):
    def serial(self, mode="release-window"):
        return (
            f"ST-K2-FINAL-OWNER PASS variant=process iterations=200 mode={mode}\n"
            "ST-K2-FINAL-OWNER PASS variant=nonlast-thread iterations=200\n"
        )

    def test_smp_requires_release_window(self):
        self.assertFalse(ORACLE.validate(self.serial(), 4, 200))
        self.assertTrue(ORACLE.validate(self.serial("sequential"), 4, 200))

    def test_up_is_explicitly_sequential(self):
        self.assertFalse(ORACLE.validate(self.serial("sequential"), 1, 200))
        self.assertTrue(ORACLE.validate(self.serial(), 1, 200))

    def test_old_receipts_are_rejected(self):
        old = "ST-K2-FINAL-OWNER PASS variant=process iterations=200\nST-K2-FINAL-OWNER PASS variant=thread iterations=200\n"
        self.assertTrue(ORACLE.validate(old, 4, 200))

    def test_missing_duplicate_and_wrong_iteration_fail(self):
        self.assertTrue(ORACLE.validate(self.serial().splitlines()[0], 4, 200))
        self.assertTrue(ORACLE.validate(self.serial() * 2, 4, 200))
        self.assertTrue(ORACLE.validate(self.serial(), 4, 300))


if __name__ == "__main__":
    unittest.main()
