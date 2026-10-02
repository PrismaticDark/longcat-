"""
tests/run_all_tests.py
~~~~~~~~~~~~~~~~~~~~~~
Unified zero-dependency test runner supporting both standard library unittest
and pytest. Discovers and runs all tests across the tests/ suite.

Execution:
    python tests/run_all_tests.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path for direct script execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_tests() -> int:
    print("=" * 75)
    print("LongCat Sentinel v2.3 Enterprise Final Hardened Edition — Test Runner")
    print("=" * 75)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(PROJECT_ROOT / "tests"), pattern="test_*.py", top_level_dir=str(PROJECT_ROOT))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 75)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("=" * 75)

    if result.wasSuccessful():
        print(">>> ALL TESTS PASSED SUCCESSFULLY (0 FAILURES, 0 ERRORS) <<<")
        return 0
    else:
        print(">>> TEST SUITE FAILED <<<")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
