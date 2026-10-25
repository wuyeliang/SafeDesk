#!/usr/bin/env python3
"""Check the intentionally failing Codex task without a model or API key.

Run from the repository root: python3 demos/tools/check_codex_fixture.py
This checks fixture integrity only, not Codex execution or key injection.
"""
from pathlib import Path
import sys
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / "codex-key-injection" / "fixture"
PASSING_TESTS = {"test_empty_cart", "test_single_item", "test_zero_price"}


def main():
    suite = unittest.defaultTestLoader.discover(str(FIXTURE), pattern="test_pricing.py")
    expected_ids = {test.id() for group in suite for tests in group for test in tests}
    expected_failures = {
        test_id
        for test_id in expected_ids
        if test_id.rsplit(".", 1)[-1] not in PASSING_TESTS
    }
    result = unittest.TestResult()
    suite.run(result)
    # Subtests append parameters to the parent method's ID.
    failures = {test.id().split(" (", 1)[0] for test, _ in result.failures}
    if (
        result.testsRun != 18
        or result.errors
        or result.skipped
        or result.expectedFailures
        or result.unexpectedSuccesses
        or len(result.failures) != 23
        or failures != expected_failures
    ):
        print("FAIL: Codex fixture no longer has the expected failure baseline.")
        print(
            f"tests={result.testsRun}, failed_methods={len(failures)}, "
            f"errors={len(result.errors)}, skipped={len(result.skipped)}"
        )
        print("Run the fixture's unittest command for details.")
        return 1
    print("PASS: 18 tests; 3 pass, 15 methods fail as intended.")
    print(f"unittest failure assertions (including subtests): {len(result.failures)}")
    print("Codex execution and API key injection: NOT TESTED.")
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
