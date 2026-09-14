"""Unified Test Runner for Trac-I Phishing Intelligence Platform."""
import os
import sys
import unittest

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, root_dir)
    print("=" * 70)
    print("TRAC-I AUTOMATED TEST SUITE: SECURITY, PIPELINE & ML VERIFICATION")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(root_dir, "tests"), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 70)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)

    if not result.wasSuccessful():
        sys.exit(1)
    print("ALL TESTS PASSED SUCCESSFULLY.")

if __name__ == "__main__":
    main()
