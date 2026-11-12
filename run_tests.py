"""
YemenScan Platform Test Runner
Executes the comprehensive unit and stage test suite.
"""
import os
import sys
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def run_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_modules = [
        "tests.test_subfinder_stage",
        "tests.test_naabu_stage",
        "tests.test_httpx_stage",
        "tests.test_kiterunner_stage",
        "tests.test_nuclei_stage",
        "tests.test_nuclei_wapiti_integration",
    ]

    for mod in test_modules:
        suite.addTests(loader.loadTestsFromName(mod))

    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    sys.exit(run_suite())
