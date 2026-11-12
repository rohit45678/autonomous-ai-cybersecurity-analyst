#!/usr/bin/env python3
"""Dependency-free test runner (the test modules are also pytest-compatible).

Usage: python tests/run_tests.py
"""

import importlib
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TEST_MODULES = ["test_triage", "test_investigation"]


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    passed = failed = 0
    for module_name in TEST_MODULES:
        module = importlib.import_module(module_name)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            test = getattr(module, name)
            try:
                test()
            except Exception:
                failed += 1
                print(f"FAIL {module_name}.{name}")
                traceback.print_exc()
            else:
                passed += 1
                print(f"PASS {module_name}.{name}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
