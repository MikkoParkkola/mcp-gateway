#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/required_mode.py: the one rule that says whether a test that cannot run on this host must fail.

TESTS_REQUIRE_ALL: unset -> decided by CI (true in any case, or 1, means required); 0 -> not required, whatever CI says;
1 -> required; any other value is an error naming it. Standard library only.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import required_mode  # noqa: E402


class Rows(unittest.TestCase):
    def test_d5_the_truth_table(self) -> None:
        table = [
            ({}, False),  # unset, no CI: skip
            ({"CI": "false"}, False),
            ({"CI": ""}, False),
            ({"CI": "true"}, True),
            ({"CI": "TRUE"}, True),
            ({"CI": "1"}, True),
            ({"TESTS_REQUIRE_ALL": "0", "CI": "true"}, False),  # explicit 0 beats CI
            ({"TESTS_REQUIRE_ALL": "1"}, True),
            ({"TESTS_REQUIRE_ALL": "1", "CI": "false"}, True),
        ]
        for env, want in table:
            self.assertEqual(required_mode.required(env), want, env)

    def test_d5_any_other_value_is_an_error_naming_it(self) -> None:
        for bad in ("banana", "yes", "", " 1"):
            with self.assertRaises(ValueError) as err:
                required_mode.required({"TESTS_REQUIRE_ALL": bad})
            self.assertIn(repr(bad), str(err.exception))

    def test_d5_fail_or_skip_fails_where_required_and_skips_elsewhere(self) -> None:
        class T(unittest.TestCase):
            def runTest(self) -> None:
                pass

        case = T()
        with self.assertRaises(AssertionError) as err:
            required_mode.skip_or_fail(case, "the uv tool", {"TESTS_REQUIRE_ALL": "1"})
        self.assertIn("required here but unavailable on this host: the uv tool", str(err.exception))
        with self.assertRaises(unittest.SkipTest):
            required_mode.skip_or_fail(case, "the uv tool", {})


if __name__ == "__main__":
    unittest.main()
