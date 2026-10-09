#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_per_call_stages.py (MIK-8014): only an inline test
module's body leaves the check; a function after a test module stays in it."""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stages", HERE / "check_per_call_stages.py")
stages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stages)


def fns(source):
    return re.findall(r"\bfn ([a-z_][a-z0-9_]*)", stages.without_test_modules(source))


class WithoutTestModules(unittest.TestCase):
    def test_an_inline_module_at_the_end_is_removed(self):
        self.assertEqual(fns("fn a(){}\n#[cfg(test)]\nmod tests {\nfn b(){ if x { } }\n}\n"), ["a"])

    def test_a_mounted_module_mid_file_keeps_what_follows(self):
        src = 'fn a(){}\n#[cfg(test)]\n#[path = "x.rs"]\nmod t;\nfn c(){}\n'
        self.assertEqual(fns(src), ["a", "c"])

    def test_an_inline_module_mid_file_keeps_what_follows(self):
        self.assertEqual(fns("fn a(){}\n#[cfg(test)]\nmod t {\n fn h(){}\n}\nfn d(){}\n"), ["a", "d"])

    def test_a_cfg_all_test_module_is_removed(self):
        self.assertEqual(fns("fn a(){}\n#[cfg(all(test, x))]\nmod t { fn h(){} }\nfn e(){}\n"), ["a", "e"])


if __name__ == "__main__":
    unittest.main()
