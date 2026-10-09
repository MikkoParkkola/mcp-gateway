#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for per_call_gate.py's verdict rules (MIK-8014): a row whose null-arm
budget is above the ceiling is VOID, a head-base difference above the budget
is OVER, anything else PASS."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "per_call_gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def judge(budget, delta):
    with contextlib.redirect_stdout(io.StringIO()):
        return gate.judge(budget, delta)


class Judge(unittest.TestCase):
    def test_within_budget_passes(self):
        self.assertEqual(judge({"r": 900}, {"r": 900}), {"r": "PASS"})

    def test_over_budget_is_over(self):
        self.assertEqual(judge({"r": 900}, {"r": 901}), {"r": "OVER"})

    def test_a_faster_head_passes(self):
        self.assertEqual(judge({"r": 900}, {"r": -5000}), {"r": "PASS"})

    def test_a_budget_above_the_ceiling_is_void_even_when_within(self):
        budget = gate.CEILING_NS + 1
        self.assertEqual(judge({"r": budget}, {"r": 0}), {"r": "VOID"})

    def test_a_budget_at_the_ceiling_still_judges(self):
        budget = gate.CEILING_NS
        self.assertEqual(judge({"r": budget}, {"r": budget + 1}), {"r": "OVER"})

    def test_each_row_is_judged_on_its_own_budget(self):
        verdict = judge({"a": 100, "b": 5000}, {"a": 50, "b": 50})
        self.assertEqual(verdict, {"a": "PASS", "b": "VOID"})


if __name__ == "__main__":
    unittest.main()
