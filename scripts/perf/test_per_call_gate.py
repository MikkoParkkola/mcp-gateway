#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for per_call_gate.py's verdict rules (MIK-8014): a row whose null-arm
budget is above the ceiling is VOID, a head-base difference above the budget
is OVER, anything else PASS; a run that cannot measure is VOID, never FAIL."""

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


def decide(*verdicts):
    with contextlib.redirect_stdout(io.StringIO()):
        return gate.decide(list(verdicts))


class Decide(unittest.TestCase):
    def test_over_twice_fails(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "OVER"}), 1)

    def test_over_once_then_pass_passes(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "PASS"}), 0)

    def test_a_void_confirmation_is_void_not_pass(self):
        self.assertEqual(decide({"r": "OVER"}, {"r": "VOID"}), 2)

    def test_a_void_row_voids_the_run(self):
        self.assertEqual(decide({"a": "PASS", "b": "VOID"}), 2)

    def test_all_pass_passes(self):
        self.assertEqual(decide({"a": "PASS", "b": "PASS"}), 0)


class Errors(unittest.TestCase):
    def test_a_failed_command_is_void_not_fail(self):
        with self.assertRaises(gate.Void) as raised:
            gate.sh(["sh", "-c", "echo broken >&2; exit 101"])
        self.assertIn("broken", str(raised.exception))

    def test_a_hung_command_is_void(self):
        with self.assertRaises(gate.Void):
            gate.sh(["sleep", "5"], timeout=0.2)


if __name__ == "__main__":
    unittest.main()
