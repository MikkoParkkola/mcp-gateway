#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the event-source scope guard refuses (MIK-7720 U10).

The guard has no behaviour of its own to see red, so these synthetic diffs are
its red: a source change that edits a core file must fail.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-event-source-scope.py"
SPEC = importlib.util.spec_from_file_location("guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

SOURCE = "src/events/schedule_source.rs"
SOURCE_TEXT = "#[async_trait::async_trait]\nimpl EventSource for ScheduleSource {}\n"


class EventSourceScope(unittest.TestCase):
    def judge(self, changes, registry=(), text=None):
        added = {SOURCE: SOURCE_TEXT} if text is None else text
        return guard.violations(changes, added, list(registry))

    def test_a_source_with_its_registry_line_passes(self):
        found = self.judge([("A", SOURCE), ("M", "src/events/mod.rs")], ["mod schedule_source;"])
        self.assertEqual(found, [])

    def test_a_source_that_edits_a_core_file_fails(self):
        found = self.judge([("A", SOURCE), ("M", "src/events/fanout.rs")])
        self.assertEqual(found, ["src/events/fanout.rs: M (core file)"])

    def test_a_source_that_deletes_a_core_file_fails(self):
        found = self.judge([("A", SOURCE), ("D", "src/events/rate.rs")])
        self.assertEqual(found, ["src/events/rate.rs: D (core file)"])

    def test_code_in_the_registry_fails(self):
        found = self.judge(
            [("A", SOURCE), ("M", "src/events/mod.rs")],
            ["mod schedule_source;", "    pub charge: bool,"],
        )
        self.assertEqual(found, ["src/events/mod.rs: not a module declaration: pub charge: bool,"])

    def test_an_inline_module_in_the_registry_fails(self):
        found = self.judge([("A", SOURCE), ("M", "src/events/mod.rs")], ["mod x { fn a() {} }"])
        self.assertEqual(len(found), 1)

    def test_a_restricted_public_declaration_passes(self):
        found = self.judge([("A", SOURCE), ("M", "src/events/mod.rs")], ["pub(crate) mod schedule_source;"])
        self.assertEqual(found, [])

    def test_its_own_test_file_and_files_outside_events_pass(self):
        found = self.judge(
            [("A", SOURCE), ("A", "src/events/schedule_source_tests.rs"), ("M", "src/gateway/server/mod.rs")]
        )
        self.assertEqual(found, [])

    def test_a_change_adding_no_source_is_not_judged(self):
        found = self.judge([("M", "src/events/fanout.rs")], text={})
        self.assertIsNone(found)

    def test_an_added_helper_without_an_impl_is_not_a_source(self):
        found = self.judge(
            [("A", "src/events/helper.rs"), ("M", "src/events/fanout.rs")],
            text={"src/events/helper.rs": "fn helper() {}\n"},
        )
        self.assertIsNone(found)

    def test_a_qualified_impl_counts_as_a_source(self):
        found = self.judge(
            [("A", SOURCE), ("M", "src/events/worker.rs")],
            text={SOURCE: "impl super::EventSource for X {}\n"},
        )
        self.assertEqual(found, ["src/events/worker.rs: M (core file)"])


if __name__ == "__main__":
    unittest.main()
