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
REGISTRY = "src/events/mod.rs"


class EventSourceScope(unittest.TestCase):
    def test_a_source_with_its_registry_line_passes(self):
        found = guard.violations([("A", SOURCE), ("M", REGISTRY)], True, ["mod schedule_source;"])
        self.assertEqual(found, [])

    def test_a_source_that_edits_a_core_file_fails(self):
        found = guard.violations([("A", SOURCE), ("M", "src/events/fanout.rs")], True, [])
        self.assertEqual(found, ["src/events/fanout.rs: M (core file)"])

    def test_a_source_that_deletes_a_core_file_fails(self):
        found = guard.violations([("A", SOURCE), ("D", "src/events/rate.rs")], True, [])
        self.assertEqual(found, ["src/events/rate.rs: D (core file)"])

    def test_code_in_the_registry_fails(self):
        found = guard.violations(
            [("A", SOURCE), ("M", REGISTRY)], True, ["mod schedule_source;", "    pub charge: bool,"]
        )
        self.assertEqual(found, [f"{REGISTRY}: not a module declaration: pub charge: bool,"])

    def test_an_inline_module_in_the_registry_fails(self):
        found = guard.violations([("A", SOURCE), ("M", REGISTRY)], True, ["mod x { fn a() {} }"])
        self.assertEqual(len(found), 1)

    def test_a_restricted_public_declaration_passes(self):
        found = guard.violations([("A", SOURCE), ("M", REGISTRY)], True, ["pub(crate) mod schedule_source;"])
        self.assertEqual(found, [])

    def test_its_own_test_file_and_files_outside_events_pass(self):
        changes = [("A", SOURCE), ("A", "src/events/schedule_source_tests.rs"), ("M", "src/gateway/server/mod.rs")]
        self.assertEqual(guard.violations(changes, True, []), [])

    def test_a_change_adding_no_source_is_not_judged(self):
        self.assertIsNone(guard.violations([("M", "src/events/fanout.rs")], False, []))

    def test_a_source_added_inside_an_existing_core_file_fails(self):
        # No new file: the impl lands in a modified core file, which is itself the edit.
        found = guard.violations([("M", "src/events/task_source.rs")], True, [])
        self.assertEqual(found, ["src/events/task_source.rs: M (core file)"])

    def test_every_impl_spelling_counts_as_a_source(self):
        for line in [
            "impl EventSource for ScheduleSource {",
            "impl super::EventSource for X {}",
            "impl crate::events::EventSource for X {}",
            "impl<T: Send> EventSource for Watch<T> {",
        ]:
            self.assertTrue(guard.SOURCE_IMPL.search(line), line)

    def test_a_mention_is_not_a_source(self):
        for line in ["// implements EventSource for timers", "use super::EventSource;", "fn f(s: &dyn EventSource) {}"]:
            self.assertFalse(guard.SOURCE_IMPL.search(line), line)


if __name__ == "__main__":
    unittest.main()
