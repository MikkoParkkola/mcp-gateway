#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what the event-source scope guard refuses (MIK-7720 U10).

The guard has no behaviour of its own to see red, so these synthetic diffs are
its red: a source change that edits a core file must fail.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "check-event-source-scope.py"
SPEC = importlib.util.spec_from_file_location("guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

SOURCE = "src/events/schedule_source.rs"
REGISTRY = "src/events/mod.rs"


class EventSourceScope(unittest.TestCase):
    def judge(self, changes, added=(), removed=(), source=True):
        return guard.violations(changes, source, list(added), list(removed))

    def test_a_source_with_its_registry_line_passes(self):
        found = self.judge([("A", SOURCE), ("M", REGISTRY)], ["mod schedule_source;"])
        self.assertEqual(found, [])

    def test_a_source_that_edits_a_core_file_fails(self):
        found = self.judge([("A", SOURCE), ("M", "src/events/fanout.rs")])
        self.assertEqual(found, ["src/events/fanout.rs: M (core file)"])

    def test_a_source_that_deletes_a_core_file_fails(self):
        found = self.judge([("A", SOURCE), ("D", "src/events/rate.rs")])
        self.assertEqual(found, ["src/events/rate.rs: D (core file)"])

    def test_code_in_the_registry_fails(self):
        found = self.judge([("A", SOURCE), ("M", REGISTRY)], ["mod schedule_source;", "    pub charge: bool,"])
        self.assertEqual(found, [f"{REGISTRY}: not a module declaration: pub charge: bool,"])

    def test_an_inline_module_in_the_registry_fails(self):
        found = self.judge([("A", SOURCE), ("M", REGISTRY)], ["mod x { fn a() {} }"])
        self.assertEqual(len(found), 1)

    def test_a_restricted_public_declaration_of_the_new_module_passes(self):
        found = self.judge([("A", SOURCE), ("M", REGISTRY)], ["pub(crate) mod schedule_source;"])
        self.assertEqual(found, [])

    def test_widening_an_existing_declaration_fails(self):
        found = self.judge([("A", SOURCE), ("M", REGISTRY)], ["pub(crate) mod limiter;"], ["mod limiter;"])
        self.assertEqual(
            found,
            [
                f"{REGISTRY}: existing line changed: mod limiter;",
                f"{REGISTRY}: declares a module this change does not add: pub(crate) mod limiter;",
            ],
        )

    def test_its_own_test_file_and_files_outside_events_pass(self):
        changes = [("A", SOURCE), ("A", "src/events/schedule_source_tests.rs"), ("M", "src/gateway/server/mod.rs")]
        self.assertEqual(self.judge(changes), [])

    def test_a_change_adding_no_source_is_not_judged(self):
        self.assertIsNone(self.judge([("M", "src/events/fanout.rs")], source=False))

    def test_a_source_added_inside_an_existing_core_file_fails(self):
        # No new file: the impl lands in a modified core file, which is itself the edit.
        found = self.judge([("M", "src/events/task_source.rs")])
        self.assertEqual(found, ["src/events/task_source.rs: M (core file)"])

    def test_a_source_impl_anywhere_outside_tests_counts(self):
        impl = "impl EventSource for Sneak {}\n"
        self.assertTrue(guard.adds_source([("src/events/fanout.rs", "fn f() {}\n", "fn f() {}\n" + impl)]))
        self.assertTrue(guard.adds_source([("src/gateway/x.rs", "", impl)]))

    def test_swapping_one_impl_for_another_is_a_new_source(self):
        before, after = "impl EventSource for Old {}\n", "impl EventSource for New {}\n"
        self.assertTrue(guard.adds_source([("src/events/a.rs", before, after)]))

    def test_moving_an_impl_between_files_is_not_a_new_source(self):
        impl = "impl EventSource for X {}\n"
        self.assertFalse(guard.adds_source([("src/events/a.rs", impl, ""), ("src/events/b.rs", "", impl)]))

    def test_a_new_source_named_like_one_in_another_file_is_seen(self):
        impl = "impl EventSource for X {}\n"
        self.assertTrue(guard.adds_source([("src/events/a.rs", impl, impl), ("src/events/b.rs", "", impl)]))

    def test_a_second_inline_module_impl_of_the_same_name_is_seen(self):
        one = "mod a { impl EventSource for X {} }\n"
        two = one + "mod b { impl EventSource for X {} }\n"
        self.assertTrue(guard.adds_source([("src/events/a.rs", one, two)]))

    def test_splitting_same_named_impls_across_files_is_not_a_new_source(self):
        a = "mod a { impl EventSource for X {} }\n"
        b = "mod b { impl EventSource for X {} }\n"
        self.assertFalse(guard.adds_source([("src/events/a.rs", a + b, a), ("src/events/b.rs", "", b)]))

    def test_an_alias_declared_in_another_file_is_followed(self):
        self.assertTrue(guard.adds_source([("src/events/a.rs", "", "impl Src for X {}\n")], {"Src"}))
        self.assertEqual(guard.aliases(["pub(crate) use super::EventSource as Src;"]), {"Src"})

    def test_a_moved_impl_is_not_a_new_source(self):
        impl = "impl EventSource for X {}\n"
        self.assertFalse(guard.adds_source([("src/events/a.rs", impl, "// moved\n" + impl)]))

    def test_a_test_mock_or_a_comment_is_not_a_source(self):
        # A core fix whose test mocks a source must not be judged as adding one.
        mock = "impl EventSource for Mock {}\n"
        self.assertFalse(guard.adds_source([("src/events/sources_tests.rs", "", mock)]))
        self.assertFalse(guard.adds_source([("tests/mik_7630_events_sources.rs", "", mock)]))
        self.assertFalse(guard.adds_source([("src/events/fanout.rs", "", "// impl EventSource for X {}\n")]))

    def test_every_impl_spelling_counts_as_a_source(self):
        for text in [
            "impl EventSource for ScheduleSource {",
            "impl super::EventSource for X {}",
            "impl crate::events::EventSource for X {}",
            "impl<T: Send> EventSource for Watch<T> {",
            "impl\n    EventSource\n    for X {}",
            "impl<T>\n    super::EventSource for W<T>\nwhere\n    T: Send,\n{}",
            "use super::EventSource as Src;\nimpl Src for X {}",
            "impl EventSource /* producer */ for X {}",
            "impl /* a\nb */ EventSource for X {}",
        ]:
            self.assertEqual(guard.impl_count(text), 1, text)

    def test_a_mention_is_not_a_source(self):
        for text in [
            "// implements EventSource for timers",
            "use super::EventSource;",
            "fn f(s: &dyn EventSource) {}",
            "impl Other for X { fn f(s: &dyn EventSource) {} }",
            "/* impl EventSource for X {} */",
        ]:
            self.assertEqual(guard.impl_count(text), 0, text)

    def test_the_cli_fails_a_real_commit_that_edits_the_core(self):
        # The plumbing too: base...HEAD span, name-status and line parsing, exit code.
        with TemporaryDirectory() as root:
            def run(*args):
                subprocess.run(["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args], cwd=root, check=True, capture_output=True)

            run("init", "-q", "-b", "base")
            events = Path(root, "src/events")
            events.mkdir(parents=True)
            (events / "mod.rs").write_text("mod fanout;\n")
            (events / "fanout.rs").write_text("fn f() {}\n")
            run("add", ".")
            run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
            run("checkout", "-qb", "head")
            (events / "x_source.rs").write_text("impl EventSource for X {}\n")
            (events / "mod.rs").write_text("mod fanout;\nmod x_source;\n")
            run("add", ".")
            run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "source")
            self.assertEqual(self.cli(root), 0)
            (events / "fanout.rs").write_text("fn f() {}\nfn g() {}\n")
            run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "core")
            self.assertEqual(self.cli(root), 1)

    def cli(self, root):
        here = os.getcwd()
        os.chdir(root)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return guard.main(["guard", "base"])
        finally:
            os.chdir(here)


if __name__ == "__main__":
    unittest.main()
