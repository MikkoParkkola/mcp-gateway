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
from unittest import mock

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


class Discovery(unittest.TestCase):
    """F1: the checked file set is derived from the anchors' child-module
    directories, not from file-name prefixes, so a function in any new
    non-test child module cannot escape the inventory."""

    def setUp(self):
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        # The five anchor files, each with one accounted function.
        self.anchors = {
            "src/gateway/router/handlers.rs": "anchor_handlers",
            "src/gateway/meta_mcp/grant_audit.rs": "anchor_grant",
            "src/gateway/meta_mcp/call_dispatch.rs": "anchor_call",
            "src/gateway/meta_mcp/invoke.rs": "anchor_invoke",
            "src/gateway/server/mod.rs": "anchor_server",
        }
        for rel, fn in self.anchors.items():
            self.write(rel, f"fn {fn}() {{}}\n")
        self.harness = self.root / "harness.rs"
        self.harness.write_text(
            'const STAGES: &[(&str, bool, usize, usize)] = &[("row_a", true, 16, 1)];\n'
        )
        self.table = self.root / "stages.tsv"
        self.table.write_text(
            "".join(f"{rel}\t{fn}\trow_a\ton the path\n" for rel, fn in self.anchors.items())
        )

    def tearDown(self):
        self.dir.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_the_anchors_alone_are_clean(self):
        self.assertEqual(stages.check(self.root, self.table, self.harness), [])

    def test_a_table_split_across_two_parts_is_clean(self):
        items = list(self.anchors.items())
        part1 = self.root / "stages_part1.tsv"
        part2 = self.root / "stages_part2.tsv"
        part1.write_text("".join(f"{rel}\t{fn}\trow_a\ton the path\n" for rel, fn in items[:2]))
        part2.write_text("".join(f"{rel}\t{fn}\trow_a\ton the path\n" for rel, fn in items[2:]))
        self.assertEqual(stages.check(self.root, (part1, part2), self.harness), [])

    def test_a_function_in_a_new_stdio_child_module_is_reported_missing(self):
        self.write("src/gateway/server/stdio_newstage.rs", "fn new_stage() {}\n")
        self.assertIn("src/gateway/server/stdio_newstage.rs", stages.path_files(self.root))
        errors = stages.check(self.root, self.table, self.harness)
        self.assertTrue(any("new_stage" in e and "no entry" in e for e in errors), errors)

    def test_a_function_in_a_new_dispatch_child_module_is_reported_missing(self):
        self.write("src/gateway/router/handlers/dispatch_new.rs", "fn new_dispatch() {}\n")
        errors = stages.check(self.root, self.table, self.harness)
        self.assertTrue(any("new_dispatch" in e and "no entry" in e for e in errors), errors)

    def test_an_arbitrarily_named_server_child_is_reported_missing(self):
        # No family prefix on either name: both live under an anchor's
        # child directory, so both are checked the moment they land.
        self.write("src/gateway/server/new_stage.rs", "fn brand_new_stage() {}\n")
        self.write("src/gateway/server/background.rs", "fn background_work() {}\n")
        found = stages.path_files(self.root)
        self.assertIn("src/gateway/server/new_stage.rs", found)
        self.assertIn("src/gateway/server/background.rs", found)
        errors = stages.check(self.root, self.table, self.harness)
        self.assertTrue(any("brand_new_stage" in e and "no entry" in e for e in errors), errors)
        self.assertTrue(any("background_work" in e and "no entry" in e for e in errors), errors)

    def test_an_arbitrarily_named_invoke_child_is_reported_missing(self):
        self.write(
            "src/gateway/meta_mcp/invoke/budget_extension.rs",
            "fn record_more_budget() {}\n",
        )
        self.write("src/gateway/meta_mcp/invoke/budget.rs", "fn record_error_budget() {}\n")
        found = stages.path_files(self.root)
        self.assertIn("src/gateway/meta_mcp/invoke/budget_extension.rs", found)
        self.assertIn("src/gateway/meta_mcp/invoke/budget.rs", found)
        errors = stages.check(self.root, self.table, self.harness)
        self.assertTrue(any("record_more_budget" in e and "no entry" in e for e in errors), errors)
        self.assertTrue(any("record_error_budget" in e and "no entry" in e for e in errors), errors)

    def test_an_arbitrarily_named_grant_audit_child_is_reported_missing(self):
        self.write(
            "src/gateway/meta_mcp/grant_audit/extra_bookkeeping.rs",
            "fn extra_bookkeeping() {}\n",
        )
        errors = stages.check(self.root, self.table, self.harness)
        self.assertTrue(any("extra_bookkeeping" in e and "no entry" in e for e in errors), errors)

    def test_test_files_stay_out_of_scope(self):
        self.write("src/gateway/server/stdio_new_tests.rs", "fn in_a_test_file() {}\n")
        self.write("src/gateway/server/tests/stdio_new.rs", "fn in_a_tests_dir() {}\n")
        self.write("src/gateway/server/new_stage_tests.rs", "fn also_a_test_file() {}\n")
        self.write(
            "src/gateway/meta_mcp/invoke/budget_tests.rs", "fn in_an_invoke_test_file() {}\n"
        )
        self.write(
            "src/gateway/meta_mcp/invoke/tests/extra.rs", "fn in_an_invoke_tests_dir() {}\n"
        )
        self.assertEqual(stages.check(self.root, self.table, self.harness), [])


class TableParts(unittest.TestCase):
    """The authoritative table is two required parts: loading reads both,
    a missing part fails closed, and a key in both parts is rejected
    instead of the later part silently overwriting the earlier one."""

    def setUp(self):
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.part1 = self.root / "per_call_stages.tsv"
        self.part2 = self.root / "per_call_stages_stdio.tsv"
        self.part1.write_text("# part 1\na.rs\tf_a\trow_a\ton the path\n")
        self.part2.write_text("# part 2\nb.rs\tf_b\t-\toff the path\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_both_parts_are_loaded_in_the_given_order(self):
        rows = stages.table((self.part1, self.part2))
        self.assertEqual(
            rows,
            {("a.rs", "f_a"): ("row_a", "on the path"), ("b.rs", "f_b"): ("-", "off the path")},
        )
        self.assertEqual(list(rows), [("a.rs", "f_a"), ("b.rs", "f_b")])

    def test_a_single_custom_path_stays_a_single_file(self):
        self.assertEqual(stages.table(self.part1), {("a.rs", "f_a"): ("row_a", "on the path")})

    def test_a_missing_required_part_fails_closed(self):
        missing = self.root / "per_call_stages_missing.tsv"
        with self.assertRaises(SystemExit) as ctx:
            stages.table((self.part1, missing))
        self.assertIn(str(missing), str(ctx.exception))
        self.assertIn("required", str(ctx.exception))

    def test_the_default_inventory_requires_its_companion_part(self):
        missing = self.root / "per_call_stages_stdio.tsv.absent"
        with mock.patch.object(stages, "TABLE_STDIO", missing):
            with self.assertRaises(SystemExit) as ctx:
                stages.table()
        self.assertIn(str(missing), str(ctx.exception))

    def test_a_duplicate_entry_across_parts_is_rejected(self):
        self.part2.write_text("a.rs\tf_a\trow_b\ta second listing\n")
        with self.assertRaises(SystemExit) as ctx:
            stages.table((self.part1, self.part2))
        self.assertIn("duplicate entry for a.rs f_a", str(ctx.exception))
        self.assertIn(str(self.part1), str(ctx.exception))

    def test_a_duplicate_entry_within_one_part_is_rejected(self):
        self.part1.write_text("a.rs\tf_a\trow_a\ton the path\na.rs\tf_a\trow_b\tagain\n")
        with self.assertRaises(SystemExit) as ctx:
            stages.table(self.part1)
        self.assertIn("duplicate entry for a.rs f_a", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
