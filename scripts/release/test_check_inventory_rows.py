#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_inventory_rows.py: each case is a throwaway git repository
with one base commit and one change, and the check must return the stated
verdict. Two cases pin bugs the first drafts had."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rows", HERE / "check_inventory_rows.py")
rows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rows)

HEADER = "path\tfn\toccurrence\ttier\tcategory\tname\treason\n"


class Repo:
    def __init__(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.git("init", "-q", "-b", "base")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.write(rows.INVENTORY, HEADER)
        self.write("src/oauth/mod.rs", "pub fn existing() {}\n")
        self.commit("base")
        self.git("checkout", "-q", "-b", "change")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True
        ).stdout

    def write(self, path: str, text: str) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def missing(self) -> list[str]:
        rows.ROOT = self.root
        return sorted(name for _, name, _, _ in rows.missing_rows("base", "HEAD"))


class CheckInventoryRows(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.dir.cleanup)

    def test_an_added_function_without_a_row_fails(self) -> None:
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn check_token() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["check_token"])

    def test_a_row_in_either_file_passes(self) -> None:
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn a() {}\nfn b() {}\n")
        self.repo.write(rows.INVENTORY, HEADER + "src/oauth/mod.rs\ta\t1\tcritical\tb\ta\tr\n")
        self.repo.write(rows.UNENFORCING, "src/oauth/mod.rs\tb\t1\tformats a message\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_a_function_off_the_seven_paths_needs_no_row(self) -> None:
        self.repo.write("src/cli/mod.rs", "fn anything() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_functions_in_a_test_module_or_test_file_need_no_row(self) -> None:
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\n#[cfg(test)]\nmod tests {\n    fn helper() {}\n}\n",
        )
        self.repo.write("src/oauth/x_tests.rs", "fn case() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_a_file_declared_only_for_tests_needs_no_row(self) -> None:
        # Declared by `#[path]` under cfg(test), and from a test file in turn.
        self.repo.write(
            "src/oauth/mod.rs",
            'pub fn existing() {}\n#[cfg(test)]\n#[path = "shape_cases.rs"]\nmod cases;\n',
        )
        self.repo.write("src/oauth/shape_cases.rs", '#[path = "shape_rows.rs"]\nmod rows;\nfn a() {}\n')
        self.repo.write("src/oauth/shape_rows.rs", "fn b() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_a_cfg_test_on_the_item_above_does_not_hide_a_module(self) -> None:
        # The second draft read the three lines above a declaration and took
        # another item's attribute for this one's.
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\n#[cfg(test)]\nmod tests;\nmod store;\n",
        )
        self.repo.write("src/oauth/tests.rs", "fn t() {}\n")
        self.repo.write("src/oauth/store.rs", "pub fn refuse() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["refuse"])

    def test_a_same_named_function_needs_its_own_row(self) -> None:
        # The first draft matched on file and name, so a second `visit_map`
        # beside an inventoried one passed unseen.
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\nimpl A {\n    fn visit(&self) {}\n}\nimpl B {\n    fn visit(&self) {}\n}\n",
        )
        self.repo.write(rows.INVENTORY, HEADER + "src/oauth/mod.rs\tvisit\t1\tcritical\td\tA::visit\tr\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["visit"])

    def test_a_bodyless_trait_declaration_needs_no_row(self) -> None:
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\npub trait Caller {\n    fn adopt(&self) -> u8;\n}\n",
        )
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_a_multiline_trait_declaration_needs_no_row(self) -> None:
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\npub trait Caller {\n    fn adopt(\n        &self,\n    ) -> u8;\n}\n",
        )
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), [])

    def test_a_semicolon_in_an_array_return_type_is_not_a_declaration(self) -> None:
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn key(\n) -> [u8; 16] {\n    [0; 16]\n}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["key"])

    def test_cfg_all_with_test_is_test_only_and_not_test_is_not(self) -> None:
        self.repo.write(
            "src/oauth/mod.rs",
            "pub fn existing() {}\n#[cfg(all(unix, test))]\nfn probe() {}\n"
            "#[cfg(all(unix, not(test)))]\nfn live() {}\n"
            "#[cfg(all(unix, any(test, debug_assertions)))]\nfn debug() {}\n"
            "#[cfg(all(unix, not(all(test, windows))))]\nfn nested() {}\n",
        )
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["debug", "live", "nested"])

    def test_an_extern_function_is_seen(self) -> None:
        self.repo.write("src/oauth/mod.rs", 'pub fn existing() {}\npub extern "C" fn hook() {}\n')
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["hook"])

    def test_an_unenforcing_row_without_a_reason_does_not_count(self) -> None:
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn a() {}\nfn b() {}\n")
        self.repo.write(rows.UNENFORCING, "src/oauth/mod.rs\ta\t1\t\nsrc/oauth/mod.rs\tb\t1\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["a", "b"])

    def test_the_whole_tree_mode_sees_a_function_older_than_the_change(self) -> None:
        # MIK-8195: `existing` came in with the base, so the diff check never
        # sees it; the whole-tree mode does, and a row satisfies it.
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn added() {}\n")
        self.repo.commit("add")
        rows.ROOT = self.repo.root
        self.addCleanup(setattr, rows, "SWEPT_AREAS", rows.SWEPT_AREAS)
        rows.SWEPT_AREAS = ("src/cli/",)
        self.assertEqual(rows.missing_rows(rows.ALL, "HEAD"), [], "an unswept area is not enforced yet")
        rows.SWEPT_AREAS = ("src/oauth/",)
        self.assertEqual(sorted(f[1] for f in rows.missing_rows(rows.ALL, "HEAD")), ["added", "existing"])
        self.repo.write(rows.UNENFORCING, "src/oauth/mod.rs\texisting\t1\tr\nsrc/oauth/mod.rs\tadded\t1\tr\n")
        self.repo.commit("rows")
        self.assertEqual(rows.missing_rows(rows.ALL, "HEAD"), [])

    def test_a_private_top_level_function_is_seen(self) -> None:
        # The wave-4 sweep's pattern missed `fn` with nothing before it.
        self.repo.write("src/oauth/mod.rs", "pub fn existing() {}\nfn helper() {}\n")
        self.repo.commit("add")
        self.assertEqual(self.repo.missing(), ["helper"])


class CoverageGradeTrigger(unittest.TestCase):
    """The CI grade's pull_request paths name exactly the COV.3 prefixes
    (MIK-8217): a prefix missing there lets a PR on that path merge ungraded.
    A GitHub `*` does not cross `/`, so a bare stem needs both its file and
    its directory form."""

    def test_the_pull_request_paths_cover_every_cov3_prefix(self) -> None:
        text = (HERE.parent.parent / ".github/workflows/coverage-probe.yml").read_text()
        block = text.split("  pull_request:", 1)[1].split("  workflow_dispatch:", 1)[0]
        listed = {line.strip()[3:-1] for line in block.splitlines()
                  if line.strip().startswith('- "')}
        wanted = set()
        for prefix in rows.PREFIXES:
            if prefix.endswith("/"):
                wanted.add(prefix + "**")
            elif prefix.endswith(".rs"):
                wanted.add(prefix)
            else:
                wanted |= {prefix + ".rs", prefix + "/**"}
        # What the grade itself reads: a change to any of these is graded too.
        wanted |= {
            "docs/release/v4.0.0-critical-functions.tsv",
            "docs/release/v4.0.0-unenforcing-functions.tsv",
            "scripts/release/critical_function_coverage.py",
            "scripts/release/critical_path_coverage.py",
            ".github/workflows/coverage-probe.yml",
        }
        self.assertEqual(listed, wanted)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
