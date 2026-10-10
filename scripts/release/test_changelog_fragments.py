#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for changelog_fragments.py: assembly output and the PR check."""

import contextlib
import importlib.util
import io
import os
import pathlib
import subprocess
import tempfile
import unittest

_SPEC = importlib.util.spec_from_file_location(
    "changelog_fragments", pathlib.Path(__file__).with_name("changelog_fragments.py")
)
cf = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cf)

CHANGELOG = """# Changelog

## [Unreleased]

<!-- note -->

### Highlights

Prose.

### Added

- existing added (#1)

### Fixed

- existing fix (#2)

## [1.0.0] - 2026-01-01

### Added

- old (#0)
"""

EXPECTED = """# Changelog

## [Unreleased]

<!-- note -->

### Highlights

Prose.

### Added

- existing added (#1)
- new feature (#9)
- second feature
  wrapped line (#10)

### Fixed

- existing fix (#2)
- a fix (#11)

### Security

- a hardening (#12)

## [1.0.0] - 2026-01-01

### Added

- old (#0)
"""


class Assemble(unittest.TestCase):
    def test_fragments_land_in_their_subsections_in_number_order(self):
        fragments = {
            "10.added.md": "- second feature\n  wrapped line (#10)\n",
            "9.added.md": "- new feature (#9)\n",
            "11.fixed.md": "- a fix (#11)\n",
            "12.security.md": "- a hardening (#12)\n",
        }
        self.assertEqual(cf.assemble(CHANGELOG, fragments), EXPECTED)

    def test_no_fragments_changes_nothing(self):
        self.assertEqual(cf.assemble(CHANGELOG, {}), CHANGELOG)
        # Right after a release there may be no Unreleased heading yet.
        released = CHANGELOG.replace("## [Unreleased]", "## [1.1.0] - 2026-02-01")
        self.assertEqual(cf.assemble(released, {}), released)

    def test_an_empty_subsection_keeps_its_blank_line(self):
        text = "## [Unreleased]\n\n### Added\n\n### Fixed\n\n- f\n\n## [1]\n"
        got = cf.assemble(text, {"3.added.md": "- a\n"})
        self.assertEqual(got, "## [Unreleased]\n\n### Added\n\n- a\n\n### Fixed\n\n- f\n\n## [1]\n")

    def test_a_missing_subsection_is_created_in_order(self):
        got = cf.assemble(CHANGELOG, {"4.changed.md": "- c (#4)\n"})
        self.assertIn("- existing added (#1)\n\n### Changed\n\n- c (#4)\n\n### Fixed", got)

    def test_fragments_after_a_release_open_a_new_unreleased_section(self):
        released = "# Changelog\n\n## [1.1.0] - 2026-02-01\n\n- x\n"
        got = cf.assemble(released, {"5.fixed.md": "- y (#5)\n"})
        self.assertEqual(got, "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- y (#5)\n\n## [1.1.0] - 2026-02-01\n\n- x\n")

    def test_released_sections_are_untouched(self):
        got = cf.assemble(CHANGELOG, {"9.removed.md": "- gone (#9)\n"})
        self.assertTrue(got.endswith("## [1.0.0] - 2026-01-01\n\n### Added\n\n- old (#0)\n"))
        self.assertIn("### Removed\n\n- gone (#9)\n\n### Fixed", got)


class Check(unittest.TestCase):
    def test_src_change_without_fragment_fails(self):
        errors = cf.check([("M", "src/lib.rs")], set())
        self.assertEqual(len(errors), 1)
        self.assertIn("adds no changelog.d", errors[0])

    def test_src_change_with_fragment_passes(self):
        self.assertEqual(cf.check([("M", "src/lib.rs"), ("A", "changelog.d/42.fixed.md")], set()), [])

    def test_label_waives_the_fragment(self):
        self.assertEqual(cf.check([("M", "src/lib.rs")], {"no-changelog"}), [])

    def test_change_outside_src_needs_no_fragment(self):
        self.assertEqual(cf.check([("M", "docs/x.md")], set()), [])

    def test_misnamed_fragment_fails_even_with_label(self):
        errors = cf.check([("A", "changelog.d/fix.md")], {"no-changelog"})
        self.assertEqual(len(errors), 1)
        self.assertIn("changelog.d/fix.md", errors[0])

    def test_a_workspace_crate_counts_as_source(self):
        self.assertEqual(len(cf.check([("M", "crates/gateway-core/src/lib.rs")], set())), 1)

    def test_shipped_files_outside_src_count_as_source(self):
        for path in (
            "Dockerfile",
            "Dockerfile.full",
            ".github/workflows/docker.yml",
            ".github/workflows/docker-full.yaml",
            "capabilities/search/brave.yaml",
            "server.json",
            "npm/package.json",
        ):
            with self.subTest(path=path):
                self.assertEqual(len(cf.check([("M", path)], set())), 1)

    def test_a_path_under_a_dockerfile_named_directory_is_not_source(self):
        self.assertEqual(cf.check([("M", "Dockerfile.d/notes.md")], set()), [])

    def test_other_workflows_need_no_fragment(self):
        self.assertEqual(cf.check([("M", ".github/workflows/ci.yml")], set()), [])

    def test_a_hand_edit_of_the_changelog_fails(self):
        errors = cf.check([("M", "CHANGELOG.md"), ("A", "changelog.d/5.fixed.md")], set())
        self.assertEqual(len(errors), 1)
        self.assertIn("edits CHANGELOG.md", errors[0])

    def test_the_release_fold_may_edit_the_changelog(self):
        self.assertEqual(cf.check([("M", "CHANGELOG.md"), ("D", "changelog.d/5.fixed.md")], set()), [])

    def test_a_partial_fold_may_not_edit_the_changelog(self):
        changes = [("M", "CHANGELOG.md"), ("D", "changelog.d/5.fixed.md")]
        errors = cf.check(changes, set(), ["6.added.md", ".gitkeep"])
        self.assertTrue(any("edits CHANGELOG.md" in e for e in errors), errors)
        self.assertTrue(any("without folding" in e for e in errors), errors)

    def test_deleting_the_placeholder_is_not_a_release_fold(self):
        self.assertEqual(len(cf.check([("M", "CHANGELOG.md"), ("D", "changelog.d/.gitkeep")], set())), 1)

    def test_editing_an_existing_fragment_does_not_count_as_adding_one(self):
        self.assertEqual(len(cf.check([("M", "src/a.rs"), ("M", "changelog.d/1.fixed.md")], set())), 1)

    def test_deleting_a_fragment_does_not_count_as_adding_one(self):
        errors = cf.check([("M", "src/a.rs"), ("D", "changelog.d/1.fixed.md")], set())
        self.assertTrue(any("adds no changelog.d" in e for e in errors))

    def test_deleting_a_fragment_outside_a_fold_fails(self):
        errors = cf.check([("D", "changelog.d/1.fixed.md")], set())
        self.assertEqual(len(errors), 1)
        self.assertIn("without folding", errors[0])

    def test_retyping_a_fragment_under_its_own_number_passes(self):
        changes = [("D", "changelog.d/1.fixed.md"), ("A", "changelog.d/1.security.md")]
        self.assertEqual(cf.check(changes, set()), [])

    def test_a_delete_beside_another_numbers_add_still_fails(self):
        changes = [("D", "changelog.d/1.fixed.md"), ("A", "changelog.d/2.security.md")]
        errors = cf.check(changes, set())
        self.assertEqual(len(errors), 1)
        self.assertIn("changelog.d/1.fixed.md", errors[0])

    def test_one_add_exempts_one_delete_of_its_number(self):
        # MIK-7946 finding 2: two entries under one number retyped into one
        # loses the other; a retype pairs one deletion with one addition.
        changes = [
            ("D", "changelog.d/2081.changed.md"),
            ("D", "changelog.d/2081.fixed.md"),
            ("A", "changelog.d/2081.security.md"),
        ]
        errors = cf.check(changes, set())
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("without folding", errors[0])
        # Control: two retyped under two additions pass.
        changes.append(("A", "changelog.d/2081.added.md"))
        self.assertEqual(cf.check(changes, set()), [])

    def test_a_retype_is_not_the_new_entry_a_shipped_change_needs(self):
        # MIK-7946 finding 3: the add half of a retype replaces an old entry.
        changes = [
            ("M", "src/a.rs"),
            ("D", "changelog.d/1.fixed.md"),
            ("A", "changelog.d/1.security.md"),
        ]
        errors = cf.check(changes, set())
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("adds no changelog.d", errors[0])
        # Control: a new fragment beside the retype satisfies it.
        changes.append(("A", "changelog.d/3.fixed.md"))
        self.assertEqual(cf.check(changes, set()), [])


class CheckAgainstGit(unittest.TestCase):
    """`check` end to end: the git diff, the fragment listing and labels."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.saved = cf.ROOT
        cf.ROOT = self.root
        self.git("init", "-q", "-b", "base")
        (self.root / "src").mkdir()
        (self.root / "changelog.d").mkdir()
        (self.root / "src/lib.rs").write_text("fn a() {}\n", encoding="utf-8")
        (self.root / "changelog.d/.gitkeep").write_text("", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "base")
        self.git("switch", "-qc", "pr")

    def tearDown(self):
        cf.ROOT = self.saved
        self.tmp.cleanup()

    def git(self, *args):
        subprocess.run(
            ["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
            cwd=self.root, check=True, capture_output=True,
        )

    def run_check(self, labels=""):
        os.environ["PR_LABELS"] = labels
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code = cf.main(["check", "--base", "base", "--head", "HEAD"])
        finally:
            del os.environ["PR_LABELS"]
        return code, err.getvalue()

    def test_a_src_commit_without_a_fragment_fails(self):
        (self.root / "src/lib.rs").write_text("fn b() {}\n", encoding="utf-8")
        self.git("commit", "-qam", "change")
        code, err = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("adds no changelog.d", err)

    def test_the_label_waives_it(self):
        (self.root / "src/lib.rs").write_text("fn b() {}\n", encoding="utf-8")
        self.git("commit", "-qam", "change")
        self.assertEqual(self.run_check("docs, no-changelog")[0], 0)

    def test_a_committed_retype_passes_through_the_git_diff(self):
        (self.root / "changelog.d/7.fixed.md").write_text("- b (#7)\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "fragment")
        self.git("branch", "-f", "base")
        self.git("mv", "changelog.d/7.fixed.md", "changelog.d/7.security.md")
        self.git("commit", "-qm", "retype")
        self.assertEqual(self.run_check()[0], 0)

    def test_a_committed_fragment_passes(self):
        (self.root / "src/lib.rs").write_text("fn b() {}\n", encoding="utf-8")
        (self.root / "changelog.d/7.fixed.md").write_text("- b (#7)\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-qm", "change")
        self.assertEqual(self.run_check()[0], 0)


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        (root / "changelog.d").mkdir()
        (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
        self.root, self.saved = root, cf.ROOT
        cf.ROOT = root

    def tearDown(self):
        cf.ROOT = self.saved
        self.tmp.cleanup()

    def test_dry_run_writes_and_deletes_nothing(self):
        (self.root / "changelog.d/9.added.md").write_text("- n (#9)\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cf.main(["assemble", "--dry-run"]), 0)
        self.assertIn("- n (#9)", out.getvalue())
        self.assertEqual((self.root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)
        self.assertTrue((self.root / "changelog.d/9.added.md").exists())

    def test_assemble_writes_and_deletes_the_fragments(self):
        (self.root / "changelog.d/9.added.md").write_text("- n (#9)\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cf.main(["assemble"]), 0)
        self.assertIn("- n (#9)", (self.root / "CHANGELOG.md").read_text(encoding="utf-8"))
        self.assertFalse((self.root / "changelog.d/9.added.md").exists())

    def test_a_directory_named_like_a_fragment_fails_cleanly(self):
        (self.root / "changelog.d/9.added.md").mkdir()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cf.main(["assemble"]), 1)
        self.assertIn("not a regular file", err.getvalue())

    def test_an_empty_fragment_fails_and_changes_nothing(self):
        (self.root / "changelog.d/9.added.md").write_text("\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cf.main(["assemble"]), 1)
        self.assertIn("empty fragment", err.getvalue())
        self.assertEqual((self.root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)


if __name__ == "__main__":
    unittest.main()
