#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for changelog_fragments.py: assembly output and the PR check."""

import contextlib
import hashlib
import importlib.util
import io
import os
import pathlib
import re
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

    def test_suffixed_fragments_follow_their_number_in_suffix_order(self):
        fragments = {
            "9-10.added.md": "- c (#9)\n",
            "9-2.added.md": "- b (#9)\n",
            "9.added.md": "- a (#9)\n",
            "10.added.md": "- d (#10)\n",
        }
        got = cf.assemble(CHANGELOG, fragments)
        self.assertIn("- a (#9)\n- b (#9)\n- c (#9)\n- d (#10)\n", got)

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

    def test_a_numeric_suffix_names_a_further_fragment_of_one_number(self):
        # A second PR for the same number cannot reuse its first fragment's name.
        changes = [("M", "src/lib.rs"), ("A", "changelog.d/8875-2.added.md")]
        self.assertEqual(cf.check(changes, set()), [])

    def test_a_suffix_must_be_digits_after_one_hyphen(self):
        # 0 and a leading zero would tie with or alias another name in the fold.
        for name in (
            "8875-x.added.md",
            "8875-.added.md",
            "8875-2-3.added.md",
            "-2.added.md",
            "8875-0.added.md",
            "8875-02.added.md",
        ):
            errors = cf.check([("A", f"changelog.d/{name}")], set())
            self.assertEqual(len(errors), 1, name)
            self.assertIn(f"changelog.d/{name}", errors[0])

    def test_a_suffixed_add_does_not_excuse_deleting_the_unsuffixed_fragment(self):
        changes = [("D", "changelog.d/8875.added.md"), ("A", "changelog.d/8875-2.added.md")]
        errors = cf.check(changes, set())
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("changelog.d/8875.added.md", errors[0])

    def test_an_unsuffixed_add_does_not_excuse_deleting_a_suffixed_fragment(self):
        changes = [("D", "changelog.d/8875-2.added.md"), ("A", "changelog.d/8875.changed.md")]
        errors = cf.check(changes, set())
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("changelog.d/8875-2.added.md", errors[0])

    def test_retyping_a_suffixed_fragment_under_its_own_name_passes(self):
        changes = [("D", "changelog.d/8875-2.added.md"), ("A", "changelog.d/8875-2.changed.md")]
        self.assertEqual(cf.check(changes, set()), [])

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


# A tracker id, built at run time so this file holds none (the public hygiene rule refuses them).
T = "MIK" + "-"

BASE = """# Changelog

## [Unreleased]

### Fixed

- existing fix (#2)

## [1.0.0] - 2026-01-01

### Fixed

- old (#0)
"""


def unreleased_fixed(text: str) -> list[str]:
    """The lines of the Unreleased section's `### Fixed` subsection, blank lines dropped."""
    section = text.split("## [Unreleased]", 1)[1].split("\n## ", 1)[0]
    return [x for x in section.split("### Fixed", 1)[1].split("\n") if x.strip()]


def hygiene_ids(text: str) -> list[str]:
    """Bare tracker ids in `text` by the hygiene rule's own patterns (scripts/dev/public-hygiene-patterns.sh):
    acceptance ids (`ac_id_regex`) set aside first, as the checks' bare() does, then `ticket_id_regex`."""
    src = pathlib.Path(__file__).resolve().parents[2] / "scripts/dev/public-hygiene-patterns.sh"
    defs = dict(x.split("=", 1) for x in src.read_text(encoding="utf-8").splitlines()
                if x.startswith(("ticket_id_regex=", "ac_id_regex=")))
    ticket, ac = (defs[k].strip("'").replace("[:alnum:]", "A-Za-z0-9") for k in ("ticket_id_regex", "ac_id_regex"))
    return [m.group(0) for m in re.finditer(ticket, re.sub(ac, "", text))]


class DropIds(unittest.TestCase):
    """The fold drops bare tracker ids from what it renders (the lead's fix, 2026-11-15)."""

    def test_each_parenthetical_shape_renders_without_its_ids(self):
        shapes = [
            ("only an id", f"- a ({T}1).", "- a."),
            ("an id beside a PR number", f"- b (#12, {T}2).", "- b (#12)."),
            ("an id with a label", f"- c ({T}3 I2).", "- c."),
            ("an id with a dotted label", f"- c2 ({T}31 MIN.2).", "- c2."),
            ("an id beside words on one line", f"- w (not a config key, {T}32).", "- w (not a config key)."),
            ("an id beside a blank part", f"- x ({T}36, ).", "- x."),
            ("a kept part beside an id and a blank part", f"- y (#12, {T}37, ).", "- y (#12)."),
            ("ids split across a line break", f"- d ({T}4,\n  {T}5).", "- d."),
            ("a kept part across a line break", f"- e (F13, {T}6,\n  #14).", "- e (F13, #14)."),
            ("a PR number and an id split by a semicolon", f"- s (#40; {T}41).", "- s (#40)."),
            ("two ids split by a semicolon", f"- s2 ({T}42; {T}43).", "- s2."),
            ("kept parts keep their semicolon", f"- c3 (#53; {T}54; #55).", "- c3 (#53; #55)."),
            ("text after a parenthetical that spans a line break", f"- e2 (F13, {T}56,\n  #57). Then a note follows.", "- e2 (F13, #57). Then a note follows."),
            ("code on the line outside the parenthetical", f"- r `cmd a,b` fixed (#72, {T}73).", "- r `cmd a,b` fixed (#72)."),
            ("an unclosed backtick in another bullet", f"- p (`open.\n- q (#70, {T}71).", "- p (`open.\n- q (#70)."),
        ]
        for name, fragment, rendered in shapes:
            with self.subTest(name):
                out = cf.assemble(BASE, {"20.fixed.md": fragment + "\n"})
                self.assertEqual(unreleased_fixed(out), ["- existing fix (#2)", *rendered.split("\n")])
                self.assertEqual(hygiene_ids(out.split("## [1.0.0]")[0]), [])

    def test_acceptance_ids_and_pr_numbers_stay(self):
        out = cf.assemble(BASE, {"21.fixed.md": f"- f ({T}7.AREA.1, #15, {T}8).\n- g {T}9.AREA.2 holds.\n"})
        self.assertEqual(unreleased_fixed(out), ["- existing fix (#2)", f"- f ({T}7.AREA.1, #15).", f"- g {T}9.AREA.2 holds."])
        # What the fold keeps must pass the hygiene rule the release gate runs.
        self.assertEqual(hygiene_ids(out.split("## [1.0.0]")[0]), [])

    def test_an_id_alone_on_its_lines_takes_those_lines_with_it(self):
        # A line left holding only spaces would read as a blank line and split the
        # bullet; a blank line the fragment itself has stays.
        for src, out in ((f"- n one\n  ({T}74)\n  two.\n\n  Kept.\n", "- n one\n  two.\n\n  Kept.\n"),
                         (f"- n2 one\n  ({T}75,\n  {T}76)\n  two.\n", "- n2 one\n  two.\n"),
                         (f"- n3 one\n  ({T}77,\n\n  {T}78)\n  two.\n", "- n3 one\n\n  two.\n"),
                         (f"- n4 one\n  ({T}79,\n  \t\n\n  {T}80)\n  two.\n", "- n4 one\n  \t\n\n  two.\n"),
                         (f"- n5 one\n  ({T}81)", "- n5 one")):
            with self.subTest(src=src):
                self.assertEqual(cf.drop_ids(src), (out, []))

    def test_assemble_itself_refuses_an_id_it_cannot_drop(self):
        HOLDS_CODE = "a tracker id in a parenthetical that holds code"
        ODD_BACKTICK = "a tracker id in a bullet with an escaped or unclosed backtick"
        SPAN_CHANGED = "dropping the tracker id would change a code span; reword the line"
        BLOCK = "a tracker id in a bullet holding a code block; move the id out of the bullet, or reword"
        cases = ((f"- s found by {T}33.\n", 1, "a tracker id in prose"),
                 (f"- t (#34)\n- u (follow-up {T}35).\n", 2, "a tracker id among other words"),
                 (f"- v (`run {T}60`, {T}61).\n", 1, HOLDS_CODE),
                 (f"- w ``see {T}62`` here.\n", 1, "a tracker id in prose"),
                 (f"- x (`open, {T}63).\n", 1, HOLDS_CODE),
                 (f"- c (`echo ready; exit 0`, {T}50).\n", 1,
                  HOLDS_CODE + "; move the id out of the parenthetical that holds code, or reword"),
                 (f"- c4 (``printf a,b``, {T}58).\n", 1, HOLDS_CODE),
                 (f"- c6 (\\`lit, `printf a,b`, \\`lit, {T}64).\n", 1, HOLDS_CODE),
                 (f"- c7 (`open ({T}65), #2).\n", 1, HOLDS_CODE),
                 (f"- c5 ``a ` f({T}59)`` here.\n", 1, "a tracker id in prose"),
                 (f"- e \\`x (#1, {T}66) here.\n", 1, ODD_BACKTICK),
                 (f"- m `f(\n{T}67)`.\n", 2, ODD_BACKTICK),
                 (f"- m2 `f(\n{T}68,\nx)`.\n", 2, ODD_BACKTICK),
                 (f"- m3 `a\n  f({T}69)\n  b`.\n", 2, ODD_BACKTICK),
                 # The drop itself would join two spans, or escape the backtick after it.
                 (f"- j `printf a,b` ({T}82)`exit 0`.\n", 1, SPAN_CHANGED),
                 (f"- j2 a\\ ({T}83)`x`.\n", 1, SPAN_CHANGED),
                 # Block code the span reader cannot see.
                 (f"- k run:\n  ~~~\n  printf \"({T}84)\"\n  ~~~\n", 3, BLOCK),
                 (f"- k2 run:\n  ```\n  printf \"({T}85)\"\n  ```\n", 3, BLOCK),
                 (f"- k3 run:\n\n      printf \"({T}86)\"\n", 3, BLOCK))
        for fragment, line, why in cases:
            with self.subTest(fragment=fragment):
                with self.assertRaises(ValueError) as caught:
                    cf.assemble(BASE, {"25.fixed.md": fragment})
                self.assertIn(f"changelog.d/25.fixed.md:{line}: {why}", str(caught.exception))

    def test_an_id_in_the_unreleased_section_is_dropped_and_a_released_one_stays(self):
        changelog = BASE.replace("- existing fix (#2)", f"- existing fix (#2, {T}14)").replace("- old (#0)", f"- old (#0, {T}13)")
        out = cf.assemble(changelog, {"22.fixed.md": "- h (#22)\n"})
        self.assertEqual(unreleased_fixed(out), ["- existing fix (#2)", "- h (#22)"])
        self.assertIn(f"- old (#0, {T}13)", out.split("## [1.0.0]")[1])

    def test_a_second_fold_adds_only_its_own_line(self):
        first = cf.assemble(BASE, {"23.fixed.md": f"- k ({T}15).\n"})
        second = cf.assemble(first, {"24.fixed.md": "- m (#24)\n"})
        self.assertEqual(unreleased_fixed(second), ["- existing fix (#2)", "- k.", "- m (#24)"])

    def test_folding_its_own_output_with_no_fragments_changes_nothing(self):
        first = cf.assemble(BASE, {"26.fixed.md": f"- z (#26, {T}18).\n"})
        self.assertEqual(cf.assemble(first, {}), first)


class DropIdsCli(unittest.TestCase):
    """A tracker id that cannot be dropped stops the fold, which then writes and deletes nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "changelog.d").mkdir()
        (self.root / "changelog.d/.gitkeep").write_text("", encoding="utf-8")
        (self.root / "CHANGELOG.md").write_text(BASE, encoding="utf-8")
        self.saved = cf.ROOT
        cf.ROOT = self.root

    def tearDown(self):
        cf.ROOT = self.saved
        self.tmp.cleanup()

    def files(self) -> dict[str, str]:
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(self.root.rglob("*")) if p.is_file()}

    def refused(self, where: str):
        before = self.files()
        for argv in (["assemble", "--dry-run"], ["assemble"]):
            with self.subTest(argv=argv):
                with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(cf.main(argv), 1)
                self.assertIn(where, err.getvalue())
                self.assertEqual(out.getvalue(), "")
                self.assertEqual(self.files(), before)

    def test_an_id_in_prose_is_refused_naming_the_fragment_and_line(self):
        (self.root / "changelog.d/30.fixed.md").write_text(f"- Found by {T}10's review.\n", encoding="utf-8")
        self.refused("changelog.d/30.fixed.md:1: ")

    def test_an_id_among_words_in_a_parenthetical_is_refused(self):
        (self.root / "changelog.d/31.fixed.md").write_text(f"- n (#31)\n- h (follow-up {T}11).\n", encoding="utf-8")
        self.refused("changelog.d/31.fixed.md:2: ")

    def test_an_id_in_prose_in_the_unreleased_section_is_refused_naming_its_line(self):
        (self.root / "CHANGELOG.md").write_text(BASE.replace("- existing fix (#2)", f"- i {T}12 holds (#2)"), encoding="utf-8")
        (self.root / "changelog.d/32.fixed.md").write_text("- p (#32)\n", encoding="utf-8")
        self.refused("CHANGELOG.md:7: ")

    def test_one_refused_fragment_keeps_every_fragment_including_a_clean_one(self):
        (self.root / "changelog.d/35.fixed.md").write_text("- clean (#35)\n", encoding="utf-8")
        (self.root / "changelog.d/36.fixed.md").write_text(f"- Seen in {T}19 first.\n", encoding="utf-8")
        self.refused("changelog.d/36.fixed.md:1: ")

    def test_a_dry_run_leaves_every_fragment_byte_for_byte(self):
        (self.root / "changelog.d/33.fixed.md").write_text(f"- q ({T}16, #33)\n", encoding="utf-8")
        before = self.files()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cf.main(["assemble", "--dry-run"]), 0)
        self.assertEqual(self.files(), before)
        self.assertIn("- q (#33)\n", out.getvalue())

    def test_the_fold_deletes_exactly_the_fragments_it_folded(self):
        (self.root / "changelog.d/34.fixed.md").write_text(f"- r ({T}17)\n", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cf.main(["assemble"]), 0)
        self.assertEqual(sorted(p.name for p in (self.root / "changelog.d").iterdir()), [".gitkeep"])
        self.assertEqual(unreleased_fixed((self.root / "CHANGELOG.md").read_text(encoding="utf-8")), ["- existing fix (#2)", "- r"])


if __name__ == "__main__":
    unittest.main()
