# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for check_changelog_sections.py.

Every row builds a throwaway git repository holding its own CHANGELOG.md,
Cargo.toml and tags, then runs the checker there as a child process. A missing
or broken checker therefore fails on the asserted exit code and output, never
on an import.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parent / "check_changelog_sections.py"

# The scratch repository must not pick up the caller's git config (signing,
# hooks, templates), so the global and system files are switched off. Inherited
# GIT_* variables are dropped too: inside a git hook GIT_DIR and GIT_INDEX_FILE
# point at the caller's repository, and git would init, commit and tag there.
GIT_ENV = {
    **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "sections-rows",
    "GIT_AUTHOR_EMAIL": "sections-rows@example.invalid",
    "GIT_COMMITTER_NAME": "sections-rows",
    "GIT_COMMITTER_EMAIL": "sections-rows@example.invalid",
}


def body(*headings):
    """CHANGELOG.md text: a title, then one bullet under each heading.

    The title takes lines 1-2, so the first heading sits on line 3 and each
    later one 4 lines further down (3, 7, 11, ...). Rows write those line
    numbers as literals.
    """
    text = "# Changelog\n\n"
    for heading in headings:
        text += heading + "\n\n- a change\n\n"
    return text


def check(headings, tags, cargo_version):
    """Run the checker in a fresh repository; return (exit code, all output)."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "CHANGELOG.md").write_text(body(*headings))
        (repo / "Cargo.toml").write_text(
            f'[package]\nname = "rows"\nversion = "{cargo_version}"\nedition = "2021"\n'
        )
        for argv in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
            subprocess.run(["git", *argv], cwd=repo, env=GIT_ENV, check=True)
        for tag in tags:
            subprocess.run(["git", "tag", tag], cwd=repo, env=GIT_ENV, check=True)
        done = subprocess.run(
            [sys.executable, str(CHECKER)],
            cwd=repo,
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )
        return done.returncode, done.stdout + done.stderr


class Sections(unittest.TestCase):
    def test_r1_a_version_section_without_its_tag_fails(self):
        rc, out = check(
            ["## [1.1.0] - 2026-01-02", "## [1.0.0] - 2026-01-01"],
            tags=["v1.0.0"],
            cargo_version="1.2.0-beta.1",
        )
        self.assertEqual((rc, out), (1, "CHANGELOG.md:3: [1.1.0] has no tag v1.1.0\n"))

    def test_r2_a_version_section_twice_fails_even_when_tagged(self):
        rc, out = check(
            ["## [1.0.0] - 2026-01-01", "## [1.0.0] - 2026-01-01"],
            tags=["v1.0.0"],
            cargo_version="1.1.0-beta.1",
        )
        self.assertEqual(
            (rc, out), (1, "CHANGELOG.md:7: [1.0.0] appears again (first at line 3)\n")
        )

    def test_r2c_every_repeat_points_at_the_first_copy(self):
        # A third copy names line 3, not the second copy on line 7.
        rc, out = check(
            ["## [1.0.0] - 2026-01-01"] * 3,
            tags=["v1.0.0"],
            cargo_version="1.1.0-beta.1",
        )
        self.assertEqual(
            (rc, out),
            (
                1,
                "CHANGELOG.md:7: [1.0.0] appears again (first at line 3)\n"
                "CHANGELOG.md:11: [1.0.0] appears again (first at line 3)\n",
            ),
        )

    def test_r2b_a_duplicate_is_reported_even_when_dated_unreleased(self):
        # The exemptions cover the tag rule only; a repeated heading is never exempt.
        rc, out = check(
            ["## [2.0.0] - Unreleased", "## [1.0.0] - 2026-01-01", "## [2.0.0] - Unreleased"],
            tags=["v1.0.0"],
            cargo_version="1.1.0",
        )
        self.assertEqual(
            (rc, out), (1, "CHANGELOG.md:11: [2.0.0] appears again (first at line 3)\n")
        )

    def test_r3_unreleased_and_the_release_being_prepared_need_no_tag(self):
        rc, out = check(
            [
                "## [Unreleased]",
                "## [2.1.0-beta.1] - 2026-02-01",
                "## [2.0.0] - Unreleased",
            ],
            tags=[],
            cargo_version="2.1.0-beta.1",
        )
        self.assertEqual((rc, out), (0, ""))

    def test_r4_every_section_tagged_passes(self):
        rc, out = check(
            ["## [1.1.0] - 2026-01-02", "## [1.0.0] - 2026-01-01"],
            tags=["v1.0.0", "v1.1.0"],
            cargo_version="1.2.0-beta.1",
        )
        self.assertEqual((rc, out), (0, ""))

    def test_r5_the_tag_alone_decides(self):
        headings = ["## [1.1.0] - 2026-01-02"]
        with self.subTest("tag v1.1.0 present"):
            self.assertEqual(check(headings, ["v1.1.0"], "9.0.0"), (0, ""))
        with self.subTest("tag v1.1.0 absent"):
            self.assertEqual(
                check(headings, [], "9.0.0"),
                (1, "CHANGELOG.md:3: [1.1.0] has no tag v1.1.0\n"),
            )

    def test_r7_a_heading_the_check_cannot_read_fails(self):
        # A "v" typed into the brackets would otherwise slip past both rules.
        rc, out = check(
            ["## [Unreleased]", "## [v1.2.0] - 2026-01-02", "## [1.0.0] - 2026-01-01"],
            tags=["v1.0.0", "v1.2.0"],
            cargo_version="1.3.0",
        )
        self.assertEqual(
            (rc, out),
            (
                1,
                "CHANGELOG.md:7: heading is neither [Unreleased] nor a version section:"
                " ## [v1.2.0] - 2026-01-02\n",
            ),
        )

    def test_r8_heading_whitespace_markdown_allows_is_still_a_section(self):
        # Markdown takes up to three leading spaces and any run of spaces or
        # tabs after `##` as the same heading; none of it may hide a section.
        with self.subTest("untagged, two spaces after ##"):
            self.assertEqual(
                check(["##  [1.1.0] - 2026-01-02"], [], "9.0.0"),
                (1, "CHANGELOG.md:3: [1.1.0] has no tag v1.1.0\n"),
            )
        with self.subTest("a repeat, indented and tab-separated"):
            self.assertEqual(
                check(["## [1.0.0] - 2026-01-01", "   ##\t[1.0.0] - 2026-01-01"], ["v1.0.0"], "9.0.0"),
                (1, "CHANGELOG.md:7: [1.0.0] appears again (first at line 3)\n"),
            )
        with self.subTest("[Unreleased] with the same spacing stays exempt"):
            self.assertEqual(check(["##  [Unreleased]"], [], "9.0.0"), (0, ""))
        with self.subTest("tabs around the date dash still read the date"):
            self.assertEqual(check(["## [2.0.0]\t-\tUnreleased"], [], "9.0.0"), (0, ""))
        with self.subTest("an unreadable heading with wide spacing still fails"):
            self.assertEqual(
                check(["##  [v1.2.0] - 2026-01-02"], ["v1.2.0"], "9.0.0"),
                (
                    1,
                    "CHANGELOG.md:3: heading is neither [Unreleased] nor a version section:"
                    " ##  [v1.2.0] - 2026-01-02\n",
                ),
            )

    def test_r6_the_cargo_exemption_covers_only_that_exact_version(self):
        with self.subTest("final version beside a beta manifest"):
            self.assertEqual(
                check(["## [2.1.0] - 2026-02-01"], [], "2.1.0-beta.1"),
                (1, "CHANGELOG.md:3: [2.1.0] has no tag v2.1.0\n"),
            )
        with self.subTest("the manifest moved on to beta.2"):
            # Same heading R3 exempts; only Cargo.toml changed, so the version
            # is read from the manifest, not matched on a "-beta" suffix.
            self.assertEqual(
                check(["## [2.1.0-beta.1] - 2026-02-01"], [], "2.1.0-beta.2"),
                (1, "CHANGELOG.md:3: [2.1.0-beta.1] has no tag v2.1.0-beta.1\n"),
            )


if __name__ == "__main__":
    unittest.main()
