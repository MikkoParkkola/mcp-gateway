#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for changelog_fragments.py: assembly output and the PR check."""

import importlib.util
import pathlib
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

    def test_a_hand_edit_of_the_changelog_fails(self):
        errors = cf.check([("M", "CHANGELOG.md"), ("A", "changelog.d/5.fixed.md")], set())
        self.assertEqual(len(errors), 1)
        self.assertIn("edits CHANGELOG.md", errors[0])

    def test_the_release_fold_may_edit_the_changelog(self):
        self.assertEqual(cf.check([("M", "CHANGELOG.md"), ("D", "changelog.d/5.fixed.md")], set()), [])

    def test_editing_an_existing_fragment_does_not_count_as_adding_one(self):
        self.assertEqual(len(cf.check([("M", "src/a.rs"), ("M", "changelog.d/1.fixed.md")], set())), 1)

    def test_deleting_a_fragment_does_not_count_as_adding_one(self):
        self.assertEqual(len(cf.check([("M", "src/a.rs"), ("D", "changelog.d/1.fixed.md")], set())), 1)


if __name__ == "__main__":
    unittest.main()
