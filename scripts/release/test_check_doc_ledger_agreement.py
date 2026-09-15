#!/usr/bin/env python3
"""Prove each agreement assertion goes red on its own.

Every case mutates the real document text rather than a fixture, so a wording
change in the matrix or the tracker surfaces here instead of quietly turning a
test green against prose nobody ships.
"""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_doc_ledger_agreement as agreement  # noqa: E402
from check_scope_acceptance import (  # noqa: E402
    BASELINE,
    ROOT,
    SCOPE,
    STATUS,
    inspect_contract,
    unique_object,
)


def derived():
    source = (ROOT / agreement.CONFORMANCE).read_text()
    majors = agreement.entries(source, "MAJOR", "Row {")
    minors = agreement.entries(source, "MINOR", "Row {")
    gaps = agreement.entries(source, "TRACKED_GAPS", "(")
    data = json.loads((ROOT / STATUS).read_text(), object_pairs_hook=unique_object)
    errors, pending, blockers = inspect_contract(
        ROOT, (ROOT / SCOPE).read_text(), data, (ROOT / BASELINE).read_text()
    )
    if errors:
        # Without this the suite would read an inconsistent contract as a valid
        # oracle and report mutation coverage it never had.
        raise RuntimeError(
            "the scope contract is inconsistent, so it cannot be this suite's "
            "oracle:\n  " + "\n  ".join(errors)
        )
    return majors, minors, gaps, len(pending), len(blockers)


MAJORS, MINORS, GAPS, PENDING, BLOCKING = derived()
TOTAL = MAJORS + MINORS
MATRIX = (ROOT / agreement.MATRIX).read_text()
TRACKER = (ROOT / agreement.TRACKER).read_text()


def newest_row(text):
    """Pick the row through the checker's own key, so both always agree."""
    rows = list(agreement.SUMMARY.finditer(text))
    return max(rows, key=agreement.row_age).group(0)


def swap(text, old, new):
    assert old in text, f"anchor absent: {old!r}"
    return text.replace(old, new, 1)


def swap_in_newest_row(old, new):
    row = newest_row(TRACKER)
    return swap(TRACKER, row, swap(row, old, new))


class RealDocumentsAgree(unittest.TestCase):
    def test_the_shipped_documents_are_green(self):
        self.assertEqual([], agreement.check_matrix(MATRIX, TOTAL - GAPS, TOTAL))
        self.assertEqual([], agreement.check_prose(MATRIX, MAJORS, MINORS))
        self.assertEqual([], agreement.check_tracker(TRACKER, PENDING, BLOCKING))


class EachNumberIsLoadBearing(unittest.TestCase):
    """One mutation per document number; a shared value cannot cover another."""

    def assert_red(self, failures):
        self.assertTrue(failures, "the mutated number was not caught")

    def test_covered_numerator(self):
        text = swap(MATRIX, f"COVERED ({TOTAL - GAPS} of", f"COVERED ({TOTAL - GAPS - 1} of")
        self.assert_red(agreement.check_matrix(text, TOTAL - GAPS, TOTAL))

    def test_covered_denominator(self):
        text = swap(
            MATRIX,
            f"COVERED ({TOTAL - GAPS} of {TOTAL})",
            f"COVERED ({TOTAL - GAPS} of {TOTAL + 1})",
        )
        self.assert_red(agreement.check_matrix(text, TOTAL - GAPS, TOTAL))

    def test_uncovered_numerator(self):
        text = swap(MATRIX, f"UNCOVERED ({GAPS} of", f"UNCOVERED ({GAPS + 1} of")
        self.assert_red(agreement.check_matrix(text, TOTAL - GAPS, TOTAL))

    def test_uncovered_denominator(self):
        text = swap(
            MATRIX,
            f"UNCOVERED ({GAPS} of {TOTAL})",
            f"UNCOVERED ({GAPS} of {TOTAL - 1})",
        )
        self.assert_red(agreement.check_matrix(text, TOTAL - GAPS, TOTAL))

    def test_prose_major_word(self):
        words = {n: w for w, n in agreement.WORDS.items()}
        text = swap(MATRIX, f"All {words[MAJORS]} major", f"All {words[MAJORS - 1]} major")
        self.assert_red(agreement.check_prose(text, MAJORS, MINORS))

    def test_prose_minor_bound(self):
        text = swap(MATRIX, f"minor 1-{MINORS} carry", f"minor 1-{MINORS - 1} carry")
        self.assert_red(agreement.check_prose(text, MAJORS, MINORS))

    def test_tracker_blocking(self):
        text = swap_in_newest_row(f"| {BLOCKING} | {PENDING} |", f"| {BLOCKING + 1} | {PENDING} |")
        self.assert_red(agreement.check_tracker(text, PENDING, BLOCKING))

    def test_tracker_pending(self):
        text = swap_in_newest_row(f"| {BLOCKING} | {PENDING} |", f"| {BLOCKING} | {PENDING - 1} |")
        self.assert_red(agreement.check_tracker(text, PENDING, BLOCKING))

    def test_tracker_total(self):
        text = swap_in_newest_row(
            f"**{BLOCKING + PENDING}**", f"**{BLOCKING + PENDING + 1}**"
        )
        self.assert_red(agreement.check_tracker(text, PENDING, BLOCKING))


class UnreadableIsNotGreen(unittest.TestCase):
    """A document the check can no longer parse must stop it, not pass it."""

    def test_a_duplicated_heading_is_refused(self):
        heading = f"### Statements with evidence — COVERED ({TOTAL - GAPS} of {TOTAL})"
        text = swap(MATRIX, heading, f"{heading}\n\n{heading}")
        with self.assertRaises(agreement.Drift):
            agreement.check_matrix(text, TOTAL - GAPS, TOTAL)

    def test_a_missing_heading_is_refused(self):
        text = swap(MATRIX, "### Statements with evidence — COVERED", "### Coverage")
        with self.assertRaises(agreement.Drift):
            agreement.check_matrix(text, TOTAL - GAPS, TOTAL)

    def test_a_renamed_array_is_refused(self):
        with self.assertRaises(agreement.Drift):
            agreement.entries("const MAJORS: &[Row] = &[];", "MAJOR", "Row {")

    def test_an_unknown_number_word_is_refused(self):
        words = {n: w for w, n in agreement.WORDS.items()}
        text = swap(MATRIX, f"All {words[MAJORS]} major", "All forty major")
        with self.assertRaises(agreement.Drift):
            agreement.check_prose(text, MAJORS, MINORS)

    def test_a_tracker_with_no_summary_rows_is_refused(self):
        with self.assertRaises(agreement.Drift):
            agreement.check_tracker("no rows here\n", PENDING, BLOCKING)


class NewestRowIsParsedNotAssumed(unittest.TestCase):
    def test_an_out_of_order_append_does_not_become_the_current_row(self):
        stale = f"| 2020-01-01a | {BLOCKING + 9} | {PENDING} | **{TOTAL}** | 0 | stale |"
        self.assertEqual(
            [], agreement.check_tracker(f"{TRACKER}\n{stale}\n", PENDING, BLOCKING)
        )

    def test_a_row_recording_a_close_is_not_skipped(self):
        """Nine shipped rows spend `-1` on the tick column; none may be invisible."""
        closed = (
            f"| 2099-01-01a | {BLOCKING} | {PENDING + 1} | **{BLOCKING + PENDING + 1}**"
            " | -1 | a criterion closed |"
        )
        self.assert_red(agreement.check_tracker(f"{TRACKER}\n{closed}\n", PENDING, BLOCKING))

    def assert_red(self, failures):
        self.assertTrue(failures, "the newest row was skipped, not read")

    def test_a_two_letter_suffix_outranks_a_one_letter_suffix(self):
        rows = list(agreement.SUMMARY.finditer("| 2099-01-01z | 1 | 1 | **2** | 0 |\n"
                                               "| 2099-01-01aa | 1 | 1 | **2** | 0 |\n"))
        self.assertEqual("aa", max(rows, key=agreement.row_age).group(2))


class TheArrayParserIsItselfTested(unittest.TestCase):
    """The oracle comes through `entries`, so it needs cases of known size."""

    SYNTHETIC = """
const MAJOR: &[Row] = &[
    Row { id: "a" },
    Row { id: "b" },
];

const MINOR: &[Row] = &[
    Row {
        id: "c",
        note: "a nested Row { } must not count twice",
    },
];
"""

    def test_top_level_entries_only(self):
        self.assertEqual(2, agreement.entries(self.SYNTHETIC, "MAJOR", "Row {"))
        self.assertEqual(1, agreement.entries(self.SYNTHETIC, "MINOR", "Row {"))

    def test_an_inline_empty_array_counts_zero(self):
        self.assertEqual(
            0, agreement.entries("const TRACKED_GAPS: &[(&str, &str)] = &[];", "TRACKED_GAPS", "(")
        )

    def test_a_terminator_inside_an_entry_undercounts_loudly(self):
        """An early cut can only lose entries, and a lost entry fails the check."""
        source = 'const MAJOR: &[Row] = &[\n    Row { id: "]; " },\n    Row { id: "b" },\n];'
        self.assertLess(agreement.entries(source, "MAJOR", "Row {"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
