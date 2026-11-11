#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what bless_ui_matrix.py writes and what it refuses.

Each case hands the script a canned test log and a scratch fragment directory,
so no cargo runs. A refusal must leave every fragment byte-for-byte as it was.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SPEC = importlib.util.spec_from_file_location("bless", Path(__file__).resolve().parent / "bless_ui_matrix.py")
bless = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bless)

# fragment file -> (header lines, rows)
OLD = {
    "a.tsv": (["#@ scoped"], ["/ui/api/a\tGET\tplain\tAdminKey\t200", "/ui/api/a\tGET\tplain\tNoKey\t401:de6b55925ef7"]),
    "b.tsv": ([], ["/ui/api/b\tGET\tplain\tAdminKey\t200"]),
}


def block(name: str, header: list[str], rows: list[str]) -> str:
    return f"{bless.FILE_MARK}{name}\n" + "".join(f"{line}\n" for line in header + rows)


def log(files: dict, count: int | None = None, extra: str = "") -> str:
    body = "".join(block(name, header, rows) for name, (header, rows) in files.items()) + extra
    n = sum(len(rows) for _, rows in files.values()) if count is None else count
    return f"running 1 test\n---- BEGIN MATRIX ----\n{body}---- END MATRIX ----\ncells={n}\ntest result: FAILED.\n"


class Bless(unittest.TestCase):
    def run_bless(self, text: str, rc: int = 101, allowed: frozenset[str] = frozenset()) -> tuple[str | None, str, dict[str, str]]:
        with TemporaryDirectory() as tmp:
            fragments = Path(tmp)
            for name, (header, rows) in OLD.items():
                (fragments / name).write_text("".join(f"{line}\n" for line in header + rows))
            before = {p.name: p.read_text() for p in fragments.glob("*")}
            try:
                said = bless.bless(text, rc, fragments, set(allowed))
            except bless.Refused as why:
                after = {p.name: p.read_text() for p in fragments.glob("*")}
                self.assertEqual(before, after, "a refusal changed a fragment")
                return None, str(why), before
            return said, "", {p.name: p.read_text() for p in fragments.glob("*")}

    def test_writes_every_fragment_and_sums_up_each_route(self):
        new = {
            "a.tsv": (["#@ scoped"], ["/ui/api/a\tGET\tplain\tAdminKey\t200", "/ui/api/a\tGET\tplain\tNoKey\t401:error.code=-32000"]),
            "b.tsv": ([], OLD["b.tsv"][1]),
        }
        said, _, files = self.run_bless(log(new))
        self.assertIn("/ui/api/a: 1 changed", said)
        self.assertIn("/ui/api/a\tGET\tplain\tNoKey\t401:error.code=-32000\n", files["a.tsv"])
        self.assertTrue(files["a.tsv"].startswith("#@ scoped\n"), "the attribute header was kept")

    def test_a_new_row_in_a_stored_fragment_is_added(self):
        new = {"a.tsv": OLD["a.tsv"], "b.tsv": ([], OLD["b.tsv"][1] + ["/ui/api/b\tGET\tplain\tNoKey\t401"])}
        said, _, files = self.run_bless(log(new))
        self.assertIn("/ui/api/b: 1 added", said)
        self.assertIn("/ui/api/b\tGET\tplain\tNoKey\t401\n", files["b.tsv"])

    def test_a_green_run_writes_nothing(self):
        said, _, _ = self.run_bless("test result: ok. 1 passed; 0 failed", rc=0)
        self.assertEqual(said, "matrix unchanged")

    def test_refuses_a_run_that_matched_no_test(self):
        self.assertIsNone(self.run_bless("spark-cargo: no test ran", rc=65)[0])

    def test_refuses_a_log_without_a_table(self):
        said, why, _ = self.run_bless("error[E0425]: cannot find value `x`\nerror: could not compile")
        self.assertIsNone(said)
        self.assertIn("no complete computed table", why)

    def test_refuses_a_truncated_table(self):
        text = log(OLD).replace("---- END MATRIX ----\n", "")
        self.assertIsNone(self.run_bless(text)[0])

    def test_refuses_a_count_that_differs(self):
        said, why, _ = self.run_bless(log(OLD, count=99))
        self.assertIsNone(said)
        self.assertIn("rows but the test computed", why)

    def test_refuses_a_row_without_five_fields(self):
        extra = "/ui/api/b\tGET\tAdminKey\t200\n"
        said, why, _ = self.run_bless(log(OLD, extra=extra))
        self.assertIsNone(said)
        self.assertIn("not 5", why)

    def test_refuses_a_duplicate_key(self):
        dup = {"a.tsv": OLD["a.tsv"], "b.tsv": ([], OLD["b.tsv"][1] + ["/ui/api/b\tGET\tplain\tAdminKey\t403"])}
        said, why, _ = self.run_bless(log(dup))
        self.assertIsNone(said)
        self.assertIn("listed twice", why)

    def test_refuses_a_block_for_a_file_that_is_not_a_fragment(self):
        extra = block("c.tsv", [], ["/ui/api/c\tGET\tplain\tAdminKey\t200"])
        said, why, _ = self.run_bless(log(OLD, extra=extra, count=4))
        self.assertIsNone(said)
        self.assertIn("not a stored fragment", why)

    def test_refuses_a_block_whose_name_escapes_the_directory(self):
        extra = f"{bless.FILE_MARK}../x.tsv\n/ui/api/x\tGET\tplain\tAdminKey\t200\n"
        said, why, _ = self.run_bless(log(OLD, extra=extra, count=4))
        self.assertIsNone(said)
        self.assertIn("not a fragment", why)

    def test_refuses_a_line_before_any_file_marker(self):
        text = log(OLD).replace("---- BEGIN MATRIX ----\n", "---- BEGIN MATRIX ----\nstray\n")
        said, why, _ = self.run_bless(text)
        self.assertIsNone(said)
        self.assertIn("before any", why)

    def test_refuses_a_well_formed_table_missing_a_route(self):
        short = {"a.tsv": OLD["a.tsv"], "b.tsv": ([], [])}
        said, why, _ = self.run_bless(log(short))
        self.assertIsNone(said)
        self.assertIn("/ui/api/b", why)

    def test_an_allowed_removal_passes_for_that_route_only(self):
        short = {"a.tsv": OLD["a.tsv"], "b.tsv": ([], [])}
        said, _, files = self.run_bless(log(short), allowed=frozenset({"/ui/api/b"}))
        self.assertIn("/ui/api/b: 1 removed", said)
        self.assertNotIn("/ui/api/b\t", files["b.tsv"])

    def test_an_allowed_removal_does_not_cover_another_missing_route(self):
        only_a_admin = {"a.tsv": ([], ["/ui/api/a\tGET\tplain\tAdminKey\t200"]), "b.tsv": ([], [])}
        said, why, _ = self.run_bless(log(only_a_admin), allowed=frozenset({"/ui/api/b"}))
        self.assertIsNone(said)
        self.assertIn("/ui/api/a", why)

    def test_a_removal_is_matched_on_the_exact_route(self):
        short = {"a.tsv": OLD["a.tsv"], "b.tsv": ([], [])}
        self.assertIsNone(self.run_bless(log(short), allowed=frozenset({"/ui/api"}))[0])


if __name__ == "__main__":
    unittest.main()
