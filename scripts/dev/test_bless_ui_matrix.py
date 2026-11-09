#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pin what bless_ui_matrix.py writes and what it refuses.

Each case hands the script a canned test log and a scratch table, so no cargo
runs. A refusal must leave the table byte-for-byte as it was.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SPEC = importlib.util.spec_from_file_location("bless", Path(__file__).resolve().parent / "bless_ui_matrix.py")
bless = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bless)

OLD = {
    "/ui/api/a\tGET\tplain\tAdminKey": "200",
    "/ui/api/a\tGET\tplain\tNoKey": "401:de6b55925ef7",
    "/ui/api/b\tGET\tplain\tAdminKey": "200",
}


def log(cells: dict[str, str], count: int | None = None, extra: str = "") -> str:
    body = "".join(f"{k}\t{v}\n" for k, v in cells.items()) + extra
    n = len(cells) + extra.count("\n") if count is None else count
    return f"running 1 test\n---- BEGIN MATRIX ----\n{body}---- END MATRIX ----\ncells={n}\ntest result: FAILED.\n"


class Bless(unittest.TestCase):
    def run_bless(self, text: str, rc: int = 101, allowed: frozenset[str] = frozenset()) -> tuple[str | None, str, str]:
        with TemporaryDirectory() as tmp:
            table = Path(tmp) / "ui_access_matrix.tsv"
            table.write_text(bless.HEADER + "".join(f"{k}\t{v}\n" for k, v in OLD.items()))
            before = table.read_text()
            try:
                said = bless.bless(text, rc, table, set(allowed))
            except bless.Refused as why:
                self.assertEqual(before, table.read_text(), "a refusal changed the table")
                return None, str(why), before
            return said, "", table.read_text()

    def test_writes_a_full_table_and_sums_up_each_route(self):
        new = dict(OLD, **{"/ui/api/a\tGET\tplain\tNoKey": "401:error.code=-32000", "/ui/api/c\tGET\tplain\tAdminKey": "200"})
        said, _, table = self.run_bless(log(new))
        self.assertIn("/ui/api/a: 1 changed", said)
        self.assertIn("/ui/api/c: 1 added", said)
        self.assertIn("/ui/api/a\tGET\tplain\tNoKey\t401:error.code=-32000\n", table)
        self.assertTrue(table.startswith(bless.HEADER))

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
        said, why, _ = self.run_bless(log(OLD, count=len(OLD) + 1))
        self.assertIsNone(said)
        self.assertIn("lines but the test computed", why)

    def test_refuses_a_line_without_five_fields(self):
        said, why, _ = self.run_bless(log(OLD, extra="/ui/api/a\tGET\tAdminKey\t200\n"))
        self.assertIsNone(said)
        self.assertIn("not 5", why)

    def test_refuses_a_duplicate_key(self):
        said, why, _ = self.run_bless(log(OLD, extra="/ui/api/b\tGET\tplain\tAdminKey\t403\n"))
        self.assertIsNone(said)
        self.assertIn("listed twice", why)

    def test_refuses_a_well_formed_table_missing_a_route(self):
        short = {k: v for k, v in OLD.items() if not k.startswith("/ui/api/b\t")}
        said, why, _ = self.run_bless(log(short))
        self.assertIsNone(said)
        self.assertIn("/ui/api/b", why)

    def test_an_allowed_removal_passes_for_that_route_only(self):
        short = {k: v for k, v in OLD.items() if not k.startswith("/ui/api/b\t")}
        said, _, table = self.run_bless(log(short), allowed=frozenset({"/ui/api/b"}))
        self.assertIn("/ui/api/b: 1 removed", said)
        self.assertNotIn("/ui/api/b\t", table)

    def test_an_allowed_removal_does_not_cover_another_missing_route(self):
        only_a_admin = {"/ui/api/a\tGET\tplain\tAdminKey": "200"}
        said, why, _ = self.run_bless(log(only_a_admin), allowed=frozenset({"/ui/api/b"}))
        self.assertIsNone(said)
        self.assertIn("/ui/api/a", why)

    def test_a_removal_is_matched_on_the_exact_route(self):
        short = {k: v for k, v in OLD.items() if not k.startswith("/ui/api/b\t")}
        self.assertIsNone(self.run_bless(log(short), allowed=frozenset({"/ui/api"}))[0])


if __name__ == "__main__":
    unittest.main()
