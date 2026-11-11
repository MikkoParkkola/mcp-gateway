#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for split-ui-matrix.py: one file per route, frozen digest names, no lost row."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

SCRIPT = Path(__file__).resolve().parent / "split-ui-matrix.py"
ROUTER = "src/gateway/router"
D1, D2 = "a" * 12, "b" * 12


def load():
    spec = importlib.util.spec_from_file_location("split_ui_matrix", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree(root: str, rows: list[str], bodies: str | None = None) -> Path:
    router = Path(root) / ROUTER
    router.mkdir(parents=True)
    (router / "ui_access_matrix.tsv").write_text("# header\n" + "\n".join(rows) + "\n")
    if bodies is not None:
        (router / "ui_access_matrix_bodies.tsv").write_text(bodies)
    return router


def row(path: str, caller: str, answer: str) -> str:
    return f"{path}\tGET\tplain\t{caller}\t{answer}"


class Split(unittest.TestCase):
    def test_slugs_are_distinct_and_file_safe(self):
        m = load()
        self.assertEqual(m.slug("/dashboard"), "__dashboard")
        self.assertEqual(m.slug("/ui/api/backends/{name}/signin"), "backends___name___signin")
        self.assertEqual(m.slug("/ui/api/activity/{id}"), "activity___id_")

    def test_every_row_lands_in_its_routes_file_and_the_old_file_goes(self):
        m = load()
        with TemporaryDirectory() as tmp:
            router = tree(tmp, [row("/ui/api/a", "NoKey", "401"), row("/ui/api/b", "NoKey", "405")])
            self.assertEqual(m.split(tmp)[0], 2)
            self.assertFalse((router / "ui_access_matrix.tsv").exists())
            a = (router / "ui_access_matrix.d/a.tsv").read_text()
            self.assertIn(row("/ui/api/a", "NoKey", "401"), a)
            self.assertNotIn("/ui/api/b", a)

    def test_a_digest_on_three_routes_is_named_and_a_rarer_one_stays_inline(self):
        m = load()
        with TemporaryDirectory() as tmp:
            rows = [row(f"/ui/api/r{i}", "NoKey", f"401:{D1}") for i in range(3)]
            rows.append(row("/ui/api/r0", "Bearer", f"403:{D2}"))
            router = tree(tmp, rows)
            self.assertEqual(m.split(tmp), (3, 1))
            self.assertIn(f"b_{D1[:8]}\t{D1}", (router / "ui_access_matrix_bodies.tsv").read_text())
            text = (router / "ui_access_matrix.d/r0.tsv").read_text()
            self.assertIn(f"401:@b_{D1[:8]}", text)
            self.assertIn(f"403:{D2}", text)

    def test_names_in_an_existing_bodies_file_are_frozen(self):
        m = load()
        with TemporaryDirectory() as tmp:
            bodies = f"# header\nrefusal\t{D2}\tkept\n"
            router = tree(tmp, [row("/ui/api/r", "NoKey", f"403:{D2}")], bodies)
            m.split(tmp)
            self.assertEqual((router / "ui_access_matrix_bodies.tsv").read_text(), bodies)
            self.assertIn("403:@refusal", (router / "ui_access_matrix.d/r.tsv").read_text())

    def test_scoped_and_store_attributes_become_header_lines(self):
        m = load()
        with TemporaryDirectory() as tmp:
            router = tree(tmp, [row("/ui/api/control-plane", "NoKey", "401")])
            m.split(tmp)
            text = (router / "ui_access_matrix.d/control-plane.tsv").read_text()
            self.assertIn("#@ scoped\n", text)
            self.assertIn("#@ store_reads\n", text)
            self.assertNotIn("store_writes", text)

    def test_it_refuses_to_overwrite_existing_fragments(self):
        m = load()
        with TemporaryDirectory() as tmp:
            router = tree(tmp, [row("/ui/api/a", "NoKey", "401")])
            (router / "ui_access_matrix.d").mkdir()
            (router / "ui_access_matrix.d/a.tsv").write_text("kept\n")
            with self.assertRaises(SystemExit):
                m.split(tmp)
            self.assertEqual((router / "ui_access_matrix.d/a.tsv").read_text(), "kept\n")
            self.assertTrue((router / "ui_access_matrix.tsv").exists())

    def test_bodies_from_another_file_supply_the_frozen_names(self):
        m = load()
        with TemporaryDirectory() as tmp:
            router = tree(tmp, [row("/ui/api/r", "NoKey", f"403:{D2}")])
            donor = Path(tmp) / "donor.tsv"
            donor.write_text(f"# header\nrefusal\t{D2}\tfrom the line\n")
            m.split(tmp, str(donor))
            self.assertIn("403:@refusal", (router / "ui_access_matrix.d/r.tsv").read_text())
            self.assertEqual((router / "ui_access_matrix_bodies.tsv").read_text(), donor.read_text())

    def test_a_malformed_line_stops_the_run(self):
        m = load()
        with TemporaryDirectory() as tmp:
            tree(tmp, ["/ui/api/a\tGET\tplain"])
            with self.assertRaises(SystemExit):
                m.split(tmp)


if __name__ == "__main__":
    unittest.main()
