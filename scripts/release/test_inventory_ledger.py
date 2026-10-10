#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for inventory_ledger.py (MIK-8279): fragments merge without conflict,
and every reader sees the same rows."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import inventory_ledger as ledger

CRIT = "docs/release/v4.0.0-critical-functions.tsv"
UNENF = "docs/release/v4.0.0-unenforcing-functions.tsv"
CRIT_HEADER = "path\tfn\toccurrence\ttier\tcategory\tqualified\treason\n"
UNENF_HEADER = "path\tfn\toccurrence\treason\n"


def crit_row(path: str, fn: str, n: int = 1) -> str:
    return f"{path}\t{fn}\t{n}\tcritical\td\t{fn}\tchecks the owner\n"


def unenf_row(path: str, fn: str, n: int = 1) -> str:
    return f"{path}\t{fn}\t{n}\tformats a message\n"


class Repo:
    """A scratch git repository holding the two base ledgers."""

    def __init__(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.git("init", "-q", "-b", "base")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.write(CRIT, CRIT_HEADER + crit_row("src/a.rs", "existing"))
        self.write(UNENF, UNENF_HEADER + unenf_row("src/a.rs", "helper"))
        self.commit("base")

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, check=check)

    def write(self, path: str, text: str) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def branch(self, name: str, path: str, text: str) -> None:
        self.git("checkout", "-q", "-b", name, "base")
        self.write(path, text)
        self.commit(name)

    def keys(self, which: str, base: str) -> set:
        return {ledger.key(r) for r in ledger.load_rev(self.root, "HEAD", which, base)}

    def close(self) -> None:
        self.dir.cleanup()


class FragmentsMerge(unittest.TestCase):
    """AC1/AC2: two branches that each add a row merge in either order with no
    conflict, for both ledgers, and the merged tree carries both rows."""

    def run_case(self, which: str, base: str, a: tuple, b: tuple, order: tuple) -> None:
        repo = Repo()
        self.addCleanup(repo.close)
        repo.branch("a", *a)
        repo.branch("b", *b)
        repo.git("checkout", "-q", "-b", "merged", "base")
        for name in order:
            done = repo.git("merge", "-q", "--no-edit", name, check=False)
            self.assertEqual(done.returncode, 0, f"merging {name} conflicted: {done.stdout}{done.stderr}")
        keys = repo.keys(which, base)
        self.assertIn(("src/x.rs", "f", 1), keys)
        self.assertIn((b[1].split("\t")[0], b[1].split("\t")[1], 1), keys)

    def test_critical_rows_for_different_files_in_both_orders(self) -> None:
        a = ("docs/release/inventory.d/101.critical.tsv", crit_row("src/x.rs", "f"))
        b = ("docs/release/inventory.d/102.critical.tsv", crit_row("src/y.rs", "g"))
        for order in (("a", "b"), ("b", "a")):
            with self.subTest(order=order):
                self.run_case(ledger.CRITICAL, CRIT, a, b, order)

    def test_critical_rows_for_the_same_file_in_both_orders(self) -> None:
        a = ("docs/release/inventory.d/101.critical.tsv", crit_row("src/x.rs", "f"))
        b = ("docs/release/inventory.d/102.critical.tsv", crit_row("src/x.rs", "g"))
        for order in (("a", "b"), ("b", "a")):
            with self.subTest(order=order):
                self.run_case(ledger.CRITICAL, CRIT, a, b, order)

    def test_unenforcing_rows_in_both_orders_for_one_and_two_files(self) -> None:
        a = ("docs/release/inventory.d/101.unenforcing.tsv", unenf_row("src/x.rs", "f"))
        for other in ("src/y.rs", "src/x.rs"):
            b = ("docs/release/inventory.d/102.unenforcing.tsv", unenf_row(other, "g"))
            for order in (("a", "b"), ("b", "a")):
                with self.subTest(other=other, order=order):
                    self.run_case(ledger.UNENFORCING, UNENF, a, b, order)

    def test_two_appends_to_the_base_still_conflict(self) -> None:
        """Control: the old way (appending to the base TSV) conflicts, so the
        rows above merge because they are fragments, not by luck."""
        repo = Repo()
        self.addCleanup(repo.close)
        base = (repo.root / CRIT).read_text()
        repo.branch("a", CRIT, base + crit_row("src/x.rs", "f"))
        repo.branch("b", CRIT, base + crit_row("src/y.rs", "g"))
        repo.git("checkout", "-q", "-b", "merged", "base")
        repo.git("merge", "-q", "--no-edit", "a")
        self.assertNotEqual(repo.git("merge", "-q", "--no-edit", "b", check=False).returncode, 0)


class ReadersAgree(unittest.TestCase):
    """AC3: the git loader and the filesystem loader each return exactly the
    expected keys, so a loader that skips fragments, or reads the other
    ledger's suffix, fails here."""

    def test_both_loaders_return_the_expected_keys_per_ledger(self) -> None:
        repo = Repo()
        self.addCleanup(repo.close)
        repo.write("docs/release/inventory.d/7.critical.tsv", "# a comment\n\n" + crit_row("src/c.rs", "c"))
        repo.write("docs/release/inventory.d/7-2.critical.tsv", crit_row("src/d.rs", "d"))
        repo.write("docs/release/inventory.d/8.unenforcing.tsv", unenf_row("src/u.rs", "u"))
        repo.write("docs/release/inventory.d/.gitkeep", "")
        repo.commit("fragments")
        critical = {("src/a.rs", "existing", 1), ("src/c.rs", "c", 1), ("src/d.rs", "d", 1)}
        unenforcing = {("src/a.rs", "helper", 1), ("src/u.rs", "u", 1)}
        self.assertEqual(repo.keys(ledger.CRITICAL, CRIT), critical)
        self.assertEqual(repo.keys(ledger.UNENFORCING, UNENF), unenforcing)
        files = {ledger.key(r) for r in ledger.load_files(ledger.CRITICAL, repo.root / CRIT)}
        self.assertEqual(files, critical)
        files = {ledger.key(r) for r in ledger.load_files(ledger.UNENFORCING, repo.root / UNENF)}
        self.assertEqual(files, unenforcing)

    def test_a_missing_fragment_directory_is_no_fragments(self) -> None:
        repo = Repo()
        self.addCleanup(repo.close)
        self.assertEqual(repo.keys(ledger.CRITICAL, CRIT), {("src/a.rs", "existing", 1)})
        rows = ledger.load_files(ledger.CRITICAL, repo.root / CRIT)
        self.assertEqual({ledger.key(r) for r in rows}, {("src/a.rs", "existing", 1)})

    def test_fragments_are_read_beside_the_given_base_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "inv.tsv"
            base.write_text(CRIT_HEADER + crit_row("src/a.rs", "a"))
            (Path(tmp) / "inventory.d").mkdir()
            (Path(tmp) / "inventory.d" / "1.critical.tsv").write_text(crit_row("src/b.rs", "b"))
            keys = {ledger.key(r) for r in ledger.load_files(ledger.CRITICAL, base)}
            self.assertEqual(keys, {("src/a.rs", "a", 1), ("src/b.rs", "b", 1)})


    def test_the_two_scripts_read_through_the_ledger(self) -> None:
        """The readers themselves, not only the loaders: a script that went
        back to reading the base TSV alone would miss the fragment rows."""
        import importlib.util

        here = Path(__file__).resolve().parent
        loaded = {}
        for name in ("check_inventory_rows", "critical_function_coverage"):
            spec = importlib.util.spec_from_file_location(f"{name}_under_test", here / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded[name] = module
        repo = Repo()
        self.addCleanup(repo.close)
        repo.write("docs/release/inventory.d/3.critical.tsv", crit_row("src/c.rs", "c"))
        repo.write("docs/release/inventory.d/4.unenforcing.tsv", unenf_row("src/u.rs", "u"))
        repo.commit("fragments")
        cir = loaded["check_inventory_rows"]
        cir.ROOT = repo.root
        head = repo.git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(cir.rows(head, cir.INVENTORY), {("src/a.rs", "existing", 1), ("src/c.rs", "c", 1)})
        self.assertEqual(cir.rows(head, cir.UNENFORCING), {("src/a.rs", "helper", 1), ("src/u.rs", "u", 1)})
        graded = {ledger.key(r) for r in loaded["critical_function_coverage"].read_inventory(repo.root / CRIT)}
        self.assertEqual(graded, {("src/a.rs", "existing", 1), ("src/c.rs", "c", 1)})


def problems(which: str, base: str, fragments: list) -> list[str]:
    try:
        ledger.merge(which, ("base.tsv", base), fragments)
    except ledger.LedgerError as error:
        return error.problems
    return []


class OneKeyOnce(unittest.TestCase):
    """A key is stated once: within a ledger (base and fragments alike) and
    across the two ledgers."""

    def test_two_base_rows_with_one_key_fail_naming_both(self) -> None:
        found = problems(ledger.CRITICAL, CRIT_HEADER + crit_row("src/a.rs", "f") * 2, [])
        self.assertEqual(len(found), 1)
        self.assertIn("base.tsv:3", found[0])
        self.assertIn("base.tsv:2", found[0])

    def test_a_fragment_restating_a_base_row_fails(self) -> None:
        found = problems(ledger.CRITICAL, CRIT_HEADER + crit_row("src/a.rs", "f"),
                         [("inventory.d/9.critical.tsv", crit_row("src/a.rs", "f"))])
        self.assertTrue(found and "inventory.d/9.critical.tsv:1" in found[0] and "base.tsv:2" in found[0])

    def test_two_fragments_with_one_key_fail(self) -> None:
        row = crit_row("src/a.rs", "g")
        found = problems(ledger.CRITICAL, CRIT_HEADER,
                         [("inventory.d/1.critical.tsv", row), ("inventory.d/2.critical.tsv", row)])
        self.assertEqual(len(found), 1)

    def test_a_key_in_both_ledgers_is_reported_on_the_unenforcing_row(self) -> None:
        critical = ledger.merge(ledger.CRITICAL, ("c.tsv", CRIT_HEADER + crit_row("src/a.rs", "f")), [])
        unenforcing = ledger.merge(ledger.UNENFORCING, ("u.tsv", UNENF_HEADER + unenf_row("src/a.rs", "f")), [])
        found = ledger.overlap(critical, unenforcing)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].startswith("u.tsv:2") and "c.tsv:2" in found[0])

    def test_the_live_ledgers_state_each_key_once(self) -> None:
        root = Path(__file__).resolve().parents[2]
        critical = ledger.load_files(ledger.CRITICAL, root / CRIT)
        unenforcing = ledger.load_files(ledger.UNENFORCING, root / UNENF)
        self.assertEqual(ledger.overlap(critical, unenforcing), [])


class RowsAreChecked(unittest.TestCase):
    """Every validation rule, one failing case each; a rule that passes the
    bad case lets an ungraded row ship."""

    def test_each_rule_rejects_its_case(self) -> None:
        cases = {
            "columns": crit_row("src/a.rs", "f").replace("\tchecks the owner", ""),
            "empty fn": "src/a.rs\t\t1\tcritical\td\tf\tr\n",
            "occurrence": "src/a.rs\tf\t0\tcritical\td\tf\tr\n",
            "not a number": "src/a.rs\tf\tone\tcritical\td\tf\tr\n",
            "tier": "src/a.rs\tf\t1\tcriticl\td\tf\tr\n",
            "reason": "src/a.rs\tf\t1\tcritical\td\tf\t \n",
        }
        for rule, row in cases.items():
            with self.subTest(rule=rule):
                self.assertTrue(problems(ledger.CRITICAL, CRIT_HEADER, [("1.critical.tsv", row)]))
        for rule, row in {"reason": "src/a.rs\tf\t1\t\n", "empty path": "\tf\t1\tr\n"}.items():
            with self.subTest(ledger="unenforcing", rule=rule):
                self.assertTrue(problems(ledger.UNENFORCING, UNENF_HEADER, [("1.unenforcing.tsv", row)]))

    def test_a_base_without_its_header_fails(self) -> None:
        self.assertTrue(problems(ledger.UNENFORCING, unenf_row("src/a.rs", "f"), []))

    def test_fragment_names(self) -> None:
        for name in ("x.tsv", "12.tsv", "12.critical.csv.tsv", "a-1.critical.tsv"):
            with self.subTest(bad=name):
                self.assertTrue(problems(ledger.CRITICAL, CRIT_HEADER, [(name, "")]))
        for name in ("12.critical.tsv", "12-3.critical.tsv", "12-3.unenforcing.tsv"):
            with self.subTest(good=name):
                self.assertEqual(problems(ledger.CRITICAL, CRIT_HEADER, [(name, "")]), [])

    def test_a_misnamed_fragment_fails_the_critical_reader_too(self) -> None:
        """The listing sees every *.tsv, so the grader cannot grade past one."""
        self.assertTrue(problems(ledger.CRITICAL, CRIT_HEADER, [("inventory.d/x.tsv", unenf_row("s", "f"))]))


class EditsInPlace(unittest.TestCase):
    """AC4: an edit, a removal and a move between ledgers are made where the
    row lives; the readers then see only the new state."""

    def test_edit_remove_and_move(self) -> None:
        repo = Repo()
        self.addCleanup(repo.close)
        repo.write("docs/release/inventory.d/5.critical.tsv", crit_row("src/m.rs", "moving") + crit_row("src/r.rs", "gone"))
        repo.commit("rows")
        repo.write(CRIT, CRIT_HEADER + crit_row("src/a.rs", "existing").replace("critical\td", "standard\td"))
        repo.write("docs/release/inventory.d/5.critical.tsv", "")
        repo.write("docs/release/inventory.d/6.unenforcing.tsv", unenf_row("src/m.rs", "moving"))
        repo.commit("edit, remove, move")
        critical = ledger.load_rev(repo.root, "HEAD", ledger.CRITICAL, CRIT)
        self.assertEqual([(ledger.key(r), r["tier"]) for r in critical], [(("src/a.rs", "existing", 1), "standard")])
        self.assertEqual(repo.keys(ledger.UNENFORCING, UNENF), {("src/a.rs", "helper", 1), ("src/m.rs", "moving", 1)})


if __name__ == "__main__":
    unittest.main()
