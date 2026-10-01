# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""critical_function_coverage.py grades each Critical function on its own lines.

A fixture crate with two same-named functions (the second picked by
occurrence), a fully covered one, one below the floor, one compiled out
(no DA records) and one that no longer exists.
"""

import importlib.util
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cfc", HERE / "critical_function_coverage.py")
cfc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cfc)

SOURCE = """\
fn guard(x: u8) -> bool {
    let s = "}";
    x > 1
}

#[cfg(unix)]
fn check(x: u8) -> bool {
    if x == 0 {
        return false;
    }
    true
}

#[cfg(windows)]
fn check(x: u8) -> bool {
    x != 0
}

fn helper() {}
"""

# guard 1-4 all hit; unix check 7-12: line 9 never hit; windows check absent.
LCOV = """\
SF:/build/repo/src/lib.rs
DA:1,3
DA:2,3
DA:3,3
DA:4,3
DA:7,2
DA:8,2
DA:9,0
DA:11,2
DA:12,2
DA:19,1
end_of_record
"""

HEADER = "# fixture\npath\tfn\toccurrence\ttier\tcategory\tqualified\treason\n"


class CriticalFunctionCoverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.dir.name)
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text(SOURCE)
        self.lcov = root / "cov.lcov"
        self.lcov.write_text(LCOV)
        self.root = root

    def tearDown(self):
        self.dir.cleanup()

    def run_rows(self, rows, lcovs=None):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        args = ["--inventory", str(inventory), "--root", str(self.root)]
        for lcov in lcovs or [self.lcov]:
            args += ["--lcov", str(lcov)]
        return cfc.main(args)

    def statuses(self, rows):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        return [r[0] for r in cfc.grade(self.root, inventory, [self.lcov])]

    def test_a_fully_covered_function_passes_despite_a_brace_in_a_string(self):
        row = "src/lib.rs\tguard\t1\tcritical\td\tguard\tr"
        self.assertEqual(self.statuses([row]), ["ok"])
        self.assertEqual(self.run_rows([row]), 0)

    def test_one_missed_line_of_five_is_below_the_floor(self):
        row = "src/lib.rs\tcheck\t1\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["BELOW"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_a_variant_no_report_measured_fails(self):
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["UNMEASURED"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_the_other_platforms_report_grades_its_variant(self):
        # The Windows run's report measures lines 15-17; the union passes.
        windows = self.root / "windows.lcov"
        windows.write_text("SF:C:\\build\\repo\\src\\lib.rs\nDA:15,1\nDA:16,1\nDA:17,1\nend_of_record\n")
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        self.assertEqual(self.run_rows([row], lcovs=[self.lcov, windows]), 0)

    def test_a_checkout_under_a_directory_named_src_still_resolves(self):
        nested = self.root / "nested.lcov"
        nested.write_text(LCOV.replace("SF:/build/repo/src/lib.rs", "SF:/src/mcp-gateway/src/lib.rs"))
        row = "src/lib.rs\tguard\t1\tcritical\td\tguard\tr"
        self.assertEqual(self.run_rows([row], lcovs=[nested]), 0)

    def test_a_vanished_function_always_fails(self):
        row = "src/lib.rs\tgone\t1\tcritical\td\tgone\tr"
        self.assertEqual(self.statuses([row]), ["MISSING"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_standard_rows_are_not_graded(self):
        row = "src/lib.rs\tcheck\t1\tstandard\tborderline\tcheck\tr"
        self.assertEqual(self.statuses([row]), [])
        self.assertEqual(self.run_rows([row]), 0)



class InventoryResolves(unittest.TestCase):
    """Every row of the real inventory names a function that exists.

    Code moves: a refactor that relocates an enforcing function must move its
    row too, or the release grade would report it MISSING.
    """

    def test_every_inventory_row_resolves_in_the_tree(self):
        root = HERE.parent.parent
        rows = cfc.read_inventory(root / "docs/release/v4.0.0-critical-functions.tsv")
        self.assertTrue(rows)
        unresolved = []
        for row in rows:
            source = root / row["path"]
            lines = source.read_text().splitlines() if source.exists() else []
            if cfc.fn_line(lines, row["fn"], int(row["occurrence"])) is None:
                unresolved.append(f"{row['path']}:{row['fn']}#{row['occurrence']}")
        self.assertEqual(unresolved, [], "move these rows to the file that now defines them")


if __name__ == "__main__":
    unittest.main()
