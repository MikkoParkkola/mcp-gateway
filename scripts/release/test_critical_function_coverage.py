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

    def run_rows(self, rows, unmeasured="fail"):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        return cfc.main(
            ["--inventory", str(inventory), "--lcov", str(self.lcov), "--root", str(self.root),
             "--unmeasured", unmeasured]
        )

    def statuses(self, rows):
        inventory = self.root / "inv.tsv"
        inventory.write_text(HEADER + "".join(r + "\n" for r in rows))
        return [r[0] for r in cfc.grade(self.root, inventory, self.lcov)]

    def test_a_fully_covered_function_passes_despite_a_brace_in_a_string(self):
        row = "src/lib.rs\tguard\t1\tcritical\td\tguard\tr"
        self.assertEqual(self.statuses([row]), ["ok"])
        self.assertEqual(self.run_rows([row]), 0)

    def test_one_missed_line_of_five_is_below_the_floor(self):
        row = "src/lib.rs\tcheck\t1\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["BELOW"])
        self.assertEqual(self.run_rows([row]), 1)

    def test_occurrence_picks_the_compiled_out_variant_which_fails_unless_reported(self):
        row = "src/lib.rs\tcheck\t2\tcritical\td\tcheck\tr"
        self.assertEqual(self.statuses([row]), ["UNMEASURED"])
        self.assertEqual(self.run_rows([row]), 1)
        self.assertEqual(self.run_rows([row], unmeasured="report"), 0)

    def test_a_vanished_function_always_fails(self):
        row = "src/lib.rs\tgone\t1\tcritical\td\tgone\tr"
        self.assertEqual(self.statuses([row]), ["MISSING"])
        self.assertEqual(self.run_rows([row], unmeasured="report"), 1)

    def test_standard_rows_are_not_graded(self):
        row = "src/lib.rs\tcheck\t1\tstandard\tborderline\tcheck\tr"
        self.assertEqual(self.statuses([row]), [])
        self.assertEqual(self.run_rows([row]), 0)


if __name__ == "__main__":
    unittest.main()
