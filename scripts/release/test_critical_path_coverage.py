# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Grade synthetic lcov reports through the path grader's public CLI.

Each report starts with every path passing, then changes the lines relevant to
one rule. DA records are the measurement; LF/LH are deliberately not an oracle.
"""

from decimal import Decimal
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "critical_path_coverage.py"
SPEC = importlib.util.spec_from_file_location("cpc", SCRIPT)
cpc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cpc)

ROOT = "/home/runner/work/mcp-gateway/mcp-gateway/"
FLOORS = {
    "startup": 92.84,
    "OAuth": 79.67,
    "HTTP dispatch": 94.69,
    "stdio dispatch": 89.66,
    "bridge": 90.49,
    "tasks": 94.87,
    "account paths": 95.93,
}


def source_path(prefix):
    return prefix + ("" if prefix.endswith(".rs") else "mod.rs")


def record(filename, lines, *, lf=None, lh=None):
    """Allow repeated line numbers and independently chosen summary counters."""
    lines = list(lines)
    fields = [f"SF:{filename}"]
    fields.extend(f"DA:{number},{count}" for number, count in lines)
    fields.extend([
        f"LF:{len(lines) if lf is None else lf}",
        f"LH:{sum(count > 0 for _, count in lines) if lh is None else lh}",
        "end_of_record",
    ])
    return "\n".join(fields) + "\n"


def entry(path, covered, count):
    return record(ROOT + path, ((line, int(line <= covered)) for line in range(1, count + 1)))


def report(overrides=None):
    """Every path at 99% on its first prefix, unless overridden by name."""
    overrides = overrides or {}
    files = [entry("src/unrelated/mod.rs", 0, 1000)]
    for name, prefixes, _ in cpc.PATHS:
        files.extend(overrides.get(name, [entry(source_path(prefixes[0]), 99, 100)]))
    return "".join(files)


def table_rows(section, *, include_header=False):
    """Markdown table cells, optionally retaining a Named path header."""
    rows = []
    for line in section.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if include_header or cells[0] not in ("Named path", ""):
            rows.append(cells)
    return rows


class CriticalPathCoverage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = pathlib.Path(temporary.name)
        self.path = self.directory / "coverage.lcov"

    def run_path(self, path):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(path)],
            capture_output=True, text=True, check=False,
        )

    def run_report(self, document):
        self.path.write_text(document, encoding="utf-8")
        return self.run_path(self.path)

    def assert_status(self, result, expected):
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)

    def graded(self, document, expected=0):
        result = self.run_report(document)
        # Assert the public status first: an unsupported input is a test failure,
        # not an exception from reaching into a parser that does not exist yet.
        self.assert_status(result, expected)
        rows = {}
        for match in re.finditer(
            r"^(.+?)\s+files=\s*(\d+)\s+(\d+)/(\d+)\s+([\d.]+)%\s+(.+)$",
            result.stdout, re.MULTILINE,
        ):
            name, files, covered, total, percent, verdict = match.groups()
            rows[name.strip()] = (
                name.strip(), int(files), int(covered), int(total), float(percent),
                [] if verdict == "ok" else verdict.split("; "),
            )
        self.assertEqual(set(FLOORS), set(rows), result.stdout)
        self.assertIn(f"paths failing: {sum(bool(row[5]) for row in rows.values())}", result.stdout)
        return rows

    def failures(self, document, expected=1):
        return {name: row[5] for name, row in self.graded(document, expected).items()}

    def test_a_missing_report_is_named_and_is_not_a_graded_fail(self):
        # A missing upload is refused distinctly from a measured failing path.
        missing = self.directory / "absent.lcov"
        result = self.run_path(missing)
        self.assert_status(result, 3)
        self.assertEqual(cpc.INPUT_MISSING, result.returncode)
        self.assertIn(f"input missing: {missing}", result.stdout)
        self.assertNotIn("paths failing", result.stdout)
        # The same invocation must grade once a usable upload is available.
        self.graded(report())

    def test_an_empty_or_unreadable_report_counts_as_missing(self):
        empty = self.directory / "empty.lcov"
        empty.write_text("")
        folder = self.directory / "folder.lcov"
        folder.mkdir()
        for bad in (empty, folder):
            with self.subTest(bad=bad.name):
                result = self.run_path(bad)
                self.assert_status(result, 3)
                self.assertIn(f"input missing: {bad}", result.stdout)
        self.graded(report())

    def test_an_unparseable_report_counts_as_missing(self):
        # A truncated upload and an invalid DA record are not graded failures.
        for text in ("SF:src/oauth/a.rs\nDA:1,1\n", "SF:src/oauth/a.rs\nDA:1\nend_of_record\n"):
            with self.subTest(text=text):
                result = self.run_report(text)
                self.assert_status(result, 3)
                self.assertIn("corrupt lcov", result.stdout + result.stderr)
        self.graded(report())

    def test_both_graders_share_one_input_missing_status(self):
        spec = importlib.util.spec_from_file_location("cfc", HERE / "critical_function_coverage.py")
        cfc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cfc)
        self.assertEqual(3, cpc.INPUT_MISSING)
        self.assertEqual(cpc.INPUT_MISSING, cfc.INPUT_MISSING)
        self.assert_status(self.run_path(self.directory / "missing.lcov"), cfc.INPUT_MISSING)
        # The shared refusal status must not be returned for a usable report.
        self.graded(report())

    def test_every_path_at_99_percent_passes(self):
        self.assertEqual({name: [] for name in FLOORS}, self.failures(report(), 0))

    def test_a_path_below_the_floor_fails_alone(self):
        result = self.failures(report({"bridge": [entry("src/gateway/input_bridge.rs", 79, 100)]}))
        self.assertIn("below the 80% floor", result["bridge"])
        self.assertEqual({"bridge"}, {name for name, reasons in result.items() if reasons})

    def test_a_path_above_the_floor_but_below_its_baseline_fails(self):
        # 94/100 clears 80% but misses tasks' converted baseline of 94.87%.
        result = self.failures(report({"tasks": [entry("src/gateway/task_service/a.rs", 94, 100)]}))
        self.assertEqual(["below its 94.87% baseline"], result["tasks"])

    def test_lines_are_summed_over_every_prefix_of_a_path(self):
        # 50/100 + 100/100 = 75% over HTTP dispatch's two prefixes.
        rows = self.graded(report({"HTTP dispatch": [
            entry("src/transport/http/a.rs", 50, 100),
            entry("src/gateway/router/b.rs", 100, 100),
        ]}), 1)
        self.assertEqual((2, 150, 200, 75.0), rows["HTTP dispatch"][1:5])
        self.assertIn("below the 80% floor", rows["HTTP dispatch"][5])

    def test_the_split_owner_file_still_grades_as_tasks(self):
        # The owner file belongs to tasks, but its adjacent test child does not.
        # Dropping owner.rs reads 100%; taking the entire directory reads 50%.
        owner = entry("src/gateway/router/handlers/tasks/owner.rs", 50, 100)
        rest = entry("src/gateway/task_service/a.rs", 100, 100)
        child = entry("src/gateway/router/handlers/tasks/intent_tests.rs", 0, 100)
        rows = self.graded(report({"tasks": [owner, rest, child]}), 1)
        self.assertEqual((2, 150, 200), rows["tasks"][1:4])
        self.assertIn("below the 80% floor", rows["tasks"][5])

    def test_a_path_with_no_measured_file_fails(self):
        self.assertIn("no measured file", self.failures(report({"OAuth": []}))["OAuth"])

    def test_a_file_outside_every_prefix_counts_nowhere(self):
        rows = self.graded(report())
        self.assertEqual(sum(row[3] for row in rows.values()), 100 * len(FLOORS))

    def test_windows_and_relative_filenames_resolve(self):
        for filename in ("C:\\work\\repo\\src\\oauth\\a.rs", "src/oauth/a.rs"):
            with self.subTest(filename=filename):
                self.assertEqual("src/oauth/a.rs", cpc.relative(filename))
                rows = self.graded(report({"OAuth": [record(filename, [(1, 1)])]}))
                self.assertEqual((1, 1, 1, 100.0), rows["OAuth"][1:5])

    def test_exit_status_follows_the_verdict(self):
        for document, status in [
            (report(), 0),
            (report({"startup": [entry("src/gateway/server/a.rs", 1, 100)]}), 1),
        ]:
            with self.subTest(status=status):
                self.assert_status(self.run_report(document), status)

    def test_g1_da_lines_override_lf_lh_summary(self):
        # Summary counters include overlaps; four distinct lines define 75%.
        file = record(ROOT + "src/oauth/a.rs", [(1, 1), (2, 2), (3, 1), (4, 0)], lf=10, lh=10)
        row = self.graded(report({"OAuth": [file]}), 1)["OAuth"]
        self.assertEqual((1, 3, 4, 75.0), row[1:5])
        self.assertIn("below the 80% floor", row[5])

    def test_g2_each_effective_floor_is_inclusive(self):
        for name, floor in FLOORS.items():
            prefix = next(prefixes[0] for path, prefixes, _ in cpc.PATHS if path == name)
            # Integer DA counts make each percentage exact to a hundredth.
            threshold = int(max(Decimal("80"), Decimal(str(floor))) * 100)
            for covered, status in ((threshold, 0), (threshold - 1, 1)):
                with self.subTest(path=name, covered=covered):
                    rows = self.graded(report({name: [entry(source_path(prefix), covered, 10000)]}), status)
                    self.assertEqual((1, covered, 10000, covered / 100), rows[name][1:5])
                    self.assertEqual({name} if status else set(), {
                        path for path, row in rows.items() if row[5]
                    })

    def test_g3_json_summary_is_not_an_lcov_report(self):
        # A formerly valid, passing summary must not silently use the old metric.
        document = json.dumps({"data": [{"files": [
            {"filename": ROOT + source_path(prefixes[0]),
             "summary": {"lines": {"covered": 99, "count": 100}}}
            for _, prefixes, _ in cpc.PATHS
        ]}]})
        result = self.run_report(document)
        self.assert_status(result, 3)
        self.assertIn("not an lcov report", result.stdout + result.stderr)

    def test_g4_plain_text_is_not_graded(self):
        # Guard: both the old JSON reader and the strict lcov reader refuse this.
        self.assert_status(self.run_report("this is not a coverage report\n"), 3)

    def test_g4b_da_requires_exactly_two_integer_fields(self):
        for da in ("DA:1,no", "DA:no,1", "DA:1,1.5", "DA:1.5,1", "DA:1", "DA:,1", "DA:1,", "DA:1,1,2"):
            with self.subTest(da=da):
                result = self.run_report(report() + f"SF:src/oauth/bad.rs\n{da}\nend_of_record\n")
                self.assert_status(result, 3)
                self.assertIn("corrupt lcov", result.stdout + result.stderr)

    def test_g5_every_record_requires_end_of_record(self):
        unfinished = "SF:src/oauth/truncated.rs\nDA:1,1\n"
        for suffix in ("", entry("src/oauth/next.rs", 1, 1)):
            with self.subTest(position="interior" if suffix else "last"):
                result = self.run_report(report() + unfinished + suffix)
                self.assert_status(result, 3)
                self.assertIn("corrupt lcov", result.stdout + result.stderr)

    def test_g6_duplicate_files_and_lines_count_once(self):
        # Complementary coverage requires both copies, in either order. A zero
        # everywhere stays uncovered; a line repeated within a record counts once.
        filename = ROOT + "src/oauth/repeated.rs"
        first = record(filename, [(1, 5), (1, 0), (2, 0), (3, 0)])
        second = record(filename, [(1, 0), (2, 7), (3, 0), (4, 1)])
        for copies in ([first, second], [second, first]):
            with self.subTest(order="first" if copies[0] == first else "reversed"):
                row = self.graded(report({"OAuth": copies}), 1)["OAuth"]
                self.assertEqual((1, 3, 4, 75.0), row[1:5])
                self.assertIn("below the 80% floor", row[5])

    def test_g7_a_prefix_needs_a_measured_da_line(self):
        # An SF with inflated LF/LH but no DA still supplies no measurement.
        for files, status in (([], 1), ([record(ROOT + "src/oauth/empty.rs", [], lf=10, lh=10)], 1),
                              ([entry("src/oauth/measured.rs", 1, 1)], 0)):
            with self.subTest(files=len(files), status=status):
                row = self.graded(report({"OAuth": files}), status)["OAuth"]
                if status:
                    self.assertEqual((0, 0), row[2:4])
                    self.assertIn("no measured file", row[5])
                else:
                    self.assertEqual((1, 1, 1, 100.0, []), row[1:])

    def test_g8_report_only_source_paths_are_graded(self):
        # A graded revision can contain a source file absent from this checkout.
        path = f"src/oauth/{self.directory.name}/report_only.rs"
        self.assertFalse((HERE.parents[1] / path).exists())
        for covered, status in ((1, 0), (0, 1)):
            with self.subTest(covered=covered):
                row = self.graded(report({"OAuth": [entry(path, covered, 1)]}), status)["OAuth"]
                self.assertEqual((1, covered, 1, covered * 100.0), row[1:5])
                self.assertNotIn("no measured file", row[5])

    def test_g9_converted_floors_are_literal(self):
        self.assertEqual(80, cpc.FLOOR)
        self.assertEqual(7, len(cpc.PATHS))
        self.assertEqual(FLOORS, {name: floor for name, _, floor in cpc.PATHS})

    def test_d1_paths_match_the_coverage_doc(self):
        # Keep the mapping cross-check; read converted floors from their header,
        # never from the retained historical measurement or a restated fixture.
        doc = (HERE.parents[1] / "docs/release/v4.0.0-critical-path-coverage.md").read_text(encoding="utf-8")
        mapping_section = doc.split("## The mapping", 1)[1].split("\n## ", 1)[0]
        mapping = {
            cells[0]: re.findall(r"`([^`]+)`", cells[1])
            for cells in table_rows(mapping_section) if "`" in cells[1]
        }
        self.assertEqual(mapping, {name: prefixes for name, prefixes, _ in cpc.PATHS})
        tables = re.findall(r"(?:^\|[^\n]*\n?)+", doc, re.MULTILINE)
        converted = []
        for table in tables:
            rows = table_rows(table, include_header=True)
            if rows and any("new floor" in cell.lower() for cell in rows[0]):
                converted.append(rows)
        self.assertEqual(1, len(converted), "expected one markdown table with a 'new floor' header")
        header, *body = converted[0]
        column = next(i for i, cell in enumerate(header) if "new floor" in cell.lower())
        floors = {}
        for cells in body:
            self.assertGreater(len(cells), column, cells)
            value = re.fullmatch(r"\s*(\d+(?:\.\d+)?)%?\s*", cells[column])
            self.assertIsNotNone(value, f"invalid new floor: {cells[column]}")
            self.assertNotIn(cells[0], floors, "duplicate path in new floor table")
            floors[cells[0]] = float(value.group(1))
        self.assertEqual({name: floor for name, _, floor in cpc.PATHS}, floors)


if __name__ == "__main__":
    unittest.main()
