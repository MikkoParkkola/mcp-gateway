#!/usr/bin/env python3
"""Red rows for the per-part export command and its real downstream checks."""

from collections import Counter
from copy import deepcopy
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from coverage_shards import CANARY_FILE, CANARY_FN, canary


ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).resolve().parent / "testdata/coverage_union"
SCRIPT = ROOT / "scripts/ci/coverage_union.py"
FAKE = DATA / "fake_llvm_cov.py"
PATH_GRADER = ROOT / "scripts/release/critical_path_coverage.py"
FUNCTION_GRADER = ROOT / "scripts/release/critical_function_coverage.py"
F_FILE = "src/gateway/server/backend_source.rs"
F_LINES = dict.fromkeys(range(317, 324), 5)


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def read_records(text):
    """Small fixture oracle; it is independent of the future union reader."""
    files = {}
    current = None
    for line in text.splitlines():
        if line.startswith("SF:"):
            current = files.setdefault(line[3:], {"functions": {}, "calls": {}, "lines": {}})
        elif line.startswith("FN:"):
            start, name = line[3:].split(",", 1)
            current["functions"][name] = int(start)
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            current["calls"][name] = int(count)
        elif line.startswith("DA:"):
            number, count = line[3:].split(",")
            current["lines"][int(number)] = int(count)
    return files


def without_other_objects(argv, keep):
    """Drop pairs only: even the position and spelling of options must survive."""
    result = []
    index = 0
    while index < len(argv):
        if argv[index] == "-object":
            if argv[index + 1] in keep:
                result.extend(argv[index:index + 2])
            index += 2
        else:
            result.append(argv[index])
            index += 1
    return result


class CoverageUnionRows(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="coverage union ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.table_path = self.root / "table.json"
        self.calls = self.root / "calls.jsonl"
        self.env = {**os.environ, "FAKE_LLVM_COV_TABLE": str(self.table_path),
                    "FAKE_LLVM_COV_LOG": str(self.calls), "PYTHONDONTWRITEBYTECODE": "1"}
        self.log = self.root / "report-lcov.log"
        self.single = self.root / "linux-single.lcov"
        self.out = self.root / "linux.lcov"

    def run_command(self, argv):
        return subprocess.run([str(arg) for arg in argv], cwd=ROOT, env=self.env,
                              capture_output=True, text=True, timeout=30)

    def success(self, done):
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def save_table(self, table):
        self.table_path.write_text(json.dumps(table), encoding="utf-8")

    def fixture(self, other_count=1):
        p1 = next(iter(read_records((DATA / "F-p1.txt").read_text()).values()))
        p4 = next(iter(read_records((DATA / "F-p4.txt").read_text()).values()))
        # Pin the real evidence before constructing any synthetic objects.
        self.assertEqual(p1["lines"], dict.fromkeys(F_LINES, 0))
        self.assertEqual(p4["lines"], F_LINES)
        self.assertEqual(p1["functions"], p4["functions"])
        self.assertEqual(set(p1["calls"].values()), {0})
        self.assertEqual(set(p4["calls"].values()), {5})
        self.f_path = write(self.root, F_FILE, "\n" * 316 +
                            "fn upstream_starts() {\n" + "    work();\n" * 5 + "}\n")
        self.inventory = write(self.root, "critical.tsv",
            "path\tfn\toccurrence\ttier\tcategory\tqualified\treason\n"
            f"{F_FILE}\tupstream_starts\t1\tcritical\tstartup\tupstream_starts\tLost part counts\n")
        table = {"objects": {}, "records": {}}
        self.parts = []
        for number in range(1, 6):
            obj = str(write(self.root, f"target/debug/deps/p{number}/lib-part", "object\n"))
            self.parts.append(obj)
            table["objects"][obj] = [
                {"file": str(self.f_path), "name": name, "start": start,
                 "hash": f"part-{number}", "lines": list(p4["lines"])}
                for name, start in p4["functions"].items()
            ]
        for name, calls in p4["calls"].items():
            table["records"][f"{name}|part-4"] = {"calls": calls, "lines": p4["lines"]}

        self.other = str(write(self.root, "target/debug/deps/integration", "object\n"))
        table["objects"][self.other] = []
        spec = importlib.util.spec_from_file_location("path_grader_fixture", PATH_GRADER)
        grader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(grader)
        # Include every prefix, even overlaps with startup, so a missing path
        # cannot explain the failure or conceal the recovery of F's seven lines.
        prefixes = {prefix for _, paths, _ in grader.PATHS for prefix in paths}
        for index, prefix in enumerate(sorted(prefixes - {"src/gateway/server/"})):
            filename = prefix + "covered.rs" if prefix.endswith("/") else prefix
            source = write(self.root, filename, "fn covered() {}\n")
            name = f"covered_{index}"
            table["objects"][self.other].append(
                {"file": str(source), "name": name, "start": 1, "hash": "shared", "lines": [1]})
            table["records"][f"{name}|shared"] = {"calls": 1, "lines": {1: 1}}
        self.others = [self.other]
        for number in range(1, other_count):
            obj = str(write(self.root, f"target/debug/deps/integration-{number}", "object\n"))
            self.others.append(obj)
            table["objects"][obj] = deepcopy(table["objects"][self.other])
        self.save_table(table)

        profile = write(self.root, "target/fixture.profdata", "fixture profile\n")
        captured = next(line for line in (DATA / "running-line.txt").read_text().splitlines()
                        if line.lstrip().startswith("Running `"))
        command = captured.split("`", 1)[1].rsplit("`", 1)[0]
        original = shlex.split(command)
        # Text replacements preserve the captured regex, option order and
        # quoting; only argv[0], the profile path and OBJECTS are substituted.
        command = command.replace(original[0], shlex.quote(str(FAKE)), 1)
        profile_arg = next(arg for arg in original if arg.startswith("-instr-profile="))
        command = command.replace(profile_arg, shlex.quote(f"-instr-profile={profile}"), 1)
        objects = [*self.parts, *self.others]
        pairs = [token for obj in objects for token in ("-object", obj)]
        command = command.replace("OBJECTS", shlex.join(pairs), 1)
        self.log.write_text(captured.replace(captured.split("`", 1)[1].rsplit("`", 1)[0], command) + "\n")
        self.argv = shlex.split(command)
        self.assertEqual(self.argv, [str(FAKE), *[
            f"-instr-profile={profile}" if arg == profile_arg else arg
            for arg in original[1:-1]], *pairs])
        self.assertTrue(profile.is_file())
        done = self.run_command(self.argv)
        self.success(done)
        self.single.write_text(done.stdout, encoding="utf-8")
        self.assertEqual(read_records(done.stdout)[str(self.f_path)]["lines"], dict.fromkeys(F_LINES, 0))
        # SINGLE's control export is not one of the command's N+1 exports.
        self.calls.write_text("")

    def run_union(self):
        done = self.run_command([sys.executable, SCRIPT, self.log, self.single, self.out])
        self.success(done)

    def grade_function(self, report):
        return self.run_command([sys.executable, FUNCTION_GRADER, "--root", self.root,
                                 "--inventory", self.inventory, "--lcov", report])

    def add_function(self, table, obj, name, calls, lines, *, start=10, filename=None):
        filename = filename or str(self.union_path)
        record_hash = f"hash-{self.parts.index(obj) + 1}"
        function = {"file": filename, "name": name, "start": start,
                    "hash": record_hash, "lines": list(lines)}
        table["objects"][obj].append(function)
        table["records"][f"{name}|{record_hash}"] = {"calls": calls, "lines": lines}

    def join_fixture(self, first=0, fourth=0):
        self.fixture()
        self.union_path = write(self.root, "src/union.rs", "\n" * 30)
        self.union_name = "joined_function"
        table = json.loads(self.table_path.read_text())
        for index, obj in enumerate(self.parts):
            count = first if index == 0 else fourth if index == 3 else 0
            self.add_function(table, obj, self.union_name, count, {10: count, 11: 0})
        return table

    def prepare_exports(self, table):
        """Exercise every fake response before the command can hide a fixture error."""
        self.save_table(table)
        single = self.run_command(self.argv)
        self.success(single)
        self.single.write_text(single.stdout, encoding="utf-8")
        self.single_records = read_records(single.stdout)
        self.exports = {}
        for key, objects in [("other", self.others), *((obj, [obj]) for obj in self.parts)]:
            done = self.run_command(without_other_objects(self.argv, set(objects)))
            self.success(done)
            self.assertTrue(read_records(done.stdout), "fixture export must contain records")
            self.exports[key] = done.stdout
        # Only calls made by coverage_union.py belong in grouping assertions.
        self.calls.write_text("")

    def union_record(self):
        return read_records(self.out.read_text())[str(self.union_path)]

    def reject_union(self, *messages):
        done = self.run_command([sys.executable, SCRIPT, self.log, self.single, self.out])
        # Missing implementation must stay red, even for expected rejection cases.
        self.assertTrue(SCRIPT.is_file(), "missing command: scripts/ci/coverage_union.py")
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.out.exists(), "a failed gate must not publish OUT")
        for message in messages:
            self.assertIn(message, done.stdout + done.stderr)

    def assert_recounted(self, report):
        records = read_records(report)
        summaries = {}
        for line in report.splitlines():
            tag, _, value = line.partition(":")
            if tag == "SF":
                current = value
                self.assertNotIn(current, summaries, "OUT must join duplicate file records")
                summaries[current] = {}
            elif tag in {"LF", "LH", "FNF", "FNH"}:
                self.assertNotIn(tag, summaries[current])
                summaries[current][tag] = int(value)
        for filename, record in records.items():
            self.assertEqual(set(record["calls"]), set(record["functions"]))
            self.assertEqual(summaries[filename], {
                "LF": len(record["lines"]),
                "LH": sum(count > 0 for count in record["lines"].values()),
                "FNF": len(record["functions"]),
                "FNH": sum(count > 0 for count in record["calls"].values()),
            }, filename)

    def test_F1_fake_reproduces_shared_and_mismatched_hashes(self):
        # Shared hashes read the same aggregate record once, without a warning.
        name = "shared_function"
        function = {"file": "src/example.rs", "name": name, "start": 317,
                    "hash": "shared", "lines": list(F_LINES)}
        table = {"objects": {"a": [function], "b": [dict(function)]},
                 "records": {f"{name}|shared": {"calls": 5, "lines": F_LINES}}}
        self.save_table(table)
        shared = self.run_command([FAKE, "export", "-format=lcov", "-object", "a", "-object", "b"])
        self.success(shared)
        self.assertEqual(shared.stderr, "")
        records = read_records(shared.stdout)["src/example.rs"]
        self.assertEqual(records["calls"], {name: 5})
        self.assertEqual(records["lines"], F_LINES)

        # A single object still warns when only another hash has profile data.
        table["objects"]["a"][0]["hash"] = "unrecorded"
        self.save_table(table)
        mismatch = self.run_command([FAKE, "export", "-format=lcov", "-object", "a"])
        self.success(mismatch)
        self.assertEqual(mismatch.stderr, "warning: 1 functions have mismatched data\n")
        records = read_records(mismatch.stdout)["src/example.rs"]
        self.assertEqual(records["calls"], {name: 0})
        self.assertEqual(records["lines"], dict.fromkeys(F_LINES, 0))

    def test_E1_union_recovers_startup_path(self):
        self.fixture()
        single = self.run_command([sys.executable, PATH_GRADER, self.single])
        # Feed actual lcov, just as the new report step will. JSON-only input
        # support must fail here rather than be hidden by a JSON conversion.
        self.assertEqual(single.returncode, 1,
                         "SINGLE must be graded and fail startup, not be refused:\n" + single.stdout + single.stderr)
        startup = next(line for line in single.stdout.splitlines() if line.startswith("startup"))
        self.assertIn("below", startup)
        self.run_union()
        self.assertEqual(read_records(self.out.read_text())[str(self.f_path)]["lines"], F_LINES)
        union = self.run_command([sys.executable, PATH_GRADER, self.out])
        self.success(union)
        self.assertRegex(union.stdout, r"(?m)^startup\s+.*100\.00%\s+ok$")
        self.assertIn("paths failing: 0", union.stdout)

    def test_E2_union_recovers_critical_function(self):
        self.fixture()
        single = self.grade_function(self.single)
        self.assertEqual(single.returncode, 1, single.stdout + single.stderr)
        self.assertRegex(single.stdout, r"BELOW\s+0\.00%\s+0/7\s+")
        self.assertIn("lines 317-323", single.stdout)
        self.assertIn("critical rows failing: 1", single.stdout)
        self.run_union()
        union = self.grade_function(self.out)
        self.success(union)
        self.assertRegex(union.stdout, r"ok\s+100\.00%\s+7/7\s+")
        self.assertIn("lines 317-323", union.stdout)
        self.assertIn("critical rows graded: 1", union.stdout)
        self.assertIn("critical rows failing: 0", union.stdout)

    def test_A1_exports_preserve_logged_argv(self):
        self.fixture()
        self.run_union()
        actual = [json.loads(line) for line in self.calls.read_text().splitlines()]
        expected = [without_other_objects(self.argv, {obj}) for obj in [self.other, *self.parts]]
        self.assertEqual(len(actual), 6, "five parts plus one non-part export, no replay of SINGLE")
        # Group execution order is not specified; each argv's internal order is.
        self.assertCountEqual(actual, expected)

    def check_line_maximum(self, first, fourth):
        table = self.join_fixture(first, fourth)
        for obj in self.parts:
            self.add_function(table, obj, "never_called", 0, {20: 0}, start=20)
        self.prepare_exports(table)
        # Recount from the exports, not from SINGLE's first-object answer.
        expected = {}
        for export in self.exports.values():
            for filename, record in read_records(export).items():
                lines = expected.setdefault(filename, {})
                for line, count in record["lines"].items():
                    lines[line] = max(lines.get(line, 0), count)
        self.assertEqual(expected[str(self.union_path)], {10: 7, 11: 0, 20: 0})
        self.run_union()
        report = self.out.read_text()
        self.assertEqual({path: record["lines"] for path, record in read_records(report).items()},
                         expected)
        self.assert_recounted(report)

    def test_U1_larger_line_count_in_earlier_export(self):
        # Both orders distinguish max from sum, boolean coverage and replacement.
        self.check_line_maximum(7, 2)

    def test_U1_larger_line_count_in_later_export(self):
        self.check_line_maximum(2, 7)

    def test_U1_branch_record_is_rejected(self):
        table = self.join_fixture()
        table["objects"][self.parts[3]][-1]["branches"] = [[10, 0, 0, 1]]
        self.prepare_exports(table)
        self.assertIn("BRDA:10,0,0,1\n", self.exports[self.parts[3]])
        self.assertNotIn("BRDA:", self.single.read_text())
        self.reject_union("branch record")

    def test_U2_objects_have_exactly_one_group(self):
        # Multiple non-part objects catch implementations that export each alone.
        self.fixture(other_count=3)
        self.run_union()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        groups = [[argv[i + 1] for i, arg in enumerate(argv) if arg == "-object"]
                  for argv in calls]
        self.assertEqual(len(groups), len(self.parts) + 1)
        self.assertCountEqual([tuple(group) for group in groups],
                              [tuple(self.others), *((obj,) for obj in self.parts)])
        self.assertEqual(Counter(obj for group in groups for obj in group),
                         Counter([*self.parts, *self.others]))

    def override_single(self, table):
        # Deliberately inconsistent fake answers isolate the join's baseline gate.
        # OUT is always produced by the command, never patched by the test.
        override = deepcopy({key: table[key] for key in ("objects", "records")})
        table["export_overrides"] = {json.dumps([*self.parts, *self.others]): override}
        return override

    def test_U3_missing_zero_line_is_rejected(self):
        table = self.join_fixture()
        single = self.override_single(table)
        single["objects"][self.parts[0]][-1]["lines"].append(29)
        single["records"][f"{self.union_name}|hash-1"]["lines"][29] = 0
        self.prepare_exports(table)
        self.assertEqual(self.single_records[str(self.union_path)]["lines"][29], 0)
        for obj in self.parts:
            self.assertNotIn(29, read_records(self.exports[obj])[str(self.union_path)]["lines"])
        self.reject_union("gate (b)")

    def test_U3_lost_line_coverage_is_rejected(self):
        table = self.join_fixture()
        single = self.override_single(table)
        single["records"][f"{self.union_name}|hash-1"]["lines"][10] = 1
        self.prepare_exports(table)
        self.assertEqual(self.single_records[str(self.union_path)]["lines"][10], 1)
        for obj in self.parts:
            self.assertEqual(read_records(self.exports[obj])[str(self.union_path)]["lines"][10], 0)
        self.reject_union("gate (b)")

    def test_U3_preserved_lines_pass(self):
        table = self.join_fixture(2, 5)
        self.prepare_exports(table)
        self.assertEqual(self.single_records[str(self.union_path)]["lines"], {10: 2, 11: 0})
        self.run_union()
        self.assertEqual(self.union_record()["lines"], {10: 5, 11: 0})

    def test_U3b_missing_function_is_rejected(self):
        table = self.join_fixture()
        single = self.override_single(table)
        # Give the extra function an already-listed line so only FN is missing.
        self.add_function(single, self.parts[0], "single_only", 0, {11: 0}, start=11)
        self.prepare_exports(table)
        self.assertIn("single_only", self.single_records[str(self.union_path)]["functions"])
        for obj in self.parts:
            record = read_records(self.exports[obj])[str(self.union_path)]
            self.assertNotIn("single_only", record["functions"])
            self.assertEqual(record["lines"], self.single_records[str(self.union_path)]["lines"])
        self.reject_union("gate (b)", self.union_name)

    def test_U3b_lower_function_count_is_rejected(self):
        table = self.join_fixture(1, 2)
        single = self.override_single(table)
        single["records"][f"{self.union_name}|hash-1"]["calls"] = 3
        self.prepare_exports(table)
        self.assertEqual(self.single_records[str(self.union_path)]["calls"][self.union_name], 3)
        self.assertEqual(max(read_records(self.exports[obj])[str(self.union_path)]["calls"]
                             [self.union_name] for obj in self.parts), 2)
        # The line gate must pass, leaving only the function count defect.
        baseline = self.single_records[str(self.union_path)]["lines"]
        for line, count in baseline.items():
            counts = [read_records(self.exports[obj])[str(self.union_path)]["lines"][line]
                      for obj in self.parts]
            self.assertTrue(count == 0 or max(counts) > 0)
        self.reject_union("gate (b)", self.union_name)

    def test_U3b_preserved_functions_pass(self):
        table = self.join_fixture(2, 3)
        self.prepare_exports(table)
        self.assertEqual(self.single_records[str(self.union_path)]["calls"], {self.union_name: 2})
        self.run_union()
        self.assertEqual(self.union_record()["functions"], {self.union_name: 10})
        self.assertEqual(self.union_record()["calls"], {self.union_name: 3})

    def test_U4_part_only_file_and_function_survive(self):
        table = self.join_fixture()
        filename = str(write(self.root, "src/part_four_only.rs", "\n" * 25))
        self.add_function(table, self.parts[3], "part_four_only", 6, {22: 6, 23: 0},
                          start=22, filename=filename)
        self.prepare_exports(table)
        for group, export in self.exports.items():
            self.assertEqual(filename in read_records(export), group == self.parts[3])
        expected = {"functions": {"part_four_only": 22}, "calls": {"part_four_only": 6},
                    "lines": {22: 6, 23: 0}}
        self.assertEqual(read_records(self.exports[self.parts[3]])[filename], expected)
        self.run_union()
        self.assertEqual(read_records(self.out.read_text())[filename], expected)

    def test_J1_conflicting_function_starts_are_rejected(self):
        table = self.join_fixture()
        table["objects"][self.parts[3]][-1]["start"] = 12
        self.prepare_exports(table)
        self.assertEqual(read_records(self.exports[self.parts[0]])[str(self.union_path)]
                         ["functions"], {self.union_name: 10})
        self.assertEqual(read_records(self.exports[self.parts[3]])[str(self.union_path)]
                         ["functions"], {self.union_name: 12})
        self.reject_union(self.union_name, "10", "12")

    def test_J1_equal_function_starts_pass(self):
        table = self.join_fixture()
        self.prepare_exports(table)
        for obj in self.parts:
            self.assertEqual(read_records(self.exports[obj])[str(self.union_path)]
                             ["functions"], {self.union_name: 10})
        self.run_union()
        self.assertEqual(self.union_record()["functions"], {self.union_name: 10})

    def check_function_maximum(self, first, fourth, expected):
        table = self.join_fixture(first, fourth)
        self.prepare_exports(table)
        for obj, count in ((self.parts[0], first), (self.parts[3], fourth)):
            self.assertEqual(read_records(self.exports[obj])[str(self.union_path)]
                             ["calls"], {self.union_name: count})
        self.run_union()
        self.assertEqual(self.union_record()["calls"], {self.union_name: expected})

    def test_J2_earlier_function_count_wins(self):
        self.check_function_maximum(5, 0, 5)

    def test_J2_later_function_count_wins(self):
        self.check_function_maximum(0, 5, 5)

    def test_J2_equal_function_counts_are_not_added(self):
        self.check_function_maximum(3, 3, 3)

    def test_J3_shared_aggregate_is_counted_once_and_passes_gate(self):
        table = self.join_fixture()
        # Both mappings read the very same aggregate profile record, not two runs.
        for obj in (self.parts[0], self.parts[3]):
            table["objects"][obj][-1]["hash"] = "shared-aggregate"
        table["records"][f"{self.union_name}|shared-aggregate"] = {
            "calls": 8, "lines": {10: 8, 11: 0}}
        self.prepare_exports(table)
        for report in (self.single.read_text(), self.exports[self.parts[0]],
                       self.exports[self.parts[3]]):
            self.assertEqual(read_records(report)[str(self.union_path)]["calls"],
                             {self.union_name: 8})
        self.run_union()
        self.assertEqual(self.union_record()["calls"], {self.union_name: 8})

    def check_canary(self, fourth_calls, expected):
        table = self.join_fixture()
        filename = str(write(self.root, CANARY_FILE, "\n" * 12))
        for index, obj in enumerate(self.parts):
            self.add_function(table, obj, CANARY_FN, fourth_calls if index == 3 else 0,
                              {10: 0, 11: 0}, filename=filename)
        for record in table["records"].values():
            record["lines"] = dict.fromkeys(record["lines"], 0)
        self.prepare_exports(table)
        self.assertEqual(canary(self.single.read_text()), [])
        for export in self.exports.values():
            self.assertTrue(all(count == 0 for record in read_records(export).values()
                                for count in record["lines"].values()))
        for obj in self.parts:
            record = read_records(self.exports[obj])[filename]
            self.assertEqual(record["lines"], {10: 0, 11: 0})
            self.assertEqual(canary(self.exports[obj]), expected if obj == self.parts[3] else [])
        self.run_union()
        self.assertEqual(canary(self.out.read_text()), expected)

    def test_C1_uncalled_canary_passes(self):
        self.check_canary(0, [])

    def test_C1_canary_called_only_in_fourth_part_is_detected(self):
        # Only FNDA changes: DA coverage cannot accidentally trigger this check.
        self.check_canary(1, ["canary called 1 times"])


if __name__ == "__main__":
    unittest.main()
