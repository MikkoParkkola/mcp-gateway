#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Red rows for the per-part export command and its real downstream checks."""

from collections import Counter
from copy import deepcopy
import importlib.util
import json
import os
import shlex
import shutil
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

    def run_union(self, script=SCRIPT):
        done = self.run_command([sys.executable, script, self.log, self.single, self.out])
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

    def reject_union(self, *messages, script=SCRIPT):
        previous = self.out.read_bytes() if self.out.exists() else None
        done = self.run_command([sys.executable, script, self.log, self.single, self.out])
        # Missing implementation must stay red, even for expected rejection cases.
        self.assertTrue(script.is_file(), "missing command: scripts/ci/coverage_union.py")
        self.assertNotEqual(done.returncode, 0, done.stdout + done.stderr)
        if previous is None:
            self.assertFalse(self.out.exists(), "a failed gate must not publish OUT")
        else:
            self.assertEqual(self.out.read_bytes(), previous, "a failed gate must preserve OUT")
        for message in messages:
            self.assertIn(message, done.stdout + done.stderr)
        return done

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
        self.reject_union("gate (b)", "single_only")

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

    def log_command(self, argv):
        return f"     Running `{shlex.join(argv)}`\n"

    def reject_object_spelling(self, spelling):
        self.fixture()
        index = self.argv.index("-object")
        path = self.argv[index + 1]
        # Keep the other groups intact: each fixture changes just one spelling.
        tokens = {
            "equals": [f"-object={path}"],
            "long": ["--object", path],
            "long_equals": [f"--object={path}"],
            "flag": ["-object", "-show-regions"],
            "trailing": ["-object"],
            "positional": [path],
        }[spelling]
        argv = self.argv[:index] + self.argv[index + 2:]
        if spelling == "positional":
            index = argv.index("export") + 1
        elif spelling == "trailing":
            index = len(argv)
        argv[index:index] = tokens
        self.log.write_text(self.log_command(argv))
        self.reject_union(tokens[0])

    def test_O1_equals_object_is_rejected(self):
        self.reject_object_spelling("equals")

    def test_O1_long_object_is_rejected(self):
        self.reject_object_spelling("long")

    def test_O1_long_equals_object_is_rejected(self):
        self.reject_object_spelling("long_equals")

    def test_O1_object_followed_by_flag_is_rejected(self):
        self.reject_object_spelling("flag")

    def test_O1_trailing_object_is_rejected(self):
        self.reject_object_spelling("trailing")

    def test_O1_positional_object_is_rejected(self):
        self.reject_object_spelling("positional")

    def test_O1_object_path_pairs_pass(self):
        self.fixture()
        self.run_union()

    def check_failed_export(self, group):
        self.fixture()
        objects = self.others if group == "other" else [self.parts[3]]
        table = json.loads(self.table_path.read_text())
        table["exit_status"] = {json.dumps(objects): 1}
        self.save_table(table)
        # Prove the fake wrote valid-looking lcov before returning failure.
        done = self.run_command(without_other_objects(self.argv, set(objects)))
        self.assertEqual(done.returncode, 1)
        self.assertTrue(read_records(done.stdout))
        self.assertTrue(done.stdout.endswith("end_of_record\n"))
        self.calls.write_text("")
        self.reject_union("llvm-cov export failed", group)

    def test_X1_other_export_nonzero_is_rejected(self):
        self.check_failed_export("other")

    def test_X1_fourth_export_nonzero_is_rejected(self):
        self.check_failed_export("p4")

    def other_mismatch(self, table):
        # One mapping has a profile under a different hash: exactly one warning.
        table["objects"][self.other][0]["hash"] = "unrecorded"
        return table

    def existing_out(self):
        self.out.write_bytes(b"previous published report\r\n\x00\xff\n")
        return self.out.read_bytes()

    def test_X2_existing_out_survives_gate_a(self):
        self.fixture()
        table = self.other_mismatch(json.loads(self.table_path.read_text()))
        self.prepare_exports(table)
        previous = self.existing_out()
        self.reject_union("mismatched data", "other")
        self.assertEqual(self.out.read_bytes(), previous)

    def test_X2_existing_out_survives_gate_b(self):
        table = self.join_fixture()
        single = self.override_single(table)
        # Only a DA count changes, leaving gate (a) and the function gate intact.
        single["records"][f"{self.union_name}|hash-1"]["lines"][10] = 1
        self.prepare_exports(table)
        previous = self.existing_out()
        self.reject_union("gate (b)")
        self.assertEqual(self.out.read_bytes(), previous)

    def test_X2_passing_run_replaces_existing_out(self):
        self.fixture()
        previous = self.existing_out()
        self.run_union()
        self.assertNotEqual(self.out.read_bytes(), previous)
        self.assertEqual(read_records(self.out.read_text())[str(self.f_path)]["lines"], F_LINES)
        self.assert_recounted(self.out.read_text())

    def test_X3_stray_reports_are_not_joined(self):
        self.fixture()
        table = json.loads(self.table_path.read_text())
        self.prepare_exports(table)
        # Neither filename is an output of this run; globbing would ingest both.
        stray_files = []
        for index, name in enumerate(("p9.lcov", "stale.lcov"), start=1):
            filename = str(self.root / f"src/stray_{index}.rs")
            stray_files.append(filename)
            write(self.out.parent, name,
                  f"SF:{filename}\nFN:901,stray_{index}\nFNDA:1,stray_{index}\n"
                  "FNF:1\nFNH:1\nDA:901,1\nLF:1\nLH:1\nend_of_record\n")
            for export in self.exports.values():
                self.assertNotIn(filename, read_records(export))
        self.run_union()
        records = read_records(self.out.read_text())
        for filename in stray_files:
            self.assertNotIn(filename, records)
        expected_files = {filename for export in self.exports.values()
                          for filename in read_records(export)}
        self.assertEqual(set(records), expected_files)

    def test_X4_hash_seeds_produce_identical_bytes(self):
        self.fixture()
        table = json.loads(self.table_path.read_text())
        filenames = []
        # Many distinct string keys expose set/dict ordering that tiny inputs hide.
        for file_index in range(17):
            filename = str(write(self.root, f"src/order_{file_index}.rs", "\n" * 30))
            filenames.append(filename)
            for function_index in range(11):
                name = f"order_{file_index}_function_{function_index}"
                line = function_index + 1
                for part_index, obj in enumerate(self.parts):
                    count = (file_index + function_index + part_index) % 9
                    self.add_function(table, obj, name, count, {line: count},
                                      start=line, filename=filename)
        self.prepare_exports(table)
        results = []
        for seed in (0, 1, 12345):
            self.env["PYTHONHASHSEED"] = str(seed)
            # Remove OUT so an implementation cannot pass by leaving it untouched.
            self.out.unlink(missing_ok=True)
            done = self.run_command([sys.executable, SCRIPT, self.log, self.single, self.out])
            results.append((seed, done, self.out.read_bytes() if self.out.exists() else None))
        for seed, done, report in results:
            self.success(done)
            self.assertIsNotNone(report, f"seed {seed} did not write OUT")
            records = read_records(report.decode("utf-8"))
            for filename in filenames:
                self.assertEqual(len(records[filename]["functions"]), 11)
            self.assert_recounted(report.decode("utf-8"))
        self.assertEqual(results[0][2], results[1][2])
        self.assertEqual(results[0][2], results[2][2])

    def test_M1_zero_running_lines_is_rejected(self):
        self.fixture()
        self.log.write_text("report had no command\n")
        self.reject_union("Running", "0")

    def test_M1_two_running_lines_are_rejected(self):
        self.fixture()
        self.log.write_text(self.log.read_text() * 2)
        self.reject_union("Running", "2")

    def test_M1_non_lcov_line_beside_lcov_is_ignored(self):
        self.fixture()
        other = [arg for arg in self.argv if arg != "-format=lcov"]
        self.log.write_text(self.log_command(other) + self.log.read_text())
        self.run_union()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 6)
        self.assertTrue(all("-format=lcov" in argv for argv in calls))

    def test_M1_non_lcov_line_alone_is_rejected(self):
        self.fixture()
        self.log.write_text(self.log_command([arg for arg in self.argv if arg != "-format=lcov"]))
        self.reject_union("Running", "0")

    def test_M1_matching_line_without_objects_is_rejected(self):
        self.fixture()
        self.log.write_text(self.log_command(without_other_objects(self.argv, set())))
        self.reject_union("no -object")

    def test_M1_missing_profile_is_rejected(self):
        self.fixture()
        profile = next(arg.split("=", 1)[1] for arg in self.argv
                       if arg.startswith("-instr-profile="))
        Path(profile).unlink()
        self.reject_union("-instr-profile")

    def three_part_tree(self, groups=(1, 2, 3), duplicate=False):
        self.fixture()
        table = json.loads(self.table_path.read_text())
        self.parts = [self.parts[number - 1] for number in groups]
        if duplicate:
            second = str(write(self.root, "target/debug/deps/p2/second-object", "object\n"))
            table["objects"][second] = deepcopy(table["objects"][self.parts[1]])
            self.parts.append(second)
        self.argv = without_other_objects(self.argv, set()) + [
            token for obj in [*self.parts, *self.others] for token in ("-object", obj)]
        self.log.write_text(self.log_command(self.argv))
        self.prepare_exports(table)
        # Run from the original cwd, but resolve N and lib_union beside the copy.
        # This rejects hardcoded N=5 and reading the build script through cwd.
        tree = self.root / "three-part-repo"
        write(tree, "scripts/dev/test-parts-build.rs", "const N: u32 = 3;\n")
        script = tree / "scripts/ci/coverage_union.py"
        script.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/ci/lib_union.py", script.parent / "lib_union.py")
        self.assertTrue(SCRIPT.is_file(), "missing command: scripts/ci/coverage_union.py")
        shutil.copy2(SCRIPT, script)
        return script

    def test_M2_three_part_build_passes(self):
        script = self.three_part_tree()
        self.run_union(script)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 4)
        self.assertCountEqual(calls, [without_other_objects(self.argv, set(objects))
                                     for objects in [self.others, *([obj] for obj in self.parts)]])

    def test_M2_missing_second_folder_is_rejected(self):
        script = self.three_part_tree(groups=(1, 3))
        self.reject_folder_set(script, "p2")

    def test_M2_extra_fourth_folder_is_rejected(self):
        script = self.three_part_tree(groups=(1, 2, 3, 4))
        self.reject_folder_set(script, "p4")

    def reject_folder_set(self, script, folder):
        done = self.reject_union(script=script)
        message = done.stdout + done.stderr
        # The diagnostic may name the offending folder or the expected set/range.
        self.assertTrue(folder in message or ("p1" in message and "p3" in message), message)

    def test_M2_two_objects_in_second_folder_are_rejected(self):
        script = self.three_part_tree(duplicate=True)
        self.reject_union("p2", script=script)

    def test_M3_zero_other_and_part_counts_are_recorded(self):
        self.fixture()
        table = json.loads(self.table_path.read_text())
        # Each part has a different warning count; p4 and other print no warning.
        for number, obj in enumerate(self.parts, start=1):
            for extra in range(number if number != 4 else 0):
                name = f"mismatch_{number}_{extra}"
                self.add_function(table, obj, name, 0, {400 + extra: 0},
                                  start=400 + extra, filename=str(self.f_path))
                table["records"].pop(f"{name}|hash-{number}")
                table["records"][f"{name}|different-hash"] = {"calls": 1, "lines": {}}
        self.prepare_exports(table)
        expected_counts = [0, 3, 4, 5, 0, 7]
        for objects, count in zip([self.others, *([obj] for obj in self.parts)], expected_counts):
            done = self.run_command(without_other_objects(self.argv, set(objects)))
            self.success(done)
            expected = f"warning: {count} functions have mismatched data\n" if count else ""
            self.assertEqual(done.stderr, expected)
        self.calls.write_text("")
        self.run_union()
        self.assertEqual((self.out.parent / "mismatch.txt").read_text(),
                         "other 0\np1 3\np2 4\np3 5\np4 0\np5 7\n")

    def test_M3_one_other_mismatch_is_rejected(self):
        self.fixture()
        table = self.other_mismatch(json.loads(self.table_path.read_text()))
        self.prepare_exports(table)
        done = self.run_command(without_other_objects(self.argv, set(self.others)))
        self.success(done)
        self.assertEqual(done.stderr, "warning: 1 functions have mismatched data\n")
        self.calls.write_text("")
        self.reject_union("mismatched data", "other")

    def check_unparsed_mismatch(self, group):
        self.fixture()
        objects = self.others if group == "other" else [self.parts[3]]
        table = json.loads(self.table_path.read_text())
        warning = "warning: mismatched data could not be counted\n"
        table["export_overrides"] = {json.dumps(objects): {"stderr": warning}}
        self.prepare_exports(table)
        done = self.run_command(without_other_objects(self.argv, set(objects)))
        self.success(done)
        self.assertEqual(done.stderr, warning)
        self.calls.write_text("")
        self.reject_union("unparsed")

    def test_M3_unparsed_other_warning_is_rejected(self):
        self.check_unparsed_mismatch("other")

    def test_M3_unparsed_part_warning_is_rejected(self):
        self.check_unparsed_mismatch("p4")


if __name__ == "__main__":
    unittest.main()
