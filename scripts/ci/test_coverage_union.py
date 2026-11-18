#!/usr/bin/env python3
"""First red rows for the per-part export command and its two real graders."""

import importlib.util
import json
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


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

    def fixture(self):
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
        objects = [*self.parts, self.other]
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


if __name__ == "__main__":
    unittest.main()
