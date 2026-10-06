# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""critical_path_coverage.py grades each named path against its floor and baseline.

A synthetic llvm-cov summary puts every path at a chosen figure; each test moves
one path and checks that exactly that path's verdict changes.
"""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cpc", HERE / "critical_path_coverage.py")
cpc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cpc)

ROOT = "/home/runner/work/mcp-gateway/mcp-gateway/"


def entry(path, covered, count):
    return {"filename": ROOT + path, "summary": {"lines": {"covered": covered, "count": count}}}


def report(overrides=None):
    """Every path at 99% on its first prefix, unless overridden by name."""
    overrides = overrides or {}
    files = [entry("src/unrelated/mod.rs", 0, 1000)]
    for name, prefixes, _ in cpc.PATHS:
        if name in overrides:
            files.extend(overrides[name])
            continue
        path = prefixes[0] + ("" if prefixes[0].endswith(".rs") else "mod.rs")
        files.append(entry(path, 99, 100))
    return {"data": [{"files": files}]}


def failures(document):
    return {row[0]: row[5] for row in cpc.grade(document)}


class CriticalPathCoverage(unittest.TestCase):
    def test_every_path_at_99_percent_passes(self):
        self.assertEqual({name: [] for name, _, _ in cpc.PATHS}, failures(report()))

    def test_a_path_below_the_floor_fails_alone(self):
        result = failures(report({"bridge": [entry("src/gateway/input_bridge.rs", 79, 100)]}))
        self.assertIn("below the 80% floor", result["bridge"])
        self.assertEqual([], result["OAuth"])

    def test_a_path_above_the_floor_but_below_its_baseline_fails(self):
        # tasks' baseline is 94.73%: 94/100 clears 80% and still fails.
        result = failures(report({"tasks": [entry("src/gateway/task_service/a.rs", 94, 100)]}))
        self.assertEqual(["below its 94.73% baseline"], result["tasks"])

    def test_lines_are_summed_over_every_prefix_of_a_path(self):
        # 50/100 + 100/100 = 75% over HTTP dispatch's two prefixes.
        result = failures(
            report(
                {
                    "HTTP dispatch": [
                        entry("src/transport/http/a.rs", 50, 100),
                        entry("src/gateway/router/b.rs", 100, 100),
                    ]
                }
            )
        )
        self.assertIn("below the 80% floor", result["HTTP dispatch"])

    def test_a_path_with_no_measured_file_fails(self):
        self.assertIn("no measured file", failures(report({"OAuth": []}))["OAuth"])

    def test_a_file_outside_every_prefix_counts_nowhere(self):
        rows = {row[0]: row for row in cpc.grade(report())}
        self.assertEqual(sum(row[3] for row in rows.values()), 100 * len(cpc.PATHS))

    def test_windows_and_relative_filenames_resolve(self):
        self.assertEqual("src/oauth/a.rs", cpc.relative("C:\\work\\repo\\src\\oauth\\a.rs"))
        self.assertEqual("src/oauth/a.rs", cpc.relative("src/oauth/a.rs"))

    def test_exit_status_follows_the_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "cov.json"
            for document, status in [
                (report(), 0),
                (report({"startup": [entry("src/gateway/server/a.rs", 1, 100)]}), 1),
            ]:
                path.write_text(json.dumps(document), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(status, cpc.main([str(path)]))


if __name__ == "__main__":
    unittest.main()
