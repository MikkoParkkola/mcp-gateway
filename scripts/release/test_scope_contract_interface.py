# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
"""Exercise the checker's public file layout, diagnostics and refusal exits."""

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


class ContractInterfaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        scripts = self.root / "scripts/release"
        scripts.mkdir(parents=True)
        shutil.copyfile(
            pathlib.Path(__file__).with_name("check_scope_acceptance.py"),
            scripts / "check_scope_acceptance.py",
        )
        # Baseline parser semantics have a separate suite. This adapter supplies
        # a complete baseline while these tests exercise the supplemental CLI.
        (scripts / "count-release-criteria.py").write_text(
            'def rows(text):\n    return [("MET", "no", "NFR.PERF.1")], False\n'
        )
        docs = self.root / "docs/requirements"
        docs.mkdir(parents=True)
        (docs / "RELEASE-4.0.0-scope-update.md").write_text(
            "Approved supplemental criteria: 1\n"
            "| GH462.CONFIG.1 | preserve config | SAFETY |\n"
        )
        (docs / "RELEASE-4.0.0-criteria-status.md").write_text("baseline fixture\n")
        self.status = docs / "RELEASE-4.0.0-scope-status.json"
        (self.root / "proof.md").write_text("Reviewed evidence.\n")
        self.data = {
            "schema_version": 1,
            "criteria": [
                {
                    "id": "GH462.CONFIG.1",
                    "status": "met",
                    "evidence": ["proof.md"],
                    "note": "Reviewed.",
                }
            ],
            "decisions": [
                {
                    "id": "reference_personal_account_journey",
                    "status": "resolved",
                    "selection": "Selected",
                    "evidence": ["proof.md"],
                }
            ],
        }
        self.write_data()

    def write_data(self):
        self.status.write_text(json.dumps(self.data))

    def cli(self, *args):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("GITHUB_", "INPUT_"))
        }
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(self.root / "scripts/release/check_scope_acceptance.py"),
                *args,
            ],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_documented_paths_and_approval_messages(self):
        plan = self.cli("--check")
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertIn("Plan check only; not release approval.", plan.stdout)
        release = self.cli("--release")
        self.assertEqual(release.returncode, 0, release.stderr)
        self.assertIn("Release acceptance complete.", release.stdout)
        self.data["criteria"][0].update(status="pending", evidence=[])
        self.write_data()
        refused = self.cli("--release")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("Release acceptance incomplete:", refused.stderr)
        self.assertIn("GH462.CONFIG.1", refused.stderr)

    def test_missing_malformed_and_duplicate_ledger_are_invalid(self):
        for raw in (None, "{", '{"schema_version":1,"schema_version":1}'):
            with self.subTest(raw=raw):
                if raw is None:
                    self.status.unlink()
                else:
                    self.status.write_text(raw)
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Invalid scope contract:", result.stderr)

    def test_mode_must_be_explicit(self):
        self.assertEqual(self.cli().returncode, 2)
        self.assertEqual(self.cli("--check", "--release").returncode, 2)

    def test_invalid_row_shapes_refuse_with_actionable_diagnostics(self):
        original = copy.deepcopy(self.data)
        cases = [
            ("criteria", "id", 7, "criterion ID must be a string"),
            ("criteria", "note", None, "a verdict needs a nonempty explanatory note"),
            ("criteria", "note", "  ", "a verdict needs a nonempty explanatory note"),
            ("criteria", "evidence", [None], "invalid evidence path"),
            ("criteria", "evidence", ["  "], "invalid evidence path"),
            ("decisions", "id", 7, "decision ID must be a string"),
            ("decisions", "selection", 7, "selection must be text"),
            ("decisions", "status", "waived", "decision must be pending or resolved"),
        ]
        for table, field, value, diagnostic in cases:
            with self.subTest(table=table, field=field, value=value):
                self.data = copy.deepcopy(original)
                self.data[table][0][field] = value
                self.write_data()
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(diagnostic, result.stderr)
        self.data = original
        self.data["decisions"][0].pop("evidence")
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "each decision needs id, status, selection and evidence", result.stderr
        )


if __name__ == "__main__":
    unittest.main()
