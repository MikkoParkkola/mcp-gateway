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
        self.scope_doc = docs / "RELEASE-4.0.0-scope-update.md"
        self.counter = scripts / "count-release-criteria.py"
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

    def write_raw_status(self, obj):
        self.status.write_text(json.dumps(obj))

    def two_criterion_two_decision_contract(self):
        """A pristine ledger with two rows per table, for row-attribution checks."""
        self.scope_doc.write_text(
            "Approved supplemental criteria: 2\n"
            "| GH462.CONFIG.1 | preserve config | SAFETY |\n"
            "| GH452.SESSION.1 | session ownership | SAFETY |\n"
        )
        self.data = {
            "schema_version": 1,
            "criteria": [
                {
                    "id": "GH462.CONFIG.1",
                    "status": "met",
                    "evidence": ["proof.md"],
                    "note": "Reviewed config.",
                },
                {
                    "id": "GH452.SESSION.1",
                    "status": "met",
                    "evidence": ["proof.md"],
                    "note": "Reviewed session.",
                },
            ],
            "decisions": [
                {
                    "id": "reference_personal_account_journey",
                    "status": "resolved",
                    "selection": "Selected",
                    "evidence": ["proof.md"],
                },
                {
                    "id": "additional_operator_decision",
                    "status": "resolved",
                    "selection": "Selected",
                    "evidence": ["proof.md"],
                },
            ],
        }
        self.write_data()

    def cli(self, *args, env_overrides=None):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("GITHUB_", "INPUT_"))
        }
        if env_overrides:
            env.update(env_overrides)
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
        duplicate = json.dumps(self.data).replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1
        )
        for raw in (None, "{", duplicate):
            with self.subTest(raw=raw):
                if raw is None:
                    self.status.unlink()
                else:
                    self.status.write_text(raw)
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2)
                self.assertIn("Invalid scope contract:", result.stderr)
                if raw == duplicate:
                    self.assertEqual(
                        result.stderr.strip(),
                        "Invalid scope contract: duplicate JSON field: schema_version",
                    )

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

    def test_manifest_diagnostics_in_publish_context(self):
        manifest = self.root / "Cargo.toml"
        publish_env = {
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/tags/v4.0.0",
        }
        cases = [
            ("absent", lambda: manifest.unlink(missing_ok=True), "Cargo.toml: "),
            ("directory", lambda: manifest.mkdir(), "Cargo.toml: "),
            (
                "invalid toml",
                lambda: manifest.write_text("this is not toml\n"),
                "Cargo.toml: invalid TOML:",
            ),
            (
                "missing version key",
                lambda: manifest.write_text('[package]\nname = "x"\n'),
                "Cargo.toml: [package].version is missing or not a string",
            ),
            (
                "non-string version",
                lambda: manifest.write_text('[package]\nname = "x"\nversion = 4\n'),
                "Cargo.toml: [package].version is missing or not a string",
            ),
            (
                "blank version",
                lambda: manifest.write_text('[package]\nname = "x"\nversion = "  "\n'),
                "Cargo.toml: [package].version is missing or not a string",
            ),
            (
                "invalid format",
                lambda: manifest.write_text(
                    '[package]\nname = "x"\nversion = "not-a-version"\n'
                ),
                "Cargo.toml: [package].version is not a valid version: 'not-a-version'",
            ),
        ]
        for label, prepare, diagnostic in cases:
            with self.subTest(case=label):
                prepare()
                result = self.cli("--publish-check", env_overrides=publish_env)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(diagnostic, result.stderr)
                manifest.unlink(missing_ok=True) if manifest.is_file() else None
                if manifest.is_dir():
                    manifest.rmdir()

    def test_publish_context_requires_an_actual_publish_signal(self):
        self.data["criteria"][0].update(status="pending", evidence=[])
        self.write_data()
        (self.root / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "4.0.0"\n'
        )
        non_publishing = [
            ("no github env at all", {}),
            (
                "pull request event",
                {
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_REF": "refs/pull/1/merge",
                },
            ),
            (
                "push without a tag ref",
                {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main"},
            ),
        ]
        for label, env in non_publishing:
            with self.subTest(case=label):
                result = self.cli("--publish-check", env_overrides=env)
                self.assertEqual(result.returncode, 0, result.stderr)
        publishing = self.cli(
            "--publish-check",
            env_overrides={
                "GITHUB_EVENT_NAME": "push",
                "GITHUB_REF": "refs/tags/v4.0.0",
            },
        )
        self.assertEqual(publishing.returncode, 1, publishing.stderr)
        self.assertIn("GH462.CONFIG.1", publishing.stderr)

    def test_evidence_error_messages_attribute_correct_criterion(self):
        self.two_criterion_two_decision_contract()
        baseline = copy.deepcopy(self.data)
        cases = [
            (
                "not a list",
                "evidence",
                "proof.md",
                "evidence must be a list of repository file paths",
            ),
            ("missing when met", "evidence", [], "completed verdict needs evidence"),
            ("blank path entry", "evidence", ["  "], "invalid evidence path"),
            ("null path entry", "evidence", [None], "invalid evidence path"),
            (
                "absolute escape",
                "evidence",
                ["/etc/passwd"],
                "evidence must remain inside the repository: /etc/passwd",
            ),
            (
                "traversal escape",
                "evidence",
                ["../proof.md"],
                "evidence must remain inside the repository: ../proof.md",
            ),
            (
                "nonexistent file",
                "evidence",
                ["missing.md"],
                "evidence file does not exist: missing.md",
            ),
        ]
        for label, field, value, fragment in cases:
            with self.subTest(case=label):
                self.data = copy.deepcopy(baseline)
                self.data["criteria"][0][field] = value
                self.write_data()
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"GH462.CONFIG.1: {fragment}", result.stderr)
                # the untouched second criterion must not be blamed for this row's defect
                self.assertNotIn(f"GH452.SESSION.1: {fragment}", result.stderr)

    def test_criterion_row_shape_and_identity_diagnostics(self):
        self.two_criterion_two_decision_contract()
        baseline = copy.deepcopy(self.data)

        self.data = copy.deepcopy(baseline)
        del self.data["criteria"][0]["note"]
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "each criterion needs id, status, evidence and note", result.stderr
        )
        self.assertNotIn("GH452.SESSION.1", result.stderr)

        self.data = copy.deepcopy(baseline)
        self.data["criteria"][0]["id"] = 7
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("criterion ID must be a string", result.stderr)
        self.assertNotIn("missing criterion verdict: GH452.SESSION.1", result.stderr)

        self.data = copy.deepcopy(baseline)
        self.data["criteria"][1]["id"] = "GH462.CONFIG.1"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("duplicate criterion: GH462.CONFIG.1", result.stderr)

        self.data = copy.deepcopy(baseline)
        self.data["criteria"][0]["status"] = "waived"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("GH462.CONFIG.1: status must be pending or met", result.stderr)
        self.assertNotIn(
            "GH452.SESSION.1: status must be pending or met", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["criteria"].pop(0)
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("missing criterion verdict: GH462.CONFIG.1", result.stderr)

        self.data = copy.deepcopy(baseline)
        self.data["criteria"][0]["id"] = "GH999.UNDECLARED.1"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "verdict without a requirement: GH999.UNDECLARED.1", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["criteria"] = "not-a-list"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("criteria must be a list", result.stderr)

    def test_decision_row_shape_and_identity_diagnostics(self):
        self.two_criterion_two_decision_contract()
        baseline = copy.deepcopy(self.data)

        self.data = copy.deepcopy(baseline)
        del self.data["decisions"][1]["evidence"]
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "each decision needs id, status, selection and evidence", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1]["id"] = 7
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("decision ID must be a string", result.stderr)

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1]["id"] = "reference_personal_account_journey"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "duplicate decision: reference_personal_account_journey", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1]["status"] = "waived"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "additional_operator_decision: decision must be pending or resolved",
            result.stderr,
        )
        self.assertNotIn(
            "reference_personal_account_journey: decision must be pending or resolved",
            result.stderr,
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1]["selection"] = 7
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "additional_operator_decision: selection must be text", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1]["selection"] = ""
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "additional_operator_decision: resolved decision needs the operator's selection",
            result.stderr,
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"][1].update(status="pending", selection="premature")
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "additional_operator_decision: do not record a selection while awaiting the operator",
            result.stderr,
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"].pop(0)
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "required decision set differs from the approved contract", result.stderr
        )

        self.data = copy.deepcopy(baseline)
        self.data["decisions"] = "not-a-list"
        self.write_data()
        result = self.cli("--release")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("decisions must be a list", result.stderr)

    def test_ledger_top_level_and_schema_version_diagnostics(self):
        self.two_criterion_two_decision_contract()
        baseline = copy.deepcopy(self.data)
        for shape in ([], None, {"criteria": [], "decisions": []}):
            with self.subTest(shape=shape):
                self.write_raw_status(shape)
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(
                    "ledger must contain schema_version, criteria and decisions",
                    result.stderr,
                )
        for version in (2, "1", True):
            with self.subTest(schema_version=version):
                self.data = copy.deepcopy(baseline)
                self.data["schema_version"] = version
                self.write_data()
                result = self.cli("--release")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("unsupported scope ledger schema_version", result.stderr)

    def test_declared_requirement_ids_must_be_unique_and_nonempty(self):
        self.two_criterion_two_decision_contract()
        self.scope_doc.write_text(
            "Approved supplemental criteria: 0\nNo IDs declared.\n"
        )
        result = self.cli("--check")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "scope requirements must declare a nonempty set of unique IDs",
            result.stderr,
        )
        self.scope_doc.write_text(
            "Approved supplemental criteria: 2\n"
            "| GH462.CONFIG.1 | preserve config | SAFETY |\n"
            "| GH462.CONFIG.1 | preserve config | SAFETY |\n"
        )
        result = self.cli("--check")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "scope requirements must declare a nonempty set of unique IDs",
            result.stderr,
        )

    def test_baseline_helper_failure_blocks_release(self):
        result = self.cli("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.counter.write_text("def rows(text):\n    return [], True\n")
        result = self.cli("--check")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(
            "baseline ledger is empty or has malformed criterion rows", result.stderr
        )


if __name__ == "__main__":
    unittest.main()
