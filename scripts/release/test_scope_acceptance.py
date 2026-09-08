# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
"""Regression tests for release acceptance, independent of live completion state."""

import copy
import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "scope_acceptance", pathlib.Path(__file__).with_name("check_scope_acceptance.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "proof.md").write_text("A reviewed test result.\n")
        self.document = "| GH462.CONFIG.1 | preserve invalid config | SAFETY |\n"
        self.baseline = "| NFR.PERF.1 | latency | MET | no |\n"
        self.data = {
            "schema_version": 1,
            "criteria": [
                {
                    "id": "GH462.CONFIG.1",
                    "status": "met",
                    "evidence": ["proof.md"],
                    "note": "Reviewed byte-preservation result.",
                }
            ],
            "decisions": [
                {
                    "id": "reference_personal_account_journey",
                    "status": "resolved",
                    "selection": "Operator-selected reference",
                    "evidence": ["proof.md"],
                }
            ],
        }

    def inspect(self):
        return gate.inspect_contract(self.root, self.document, self.data, self.baseline)

    def cli(self, mode):
        for relative, content in [
            (gate.SCOPE, self.document),
            (gate.BASELINE, self.baseline),
            (gate.STATUS, json.dumps(self.data)),
        ]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        # The baseline counter has its own regression suite. Isolate its exit
        # here while exercising real CLI reads, parsing and release-mode exit.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(
                gate.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
        ):
            return gate.main([mode])

    def test_complete_release_positive_control(self):
        self.assertEqual(self.inspect(), ([], [], []))
        self.assertEqual(self.cli("--release"), 0)

    def test_consistent_pending_work_is_not_release_acceptance(self):
        self.data["criteria"][0].update(status="pending", evidence=[])
        self.assertEqual(self.cli("--check"), 0)
        self.assertEqual(self.cli("--release"), 1)

    def test_baseline_blocker_alone_prevents_release(self):
        self.baseline = "| NFR.PERF.1 | latency | PARTIAL | yes |\n"
        self.assertEqual(self.cli("--check"), 0)
        self.assertEqual(self.cli("--release"), 1)

    def test_unanswered_operator_decision_prevents_release(self):
        self.data["decisions"][0].update(status="pending", selection="", evidence=[])
        self.assertEqual(self.cli("--check"), 0)
        self.assertEqual(self.cli("--release"), 1)

    def test_missing_criterion_cannot_disappear_from_acceptance(self):
        self.data["criteria"] = []
        self.assertTrue(self.inspect()[0])
        self.assertEqual(self.cli("--release"), 2)

    def test_duplicate_or_undeclared_criterion_is_invalid(self):
        self.data["criteria"].append(copy.deepcopy(self.data["criteria"][0]))
        self.assertTrue(self.inspect()[0])
        self.data["criteria"][1]["id"] = "GH452.SESSION.1"
        self.assertTrue(self.inspect()[0])

    def test_missing_or_duplicate_required_decision_is_invalid(self):
        self.data["decisions"].append(copy.deepcopy(self.data["decisions"][0]))
        self.assertTrue(self.inspect()[0])
        self.data["decisions"] = []
        self.assertTrue(self.inspect()[0])

    def test_met_without_existing_evidence_is_invalid(self):
        for evidence in ([], ["absent.md"], ["."], "proof.md"):
            with self.subTest(evidence=evidence):
                self.data["criteria"][0]["evidence"] = evidence
                self.assertTrue(self.inspect()[0])

    def test_outside_or_symlinked_evidence_cannot_satisfy_gate(self):
        with tempfile.TemporaryDirectory() as outside:
            proof = pathlib.Path(outside) / "proof.md"
            proof.write_text("outside the release checkout")
            (self.root / "escape.md").symlink_to(proof)
            for evidence in ([str(proof)], ["escape.md"], ["../proof.md"]):
                with self.subTest(evidence=evidence):
                    self.data["criteria"][0]["evidence"] = evidence
                    self.assertTrue(self.inspect()[0])

    def test_unknown_or_na_status_cannot_waive_approved_requirement(self):
        for status in ("MET", "na", "waived", None):
            with self.subTest(status=status):
                self.data["criteria"][0]["status"] = status
                self.assertTrue(self.inspect()[0])

    def test_resolved_decision_needs_selection_and_evidence(self):
        self.data["decisions"][0]["selection"] = ""
        self.assertTrue(self.inspect()[0])
        self.data["decisions"][0].update(selection="Selected", evidence=[])
        self.assertTrue(self.inspect()[0])

    def test_pending_decision_cannot_claim_a_selection(self):
        self.data["decisions"][0]["status"] = "pending"
        self.assertTrue(self.inspect()[0])

    def test_empty_or_malformed_baseline_and_duplicate_requirement_are_invalid(self):
        for baseline in ("", "| NFR.PERF.1 | latency | PARTIAL | maybe |\n"):
            with self.subTest(baseline=baseline):
                self.baseline = baseline
                self.assertTrue(self.inspect()[0])
        self.document += self.document
        self.assertTrue(self.inspect()[0])

    def test_malformed_json_shapes_return_errors_not_a_release(self):
        for data in (
            [],
            {},
            {**self.data, "schema_version": True},
            {**self.data, "criteria": None},
            {**self.data, "criteria": [{"id": "GH462.CONFIG.1"}]},
            {**self.data, "decisions": None},
        ):
            with self.subTest(data=data):
                self.assertTrue(
                    gate.inspect_contract(
                        self.root, self.document, data, self.baseline
                    )[0]
                )

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            json.loads(
                '{"status":"pending","status":"met"}',
                object_pairs_hook=gate.unique_object,
            )

    def test_baseline_consistency_failure_is_not_hidden(self):
        self.cli("--check")  # write a valid temporary contract
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            mock.patch.object(gate, "ROOT", self.root),
            mock.patch.object(
                gate.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1, "bad counts", ""),
            ),
        ):
            self.assertEqual(gate.main(["--release"]), 2)


if __name__ == "__main__":
    unittest.main()
