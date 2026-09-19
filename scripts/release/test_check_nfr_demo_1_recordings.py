# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Negative controls for the NFR.DEMO.1 recording gate.

Each test breaks one thing in a known-good manifest and asserts the gate says so.
A gate nobody has seen fail proves nothing, so the failing cases are the tests.
Run: python3 scripts/release/test_check_nfr_demo_1_recordings.py
"""

import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "demo_gate", pathlib.Path(__file__).with_name("check_nfr_demo_1_recordings.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def _scenario(num, slug, phrase):
    return {
        "id": num,
        "slug": slug,
        "criterion_phrase": phrase,
        "status": "recorded",
        "driver": f"scripts/release/demo/{num}-{slug}.sh",
        "transcript": f"docs/release/demo/{num}-{slug}-transcript.txt",
        "results_json": f"docs/release/demo/{num}-{slug}-results.json",
        "versions": {"gateway": "4.0.0"},
        "negative_control": "a broken build shows something else",
        "rows": [
            {"id": f"S{num}.ROW1", "expected": "ok", "actual": "ok", "status": "PASS"}
        ],
    }


GOOD = {
    "criterion": "NFR.DEMO.1",
    "verdict": "4/5 RECORDED, 1 BLOCKED",
    "revision_under_test": {
        "gateway_version": "mcp-gateway 4.0.0",
        "binary_sha256": "0" * 64,
        "build_sha_confidence": "assumption",
    },
    "scenarios": [
        _scenario(1, "mixed-era", "mixed-era interaction"),
        _scenario(2, "reconnectable-task", "reconnectable task"),
        dict(
            _scenario(3, "personal-accounts", "two personal accounts"),
            not_evidence_for=[
                {"criterion": "MIK-6745.JOURNEY.1", "reason": "scripted provider"}
            ],
        ),
        {
            "id": 4,
            "slug": "large-catalogue",
            "criterion_phrase": "large-catalogue discovery",
            "status": "blocked",
            "blocked_on": "MIK-7469",
            "versions": {"note": "not recorded"},
            "negative_control": "see design scenario 4",
        },
        _scenario(5, "error-budget", "error-budget diagnosis/recovery"),
    ],
}


class DemoGateTest(unittest.TestCase):
    def run_gate(self, manifest):
        """Materialise a tree matching `manifest` and return (exit, output)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for scenario in manifest.get("scenarios", []):
                for key in ("driver", "transcript"):
                    rel = scenario.get(key)
                    if rel and not scenario.get("_skip_" + key):
                        path = root / rel
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("content\n", encoding="utf-8")
                rel = scenario.get("results_json")
                if rel and not scenario.get("_skip_results_json"):
                    path = root / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    rows = scenario.get("_driver_rows", scenario.get("rows") or [])
                    path.write_text(json.dumps(rows), encoding="utf-8")
            doc = root / gate.VERDICT_DOC_REL
            doc.parent.mkdir(parents=True, exist_ok=True)
            doc.write_text(f"VERDICT: {manifest.get('verdict', '')}\n", encoding="utf-8")
            man = root / gate.MANIFEST_REL
            man.parent.mkdir(parents=True, exist_ok=True)
            man.write_text(json.dumps(manifest), encoding="utf-8")

            failures = []
            gate.check_manifest(root, manifest, failures)
            return failures

    def test_positive_control_passes(self):
        self.assertEqual(self.run_gate(copy.deepcopy(GOOD)), [])

    def test_missing_scenario_fails(self):
        manifest = copy.deepcopy(GOOD)
        del manifest["scenarios"][1]
        failures = self.run_gate(manifest)
        self.assertTrue(any("reconnectable task" in f and "expected exactly 1" in f
                            for f in failures), failures)

    def test_expected_not_equal_actual_fails(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][0]["rows"][0]["actual"] = "something else"
        manifest["scenarios"][0]["_driver_rows"] = manifest["scenarios"][0]["rows"]
        failures = self.run_gate(manifest)
        self.assertTrue(any("expected != actual" in f for f in failures), failures)

    def test_absent_transcript_fails(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][4]["_skip_transcript"] = True
        failures = self.run_gate(manifest)
        self.assertTrue(any("transcript" in f and "does not exist" in f
                            for f in failures), failures)

    def test_manifest_actual_diverging_from_driver_row_fails(self):
        """A hand-edited manifest is the drift this gate exists to catch."""
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][0]["_driver_rows"] = [
            {"id": "S1.ROW1", "expected": "ok", "actual": "FAILED", "status": "FAIL"}
        ]
        failures = self.run_gate(manifest)
        self.assertTrue(any("does not match the driver's own row" in f
                            for f in failures), failures)

    def test_driver_row_omitted_from_manifest_fails(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][0]["_driver_rows"] = [
            manifest["scenarios"][0]["rows"][0],
            {"id": "S1.ROW2", "expected": "ok", "actual": "ok", "status": "PASS"},
        ]
        failures = self.run_gate(manifest)
        self.assertTrue(any("manifest omits it" in f for f in failures), failures)

    def test_scenario_3_non_reuse_constraint_required(self):
        manifest = copy.deepcopy(GOOD)
        del manifest["scenarios"][2]["not_evidence_for"]
        failures = self.run_gate(manifest)
        self.assertTrue(any("MIK-6745.JOURNEY.1" in f for f in failures), failures)

    def test_blocked_scenario_needs_a_blocker_reference(self):
        manifest = copy.deepcopy(GOOD)
        del manifest["scenarios"][3]["blocked_on"]
        failures = self.run_gate(manifest)
        self.assertTrue(any("no blocked_on" in f for f in failures), failures)

    def test_blocked_scenario_may_not_read_as_recorded(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][3]["transcript"] = "docs/release/demo/4-x-transcript.txt"
        failures = self.run_gate(manifest)
        self.assertTrue(any("must not read as recorded" in f for f in failures), failures)

    def test_verdict_must_admit_a_blocked_scenario(self):
        manifest = copy.deepcopy(GOOD)
        manifest["verdict"] = "5/5 RECORDED"
        failures = self.run_gate(manifest)
        self.assertTrue(any("does not say BLOCKED" in f for f in failures), failures)

    def test_missing_versions_fails(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][0]["versions"] = {}
        failures = self.run_gate(manifest)
        self.assertTrue(any("no versions block" in f for f in failures), failures)

    def test_missing_negative_control_fails(self):
        manifest = copy.deepcopy(GOOD)
        manifest["scenarios"][0]["negative_control"] = ""
        failures = self.run_gate(manifest)
        self.assertTrue(any("no negative_control" in f for f in failures), failures)

    def test_revision_block_required(self):
        manifest = copy.deepcopy(GOOD)
        del manifest["revision_under_test"]["binary_sha256"]
        failures = self.run_gate(manifest)
        self.assertTrue(any("binary_sha256" in f for f in failures), failures)


if __name__ == "__main__":
    unittest.main(verbosity=2)
