# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
"""Regression tests for release acceptance, independent of live completion state."""

import copy
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "scope_acceptance", pathlib.Path(__file__).with_name("check_scope_acceptance.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

# Tiny successful baseline-counter fixture. The real
# count-release-criteria.py has its own 32-test suite; isolating it here
# keeps those checks from coupling to --publish-check coverage. The copied
# acceptance checker, argparse, env, and exit codes run unmocked.
BASELINE_COUNTER_FIXTURE = """\
#!/usr/bin/env python3
import sys


def rows(baseline):
    parsed = []
    malformed = []
    for line in baseline.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 4:
            malformed.append(line)
            continue
        ident, _title, _status, blocking = cells
        parsed.append((None, blocking, ident))
    return parsed, malformed


if __name__ == "__main__":
    raise SystemExit(0 if "--check" in sys.argv else 2)
"""


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / "proof.md").write_text("A reviewed test result.\n")
        self.document = (
            "Approved supplemental criteria: 1\n"
            "| GH462.CONFIG.1 | preserve invalid config | SAFETY |\n"
        )
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

    def test_joint_document_and_ledger_deletion_is_invalid(self):
        self.document = (
            "Approved supplemental criteria: 2\n" + self.document.split("\n", 1)[1]
        )
        second = "| GH452.SESSION.1 | session ownership | SAFETY |\n"
        self.document += second
        self.data["criteria"].append(
            {**self.data["criteria"][0], "id": "GH452.SESSION.1"}
        )
        self.assertEqual(self.inspect(), ([], [], []))
        self.document = self.document.removesuffix(second)
        self.data["criteria"].pop()
        self.assertIn(
            "approved supplemental criterion count does not match requirements",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--check"), 2)

    def test_extra_pending_decision_blocks_release_not_plan_consistency(self):
        self.data["decisions"].append(
            {
                "id": "additional_operator_decision",
                "status": "pending",
                "selection": "",
                "evidence": [],
            }
        )
        errors, pending, _ = self.inspect()
        self.assertEqual(errors, [])
        self.assertIn("decision:additional_operator_decision", pending)
        self.assertEqual(self.cli("--check"), 0)
        self.assertEqual(self.cli("--release"), 1)

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


class PublishCheckTests(unittest.TestCase):
    """Subprocess regressions for --publish-check in a temp fixture repo.

    Pending work stays pending on every no-release control so treating this
    flag as unconditional --release is visible. Host GitHub/Actions env is
    stripped before each run so CI variables cannot leak into the checker.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        scripts = self.root / "scripts" / "release"
        scripts.mkdir(parents=True)
        source = pathlib.Path(__file__).with_name("check_scope_acceptance.py")
        self.checker = scripts / "check_scope_acceptance.py"
        self.checker.write_bytes(source.read_bytes())
        (scripts / "count-release-criteria.py").write_text(BASELINE_COUNTER_FIXTURE)
        (self.root / "proof.md").write_text("A reviewed test result.\n")
        self._write_contract(pending=True)
        self._write_manifest("4.0.0")

    def _write_contract(self, *, pending):
        document = (
            "Approved supplemental criteria: 1\n"
            "| GH462.CONFIG.1 | preserve invalid config | SAFETY |\n"
        )
        baseline = "| NFR.PERF.1 | latency | MET | no |\n"
        criterion = {
            "id": "GH462.CONFIG.1",
            "status": "pending",
            "evidence": [],
            "note": "Awaiting release acceptance evidence.",
        }
        if not pending:
            criterion = {
                "id": "GH462.CONFIG.1",
                "status": "met",
                "evidence": ["proof.md"],
                "note": "Reviewed byte-preservation result.",
            }
        data = {
            "schema_version": 1,
            "criteria": [criterion],
            "decisions": [
                {
                    "id": "reference_personal_account_journey",
                    "status": "resolved",
                    "selection": "Operator-selected reference",
                    "evidence": ["proof.md"],
                }
            ],
        }
        for relative, content in (
            (gate.SCOPE, document),
            (gate.BASELINE, baseline),
            (gate.STATUS, json.dumps(data)),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)

    def _write_manifest(self, version=None, *, raw=None, absent=False):
        path = self.root / "Cargo.toml"
        if absent:
            path.unlink(missing_ok=True)
            return
        if raw is not None:
            path.write_text(raw)
            return
        path.write_text(f'[package]\nname = "mcp-gateway"\nversion = "{version}"\n')

    def _isolated_env(self, **github):
        """Drop host GitHub/Actions variables so CI cannot leak into the checker."""
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("GITHUB_") or key.startswith("INPUT_"):
                del env[key]
        env.update(github)
        return env

    def _publish_check(self, **github):
        result = subprocess.run(
            [sys.executable, str(self.checker), "--publish-check"],
            cwd=self.root,
            env=self._isolated_env(**github),
            capture_output=True,
            text=True,
        )
        return result.returncode

    def test_tag_v4_0_0_pending_publish_is_incomplete(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            1,
        )

    def test_prerelease_rc_tag_pending_publish_is_incomplete(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0-rc.1",
            ),
            1,
        )

    def test_workflow_dispatch_input_tag_pending_publish_is_incomplete(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="workflow_dispatch",
                GITHUB_REF="refs/heads/main",
                INPUT_TAG="4.0.0",
            ),
            1,
        )

    def test_unrelated_v3_tag_with_manifest_4_pending_publish_is_incomplete(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v3.1.0",
            ),
            1,
        )

    def test_manifest_3_and_v4_tag_pending_publish_is_incomplete(self):
        self._write_manifest("3.9.0")
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            1,
        )

    def test_manifest_3_and_workflow_dispatch_input_tag_4_pending_publish_is_incomplete(
        self,
    ):
        self._write_manifest("3.9.0")
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="workflow_dispatch",
                GITHUB_REF="refs/heads/main",
                INPUT_TAG="4.0.0",
            ),
            1,
        )

    def test_manifest_3_and_unprefixed_tag_ref_4_pending_publish_is_incomplete(self):
        self._write_manifest("3.9.0")
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/4.0.0",
            ),
            1,
        )

    def test_manifest_3_and_v3_tag_is_consistency_only(self):
        self._write_manifest("3.9.0")
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v3.9.0",
            ),
            0,
        )

    def test_pull_request_with_manifest_4_is_consistency_only(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="pull_request",
                GITHUB_REF="refs/pull/1/merge",
            ),
            0,
        )

    def test_branch_push_with_manifest_4_is_consistency_only(self):
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/heads/main",
            ),
            0,
        )

    def test_absent_manifest_in_publish_context_fails_closed(self):
        self._write_manifest(absent=True)
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            2,
        )

    def test_invalid_manifest_toml_in_publish_context_fails_closed(self):
        self._write_manifest(raw="this is not TOML\n")
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            2,
        )

    def test_invalid_manifest_version_in_publish_context_fails_closed(self):
        self._write_manifest(
            raw='[package]\nname = "mcp-gateway"\nversion = "not-a-version"\n'
        )
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            2,
        )

    def test_completed_v4_tag_publish_is_accepted(self):
        self._write_contract(pending=False)
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            0,
        )


if __name__ == "__main__":
    # unittest discovers this imported TestCase when running the workflow entry point.
    from test_scope_contract_interface import ContractInterfaceTests  # noqa: F401

    unittest.main()
