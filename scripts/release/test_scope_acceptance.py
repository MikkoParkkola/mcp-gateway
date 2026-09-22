# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
                    "stage": "met",
                    "blocked_on": "none",
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
        self.pristine = copy.deepcopy(self.data)

    def approve_waiver(self, ident="GH462.CONFIG.1"):
        """Treat the fixture's waiver as this release's approved one.

        The approved set is a gate constant, so a test that wants a valid
        waiver has to say which ID it is standing in for, exactly as a real
        new waiver has to be added to the gate and reviewed.
        """
        patcher = mock.patch.object(gate, "APPROVED_WAIVERS", frozenset({ident}))
        patcher.start()
        self.addCleanup(patcher.stop)

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
        self.stdout = io.StringIO()
        with (
            contextlib.redirect_stdout(self.stdout),
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
        self.data["criteria"][0].update(status="pending", stage="proven", evidence=[])
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

    def test_stage_cannot_disagree_with_status_or_leave_the_ladder(self):
        stages = ", ".join(gate.STAGES)
        blockers = ", ".join(gate.BLOCKED_ON)
        disagree = "stage 'met' and status 'met' must agree"
        for patch, expected in (
            ({"stage": "shipped"}, f"stage must be one of {stages}"),
            ({"stage": "proven"}, disagree),
            ({"stage": "met", "status": "pending"}, disagree),
            ({"blocked_on": "someone"}, f"blocked_on must be one of {blockers}"),
            ({"blocked_on": "operator"}, "a met criterion cannot still be blocked"),
        ):
            with self.subTest(**patch):
                self.setUp()
                self.data["criteria"][0].update(patch)
                # Match the exact diagnostic. Every input here also trips a
                # neighbouring rule, so asserting "some error" would stay green
                # with the rule under test deleted or widened.
                self.assertIn(f"GH462.CONFIG.1: {expected}", self.inspect()[0])
                self.assertEqual(self.cli("--check"), 2)

    def test_a_held_criterion_is_accepted_and_named_in_the_burnup(self):
        self.data["criteria"][0].update(
            status="pending", stage="proven", blocked_on="external", evidence=[]
        )
        self.assertEqual(self.cli("--check"), 0)
        self.assertIn(
            "Stage burnup: 0/1 met; ungraded 0 | graded 0 | built 0"
            " | on-line 0 | proven 1 | met 0; held: GH462.CONFIG.1 (external)",
            self.stdout.getvalue(),
        )

    def test_resolved_decision_needs_selection_and_evidence(self):
        self.data["decisions"][0]["selection"] = ""
        self.assertTrue(self.inspect()[0])
        self.data["decisions"][0].update(selection="Selected", evidence=[])
        self.assertTrue(self.inspect()[0])

    def test_evidence_may_cite_a_line_or_a_range(self):
        (self.root / "proof.md").write_text("one\ntwo\nthree\n")
        self.data["criteria"][0]["evidence"] = ["proof.md:2", "proof.md:1-3"]
        self.assertEqual(self.inspect(), ([], [], []))

    def test_evidence_line_beyond_the_last_line_is_invalid(self):
        self.data["criteria"][0]["evidence"] = ["proof.md:99"]
        errors, _, _ = self.inspect()
        self.assertTrue(any("line 99" in error for error in errors), errors)

    def test_evidence_line_citation_requires_an_existing_path(self):
        self.data["criteria"][0]["evidence"] = ["absent.md:1"]
        errors, _, _ = self.inspect()
        self.assertTrue(any("absent.md:1" in error for error in errors), errors)

    def test_evidence_range_must_be_ordered(self):
        (self.root / "proof.md").write_text("one\ntwo\nthree\n")
        self.data["criteria"][0]["evidence"] = ["proof.md:3-1"]
        errors, _, _ = self.inspect()
        self.assertTrue(any("range" in error for error in errors), errors)

    def test_decision_may_carry_a_documented_rationale(self):
        # A ruling records why it was taken and who took it. The four required
        # keys stay mandatory; the optional ones must not be an escape hatch.
        self.data["decisions"][0].update(
            resolved="2026-09-17",
            authority="release owner ruling recorded in this ledger",
            rationale="A narrower published claim would be the dishonest one.",
            consequence="The parent criterion stays pending on its other checks.",
        )
        self.assertEqual(self.inspect(), ([], [], []))

    def test_decision_rejects_an_undocumented_key(self):
        self.data["decisions"][0]["freeform"] = "smuggled"
        errors, _, _ = self.inspect()
        self.assertTrue(any("freeform" in error for error in errors), errors)

    def test_optional_decision_field_must_carry_text(self):
        self.data["decisions"][0]["rationale"] = "   "
        errors, _, _ = self.inspect()
        self.assertTrue(any("rationale" in error for error in errors), errors)

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

    # A waived criterion ships unmet by operator ruling. It must stay out of the
    # pending set without becoming a way to retire any other blocking row, so
    # every case below asserts the diagnostic or the surviving list, not just an
    # exit code: --check returns 0 with pending work and would pass regardless.
    def waive(self, **overrides):
        """Accept the single criterion unmet under the ruling that authorises it."""
        row = {
            "status": "waived",
            "stage": "graded",
            "evidence": [],
            "waived_by": "reference_personal_account_journey",
            "waiver_kind": "deferred",
        }
        row.update(overrides)
        self.data["criteria"][0].update(row)
        self.data["decisions"][0]["selection"] = (
            "GH462.CONFIG.1 ships unmet in this release by operator ruling."
        )

    def test_waived_criterion_is_accepted_and_excluded_from_pending(self):
        self.waive()
        self.approve_waiver()
        self.assertEqual(self.inspect(), ([], [], []))
        self.assertEqual(self.cli("--release"), 0)

    def test_waived_criterion_is_reported_with_its_authority_and_kind(self):
        self.waive()
        self.approve_waiver()
        self.assertEqual(self.cli("--release"), 0)
        printed = self.stdout.getvalue()
        self.assertIn("0 met / 1 waived / 0 pending", printed)
        self.assertIn(
            "GH462.CONFIG.1 waived by reference_personal_account_journey"
            " (deferred)",
            printed,
        )

    def test_waiver_authority_must_name_an_existing_decision(self):
        self.waive(waived_by="no_such_ruling")
        self.assertIn(
            "GH462.CONFIG.1: waived_by names no decision: no_such_ruling",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waiver_authority_must_be_a_resolved_decision(self):
        self.waive()
        self.data["decisions"][0].update(status="pending", selection="", evidence=[])
        self.assertIn(
            "GH462.CONFIG.1: waiver authority reference_personal_account_journey"
            " is not resolved",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waiver_authority_must_name_the_criterion_it_waives(self):
        # The attack this closes: pointing a waiver at any resolved decision.
        self.waive()
        self.data["decisions"][0]["selection"] = "Operator-selected reference"
        self.assertIn(
            "GH462.CONFIG.1: decision reference_personal_account_journey does not"
            " name this criterion in the operator's selection",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waived_criterion_without_an_authority_is_invalid(self):
        self.waive()
        del self.data["criteria"][0]["waived_by"]
        self.assertIn(
            "GH462.CONFIG.1: a waived criterion needs waived_by naming the"
            " authorising decision",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waiver_fields_belong_only_on_a_waived_criterion(self):
        baseline = copy.deepcopy(self.data)
        for status, stage, evidence in (
            ("met", "met", ["proof.md"]),
            ("pending", "graded", []),
        ):
            for field in ("waived_by", "waiver_kind"):
                with self.subTest(status=status, field=field):
                    self.data = copy.deepcopy(baseline)
                    self.waive()
                    del self.data["criteria"][0][
                        "waiver_kind" if field == "waived_by" else "waived_by"
                    ]
                    self.data["criteria"][0].update(
                        status=status, stage=stage, evidence=evidence
                    )
                    self.assertIn(
                        f"GH462.CONFIG.1: {field} belongs only on a waived criterion",
                        self.inspect()[0],
                    )
                    self.assertEqual(self.cli("--release"), 2)

    def test_waiver_kind_must_be_declared_and_known(self):
        baseline = copy.deepcopy(self.data)
        for kind in (None, "", "postponed", 7):
            with self.subTest(kind=kind):
                self.data = copy.deepcopy(baseline)
                self.waive()
                if kind is None:
                    del self.data["criteria"][0]["waiver_kind"]
                else:
                    self.data["criteria"][0]["waiver_kind"] = kind
                self.assertIn(
                    "GH462.CONFIG.1: waiver_kind must be one of measured, deferred",
                    self.inspect()[0],
                )
                self.assertEqual(self.cli("--release"), 2)

    def test_waiver_authority_must_name_the_criterion_on_a_token_boundary(self):
        # A longer ID containing this one is a different criterion. Containment
        # would let a ruling about RANKING.31 authorise waiving RANKING.3.
        for selection in (
            "GH462.CONFIG.11 ships unmet in this release.",
            "GH462.CONFIG.1a ships unmet in this release.",
            "XGH462.CONFIG.1 ships unmet in this release.",
            "GH462.CONFIG.10 and GH462.CONFIG.12 ship unmet.",
        ):
            with self.subTest(selection=selection):
                self.data = copy.deepcopy(self.pristine)
                self.waive()
                self.data["decisions"][0]["selection"] = selection
                self.assertIn(
                    "GH462.CONFIG.1: decision reference_personal_account_journey"
                    " does not name this criterion in the operator's selection",
                    self.inspect()[0],
                )
                self.assertEqual(self.cli("--release"), 2)

    def test_waiver_authority_accepts_the_criterion_beside_punctuation(self):
        for selection in (
            "GH462.CONFIG.1 ships unmet in this release.",
            "Ships unmet: GH462.CONFIG.1.",
            "Ships unmet (GH462.CONFIG.1) by ruling.",
            "GH462.CONFIG.1, carried forward, ships unmet.",
        ):
            with self.subTest(selection=selection):
                self.data = copy.deepcopy(self.pristine)
                self.waive()
                self.approve_waiver()
                self.data["decisions"][0]["selection"] = selection
                self.assertEqual(self.inspect(), ([], [], []))

    def test_blank_or_non_string_waiver_authority_is_invalid(self):
        for authority in ("", "   ", 7, None, ["ranking_3_ships_unmet"]):
            with self.subTest(authority=authority):
                self.data = copy.deepcopy(self.pristine)
                self.waive(waived_by=authority)
                self.assertIn(
                    "GH462.CONFIG.1: a waived criterion needs waived_by naming the"
                    " authorising decision",
                    self.inspect()[0],
                )
                self.assertEqual(self.cli("--release"), 2)

    def test_retiring_a_waiver_must_shrink_the_approved_set(self):
        # A ratchet, not a high-water mark: the gate fails on the improvement
        # so the approved set shrinks in the same reviewed change, and cannot
        # keep holding permission to re-waive the row later.
        self.approve_waiver()  # approved, but the fixture row is met
        self.assertIn(
            "GH462.CONFIG.1: approved as a waiver but no longer waived; remove it"
            " from APPROVED_WAIVERS in this change",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)
        self.data["criteria"][0].update(status="pending", stage="graded", evidence=[])
        self.assertIn(
            "GH462.CONFIG.1: approved as a waiver but no longer waived; remove it"
            " from APPROVED_WAIVERS in this change",
            self.inspect()[0],
        )

    def test_only_an_approved_criterion_may_be_waived(self):
        # The escape hatch this closes: a second waiver added by editing the
        # ledger alone. The approved set lives in the gate, so widening it is a
        # reviewed code change with a test, not a JSON edit.
        self.waive()
        self.assertIn(
            "GH462.CONFIG.1: not an approved waiver for this release",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waiver_output_states_that_authority_is_human_reviewed(self):
        # The gate proves a resolved decision names this criterion. It cannot
        # prove the ruling authorised shipping unmet in this release, and must
        # not let its own output imply otherwise.
        self.waive()
        self.approve_waiver()
        self.assertEqual(self.cli("--release"), 0)
        printed = self.stdout.getvalue()
        self.assertIn("asserted by the named ruling, not proved by this gate", printed)

    def test_a_refusal_or_wrong_release_ruling_is_a_stated_limit(self):
        # Neither is machine-detectable: the decision schema has no field for
        # the release a ruling covers or for what it authorises, and parsing
        # prose for intent is a guard that cannot fail for the right reason.
        # These are accepted, and the caveat above is what carries the risk.
        for selection in (
            "GH462.CONFIG.1 is REFUSED a waiver; it must be met before the tag.",
            "GH462.CONFIG.1 ships unmet in 5.0.0, not in this release.",
        ):
            with self.subTest(selection=selection):
                self.data = copy.deepcopy(self.pristine)
                self.waive()
                self.approve_waiver()
                self.data["decisions"][0]["selection"] = selection
                self.assertEqual(self.inspect(), ([], [], []))
                self.assertEqual(self.cli("--release"), 0)
                self.assertIn(
                    "asserted by the named ruling, not proved by this gate",
                    self.stdout.getvalue(),
                )

    def test_unknown_criterion_field_is_rejected(self):
        # Admitting the waiver pair must not admit anything else. The row shape
        # was an exact key set before, which refused every stray key on its own.
        self.data["criteria"][0]["waived_because"] = "the operator said so"
        self.assertIn(
            "GH462.CONFIG.1: waived_because is not a criterion field",
            self.inspect()[0],
        )
        self.assertEqual(self.cli("--release"), 2)

    def test_waiver_does_not_suppress_a_baseline_blocking_row(self):
        self.baseline = "| NFR.PERF.1 | latency | PARTIAL | yes |\n"
        self.waive()
        self.approve_waiver()
        errors, pending, blockers = self.inspect()
        self.assertEqual((errors, pending), ([], []))
        self.assertEqual(blockers, ["NFR.PERF.1"])
        self.assertEqual(self.cli("--release"), 1)

    def test_waiver_does_not_suppress_another_pending_criterion(self):
        self.document = (
            "Approved supplemental criteria: 2\n"
            "| GH462.CONFIG.1 | preserve invalid config | SAFETY |\n"
            "| GH452.SESSION.1 | session ownership | SAFETY |\n"
        )
        self.data["criteria"].append(
            {
                "id": "GH452.SESSION.1",
                "status": "pending",
                "stage": "graded",
                "blocked_on": "none",
                "evidence": [],
                "note": "Awaiting release acceptance evidence.",
            }
        )
        self.waive()
        self.approve_waiver()
        errors, pending, _ = self.inspect()
        self.assertEqual(errors, [])
        self.assertEqual(pending, ["GH452.SESSION.1"])
        self.assertEqual(self.cli("--release"), 1)

    def test_ledger_without_waivers_keeps_its_prior_verdict(self):
        self.assertEqual(self.inspect(), ([], [], []))
        self.assertEqual(self.cli("--release"), 0)
        self.assertIn("1 met / 0 waived / 0 pending", self.stdout.getvalue())
        self.data["criteria"][0].update(status="pending", stage="proven", evidence=[])
        errors, pending, blockers = self.inspect()
        self.assertEqual((errors, pending, blockers), ([], ["GH462.CONFIG.1"], []))
        self.assertEqual(self.cli("--check"), 0)
        self.assertEqual(self.cli("--release"), 1)


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

    def _write_contract(self, *, pending, waived=False):
        document = (
            "Approved supplemental criteria: 1\n"
            "| GH462.CONFIG.1 | preserve invalid config | SAFETY |\n"
        )
        baseline = "| NFR.PERF.1 | latency | MET | no |\n"
        criterion = {
            "id": "GH462.CONFIG.1",
            "status": "pending",
            "stage": "proven",
            "blocked_on": "none",
            "evidence": [],
            "note": "Awaiting release acceptance evidence.",
        }
        if not pending:
            criterion = {
                "id": "GH462.CONFIG.1",
                "status": "met",
                "stage": "met",
                "blocked_on": "none",
                "evidence": ["proof.md"],
                "note": "Reviewed byte-preservation result.",
            }
        selection = "Operator-selected reference"
        if waived:
            # A subprocess cannot patch the gate's approved set, so this
            # fixture uses the release's real approved waiver end to end.
            document = (
                "Approved supplemental criteria: 1\n"
                "| MIK-3274.RANKING.3 | ranking baseline | PERF |\n"
            )
            criterion = {
                "id": "MIK-3274.RANKING.3",
                "status": "waived",
                "stage": "graded",
                "blocked_on": "none",
                "evidence": [],
                "note": "Ships unmet by operator ruling.",
                "waived_by": "reference_personal_account_journey",
                "waiver_kind": "measured",
            }
            selection = "MIK-3274.RANKING.3 ships unmet in this release."
        data = {
            "schema_version": 1,
            "criteria": [criterion],
            "decisions": [
                {
                    "id": "reference_personal_account_journey",
                    "status": "resolved",
                    "selection": selection,
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
        self.last = result
        return result.returncode

    def test_tag_v4_0_0_waived_publish_is_accepted(self):
        self._write_contract(pending=False, waived=True)
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            0,
            self.last.stderr,
        )
        self.assertIn("0 met / 1 waived / 0 pending", self.last.stdout)
        self.assertIn(
            "MIK-3274.RANKING.3 waived by reference_personal_account_journey"
            " (measured)",
            self.last.stdout,
        )
        self.assertIn(
            "asserted by the named ruling, not proved by this gate",
            self.last.stdout,
        )

    def test_tag_v4_0_0_waiver_with_a_dangling_authority_is_invalid(self):
        self._write_contract(pending=False, waived=True)
        status = self.root / gate.STATUS
        status.write_text(
            status.read_text().replace(
                '"waived_by": "reference_personal_account_journey"',
                '"waived_by": "absent_ruling"',
            )
        )
        self.assertEqual(
            self._publish_check(
                GITHUB_EVENT_NAME="push",
                GITHUB_REF="refs/tags/v4.0.0",
            ),
            2,
        )
        self.assertIn("waived_by names no decision", self.last.stderr)

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
