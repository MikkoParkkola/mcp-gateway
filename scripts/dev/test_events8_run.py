#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""events8_run.py evidence: a run that did not do what the criterion says must FAIL.

Each test writes the files a real run leaves under --dir and asserts on the exit
status of `evidence`. The false-pass cases are the ones the operator cannot see
by eye: a subscription with no filter, and an unsubscribe the gateway never
applied to that subscription.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "events8_run.py"
EVENT = "webhook.github.push.received"
SUB = "sub-123"
T0 = 1_000_000.0
REPO = "demo/repo"


def shim_rows(sub_args, unsub_args, result_id=SUB):
    def http(ts, method, params=None, **kw):
        row = {"kind": "http", "ts": ts, "status": 200, "error_code": None, "reply_ok": True, "rpc": [method], **kw}
        if params is not None:
            row["rpc_params"] = [{"method": method, **params}]
        return row

    return [
        {"kind": "oauth", "ts": T0 + 1, "step": "token"},
        http(T0 + 2, "server/discover"),
        http(T0 + 3, "events/list"),
        http(T0 + 5, "events/subscribe", {"name": EVENT, "arguments": sub_args}, result_has_id=True,
             result_id=result_id),
        http(T0 + 20, "events/unsubscribe", {"name": EVENT, "arguments": unsub_args}),
    ]


def audit_rows(unsub_id=SUB, unsub_detail="removed", first_seen=T0 + 10.5):
    return [
        {"ts": first_seen, "action": "events.delivery_attempt", "event_id": "ev-1", "subscription_id": SUB},
        {"ts": T0 + 4, "action": "events.verification", "detail": "verified", "outcome": "ok",
         "subscription_id": SUB},
        {"ts": T0 + 11, "action": "events.delivery_outcome", "delivered": True, "subscription_id": SUB,
         "event_id": "ev-1"},
        {"ts": T0 + 21, "action": "events.unsubscribe", "subscription_id": unsub_id, "detail": unsub_detail},
    ]


def run_evidence(shim, audit):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "state.json").write_text(json.dumps({"started": T0}))
        (d / "shim.jsonl").write_text("\n".join(json.dumps(r) for r in shim) + "\n")
        (d / "audit.jsonl").write_text("\n".join(json.dumps(r) for r in audit) + "\n")
        (d / "fire.json").write_text(json.dumps(
            {"signed": True, "status": 200, "ts": T0 + 10, "ref": "refs/heads/x", "repo": REPO}))
        out = subprocess.run([sys.executable, str(SCRIPT), "--dir", str(d), "evidence"],
                             capture_output=True, text=True)
        return out.returncode, out.stdout


class EvidenceTests(unittest.TestCase):
    def test_a_filtered_subscribe_and_applied_unsubscribe_pass(self):
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args), audit_rows())
        self.assertEqual(code, 0, out)

    def test_an_unfiltered_subscribe_fails(self):
        code, out = run_evidence(shim_rows({}, {}), audit_rows())
        self.assertEqual(code, 1, out)

    def test_a_subscribe_for_another_repo_fails(self):
        other = {"repo": "someone/else"}
        code, out = run_evidence(shim_rows(other, other), audit_rows())
        self.assertEqual(code, 1, out)

    def test_an_unsubscribe_the_gateway_did_not_apply_to_that_subscription_fails(self):
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args), audit_rows(unsub_id="sub-other"))
        self.assertEqual(code, 1, out)

    def test_an_unsubscribe_that_found_nothing_fails(self):
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args), audit_rows(unsub_detail="absent"))
        self.assertEqual(code, 1, out)

    def test_delivery_and_removal_of_another_subscription_fail(self):
        # The filtered subscribe answered sub-b; the audit shows only sub-123.
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args, result_id="sub-b"), audit_rows())
        self.assertEqual(code, 1, out)

    def test_a_removal_logged_before_the_shim_response_still_passes(self):
        args = {"repo": REPO}
        audit = audit_rows()
        audit[3]["ts"] = T0 + 15  # audit written 5 s before the shim logged the response at T0+20
        code, out = run_evidence(shim_rows(args, args), audit)
        self.assertEqual(code, 0, out)

    def test_a_later_complete_chain_passes_after_an_earlier_incomplete_subscribe(self):
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        earlier = {"kind": "http", "ts": T0 + 4, "status": 200, "error_code": None,
                   "rpc": ["events/subscribe"], "result_has_id": True, "result_id": "sub-a",
                   "rpc_params": [{"method": "events/subscribe", "name": EVENT, "arguments": args}]}
        rows.insert(3, earlier)
        code, out = run_evidence(rows, audit_rows())
        self.assertEqual(code, 0, out)

    def test_a_malformed_reply_does_not_count_as_an_answer(self):
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        rows[-1].pop("reply_ok")
        rows[-1]["parse_error"] = "ValueError"
        code, out = run_evidence(rows, audit_rows())
        self.assertEqual(code, 1, out)

    def test_a_retried_older_delivery_does_not_count_for_this_fire(self):
        # Delivered after the fire, but the event was first seen before it.
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args), audit_rows(first_seen=T0 + 6))
        self.assertEqual(code, 1, out)

    def test_an_unsubscribe_with_other_arguments_fails(self):
        code, out = run_evidence(shim_rows({"repo": REPO}, {"repo": "someone/else"}), audit_rows())
        self.assertEqual(code, 1, out)


class ShimReplyTests(unittest.TestCase):
    """The shim's own reply parser, not a hand-made `reply_ok` flag."""

    @staticmethod
    def facts(text, stream=False):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "events_shim", Path(__file__).resolve().parent / "mcp_events_oauth_shim.py")
        shim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shim)
        return shim.reply_facts(text, stream)

    def test_which_replies_count_as_valid(self):
        cases = {
            "good result": ('{"jsonrpc":"2.0","id":1,"result":{"id":"s1"}}', True),
            "error with an empty object": ('{"jsonrpc":"2.0","id":1,"error":{}}', False),
            "result and error together": ('{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1}}', False),
            "not json": ("<html>502</html>", False),
            "not an object": ("5", False),
        }
        for name, (text, valid) in cases.items():
            with self.subTest(name):
                self.assertIs(self.facts(text)["reply_ok"], valid)

    def test_a_good_result_keeps_its_id(self):
        facts = self.facts('{"result":{"id":"s1"}}')
        self.assertEqual((facts["result_id"], facts["result_has_id"]), ("s1", True))

    def test_a_streamed_reply_is_read_from_its_last_data_line(self):
        self.assertIs(self.facts('event: message\ndata: {"result":{}}\n\n', stream=True)["reply_ok"], True)


if __name__ == "__main__":
    unittest.main()
