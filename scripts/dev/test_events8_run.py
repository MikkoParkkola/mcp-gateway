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
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "events8_run.py"


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def setUpModule():
    # The script's fixed ports may be held on a shared runner; every run here
    # gets ports nothing else holds, so a refusal is never a port collision.
    os.environ["EVENTS8_GW_PORT"] = str(free_port())
    os.environ["EVENTS8_SHIM_PORT"] = str(free_port())
EVENT = "webhook.github.push.received"
SUB = "sub-123"
T0 = 1_000_000.0
REPO = "demo/repo"
KEY = "k-1"  # the shim's digest of (name, delivery url, arguments)


def shim_rows(sub_args, unsub_args, result_id=SUB, sub_key=KEY, unsub_key=KEY):
    def http(ts, method, params=None, **kw):
        row = {"kind": "http", "ts": ts, "status": 200, "error_code": None, "reply_ok": True, "rpc": [method], **kw}
        if params is not None:
            row["rpc_params"] = [{"method": method, **params}]
        return row

    return [
        {"kind": "oauth", "ts": T0 + 1, "step": "token"},
        http(T0 + 2, "server/discover"),
        http(T0 + 3, "events/list"),
        http(T0 + 5, "events/subscribe", {"name": EVENT, "arguments": sub_args, "key": sub_key},
             result_has_id=True, result_id=result_id),
        http(T0 + 20, "events/unsubscribe", {"name": EVENT, "arguments": unsub_args, "key": unsub_key}),
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

    def test_a_stale_subscription_delivered_before_this_fire_is_not_picked(self):
        # MIK-7945 D6.PLATFORM.3: an earlier run's subscription, delivered
        # before this fire, must not displace the one this fire exercised.
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        stale = {"kind": "http", "ts": T0 + 4, "status": 200, "error_code": None, "reply_ok": True,
                 "rpc": ["events/subscribe"], "result_has_id": True, "result_id": "sub-old",
                 "rpc_params": [{"method": "events/subscribe", "name": EVENT, "arguments": args,
                                 "key": "k-old"}]}
        rows.insert(3, stale)
        audit = audit_rows()
        audit.insert(0, {"ts": T0 + 6, "action": "events.delivery_outcome", "delivered": True,
                         "subscription_id": "sub-old", "event_id": "ev-0"})
        code, out = run_evidence(rows, audit)
        self.assertEqual(code, 0, out)

    def test_a_stale_event_retried_after_this_fire_does_not_pick_its_subscription(self):
        # Review r1: delivered after the fire, but the event was first seen before it.
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        stale = {"kind": "http", "ts": T0 + 4, "status": 200, "error_code": None, "reply_ok": True,
                 "rpc": ["events/subscribe"], "result_has_id": True, "result_id": "sub-old",
                 "rpc_params": [{"method": "events/subscribe", "name": EVENT, "arguments": args,
                                 "key": "k-old"}]}
        rows.insert(3, stale)
        audit = audit_rows()
        audit[:0] = [
            {"ts": T0 + 6, "action": "events.delivery_attempt", "event_id": "ev-0", "subscription_id": "sub-old"},
            {"ts": T0 + 12, "action": "events.delivery_outcome", "delivered": True,
             "subscription_id": "sub-old", "event_id": "ev-0"},
        ]
        code, out = run_evidence(rows, audit)
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

    def test_an_unsubscribe_for_another_delivery_url_fails(self):
        # MIK-7892.EVIDENCE.2: same event and arguments, but another callback, so
        # another subscription; the gateway's removal row for sub_id is not this call's.
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args, unsub_key="k-other"), audit_rows())
        self.assertEqual(code, 1, out)

    def test_rows_without_a_subscription_key_fail(self):
        # A log from before the shim recorded keys cannot bind the unsubscribe.
        args = {"repo": REPO}
        code, out = run_evidence(shim_rows(args, args, sub_key=None, unsub_key=None), audit_rows())
        self.assertEqual(code, 1, out)

    def test_a_batched_subscribe_whose_id_may_belong_to_another_event_fails(self):
        # MIK-7892.EVIDENCE.1: the reply's id is the first reply's, which can be
        # the other event's subscription; only a single-call row binds it.
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        rows[3]["rpc"] = ["events/subscribe", "events/subscribe"]
        rows[3]["rpc_params"].insert(0, {"method": "events/subscribe", "name": "other.event",
                                         "arguments": args, "key": "k-0"})
        code, out = run_evidence(rows, audit_rows())
        self.assertEqual(code, 1, out)

    def test_a_batched_unsubscribe_whose_reply_may_be_another_calls_fails(self):
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        rows[-1]["rpc"] = ["events/unsubscribe", "events/unsubscribe"]
        code, out = run_evidence(rows, audit_rows())
        self.assertEqual(code, 1, out)

    def test_the_shims_own_keys_bind_the_unsubscribe_to_its_callback(self):
        # Rows built from what the shim records for real calls, not hand-made keys.
        def call(method, url):
            return {"method": method, "params": {"name": EVENT, "delivery": {"url": url},
                                                 "arguments": {"repo": REPO}}}

        for unsub_url, code_wanted in (("https://cb.example/a", 0), ("https://cb.example/b", 1)):
            with self.subTest(unsub_url):
                rows = shim_rows({}, {})
                rows[3]["rpc_params"] = ShimReplyTests.params(call("events/subscribe", "https://cb.example/a"))
                rows[-1]["rpc_params"] = ShimReplyTests.params(call("events/unsubscribe", unsub_url))
                code, out = run_evidence(rows, audit_rows())
                self.assertEqual(code, code_wanted, out)

    def test_an_unsubscribe_bound_to_a_mismatched_subscribe_param_fails(self):
        # The key and arguments must come from the param that named this event and repo.
        args = {"repo": REPO}
        rows = shim_rows(args, args)
        rows[3]["rpc_params"].append({"method": "events/subscribe", "name": "other.event",
                                      "arguments": {"repo": "x/y"}, "key": "k-x"})
        rows[3]["rpc_params"].reverse()
        rows[-1]["rpc_params"][0].update(arguments={"repo": "x/y"}, key="k-x")
        code, out = run_evidence(rows, audit_rows())
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

    @staticmethod
    def params(doc):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "events_shim", Path(__file__).resolve().parent / "mcp_events_oauth_shim.py")
        shim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shim)
        return shim.subscription_params(doc)

    def test_the_key_names_one_subscription_without_logging_the_url(self):
        url = "https://cb.example/hook/secret-path-token"

        def call(method="events/subscribe", name=EVENT, url=url, **args):
            return {"method": method, "params": {"name": name, "delivery": {"url": url, "secret": "s3"},
                                                 "arguments": {"repo": REPO, **args}}}

        key = lambda c: self.params(c)[0]["key"]
        base = key(call())
        self.assertTrue(base)
        self.assertEqual(base, key(call(method="events/unsubscribe")), "same subscription, same key")
        for name, other in {"url": call(url="https://cb.example/other"), "event": call(name="e2"),
                            "filtered arg": call(ref="refs/heads/x"),
                            "unlisted arg": call(extra="1")}.items():
            with self.subTest(name):
                self.assertNotEqual(base, key(other))
        out = json.dumps(self.params([call(), call(method="events/unsubscribe")]))
        self.assertNotIn("secret-path-token", out)
        self.assertNotIn("s3", out)

    def test_a_call_without_a_delivery_url_has_no_key(self):
        self.assertIsNone(self.params({"method": "events/unsubscribe", "params": {"name": EVENT}})[0]["key"])

    def test_a_streamed_reply_is_read_from_its_last_data_line(self):
        self.assertIs(self.facts('event: message\ndata: {"result":{}}\n\n', stream=True)["reply_ok"], True)



class UpCleanupTests(unittest.TestCase):
    """MIK-7893.SHIM.3: `up` empties --dir only when its state.json names this
    script as the owner. A missing gateway binary stops `up` right after the
    cleanup decision, so nothing is started."""

    def up(self, state):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "state.json").write_text(state)
        (d / "keep.txt").write_text("not the script's")
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        return d, done

    def test_a_foreign_state_json_is_refused_and_nothing_is_removed(self):
        for state in ("{}", json.dumps({"started": T0}), "not json", "[]"):
            with self.subTest(state=state):
                d, done = self.up(state)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("not an events8 run directory", done.stderr)
                self.assertTrue((d / "keep.txt").exists(), "a directory the script does not own was emptied")

    def test_a_foreign_directory_is_refused_while_a_port_is_busy(self):
        """Ownership is judged before the ports, so a busy port on a shared
        host cannot mask the refusal of a directory the script does not own."""
        import socket
        busy = socket.socket()
        self.addCleanup(busy.close)
        busy.bind(("127.0.0.1", int(os.environ["EVENTS8_SHIM_PORT"])))
        busy.listen()
        d, done = self.up("{}")
        self.assertIn("not an events8 run directory", done.stderr)
        self.assertTrue((d / "keep.txt").exists(), "a directory the script does not own was emptied")

    def test_a_symlinked_state_json_does_not_lend_ownership(self):
        owner = tempfile.TemporaryDirectory()
        self.addCleanup(owner.cleanup)
        marker = Path(owner.name) / "state.json"
        marker.write_text(json.dumps({"owner": "events8_run"}))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "state.json").symlink_to(marker)
        (d / "keep.txt").write_text("not the script's")
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        self.assertIn("not an events8 run directory", done.stderr)
        self.assertTrue((d / "keep.txt").exists(), "a borrowed marker emptied the directory")

    def test_a_hard_linked_state_json_does_not_lend_ownership(self):
        owner = tempfile.TemporaryDirectory()
        self.addCleanup(owner.cleanup)
        marker = Path(owner.name) / "state.json"
        marker.write_text(json.dumps({"owner": "events8_run"}))
        tmp = tempfile.TemporaryDirectory(dir=owner.name)
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        os.link(marker, d / "state.json")
        (d / "keep.txt").write_text("not the script's")
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        self.assertIn("not an events8 run directory", done.stderr)
        self.assertTrue((d / "keep.txt").exists(), "a borrowed marker emptied the directory")

    def test_a_symlinked_run_directory_is_refused_and_its_target_kept(self):
        # MIK-7945 D6.PLATFORM.1: the directory is judged and emptied through
        # one handle that does not follow a symlink, so a link (or a swap made
        # between the check and the removal) cannot point the cleanup elsewhere.
        target = tempfile.TemporaryDirectory()
        self.addCleanup(target.cleanup)
        t = Path(target.name)
        (t / "state.json").write_text(json.dumps({"owner": "events8_run"}))
        (t / "keep.txt").write_text("behind a link")
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        d = Path(holder.name) / "run"
        d.symlink_to(t, target_is_directory=True)
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(t / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        self.assertIn("not an events8 run directory", done.stderr)
        self.assertTrue((t / "keep.txt").exists(), "a symlinked --dir emptied its target")

    def test_a_fifo_marker_is_refused_without_waiting(self):
        # Review r1: a FIFO state.json with no writer must not hang `up`.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        os.mkfifo(d / "state.json")
        (d / "keep.txt").write_text("not the script's")
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=20)
        self.assertIn("not an events8 run directory", done.stderr)
        self.assertTrue((d / "keep.txt").exists())

    def test_nested_files_of_an_owned_directory_are_cleared(self):
        # Review r1: the handle-relative removal descends into subdirectories.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "state.json").write_text(json.dumps({"owner": "events8_run"}))
        (d / "old" / "deeper").mkdir(parents=True)
        (d / "old" / "deeper" / "f.log").write_text("x")
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        (Path(outside.name) / "keep.txt").write_text("outside")
        (d / "old" / "link").symlink_to(outside.name, target_is_directory=True)
        subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        self.assertFalse((d / "old").exists(), "a nested directory was left")
        self.assertTrue((Path(outside.name) / "keep.txt").exists(), "removal followed a symlink")

    def test_a_directory_the_script_owns_is_cleared(self):
        d, done = self.up(json.dumps({"owner": "events8_run"}))
        self.assertNotIn("not an events8 run directory", done.stderr)
        self.assertFalse((d / "keep.txt").exists(), "the previous run's files were left")

    def test_a_directory_left_by_an_earlier_up_is_cleared_again(self):
        d, _ = self.up(json.dumps({"owner": "events8_run"}))
        (d / "keep.txt").write_text("from the earlier run")
        done = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(d), "up", "--gateway", str(d / "no-such-gateway")],
            capture_output=True, text=True, timeout=60)
        self.assertNotIn("not an events8 run directory", done.stderr)
        self.assertFalse((d / "keep.txt").exists(), "up did not recognise its own marker")


if __name__ == "__main__":
    unittest.main()
