#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Generate tests/fixtures/tenant-reads-corpus.jsonl (MIK-7116.MIN.4, design §5): python3 tests/fixtures/gen_tenant_reads_corpus.py > tests/fixtures/tenant-reads-corpus.jsonl.

One line per outbound frame. Labels come from the generating pattern, never
from the guard. Deterministic: no randomness, so the pinned counts are stable.
"""
import json
import sys

WINDOW = 3600
OPAQUE = "{not json: a body the attribution cannot read"
rows = []
counts = {}


def text(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj)}], "isError": False}


def answer(result):
    return {"kind": "response", "frame": {"jsonrpc": "2.0", "id": 1, "result": result}}


def session(pattern, n, frames, key=None):
    counts[pattern] = counts.get(pattern, 0) + 1
    sid = f"{pattern}-{n}"
    for t, f in frames:
        row = {"session": sid, "caller_key": key or f"api_key:{sid}", "t_secs": t, "pattern": pattern}
        row.update(f)
        rows.append(row)


def t_read(tenant, extra=None):
    body = {"customer_id": tenant, "rows": [1, 2, 3]}
    body.update(extra or {})
    return answer(text(body))


for n in range(20):
    session("single_tenant", n, [(i * 30, t_read(f"t{n}")) for i in range(5)])
for n in range(10):
    session("retry_same_tenant", n, [(i, t_read(f"r{n}")) for i in range(3)])
for n in range(10):
    session("mixed_workload", n, [(0, answer(text({"status": "ok"}))), (5, t_read(f"m{n}")),
                                   (9, answer(text({"tools": ["a", "b"]})))])
for n in range(5):
    session("opaque_only", n, [(0, answer({"content": [{"type": "text", "text": OPAQUE}]}))])
for n in range(5):
    session("support_handoff_slow", n, [(0, t_read(f"s{n}a")), (WINDOW + 60, t_read(f"s{n}b"))])
for n in range(5):
    session("window_boundary", n, [(0, t_read(f"w{n}a")), (WINDOW + 1, t_read(f"w{n}b"))])
# Known false positives (excluded from gate 1).
for n in range(5):
    op = answer({"content": [{"type": "text", "text": OPAQUE}]})
    session("opaque_only_multi", n, [(0, op), (10, op)])
for n in range(5):
    session("support_handoff_fast", n, [(0, t_read(f"f{n}a")), (60, t_read(f"f{n}b"))])
for n in range(3):
    session("admin_sweep", n, [(i, t_read(f"adm{n}-{i}")) for i in range(4)])
for n in range(3):
    session("large_single_tenant", n, [(0, answer(text({"customer_id": f"big{n}",
                                                          "related": [{"customer_id": f"big{n}-sub"}]})))])
# Cross-tenant.
for n in range(5):
    session("a_then_b", n, [(0, t_read("a")), (30, t_read("b"))])
    session("a_then_b_request_only", n, [(0, t_read("a")),
                                         (30, {"kind": "response", "request": {"name": "prompts/get", "arguments": {"customer_id": "b"}},
                                               "frame": {"jsonrpc": "2.0", "id": 2, "result": {"messages": []}}})])
    session("a_then_opaque", n, [(0, t_read("a")), (30, answer({"content": [{"type": "text", "text": OPAQUE}]}))])
    session("opaque_then_b", n, [(0, answer({"content": [{"type": "text", "text": OPAQUE}]})), (30, t_read("b"))])
    session("a_result_then_b_notification", n, [(0, t_read("a")),
                                                (5, {"kind": "notification", "frame": {"jsonrpc": "2.0", "method": "notifications/resources/updated",
                                                                                       "params": {"uri": "rows://x", "customer_id": "b"}}})])
    session("a_then_b_error_data", n, [(0, t_read("a")),
                                       (5, {"kind": "response", "frame": {"jsonrpc": "2.0", "id": 3,
                                                                          "error": {"code": -32000, "message": "upstream", "data": {"customer_id": "b"}}}})])
    session("a_then_b_webhook", n, [(0, t_read("a")),
                                    (5, {"kind": "event", "raw": {"kind": "row", "customer_id": "b"}, "frame": {"kind": "row"}})])
    session("a_then_b_proxy_request", n, [(0, t_read("a")),
                                          (5, {"kind": "request", "frame": {"jsonrpc": "2.0", "id": "gw-1", "method": "sampling/createMessage",
                                                                            "params": {"messages": [{"role": "user", "content": {"type": "text", "text": json.dumps({"customer_id": "b"})}}]}}})])
    session("a_then_b_event_callback", n, [(0, t_read("a")),
                                           (5, {"kind": "callback", "raw": {"type": "ticket.updated", "data": {"customer_id": "b", "note": "x"}},
                                                "frame": {"type": "ticket.updated", "data": {"note": "x"}}})])
    session("a_then_b_method_string", n, [(0, t_read("a")),
                                          (5, {"kind": "notification", "frame": {"jsonrpc": "2.0", "method": json.dumps({"customer_id": "b"})}})])
    key = f"api_key:two-sessions-{n}"
    counts["two_sessions_one_key"] = counts.get("two_sessions_one_key", 0) + 1
    rows.append({"session": f"two_sessions_one_key-{n}/s1", "principal_session": f"two_sessions_one_key-{n}",
                 "caller_key": key, "t_secs": 0, "pattern": "two_sessions_one_key", **t_read("a")})
    rows.append({"session": f"two_sessions_one_key-{n}/s2", "principal_session": f"two_sessions_one_key-{n}",
                 "caller_key": key, "t_secs": 20, "pattern": "two_sessions_one_key", **t_read("b")})

out = sys.stdout
out.write(json.dumps({"header": True, "window_secs": WINDOW, "sessions": counts}, sort_keys=True) + "\n")
for row in rows:
    out.write(json.dumps(row, sort_keys=True) + "\n")
