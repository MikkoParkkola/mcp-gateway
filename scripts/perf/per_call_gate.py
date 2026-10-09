#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8014 per-call timing gate (design: docs/internal/design/2026-10-09-mik-8014-perf-per-call-family.md).

Runs ON the bench host, never on shared CI runners. For BASE and HEAD it builds
the lib test binary (the harness's test-only files overlaid on BASE, so BASE's
production code is what is measured), then:

  * an A/A null arm: K base-vs-base pairs; a row's budget is the largest
    |difference| among them (per-row false-alarm rate ~ 1/(K+1));
  * the head arm: ABBA blocks (start arm seeded and printed), head - base;
  * a negative-control arm: HEAD with PER_CALL_NEGATIVE_CONTROL=1, which must
    FAIL every row, or the run is VOID (the gate checks itself).

Verdict per row: VOID if its budget exceeds CEILING_NS (the run cannot see the
class of cost the family stops); FAIL only if head - base exceeds the budget in
this run AND in one confirmation run with a fresh null arm; else PASS. Exit 0 =
PASS, 1 = FAIL, 2 = VOID. The whole job holds one bench lock.
"""

import argparse
import fcntl
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

CEILING_NS = 4000
TEST = "gateway::server::signing_allocation_tests::per_call_timing::per_call_timing"
# Test-only files the harness needs; overlaid onto BASE so both arms run it.
HARNESS = [
    "src/gateway/server/tests/per_call_timing.rs",
    "src/gateway/server/tests/invoke_argument_copies.rs",
    "src/gateway/server/tests/mod.rs",
]
LOCK = os.path.expanduser("~/mirrors/.locks/bench.lock")


def sh(cmd, cwd=None, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout


def build(repo, ref, work, overlay_from=None):
    tree = os.path.join(work, ref.replace("/", "_"))
    sh(["git", "worktree", "add", "--detach", tree, ref], cwd=repo)
    for path in HARNESS if overlay_from else []:
        shutil.copy(os.path.join(overlay_from, path), os.path.join(tree, path))
    # Release: debug timings are dominated by unoptimised code, and the 4 us
    # ceiling would be meaningless there.
    out = sh(["cargo", "test", "--release", "--lib", "--no-run", "--message-format=json"], cwd=tree)
    exe = [m.group(1) for m in re.finditer(r'"executable":"([^"]+mcp_gateway-[^"]+)"', out)]
    if not exe:
        sys.exit(f"no lib test binary for {ref}")
    return tree, exe[-1]


def run(binary, negative=False):
    env = dict(os.environ)
    if negative:
        env["PER_CALL_NEGATIVE_CONTROL"] = "1"
    out = sh([binary, "--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"], env=env)
    rows = dict(re.findall(r"PER_CALL_NS (\S+) (\d+)", out))
    if not rows:
        sys.exit(f"the harness printed no rows:\n{out}")
    return {k: int(v) for k, v in rows.items()}


def null_budget(base, k):
    diffs = {}
    for _ in range(k):
        a, b = run(base), run(base)
        for row in a:
            diffs.setdefault(row, []).append(abs(a[row] - b[row]))
    return {row: max(v) for row, v in diffs.items()}


def paired(base, head, blocks, rng):
    start_head = rng.random() < 0.5
    print(f"ABBA start arm: {'head' if start_head else 'base'}")
    deltas = {}
    for _ in range(blocks):
        order = [head, base, base, head] if start_head else [base, head, head, base]
        results = [(arm is head, run(arm)) for arm in order]
        for row in results[0][1]:
            h = statistics.mean(r[row] for is_head, r in results if is_head)
            b = statistics.mean(r[row] for is_head, r in results if not is_head)
            deltas.setdefault(row, []).append(h - b)
    return {row: statistics.median(v) for row, v in deltas.items()}


def judge(budget, delta):
    verdict = {}
    for row, d in delta.items():
        if budget[row] > CEILING_NS:
            verdict[row] = "VOID"
        elif d > budget[row]:
            verdict[row] = "OVER"
        else:
            verdict[row] = "PASS"
        print(f"{row}: head-base {d:.0f} ns, budget {budget[row]} ns -> {verdict[row]}")
    return verdict


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--k", type=int, default=19)
    p.add_argument("--blocks", type=int, default=4)
    p.add_argument("--seed", type=int, default=random.randrange(1 << 30))
    a = p.parse_args()
    repo = sh(["git", "rev-parse", "--show-toplevel"]).strip()
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rng = random.Random(a.seed)
        print(f"seed {a.seed}; K={a.k} (per-row false-alarm ~{1 / (a.k + 1):.0%}); blocks={a.blocks}")
        with tempfile.TemporaryDirectory() as work:
            head_tree, head = build(repo, a.head, work)
            _, base = build(repo, a.base, work, overlay_from=head_tree)

            control = judge(null_budget(base, a.k), {
                row: v - run(base)[row] for row, v in run(head, negative=True).items()})
            if any(v != "OVER" for v in control.values()):
                print("VOID: the negative control did not fail every row")
                return 2

            verdict = judge(null_budget(base, a.k), paired(base, head, a.blocks, rng))
            if "OVER" in verdict.values():
                print("confirmation run with a fresh null arm")
                again = judge(null_budget(base, a.k), paired(base, head, a.blocks, rng))
                failed = [r for r, v in verdict.items() if v == "OVER" and again[r] == "OVER"]
                if failed:
                    print(f"FAIL: {failed} over budget twice")
                    return 1
            if "VOID" in verdict.values():
                print("VOID: a row's budget exceeds the ceiling; rerun on a quieter host")
                return 2
            print("PASS")
            return 0


if __name__ == "__main__":
    sys.exit(main())
