#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8014 per-call timing gate (design: docs/internal/design/2026-10-09-mik-8014-perf-per-call-family.md).

Runs ON the bench host, never on shared CI runners. For BASE and HEAD it builds
the lib test binary (the harness's test-only files overlaid on BASE, so BASE's
production code is what is measured), then:

  * every comparison is the same statistic: per row, the median over ABBA
    blocks (start arm seeded) of the second arm's mean minus the first's;
  * an A/A null arm: K base-vs-base comparisons; a row's budget is the
    largest |delta| among them (per-row false-alarm rate ~ 1/(K+1));
  * the head arm: base vs head;
  * a negative-control arm: unarmed HEAD vs HEAD with
    PER_CALL_NEGATIVE_CONTROL=1, which must be OVER on every row.

VOID (exit 2, no verdict): a row's budget above CEILING_NS in any run, a
negative control that did not fail every row, a busy host, or any error.
FAIL (exit 1): a row OVER in the run and in one confirmation with a fresh
null arm. Else PASS (exit 0). The whole job holds one bench lock.
"""

import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile

CEILING_NS = 4000
# The bench host also builds other work; a run under load is VOID, never PASS.
MAX_LOAD = 4.0
TEST = "gateway::server::signing_allocation_tests::per_call_timing::per_call_timing"
# Test-only files the harness needs; overlaid onto BASE so both arms run it.
HARNESS = [
    "src/gateway/server/tests/per_call_timing.rs",
    "src/gateway/server/tests/invoke_argument_copies.rs",
    "src/gateway/server/tests/mod.rs",
]
# One harness run takes seconds; a hang is no measurement.
RUN_TIMEOUT_S = 300
LOCK = os.path.expanduser("~/mirrors/.locks/bench.lock")


class Void(Exception):
    """No verdict: the run could not measure (exit 2, never 1)."""


def sh(cmd, cwd=None, env=None, timeout=None):
    try:
        done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Void(f"{' '.join(cmd[:4])} ran past {timeout} s") from None
    if done.returncode != 0:
        tail = "\n".join(done.stderr.splitlines()[-30:])
        raise Void(f"{' '.join(cmd[:4])} exited {done.returncode}:\n{tail}")
    return done.stdout


def build(repo, ref, work, key, commits, overlay_from=None):
    """The release lib test binary for `ref`, at work/<key>.bin. `key` names
    the exact source (commit SHAs), so a binary already there is reused."""
    tree = os.path.join(work, key)
    binary = os.path.join(work, key + ".bin")
    if os.path.exists(binary):
        try:
            verified(binary, commits)
            print(f"reusing {binary}")
            return tree, binary
        except Void:
            pass  # stale or unrecorded: rebuild
    shutil.rmtree(tree, ignore_errors=True)
    # An export, not a checkout: nothing is registered in the host's clone.
    os.makedirs(tree)
    archive = subprocess.run(["git", "archive", ref], cwd=repo, capture_output=True)
    if archive.returncode != 0:
        raise Void(f"git archive {ref} exited {archive.returncode}")
    subprocess.run(["tar", "-x", "-C", tree], input=archive.stdout, check=True)
    for path in HARNESS if overlay_from else []:
        shutil.copy(os.path.join(overlay_from, path), os.path.join(tree, path))
    # Release: debug timings are dominated by unoptimised code, and the 4 us
    # ceiling would be meaningless there. One target dir for both arms, so the
    # second build reuses the dependencies; the binary is copied out because
    # the next build writes the same path.
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(work, "target"))
    out = sh(["cargo", "test", "--release", "--lib", "--no-run", "--message-format=json"], cwd=tree, env=env)
    exe = [m.group(1) for m in re.finditer(r'"executable":"([^"]+mcp_gateway-[^"]+)"', out)]
    if not exe:
        raise Void(f"no lib test binary for {ref}")
    shutil.copy(exe[-1], binary + ".partial")
    os.replace(binary + ".partial", binary)
    write_manifest(binary, commits)
    return tree, binary


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(binary, commits):
    with open(binary + ".json", "w") as f:
        json.dump({"commits": commits, "sha256": digest(binary)}, f)


def verified(binary, commits):
    """`binary` if its manifest names exactly `commits` and its bytes still
    hash to the recorded digest; else Void (a measure-only run never builds)."""
    try:
        with open(binary + ".json") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        raise Void(f"no prebuilt binary for {commits} (run --prebuild-only first)") from None
    if manifest.get("commits") != commits:
        raise Void(f"{binary} was built from {manifest.get('commits')}, not {commits}")
    if not os.path.exists(binary) or manifest.get("sha256") != digest(binary):
        raise Void(f"{binary} does not match its manifest")
    return binary


def STAGES_FROM_HARNESS():  # noqa: N802 - names the Rust constant it reads
    """The harness's STAGES table: every row a run must print."""
    path = os.path.join(os.path.dirname(__file__), "../../src/gateway/server/tests/per_call_timing.rs")
    with open(path) as f:
        block = re.search(r"const STAGES: &\[&str\] = &\[(.*?)\];", f.read(), re.S)
    return set(re.findall(r'"([^"]+)"', block.group(1)))


# The highest 1-minute load seen before any harness run in this job.
PEAK_LOAD = [0.0]


def run(binary, negative=False):
    PEAK_LOAD[0] = max(PEAK_LOAD[0], os.getloadavg()[0])
    env = dict(os.environ)
    if negative:
        env["PER_CALL_NEGATIVE_CONTROL"] = "1"
    out = sh([binary, "--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"], env=env, timeout=RUN_TIMEOUT_S)
    rows = dict(re.findall(r"PER_CALL_NS (\S+) (\d+)", out))
    stages = STAGES_FROM_HARNESS()
    if set(rows) != stages:
        raise Void(f"every STAGES row must be measured: printed {sorted(rows)}, table {sorted(stages)}")
    return {k: int(v) for k, v in rows.items()}


def paired(first, second, blocks, rng):
    """Per row, the median over ABBA blocks of mean(second) - mean(first).
    An arm is (binary, negative); arms are told apart by position, so the
    same binary may stand on both sides (the null arm, the control)."""
    deltas = {}
    for _ in range(blocks):
        start_second = rng.random() < 0.5
        order = [1, 0, 0, 1] if start_second else [0, 1, 1, 0]
        results = [(side, run(*(first, second)[side])) for side in order]
        for row in results[0][1]:
            two = statistics.mean(r[row] for side, r in results if side == 1)
            one = statistics.mean(r[row] for side, r in results if side == 0)
            deltas.setdefault(row, []).append(two - one)
    return {row: statistics.median(v) for row, v in deltas.items()}


def null_budget(base, k, blocks, rng):
    """Per row, the largest |delta| among K base-vs-base runs of the same
    statistic the head is judged on (per-row false alarm ~ 1/(K+1))."""
    nulls = [paired((base, False), (base, False), blocks, rng) for _ in range(k)]
    return {row: max(abs(n[row]) for n in nulls) for row in nulls[0]}


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
    p.add_argument("--work", help="where the binaries live (default: a temp dir)")
    p.add_argument("--prebuild-only", action="store_true",
                   help="build both binaries into --work and stop; takes no bench lock")
    p.add_argument("--measure-only", action="store_true",
                   help="measure the binaries in --work; refuse unless their manifests match")
    a = p.parse_args()
    if a.k < 1 or a.blocks < 1:
        p.error("--k and --blocks must be at least 1")
    if (a.prebuild_only or a.measure_only) and not a.work:
        p.error("--prebuild-only and --measure-only need --work")
    if a.prebuild_only and a.measure_only:
        p.error("choose one of --prebuild-only and --measure-only")
    repo = sh(["git", "rev-parse", "--show-toplevel"]).strip()
    try:
        if a.prebuild_only:
            os.makedirs(a.work, exist_ok=True)
            for binary in builds(repo, a, a.work):
                print(f"built {binary}")
            return 0
        os.makedirs(os.path.dirname(LOCK), exist_ok=True)
        with open(LOCK, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            rng = random.Random(a.seed)
            print(f"seed {a.seed}; K={a.k} (per-row false-alarm ~{1 / (a.k + 1):.0%}); blocks={a.blocks}")
            if a.measure_only:
                return measure(a, rng, prebuilt(repo, a, a.work))
            if a.work:
                os.makedirs(a.work, exist_ok=True)
                return measure(a, rng, builds(repo, a, a.work))
            with tempfile.TemporaryDirectory() as work:
                return measure(a, rng, builds(repo, a, work))
    except Void as why:
        print(f"VOID: {why}")
        return 2
    except Exception as why:  # noqa: BLE001 - any crash is no measurement
        print(f"VOID: {type(why).__name__}: {why}")
        return 2


def shas(repo, a):
    return tuple(sh(["git", "rev-parse", "--verify", f"{r}^{{commit}}"], cwd=repo).strip()
                 for r in (a.base, a.head))


def keys(base_sha, head_sha):
    """BASE carries HEAD's harness files, so its key and manifest name both."""
    return (f"{base_sha[:12]}+{head_sha[:12]}", [base_sha, head_sha]), (head_sha[:12], [head_sha])


def builds(repo, a, work):
    """(base, head) binaries, built or reused."""
    base_sha, head_sha = shas(repo, a)
    (base_key, base_commits), (head_key, head_commits) = keys(base_sha, head_sha)
    head_tree, head = build(repo, head_sha, work, head_key, head_commits)
    _, base = build(repo, base_sha, work, base_key, base_commits, overlay_from=head_tree)
    return base, head


def prebuilt(repo, a, work):
    """(base, head) from --work, each checked against its manifest; never builds."""
    base_sha, head_sha = shas(repo, a)
    (base_key, base_commits), (head_key, head_commits) = keys(base_sha, head_sha)
    return (verified(os.path.join(work, base_key + ".bin"), base_commits),
            verified(os.path.join(work, head_key + ".bin"), head_commits))


def measure(a, rng, binaries):
    base, head = binaries
    # One null arm judges the control and the head: same base, same statistic.
    budget = null_budget(base, a.k, a.blocks, rng)
    # The gate checks itself: HEAD slowed on purpose must be OVER on every row,
    # judged against unarmed HEAD so HEAD's own change cannot mask it.
    control = judge(budget, paired((head, False), (head, True), a.blocks, rng))
    verdicts = [judge(budget, paired((base, False), (head, False), a.blocks, rng))]
    if "OVER" in verdicts[0].values():
        print("confirmation run with a fresh null arm")
        verdicts.append(judge(null_budget(base, a.k, a.blocks, rng),
                              paired((base, False), (head, False), a.blocks, rng)))

    # Load is sampled before every harness run; any breach anywhere is VOID.
    peak = max(PEAK_LOAD[0], os.getloadavg()[0])
    print(f"host load: peak {peak:.1f} over the run (max {MAX_LOAD})")
    if peak > MAX_LOAD:
        print("VOID: the bench host was busy; rerun when it is quiet")
        return 2
    if any(v != "OVER" for v in control.values()):
        print("VOID: the negative control did not fail every row")
        return 2
    return decide(verdicts)


def decide(verdicts):
    """VOID if any run could not judge a row; FAIL if a row is OVER in the
    first run and its confirmation; else PASS."""
    if any("VOID" in v.values() for v in verdicts):
        print("VOID: a row's budget exceeds the ceiling; rerun on a quieter host")
        return 2
    if len(verdicts) == 2:
        failed = [r for r, v in verdicts[0].items() if v == "OVER" and verdicts[1][r] == "OVER"]
        if failed:
            print(f"FAIL: {failed} over budget twice")
            return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
