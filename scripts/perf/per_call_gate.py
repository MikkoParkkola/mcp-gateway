#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8014 per-call timing gate (design: docs/internal/design/2026-10-09-mik-8014-perf-per-call-family.md).

Runs ON the bench host, never on shared CI runners. For BASE and HEAD it builds
the lib test binary (only the harness file overlaid on BASE and mounted with
its `mod` line, so BASE's production code is what is measured), then:

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

Statistical assumptions, and a limit that is NOT corrected (F4): the null
arm runs ONE binary on both sides, while the head arm compares two separate
builds. A fixed code-layout (or link-order) bias between the two builds
therefore never enters a row's budget: a layout shift alone can push a row
OVER, and can also mask a real slowdown of the same size. No second base
build is made to measure that bias (it would double the build cost to bound
a term the family accepts as unmeasured). Per row, the false-alarm rate is
~1/(K+1) and the smallest detectable slowdown is that row's budget (itself
capped at CEILING_NS, above which the run is VOID). `print_assumptions`
repeats this with every verdict, VOID included, so no verdict is read
without it.
"""

import argparse
import fcntl
import functools
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
import threading

CEILING_NS = 4000
# The bench host also builds other work; a run under load is VOID, never PASS.
MAX_LOAD = 4.0
# Host load is re-sampled this often while a harness process runs.
LOAD_SAMPLE_S = 0.5
# The one build profile a measurement may use; a cached binary built with
# another profile (or another rustc) is stale (F7).
PROFILE = "release"
TEST = "gateway::server::signing_allocation_tests::per_call_timing::per_call_timing"
# The only file overlaid onto BASE (F2). Everything else in BASE's test
# tree -- its whole tests/mod.rs and the shared helpers per_call_timing
# calls -- stays BASE's own, so a later PR cannot break the BASE build or
# confound the comparison through the overlay; ensure_harness_mounted adds
# only the `mod` line that mounts this file when BASE predates it.
HARNESS = [
    "src/gateway/server/tests/per_call_timing.rs",
]
TESTS_MOD = "src/gateway/server/tests/mod.rs"
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
    # The overlay is read from git at HEAD's commit, never from a tree on
    # disk that a reused build left behind.
    for path in HARNESS if overlay_from else []:
        blob = subprocess.run(["git", "show", f"{overlay_from}:{path}"], cwd=repo, capture_output=True)
        if blob.returncode != 0:
            raise Void(f"git show {overlay_from[:12]}:{path} exited {blob.returncode}")
        with open(os.path.join(tree, path), "wb") as f:
            f.write(blob.stdout)
    if overlay_from:
        ensure_harness_mounted(tree)
    # Release: debug timings are dominated by unoptimised code, and the 4 us
    # ceiling would be meaningless there. One target dir for both arms, so the
    # second build reuses the dependencies; the binary is copied out because
    # the next build writes the same path.
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(work, "target"))
    out = sh(["cargo", "test", f"--{PROFILE}", "--lib", "--no-run", "--message-format=json"], cwd=tree, env=env)
    exe = [m.group(1) for m in re.finditer(r'"executable":"([^"]+mcp_gateway-[^"]+)"', out)]
    if not exe:
        raise Void(f"no lib test binary for {ref}")
    shutil.copy(exe[-1], binary + ".partial")
    os.replace(binary + ".partial", binary)
    write_manifest(binary, commits)
    return tree, binary


def ensure_harness_mounted(tree):
    """Mount the overlaid harness in BASE's own tests/mod.rs (F2): add the
    `mod per_call_timing;` line when BASE predates it, and change nothing
    else in the file."""
    path = os.path.join(tree, TESTS_MOD)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise Void(f"{TESTS_MOD} missing in the BASE tree; cannot mount the harness") from None
    mounted = re.search(
        rb"(?m)^[ \t]*(?:#\[[^\]\n]*\][ \t]*)*"
        rb"(?:pub(?:\([^)]*\))?[ \t]+)?mod[ \t]+per_call_timing[ \t]*;",
        data,
    )
    if mounted:
        return
    # Append only the mounting line: every existing byte stays as it was.
    separator = b"" if not data or data.endswith(b"\n") else b"\n"
    with open(path, "wb") as f:
        f.write(data + separator + b"mod per_call_timing;\n")


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def current_rustc():
    """This host's `rustc -V`. Fails closed (F7): when the current compiler
    cannot be determined there is no usable identity to certify or compare
    against, so the run is VOID rather than silently unverified."""
    try:
        done = subprocess.run(["rustc", "-V"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as why:
        raise Void(f"current rustc version unavailable: cannot run rustc -V ({why})") from None
    version = done.stdout.strip() if done.returncode == 0 else ""
    if not version:
        raise Void(
            f"current rustc version unavailable: rustc -V exited {done.returncode} "
            "without a usable version"
        )
    return version


def write_manifest(binary, commits, rustc_version=None, profile=None):
    """Record what the binary was built from (F7): the commits, the digest,
    the compiler version and the build profile. Never certifies an unknown
    compiler: an unavailable or empty version is VOID before anything is
    written."""
    version = current_rustc() if rustc_version is None else rustc_version
    if not version or not str(version).strip():
        raise Void(f"refusing to certify {binary}: rustc version unavailable or empty")
    with open(binary + ".json.partial", "w") as f:
        json.dump({
            "commits": commits,
            "sha256": digest(binary),
            "rustc_version": version,
            "profile": PROFILE if profile is None else profile,
        }, f)
    os.replace(binary + ".json.partial", binary + ".json")


def verified(binary, commits, rustc_version=None, profile=None):
    """`binary` if its manifest names exactly `commits`, its bytes still
    hash to the recorded digest, and it was built by this host's rustc with
    this profile; else Void. A stale binary is rebuilt by `build` and
    refused (VOID) under --measure-only, which never builds (F7)."""
    try:
        with open(binary + ".json") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        raise Void(f"no prebuilt binary for {commits} (run --prebuild-only first)") from None
    if manifest.get("commits") != commits:
        raise Void(f"{binary} was built from {manifest.get('commits')}, not {commits}")
    want_profile = PROFILE if profile is None else profile
    if manifest.get("profile") != want_profile:
        raise Void(
            f"{binary} is stale: built with profile {manifest.get('profile')!r}, not {want_profile!r}"
        )
    want_rustc = current_rustc() if rustc_version is None else rustc_version
    if not want_rustc or not str(want_rustc).strip():
        raise Void(f"{binary} cannot be verified: current rustc version unavailable or empty")
    built_rustc = manifest.get("rustc_version")
    if not built_rustc or not str(built_rustc).strip():
        raise Void(
            f"{binary} is stale: built with unknown rustc "
            f"(manifest compiler missing or empty), not {want_rustc!r}"
        )
    if built_rustc != want_rustc:
        raise Void(f"{binary} is stale: built with {built_rustc!r}, not {want_rustc!r}")
    if not os.path.exists(binary) or manifest.get("sha256") != digest(binary):
        raise Void(f"{binary} does not match its manifest")
    return binary


@functools.cache
def STAGES_FROM_HARNESS():  # noqa: N802 - names the Rust constant it reads
    """The harness's STAGES table: every row a run must print. Each entry
    keeps its name with its parameters (F6); the name is its only string."""
    path = os.path.join(os.path.dirname(__file__), "../../src/gateway/server/tests/per_call_timing.rs")
    with open(path) as f:
        block = re.search(r"const STAGES\b[^=]*=\s*&\[(.*?)\];", f.read(), re.S)
    return set(re.findall(r'"([^"]+)"', block.group(1)))


# The highest 1-minute load sampled anywhere in this job, before, during
# and after harness runs. Any sample above MAX_LOAD voids the job.
PEAK_LOAD = [0.0]


def sample_load():
    """Fold this host's 1-minute load into the job's peak; returns it."""
    PEAK_LOAD[0] = max(PEAK_LOAD[0], os.getloadavg()[0])
    return PEAK_LOAD[0]


def _sample_while(stop, errors):
    while True:
        try:
            sample_load()
        except Exception as why:  # noqa: BLE001 - a failed observation is VOID
            # Record, do not swallow: run() refuses after joining this
            # thread, so one failed sample cannot pass as a quiet host.
            errors.append(why)
            return
        if stop.wait(LOAD_SAMPLE_S):
            return


def run(binary, negative=False):
    # Sample before, during and after the harness process (F3): a breach
    # while it runs must void the job, not pass unseen between runs.
    sample_load()
    env = dict(os.environ)
    if negative:
        env["PER_CALL_NEGATIVE_CONTROL"] = "1"
    stop = threading.Event()
    sampler_errors = []
    sampler = threading.Thread(
        target=_sample_while, args=(stop, sampler_errors), daemon=True
    )
    sampler.start()
    try:
        out = sh([binary, "--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"], env=env, timeout=RUN_TIMEOUT_S)
    finally:
        stop.set()
        sampler.join()
    if sampler_errors:
        why = sampler_errors[0]
        raise Void(f"host load sampler failed during the run: {type(why).__name__}: {why}")
    sample_load()
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


def judge(budget, delta, label="head-base"):
    verdict = {}
    for row, d in delta.items():
        if budget[row] > CEILING_NS:
            verdict[row] = "VOID"
        elif d > budget[row]:
            verdict[row] = "OVER"
        else:
            verdict[row] = "PASS"
        print(f"{row}: {label} {d:.0f} ns, budget {budget[row]} ns -> {verdict[row]}")
    return verdict


def print_assumptions(k, budgets=None):
    """The statistical assumptions and the uncorrected layout limit (F4),
    printed with every verdict, VOID included."""
    print(f"assumptions: K={k}; per-row false-alarm rate ~1/(K+1) = {1 / (k + 1):.1%}; "
          f"budget ceiling {CEILING_NS} ns (a row above it is VOID)")
    if budgets:
        smallest = ", ".join(f"{row} {budgets[row]:.0f} ns" for row in sorted(budgets))
        print(f"assumptions: per-row minimum detectable delta (= the row's budget): {smallest}")
    else:
        print("assumptions: per-row minimum detectable delta = the row's budget "
              "(no budget was measured in this run)")
    print("limit: the A/A null arm runs one binary on both sides, the head arm two "
          "separate builds; a fixed code-layout bias between builds is not in any "
          "budget and is not corrected")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--k", type=int, default=19)
    p.add_argument("--blocks", type=int, default=4)
    p.add_argument("--seed", type=int, default=random.randrange(1 << 30))
    p.add_argument("--work", help="where the binaries live (default: a temp dir)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--prebuild-only", action="store_true",
                   help="build both binaries into --work and stop; takes no bench lock")
    mode.add_argument("--measure-only", action="store_true",
                   help="measure the binaries in --work; refuse unless their manifests match")
    a = p.parse_args()
    if a.k < 1 or a.blocks < 1:
        p.error("--k and --blocks must be at least 1")
    if (a.prebuild_only or a.measure_only) and not a.work:
        p.error("--prebuild-only and --measure-only need --work")
    try:
        repo = sh(["git", "rev-parse", "--show-toplevel"]).strip()
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
        print_assumptions(a.k)
        return 2
    except Exception as why:  # noqa: BLE001 - any crash is no measurement
        print(f"VOID: {type(why).__name__}: {why}")
        print_assumptions(a.k)
        return 2


def shas(repo, a):
    return tuple(sh(["git", "rev-parse", "--verify", f"{r}^{{commit}}"], cwd=repo).strip()
                 for r in (a.base, a.head))


def keys(base_sha, head_sha):
    """BASE carries HEAD's harness file, so its key and manifest name both."""
    return (f"{base_sha[:12]}+{head_sha[:12]}", [base_sha, head_sha]), (head_sha[:12], [head_sha])


def builds(repo, a, work):
    """(base, head) binaries, built or reused. One builder at a time per
    work dir: both arms share its target dir, and a concurrent build could
    overwrite the binary this one is about to copy out and certify."""
    base_sha, head_sha = shas(repo, a)
    (base_key, base_commits), (head_key, head_commits) = keys(base_sha, head_sha)
    with open(os.path.join(work, ".build.lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _, head = build(repo, head_sha, work, head_key, head_commits)
        _, base = build(repo, base_sha, work, base_key, base_commits, overlay_from=head_sha)
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
    control = judge(budget, paired((head, False), (head, True), a.blocks, rng), "control armed-unarmed")
    verdicts = [judge(budget, paired((base, False), (head, False), a.blocks, rng))]
    budgets = budget
    if "OVER" in verdicts[0].values():
        print("confirmation run with a fresh null arm")
        budgets = null_budget(base, a.k, a.blocks, rng)
        verdicts.append(judge(budgets,
                              paired((base, False), (head, False), a.blocks, rng)))

    # Load is sampled before, during and after every harness run (F3);
    # any sample above MAX_LOAD anywhere in the job is VOID.
    peak = sample_load()
    print(f"host load: peak {peak:.1f} over the run (max {MAX_LOAD})")
    if peak > MAX_LOAD:
        print("VOID: the bench host was busy; rerun when it is quiet")
        print_assumptions(a.k, budgets)
        return 2
    if any(v != "OVER" for v in control.values()):
        print("VOID: the negative control did not fail every row")
        print_assumptions(a.k, budgets)
        return 2
    verdict = decide(verdicts)
    print_assumptions(a.k, budgets)
    return verdict


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
