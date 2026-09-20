#!/usr/bin/env python3
"""Self-check for eval_workload.py. Proves the four verdicts are distinct.

Run: python3 benchmarks/workload/test_eval_workload.py
"""

from __future__ import annotations

import json
import math
import random
import subprocess
import sys
import tempfile
from pathlib import Path

EVAL = Path(__file__).resolve().parent / "eval_workload.py"
ARCHIVE = Path(__file__).resolve().parents[1] / "results" / "gating-2026-09-20c"

sys.path.insert(0, str(EVAL.parent))
import eval_workload as ev  # noqa: E402  (path is set immediately above)

CELLS = {
    "A": ("3.5.0", "aaaaaaa"),
    "B": ("3.5.1", "bbbbbbb"),
    "C": ("4.0.0", "ccccccc"),
    "D": ("4.0.0", "ccccccc"),
    "E": ("4.0.0", "ccccccc"),
}
DIGEST = "sha256:deadbeef"


def summary(p50, p99, *, http_err=0.0, semantic=1.0, checks=1.0):
    return {
        "metrics": {
            "mcp_tools_call_latency": {"p(50)": p50, "p(99)": p99},
            # k6's --summary-export spells a Rate metric "value", never
            # "rate". The fixtures use the real spelling so a parse defect
            # cannot hide behind a shape the load generator never emits.
            "http_error_rate": {"value": http_err},
            "semantic_assertion_rate": {"value": semantic},
            "checks": {"value": checks},
        }
    }


def build(run: Path, latencies, *, reps=6, **overrides):
    """latencies: {cell: (p50, p99)} applied to every rep.

    reps defaults to 6, the coverage floor of the #614 interval. Below it the
    gate is insufficient by construction, so a 3-rep fixture can only ever
    grade INCONCLUSIVE -- see main()'s "inconclusive/n=3 insufficiency" case,
    which asserts exactly that.

    The rep count is DECLARED in pins.json rather than discovered by globbing
    the run directory: a run that died mid-arm leaves fewer files, and that
    must stay VOID (a missing measured rep) rather than silently regrade as a
    smaller, insufficient sample. pins.json omitting "reps" falls back to
    eval_workload.MEASURED_REPS, which is what the archived 3-rep run does.
    """
    pins = {
        "k6_image_digest": DIGEST,
        "reps": list(range(1, reps + 1)),
        "cells": {
            c: {"health_version": v, "checkout_sha": s} for c, (v, s) in CELLS.items()
        },
    }
    (run / "pins.json").write_text(json.dumps(pins))

    for cell, (p50, p99) in latencies.items():
        for rep in range(1, reps + 1):
            name = f"{cell}{rep}"
            jitter = overrides.get("jitter", {}).get(name)
            s = summary(
                jitter[0] if jitter else p50,
                jitter[1] if jitter else p99,
                **overrides.get("summary", {}).get(name, {}),
            )
            (run / f"{name}.summary.json").write_text(json.dumps(s))
            meta = {
                "argv": ["mcp-gateway", "--port", "39420"],
                "checkout_sha": CELLS[cell][1],
                "health_version": CELLS[cell][0],
                "k6_image_digest": DIGEST,
            }
            meta.update(overrides.get("meta", {}).get(name, {}))
            (run / f"{name}.meta.json").write_text(json.dumps(meta))


def run_eval(run: Path) -> int:
    proc = subprocess.run(
        [sys.executable, str(EVAL), str(run)], capture_output=True, text=True
    )
    return proc.returncode


def case(name, latencies, expected, **overrides):
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        build(run, latencies, **overrides)
        got = run_eval(run)
        assert got == expected, f"{name}: expected exit {expected}, got {got}"
        print(f"  ok  {name} -> exit {expected}")


FLAT = {c: (10.0, 20.0) for c in CELLS}


# ---------------------------------------------------------------------------
# Stability gate (#614): the distribution-free order-statistic interval on the
# pooled median, which replaces spread() as the gate.
#
# API these checks assume of eval_workload:
#   CONF                          0.95, the required interval coverage
#   median_interval(values)       (lo, hi) order statistics, or None when no
#                                 k >= 1 reaches CONF ("insufficient")
#   rel_half_width(values)        (hi - lo) / 2 / pooled(values); float("inf")
#                                 when insufficient or pooled <= 0
#   interval_insufficient(n)      True when no k >= 1 reaches CONF at that n
#   pins["reps"]                  optional list of rep numbers for the run;
#                                 absent means MEASURED_REPS, so the archived
#                                 3-rep run still grades as it did. Declared,
#                                 never globbed: a run that died mid-arm must
#                                 stay VOID, not regrade as a smaller sample.
#   report["cells"][C]["p50_rel_half_width"] / ["p99_rel_half_width"]
#   report["unstable"] entries naming insufficiency, never "spread"
#
# NOTE: the design's P1 (non-increasing in expectation as N grows) is NOT
# asserted here. It is false for this statistic -- see
# test_observed_k_plateau_sawtooth -- and is unresolved in the design.
#
# Every check is seeded from one constant and every population has a median
# known in closed form, so each assertion has a ground truth rather than a
# reference to whatever the harness happened to produce.
# ---------------------------------------------------------------------------

SEED = 20260920
CONF = 0.95

COVERAGE_N = (6, 8, 10, 25)
COVERAGE_TRIALS = 30_000
# True coverage bottoms out at 0.9567 (n=25), so the floor has 0.0067 of
# headroom. 4 Monte-Carlo standard errors at 30k trials is 0.005, inside it.
COVERAGE_TOLERANCE = 0.005

# k is an INTEGER order statistic, so it is pinned across ranges of n. Inside a
# plateau the interval is unchanged while the sample grows, so its expected
# width GROWS -- exactly like the spread() statistic this replaces. The
# measured table below is (n, k, exact coverage); None means insufficient.
K_PLATEAUS = (
    (3, None, None),
    (4, None, None),
    (5, None, None),
    (6, 1, 0.96875),
    (7, 1, 0.984375),
    (8, 1, 0.9921875),
    (9, 2, 0.9609375),
    (10, 2, 0.978515625),
    (11, 2, 0.98828125),
    (12, 3, 0.96142578125),
    (13, 3, 0.9775390625),
    # Past n=13 on purpose. A table that stops at 13 only ever pins k in
    # {1,2,3}, so an implementation that caps the rank at 3 reads as correct
    # everywhere the table can see. n=15 is the first n whose rank is 4, so
    # the table has to reach it -- and past it, because the next cap anyone
    # would plausibly write is the largest rank the table happens to show.
    # The gate's own rep count is a moving target (3 per cell as of
    # gating-2026-09-20c, and it must rise to at least 6 before the gate can
    # ever pass), which is exactly why the reach is chosen from the ranks
    # rather than from today's configuration.
    (14, 3, 0.987060546875),
    (15, 4, 0.96484375),
    (16, 4, 0.978729248046875),
    (17, 5, 0.950958251953125),
    (18, 5, 0.9691162109375),
    (19, 5, 0.9807891845703125),
    (20, 6, 0.9586105346679688),
)
# The largest n the table reaches; the maximality check recomputes k from the
# definition over the whole of range(3, K_TABLE_MAX + 1), so a gap in the table
# cannot hide a rank. 25 is the largest n the coverage simulation uses and the
# n at which true coverage bottoms out (0.9567, k=8), so the rank check and the
# calibration check meet at the same worst case.
K_TABLE_MAX = 25
# n pairs inside one k-plateau, where the mean width is observed to RISE.
PLATEAU_RISES = (
    (6, 7),
    (7, 8),
    (9, 10),
    (10, 11),
    (12, 13),
    (13, 14),
    (15, 16),
    (17, 18),
    (18, 19),
)
# n pairs straddling a k increment, where it is observed to DROP. These are the
# ADJACENT crossings (one extra rep is enough), which is the stronger claim.
PLATEAU_DROPS = ((8, 9), (11, 12), (14, 15), (16, 17), (19, 20))
SAWTOOTH_TRIALS = 20_000

RESOLVING_TRIALS = 2_000

# The token the gate must record when a cell is unstable by insufficiency.
INSUFFICIENT_TOKEN = "insufficient"

FAILURES: list[str] = []


def draw_uniform(r):
    return r.uniform(0.5, 1.5)


def draw_lognormal(r):
    return math.exp(r.gauss(0.0, 1.0))


def draw_bimodal(r):
    """The population that refuted the t-based first draft at 85.5% coverage."""
    return r.uniform(0.99, 1.01) if r.random() < 0.49 else r.uniform(1.99, 2.01)


# 0.49 of the mass sits below 1.01, so the median lands in the upper component
# where the remaining 0.01 of probability is spent at density 0.51/0.02.
BIMODAL_MEDIAN = 1.99 + 0.02 * (0.01 / 0.51)

POPULATIONS = (
    ("uniform", draw_uniform, 1.0),
    ("lognormal", draw_lognormal, 1.0),
    ("bimodal", draw_bimodal, BIMODAL_MEDIAN),
)


def sample(r, draw, n):
    return [draw(r) for _ in range(n)]


def exact_coverage(n, k):
    """P(x_(k) <= median <= x_(n-k+1)) for a continuous population, exactly."""
    if k < 1 or 2 * k > n:
        return 0.0
    return 1 - 2 * sum(math.comb(n, i) for i in range(k)) / 2**n


def test_exact_interval_values():
    """Hand-computed values. Thresholds alone cannot see a scale or centre error.

    Every other check here compares a statistic against a bound it clears by a
    margin, so a dropped factor of two or a mean-for-median swap survives them:
    a width that is 2x too large still sits inside a generous budget, and mean
    and median agree on any near-symmetric population. These two fixtures are
    deliberately SKEWED, so the two centres differ by a factor of three, and
    the expected values are worked out by hand in the comments rather than
    recorded from whatever the implementation produced.
    """
    # n=7 (odd, so the median is the single middle value), k=1, so the
    # interval is (x[0], x[6]) = (1, 60).
    #   median         = 4
    #   mean           = (1+2+3+4+8+16+60)/7 = 94/7 = 13.428571...
    #   half-width     = (60 - 1)/2 = 29.5
    #   rel_half_width = 29.5 / 4 = 7.375   <- exact in binary
    # The mean-instead-of-median mutant reads 29.5/(94/7) = 2.196808...
    # The dropped-/2 mutant reads 59/4 = 14.75.
    odd = [1.0, 2.0, 3.0, 4.0, 8.0, 16.0, 60.0]
    assert ev.median_interval(odd) == (1.0, 60.0), ev.median_interval(odd)
    got = ev.rel_half_width(odd)
    assert got == 7.375, f"odd/skewed: {got} != 7.375 (mean form gives 2.1968)"

    # n=10 (even, so the median is the MEAN of the two middle values), k=2, so
    # the interval is (x[1], x[8]) = (2, 9).
    #   median         = (5 + 6)/2 = 5.5
    #   mean           = (45 + 100)/10 = 14.5
    #   half-width     = (9 - 2)/2 = 3.5
    #   rel_half_width = 3.5 / 5.5 = 7/11 = 0.636363...
    # The mean-instead-of-median mutant reads 3.5/14.5 = 7/29 = 0.241379...
    # The dropped-/2 mutant reads 7/5.5 = 14/11 = 1.272727...
    # A median taken as the LOWER middle value reads 3.5/5 = 0.7.
    even = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 100.0]
    assert ev.median_interval(even) == (2.0, 9.0), ev.median_interval(even)
    got = ev.rel_half_width(even)
    assert abs(got - 7 / 11) < 1e-12, (
        f"even/skewed: {got} != {7 / 11} (mean form gives {7 / 29}, "
        f"lower-middle median gives 0.7)"
    )


def test_coverage_calibration():
    """P2: the interval attains 95% coverage by simulation, not by asymptotics."""
    for name, draw, median in POPULATIONS:
        for n in COVERAGE_N:
            r = random.Random(SEED)
            hits = 0
            for _ in range(COVERAGE_TRIALS):
                interval = ev.median_interval(sample(r, draw, n))
                assert interval is not None, f"{name}/n={n}: no interval at n >= 6"
                lo, hi = interval
                if lo <= median <= hi:
                    hits += 1
            got = hits / COVERAGE_TRIALS
            assert got >= CONF - COVERAGE_TOLERANCE, (
                f"coverage {name}/n={n}: {got:.4f} < "
                f"{CONF - COVERAGE_TOLERANCE:.4f} (true median {median:.6f})"
            )


def test_observed_k_plateau_sawtooth():
    """Pins the MEASURED sawtooth. This is NOT the design's P1 assertion.

    P1 ("non-increasing in expectation as N grows") is FALSE for this
    statistic and is unresolved in docs/design/614-stability-gate.md. k is an
    integer order statistic pinned across ranges of n; inside a plateau the
    interval is the same pair of order statistics while the sample grows, so
    its expected width rises exactly as spread() does. It falls only when k
    increments.

    This check therefore documents what the statistic does -- the k table, the
    rises inside each plateau, the drops at each increment -- rather than
    asserting a property the statistic does not have. Choosing an n-grid that
    makes a monotonicity assertion pass would hide the defect, which is the
    failure mode already removed from this design once.
    """
    for n, want_k, want_coverage in K_PLATEAUS:
        # Distinct ascending values make the interval read back its own k:
        # median_interval returns (x[k-1], x[n-k]) == (k-1, n-k).
        interval = ev.median_interval([float(i) for i in range(n)])
        if want_k is None:
            assert interval is None, f"n={n} must be insufficient, got {interval}"
            assert ev.interval_insufficient(n), f"n={n} must be insufficient"
            continue
        assert interval is not None, f"n={n} must yield an interval"
        lo, hi = interval
        got_k = int(lo) + 1
        assert got_k == want_k, f"n={n}: k={got_k}, expected {want_k}"
        assert hi == n - want_k, f"n={n}: upper order statistic {hi} != {n - want_k}"
        coverage = 1 - 2 * sum(math.comb(n, i) for i in range(want_k)) / 2**n
        assert math.isclose(coverage, want_coverage), (
            f"n={n}, k={want_k}: coverage {coverage} != {want_coverage}"
        )
        assert coverage >= CONF, f"n={n}: k={want_k} gives {coverage} < {CONF}"

    # MAXIMALITY. Coverage is monotone DECREASING in k, so a rank that is too
    # small yields an interval that is too WIDE and whose coverage is HIGHER
    # than required -- test_coverage_calibration passes every under-selecting
    # implementation, including one whose rank is hard-capped at a constant.
    # The floor can only fail in the direction that was already safe. So the
    # rank must also be shown MAXIMAL: k+1 has to breach CONF. This loop
    # recomputes the oracle from the definition rather than reading the table
    # above, and runs over every n in range, not only the tabulated ones.
    for n in range(3, K_TABLE_MAX + 1):
        want_k = None
        for k in range(1, n // 2 + 1):
            if exact_coverage(n, k) >= CONF:
                want_k = k
        interval = ev.median_interval([float(i) for i in range(n)])
        if want_k is None:
            assert interval is None, f"n={n}: no rank attains {CONF}, got {interval}"
            continue
        assert interval is not None, f"n={n}: rank {want_k} exists but no interval"
        got_k = int(interval[0]) + 1
        assert got_k == want_k, f"n={n}: k={got_k}, maximal k is {want_k}"
        assert exact_coverage(n, want_k) >= CONF, f"n={n}: k={want_k} under {CONF}"
        assert exact_coverage(n, want_k + 1) < CONF, (
            f"n={n}: k={want_k + 1} also attains "
            f"{exact_coverage(n, want_k + 1)} >= {CONF}, so k={want_k} is not "
            f"maximal and the interval is wider than it needs to be"
        )

    r = random.Random(SEED)
    mean = {}
    for n, want_k, _ in K_PLATEAUS:
        if want_k is None:
            continue
        total = 0.0
        for _ in range(SAWTOOTH_TRIALS):
            total += ev.rel_half_width([r.gauss(1.0, 0.02) for _ in range(n)])
        mean[n] = total / SAWTOOTH_TRIALS

    for lo_n, hi_n in PLATEAU_RISES:
        assert mean[hi_n] > mean[lo_n], (
            f"inside a k-plateau the mean width must rise: n={lo_n} "
            f"{mean[lo_n]:.5f} -> n={hi_n} {mean[hi_n]:.5f}"
        )
    for lo_n, hi_n in PLATEAU_DROPS:
        assert mean[hi_n] < mean[lo_n], (
            f"at a k increment the mean width must drop: n={lo_n} "
            f"{mean[lo_n]:.5f} -> n={hi_n} {mean[hi_n]:.5f}"
        )


def test_resolving_power():
    """P3: a calibrated interval that can never fit the margin is still useless.

    Both halves must hold. A gate that always says unstable passes the
    archived-run check perfectly while measuring nothing.

    Asserting a per-trial verdict is only sound where the bound is arithmetic
    rather than statistical, and that holds for exactly one of the two cases
    here. The tight draw spans [0.99, 1.01], so the widest interval it can
    produce is 0.02 against a median of at least 0.99: a relative half-width
    of at most 0.0102, below the 0.05 margin for every sample that can be
    drawn, at any seed. Per-trial is a theorem there.

    The wide draw is NOT deterministic and must not be asserted as if it were.
    It spans [0.3, 1.7], and although its typical relative half-width is an
    order of magnitude above the margin, a sufficiently clustered draw slips
    under: measured at 2 violations in 200_000 draws (1e-5), which over the
    2_000 trials below is a ~2% chance of a spurious red per seed. The current
    SEED happens to produce none, and a per-trial assertion would therefore be
    recording seed luck as a property. It is asserted as a RATE with the
    measured violation rate as its tolerance.
    """
    margin = ev.P50_BUDGET - 1.0
    cases = (
        # 1% dispersion resolves a 5% margin comfortably. The bound is
        # arithmetic, so no draw may violate it: tolerance 0.
        ("tight", lambda r: r.uniform(0.99, 1.01), 9, True, 0.0),
        # 70% dispersion does not resolve it, even at 25 reps -- but a
        # clustered draw slips under at a measured 1e-5, so allow 0.1%.
        ("wide", lambda r: r.uniform(0.3, 1.7), 25, False, 0.001),
    )
    for label, draw, n, expect_stable, tolerance in cases:
        r = random.Random(SEED)
        wrong = 0
        worst = None
        for _ in range(RESOLVING_TRIALS):
            rel = ev.rel_half_width(sample(r, draw, n))
            if (rel <= margin) is not expect_stable:
                wrong += 1
                if worst is None or abs(rel - margin) > abs(worst - margin):
                    worst = rel
        rate = wrong / RESOLVING_TRIALS
        assert rate <= tolerance, (
            f"resolving/{label} n={n}: {wrong}/{RESOLVING_TRIALS} trials "
            f"({rate:.4f}) disagreed with "
            f"{'stable' if expect_stable else 'unstable'} against margin "
            f"{margin:.3f}, tolerance {tolerance:.4f}; worst rel half-width "
            f"{worst:.4f}"
        )


def test_insufficiency_floor():
    """n <= 5 is unstable by insufficiency even when every rep is identical.

    Deliberate behaviour change: spread() graded a zero-variance cell at n=3 as
    stable, and that was never a 95% statement about the median.
    """
    assert ev.CONF == CONF, f"required coverage is {CONF}, module says {ev.CONF}"
    for n in range(1, 6):
        assert ev.interval_insufficient(n), f"n={n} must be insufficient"
        identical = [1.0] * n
        assert ev.median_interval(identical) is None, (
            f"n={n}: identical reps must not yield an interval"
        )
        assert ev.rel_half_width(identical) == float("inf"), (
            f"n={n}: identical reps must be unstable by insufficiency"
        )
    assert not ev.interval_insufficient(6), "n=6 is the coverage floor"
    assert ev.rel_half_width([1.0] * 6) == 0.0, (
        "n=6 identical reps must grade stable with a zero-width interval"
    )


def test_degenerate_input():
    """n=1 and a zero pooled value fail closed, preserving the inf path."""
    assert ev.rel_half_width([1.0]) == float("inf"), "n=1 must not raise"
    assert ev.rel_half_width([0.0] * 6) == float("inf"), "zero pooled must not raise"
    # n=6, so this is the pooled <= 0 guard rather than insufficiency.
    zero_median = [-1.0, 0.0, 0.0, 0.0, 1.0, 2.0]
    assert ev.rel_half_width(zero_median) == float("inf"), "pooled 0.0 must fail closed"


def test_archived_run_regrades_as_insufficiency():
    """Verdict wiring: exit 2 AND the recorded reason is insufficiency at n=3.

    The raw artifacts live on Spark; the per-rep p50/p99 that the gate reads
    are recorded in the archived verdict.json, so the run dir is rebuilt from
    those. This establishes provenance only -- test_resolving_power is the
    correctness oracle.
    """
    archived = json.loads((ARCHIVE / "verdict.json").read_text())
    pins = json.loads((ARCHIVE / "pins.json").read_text())
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        (run / "pins.json").write_text(json.dumps(pins))
        for cell, reps in archived["per_rep"].items():
            for rep in reps:
                name = rep["rep"]
                (run / f"{name}.summary.json").write_text(
                    json.dumps(summary(rep["p50"], rep["p99"]))
                )
                (run / f"{name}.meta.json").write_text(
                    json.dumps(
                        {
                            "argv": ["mcp-gateway", "--port", "39420"],
                            "checkout_sha": pins["cells"][cell]["checkout_sha"],
                            "health_version": pins["cells"][cell]["health_version"],
                            "k6_image_digest": pins["k6_image_digest"],
                        }
                    )
                )
        status = run_eval(run)
        assert status == 2, (
            f"archived run must re-grade INCONCLUSIVE, got exit {status}"
        )

        report = json.loads((run / "verdict.json").read_text())
        assert report["verdict"] == "INCONCLUSIVE", report["verdict"]

        # The reason is the rep count, not the dispersion.
        assert ev.interval_insufficient(len(ev.MEASURED_REPS)), (
            f"MEASURED_REPS n={len(ev.MEASURED_REPS)} should be insufficient"
        )
        # In memory the insufficient width is the inf sentinel; ON DISK it must
        # be null. json.dumps writes float("inf") as the bare token Infinity,
        # which RFC 8259 does not admit -- jq or any non-Python reader rejects
        # the whole document. Reading the file back with a parser that refuses
        # the constant is the check that a round trip through Python cannot
        # make, because json.loads accepts Infinity by default.
        def strict(_const):
            raise AssertionError("verdict.json contains a non-JSON constant")

        report = json.loads((run / "verdict.json").read_text(), parse_constant=strict)
        assert ev.rel_half_width([1.0, 2.0, 3.0]) == float("inf"), (
            "the in-memory sentinel for an insufficient sample must stay inf"
        )
        for cell in ev.LEGACY_CELLS:
            for stat in ("p50", "p99"):
                key = f"{stat}_rel_half_width"
                got = report["cells"][cell][key]
                assert got is None, (
                    f"{cell}.{key} = {got!r}, expected null -- an insufficient "
                    f"width must serialize as null, never as Infinity"
                )

        reasons = report["unstable"]
        assert reasons, "an insufficient run must record why it is inconclusive"
        assert all(INSUFFICIENT_TOKEN in r.lower() for r in reasons), reasons
        assert not any("spread" in r.lower() for r in reasons), (
            f"the reason must not be a spread comparison: {reasons}"
        )


def test_duplicate_reps_void():
    """A repeated rep id is a VOID, not a six-rep sample.

    Found by external review of the #614 implementation. pins.json declares
    the sample, and nothing re-read the declaration: six copies of rep 1 name
    one summary file six times, which clears the n>=6 insufficiency floor and,
    being six identical values, collapses the interval to zero width. The run
    graded PASS on a single measurement -- the exact failure the interval was
    introduced to make impossible.

    A too-short rep list is already VOID by the missing-file path; a repeated
    one has every file it needs, so it has to be caught at the pin.
    """
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        build(run, FLAT, reps=6)
        pins = json.loads((run / "pins.json").read_text())
        pins["reps"] = [1, 1, 1, 1, 1, 1]
        (run / "pins.json").write_text(json.dumps(pins))
        status = run_eval(run)
        assert status == ev.EXIT_VOID, (
            f"six copies of one rep must VOID, got exit {status}"
        )

    for bad in ([1, 2, 3, 4, 5, 0], [1, 2, 3, 4, 5, -6], [1, 2, 3, 4, 5, "6"]):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            build(run, FLAT, reps=6)
            pins = json.loads((run / "pins.json").read_text())
            pins["reps"] = bad
            (run / "pins.json").write_text(json.dumps(pins))
            status = run_eval(run)
            assert status == ev.EXIT_VOID, (
                f"pins.reps {bad} must VOID, got exit {status}"
            )


def test_spread_is_reported_but_never_gates():
    """spread survives as a diagnostic and decides nothing.

    The design keeps it deliberately: a cell whose range blows out while its
    interval stays tight is a machine-conditions story, not a code story, and
    that is only visible if both numbers are in the report. The first
    implementation dropped the fields silently, which is why this asserts
    their presence as well as their irrelevance to the verdict.

    The fixture gives cell A one outlier rep at nine reps, where the maximal
    rank is k=2 and the interval is (x_(2), x_(8)) -- so the outlier sits
    outside it. Six reps would not show this: at n=6 the maximal rank is k=1
    and the interval IS the min-to-max range, which is why the two statistics
    only visibly diverge once n clears the first k-increment.
    """
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        build(run, FLAT, reps=9, jitter={"A1": (40.0, 20.0)})
        status = run_eval(run)
        report = json.loads((run / "verdict.json").read_text())
        cell = report["cells"]["A"]
        assert "p50_spread" in cell and "p99_spread" in cell, (
            f"spread must stay in the report as a diagnostic: {sorted(cell)}"
        )
        assert cell["p50_spread"] > 2.0, (
            f"fixture must produce a wide range, got {cell['p50_spread']}"
        )
        assert cell["p50_rel_half_width"] == 0.0, (
            "one outlier must not move the k=1 interval, got "
            f"{cell['p50_rel_half_width']}"
        )
        assert status == ev.EXIT_PASS, (
            f"a wide spread must not decide the verdict, got exit {status}"
        )


def check(name, fn):
    """Run one gate check, record the failure, keep going.

    Script mode aborts on the first bare assert; these six need to report
    independently so all of them can be read in one run.
    """
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 -- this is the reporting boundary
        FAILURES.append(name)
        print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    else:
        print(f"  ok  {name}")


def main() -> None:
    print("eval_workload self-check")

    # Every case below runs at build()'s default of six reps, which is the
    # coverage floor of the #614 interval. That is deliberate: at n < 6 the
    # gate is insufficient and EVERY verdict collapses to INCONCLUSIVE, so a
    # gate wired to grade everything inconclusive would still satisfy a suite
    # built on 3-rep fixtures. The PASS and FAIL cases here are what separate
    # a working gate from a stuck one -- a gate that always says INCONCLUSIVE
    # fails all five of them.

    # PASS: candidate equal to the legacy arms.
    case("pass/equal", FLAT, 0)

    # PASS: candidate inside both budgets (4% p50, 9% p99).
    inside = dict(FLAT, C=(10.4, 21.8))
    case("pass/inside budget", inside, 0)

    # FAIL: p50 over the 5% budget.
    case("fail/p50 over", dict(FLAT, C=(10.6, 20.0)), 1)

    # FAIL: p99 over the 10% budget.
    case("fail/p99 over", dict(FLAT, C=(10.0, 22.1)), 1)

    # FAIL: budget is held against the faster legacy arm, not the slower one.
    # B is faster, so C must be judged against B even though A is generous.
    case("fail/min baseline", dict(FLAT, A=(20.0, 40.0), B=(10.0, 20.0), C=(10.6, 20.0)), 1)

    # INCONCLUSIVE: a genuinely unstable legacy arm at a SUFFICIENT rep count.
    # Cell A's six p50 reps are 10,10,10,10,10,12. n=6 so k=1 and the interval
    # is (min, max) = (10, 12): half-width 1.0 over a pooled median of
    # (10+10)/2 = 10, i.e. a relative half-width of 0.100, twice the 0.050 p50
    # margin. The pooled median is still exactly 10.0, so the arm would have
    # PASSED on its point estimate -- the verdict has to turn on dispersion,
    # not on the pooled number. The other cells are flat, so this is the one
    # unstable cell in an otherwise sufficient run.
    case(
        "inconclusive/unstable arm at n=6",
        FLAT,
        2,
        jitter={
            "A1": (10.0, 20.0),
            "A2": (10.0, 20.0),
            "A3": (10.0, 20.0),
            "A4": (10.0, 20.0),
            "A5": (10.0, 20.0),
            "A6": (12.0, 20.0),
        },
    )

    # INCONCLUSIVE by INSUFFICIENCY: the deliberate behaviour change. Three
    # identical reps have zero dispersion and used to grade PASS under
    # spread(); no rank k >= 1 reaches 95% coverage of the median at n=3, so
    # there is no interval to compare against the margin and the run cannot
    # answer the question. This is the ONLY reason the run is inconclusive --
    # the latencies are the same FLAT ones that pass at n=6 two cases above,
    # so the rep count is the only variable between them.
    case("inconclusive/n=3 insufficiency", FLAT, 2, reps=3)

    # VOID: health version differs by patch only -- a prefix match would pass.
    case("void/health version", FLAT, 3, meta={"B2": {"health_version": "3.5.0"}})

    # VOID: runner never wrote the checkout SHA.
    case("void/missing sha", FLAT, 3, meta={"C1": {"checkout_sha": ""}})

    # VOID: load generator not the pinned digest.
    case("void/unpinned k6", FLAT, 3, meta={"A3": {"k6_image_digest": "sha256:other"}})

    # VOID: a semantic assertion failed.
    case("void/semantic", FLAT, 3, summary={"C2": {"semantic": 0.999}})

    # VOID: an HTTP error in a measured rep.
    case("void/http error", FLAT, 3, summary={"A1": {"http_err": 0.0001}})

    # VOID: checks pass rate under 99%.
    case("void/checks", FLAT, 3, summary={"B1": {"checks": 0.98}})

    # VOID: a missing rep file, which is what a run that died mid-arm leaves.
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        build(run, FLAT)
        (run / "C3.summary.json").unlink()
        assert run_eval(run) == 3, "void/missing rep"
        print("  ok  void/missing rep -> exit 3")

    # VOID: an unparseable summary, the Amendment 5 shared-descriptor defect.
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp)
        build(run, FLAT)
        (run / "A2.summary.json").write_text('{"metrics": {} garbage')
        assert run_eval(run) == 3, "void/unparseable"
        print("  ok  void/unparseable -> exit 3")

    print("stability gate (#614)")
    check("gate/coverage calibration (P2)", test_coverage_calibration)
    check("gate/exact interval values", test_exact_interval_values)
    check("gate/observed k-plateau sawtooth (NOT P1)", test_observed_k_plateau_sawtooth)
    check("gate/resolving power (P3)", test_resolving_power)
    check("gate/insufficiency floor", test_insufficiency_floor)
    check("gate/degenerate input", test_degenerate_input)
    check("gate/archived run wiring", test_archived_run_regrades_as_insufficiency)
    check("gate/duplicate reps VOID", test_duplicate_reps_void)
    check("gate/spread reported, never gating", test_spread_is_reported_but_never_gates)

    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} stability-gate check(s): {', '.join(FAILURES)}")
        raise SystemExit(1)

    print("all eval_workload checks passed")


if __name__ == "__main__":
    main()
