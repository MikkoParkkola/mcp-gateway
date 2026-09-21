#!/usr/bin/env python3
"""Summarise the powered end-to-end A/B into quotable percentiles.

NFR.PERF.1's residual asks for a P50/P99 for the release line that may be
quoted publicly, with an interval. Each rep of the k6 workload yields one
estimate of each percentile; this reduces the per-rep estimates to a central
value plus a 95% interval.

The interval is a distribution-free order-statistic interval on the median of
the per-rep estimates, NOT a normal error bar derived from a coefficient of
variation. That distinction is load-bearing: a CV-based normal interval assumes
the statistic is approximately normal with a known spread, which is defensible
for a median of a dense sample and is NOT defensible for P99, where each rep's
estimate rests on roughly the top 1% of its own requests. The order-statistic
interval makes no distributional assumption at all, so the same method covers
P50 and P99 honestly.

Coverage is exact-by-construction: for n reps the interval is
[x_(k), x_(n+1-k)] with the largest k such that P(Bin(n, 0.5) < k) <= 0.025,
and the realised coverage is reported rather than rounded to "95%".

Usage: summarize-powered-ab.py <reps.csv>
VOID reps are dropped with a note and cost only sample size. Exit 1 if the
surviving sample cannot support an interval, or if the CSV holds duplicate
rep/arm rows, which would inflate n and narrow every interval.
"""

from __future__ import annotations

import csv
import sys
from math import comb


COLS = (("p50_ms", "P50"), ("p90_ms", "P90"), ("p95_ms", "P95"), ("p99_ms", "P99"))


def paired_ratios(rows: list[dict]) -> dict[str, list[float]]:
    """Per-rep release/control ratios, keyed by percentile column.

    The ratio is always rel/b -- keyed by ARM, never by slot position. That
    distinction is the whole point: a position-keyed ratio silently inverts when
    a block runs the arms in the opposite order, so the forward and reversed
    blocks would not be comparable and the inversion would not show up as an
    error. Defining it by arm is what makes the crossover contrast possible.
    """
    by_rep: dict[str, dict[str, dict]] = {}
    for r in rows:
        by_rep.setdefault(r["rep"], {})[r["arm"]] = r
    return {
        col: [
            float(cells["rel"][col]) / float(cells["b"][col])
            for cells in by_rep.values()
            if "rel" in cells and "b" in cells
        ]
        for col, _ in COLS
    }


def median_ci(values: list[float]) -> tuple[float, float, float, float]:
    """Return (median, lo, hi, realised_coverage) for a sorted-safe sample."""
    xs = sorted(values)
    n = len(xs)
    # Largest k with P(Bin(n,0.5) < k) <= 0.025, i.e. sum_{i<k} C(n,i) / 2^n.
    tail = 0.0
    k = 0
    while k < n:
        nxt = tail + comb(n, k) / 2**n
        if nxt > 0.025:
            break
        tail = nxt
        k += 1
    if k == 0:
        raise ValueError(f"n={n} is too small to support a 95% median interval")
    mid = (xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2)
    return mid, xs[k - 1], xs[n - k], 1 - 2 * tail


def main(path: str) -> int:
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        print("no rows", file=sys.stderr)
        return 1

    # A VOID rep costs sample size and nothing else, so drop it and report the
    # reduced n rather than refusing to summarise the reps that did succeed.
    # A duplicate row is different in kind: it means the CSV was appended twice
    # and n is inflated, which silently narrows every interval below.
    voids = [r for r in rows if r["p50_ms"] == "VOID"]
    for r in voids:
        print(f"  dropped VOID rep {r['rep']} arm {r['arm']}", file=sys.stderr)
    rows = [r for r in rows if r["p50_ms"] != "VOID"]

    seen: set[tuple[str, str]] = set()
    for r in rows:
        key = (r["rep"], r["arm"])
        if key in seen:
            print(f"duplicate rep/arm row {key}; CSV was appended twice", file=sys.stderr)
            return 1
        seen.add(key)

    for arm in ("rel", "b"):
        sample = [r for r in rows if r["arm"] == arm]
        if not sample:
            continue
        label = "release line" if arm == "rel" else "3.5.1 drift control"
        reqs = sum(int(r["http_reqs"]) for r in sample)
        # Every rep's sha, not just the first. A rebuilt arm still answers
        # /health with the same version string, so the recorded sha is the only
        # signal that the binary moved under a block -- which would silently
        # break any comparison between two blocks that assume the same pair.
        shas = sorted({r["sha"] for r in sample})
        if len(shas) > 1:
            print(f"arm {arm} spans {len(shas)} distinct shas: {shas}", file=sys.stderr)
            return 1
        print(f"\n{label}  ({shas[0]})")
        print(f"  reps {len(sample)}   requests {reqs:,}")
        for col, name in COLS:
            vals = [float(r[col]) for r in sample]
            mid, lo, hi, cov = median_ci(vals)
            # The observed spread is printed next to the interval so a single
            # excursion stays visible. The interval itself is an order statistic
            # and barely moves when one rep misbehaves, which is the point of
            # choosing it -- but a reader is entitled to see that it happened.
            print(f"  {name}  {mid:.4f} ms   95% CI [{lo:.4f}, {hi:.4f}]   (exact coverage {cov:.3f})")
            print(f"        observed spread [{min(vals):.4f}, {max(vals):.4f}]")

    # The arms are interleaved within a rep, so the design is paired and the
    # per-arm sections above discard that pairing. The ratio below keeps it, and
    # is the only figure that can be compared across a forward and a reversed
    # block: with multiplicative effects the forward ratio carries code+position
    # and the reversed one carries code-position, so their geometric mean
    # isolates the code effect and sqrt(forward/reversed) isolates position.
    ratios = paired_ratios(rows)
    n_pairs = len(ratios["p50_ms"])
    if n_pairs:
        print(f"\npaired release/control ratio   ({n_pairs} complete pairs)")
        if n_pairs <= 6:
            print("  note: at n<=6 the order-statistic interval degenerates to [min, max]")
            print("        and the sign test is decisive only on unanimity (6/6 -> p=0.031,")
            print("        5/6 -> p=0.22). Pool a second block rather than reading n=6 alone.")
        for col, name in COLS:
            vals = ratios[col]
            above = sum(1 for v in vals if v > 1.0)
            try:
                mid, lo, hi, cov = median_ci(vals)
            except ValueError as exc:
                print(f"  {name}  {sorted(vals)[len(vals) // 2]:.4f}   (no interval: {exc})")
                continue
            print(f"  {name}  {mid:.4f}   95% CI [{lo:.4f}, {hi:.4f}]   (exact coverage {cov:.3f})")
            print(f"        {above}/{len(vals)} reps above 1.0")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
