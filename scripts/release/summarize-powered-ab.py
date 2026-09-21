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
        print(f"\n{label}  ({sample[0]['sha']})")
        print(f"  reps {len(sample)}   requests {reqs:,}")
        for col, name in (("p50_ms", "P50"), ("p90_ms", "P90"), ("p95_ms", "P95"), ("p99_ms", "P99")):
            vals = [float(r[col]) for r in sample]
            mid, lo, hi, cov = median_ci(vals)
            # The observed spread is printed next to the interval so a single
            # excursion stays visible. The interval itself is an order statistic
            # and barely moves when one rep misbehaves, which is the point of
            # choosing it -- but a reader is entitled to see that it happened.
            print(f"  {name}  {mid:.4f} ms   95% CI [{lo:.4f}, {hi:.4f}]   (exact coverage {cov:.3f})")
            print(f"        observed spread [{min(vals):.4f}, {max(vals):.4f}]")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
