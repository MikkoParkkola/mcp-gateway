#!/usr/bin/env python3
"""NFR.PERF.1 evaluator -- frozen before the scored run, per contract A8.

Two properties this file exists to guarantee:

1. ORDER STATISTICS, NOT SUMMARY STATISTICS. P50 and P99 are read off the sorted
   raw per-request samples k6 wrote. They are never taken from a summary block,
   never averaged across reps, and never inferred from a mean or a confidence
   interval about a mean. Averaging three p99 values is not the p99 of three reps.
2. THE PASS RULE IS READ FROM DISK. `--verdict` loads the thresholds and the rep
   count from the gate file `--register` wrote before the first scored rep. It
   cannot re-derive them from the data it is scoring.

Identical inputs give an identical verdict, which is the only version of "the
rule was not chosen afterwards" that a reader who was not there can check.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import statistics
import sys
from datetime import datetime, timezone

METRIC = "mcp_tools_call_latency"


def _open(path: str):
    return gzip.open(path, "rt") if path.endswith(".gz") else open(path, "rt")


def quantile(sorted_vals: list[float], q: float) -> float:
    """Nearest-rank order statistic. No interpolation, no model, no smoothing."""
    if not sorted_vals:
        raise ValueError("empty sample")
    rank = max(1, math.ceil(q * len(sorted_vals)))
    return sorted_vals[rank - 1]


def read_samples(path: str) -> list[float]:
    vals: list[float] = []
    with _open(path) as fh:
        for row in csv.DictReader(fh):
            if row.get("metric_name") == METRIC:
                try:
                    vals.append(float(row["metric_value"]))
                except (TypeError, ValueError):
                    continue
    vals.sort()
    return vals


def read_rep(summary_path: str, samples_path: str) -> str:
    """One line: `OK p50 p90 p95 p99 max reqs iters` or `VOID <reason>`.

    A rep with any http error, any failed semantic assertion, or a missing
    metric is VOID with a reason -- never a number that silently joins the
    distribution.
    """
    try:
        summary = json.load(open(summary_path))
    except Exception as exc:  # noqa: BLE001 - any unreadable summary is a void
        return f"VOID summary-unreadable-{type(exc).__name__}"

    metrics = summary.get("metrics", {})

    def rate(name: str) -> float | None:
        block = metrics.get(name)
        if not isinstance(block, dict):
            return None
        val = block.get("rate") if "rate" in block else block.get("value")
        return float(val) if val is not None else None

    http_err = rate("http_error_rate")
    if http_err is None:
        return "VOID no-http-error-rate"
    if http_err > 0:
        return f"VOID http-errors-{http_err:.6f}"

    semantic = rate("semantic_assertion_rate")
    if semantic is None:
        return "VOID no-semantic-assertion-rate"
    if semantic < 1.0:
        return f"VOID semantic-assertion-rate-{semantic:.6f}"

    failures = metrics.get("semantic_failures", {})
    if isinstance(failures, dict) and float(failures.get("count", 0) or 0) > 0:
        return f"VOID semantic-failures-{failures.get('count')}"

    try:
        vals = read_samples(samples_path)
    except Exception as exc:  # noqa: BLE001
        return f"VOID samples-unreadable-{type(exc).__name__}"
    if len(vals) < 1000:
        # Below 1000 the p99 is not a real order statistic: it is one of the
        # last handful of samples and moves by whole ranks.
        return f"VOID too-few-samples-{len(vals)}"
    if not all(math.isfinite(v) for v in vals):
        return "VOID non-finite-sample"

    iters = metrics.get("iterations", {}).get("count", 0)
    return (
        f"OK {quantile(vals, 0.50):.6f} {quantile(vals, 0.90):.6f} "
        f"{quantile(vals, 0.95):.6f} {quantile(vals, 0.99):.6f} "
        f"{vals[-1]:.6f} {len(vals)} {int(iters or 0)}"
    )


def load_pairs(csv_path: str, scored_only: bool, min_iters: int = 0) -> tuple[list[dict], dict]:
    """Pairs with both arms OK. A pair missing either arm is dropped whole.

    `min_iters` is the pre-registered void gate: a rep that delivered fewer
    iterations than the scenario offers spent that time blocked, so its tail is
    host noise rather than gateway latency. The threshold is registered before
    any scored rep and read back here; it is never re-derived from scored data.
    """
    rows: dict[int, dict] = {}
    with open(csv_path) as fh:
        for row in csv.DictReader(fh):
            pair = int(row["pair"])
            if scored_only and pair < 1000:
                continue
            if not scored_only and pair >= 1000:
                continue
            slot = rows.setdefault(pair, {"pair": pair})
            if row["status"] != "OK":
                slot["void"] = row.get("reason") or "unspecified"
                continue
            slot[row["arm"]] = {
                "p50": float(row["p50_ms"]),
                "p99": float(row["p99_ms"]),
                "iters": int(row["iters"] or 0),
                "order": int(row["order"]),
            }
    out, dropped = [], {"void": 0, "incomplete": 0, "below_iteration_gate": 0}
    for pair in sorted(rows):
        rec = rows[pair]
        if "void" in rec:
            dropped["void"] += 1
            continue
        if "base" not in rec or "rel" not in rec:
            dropped["incomplete"] += 1
            continue
        if min_iters and min(rec["base"]["iters"], rec["rel"]["iters"]) < min_iters:
            # Void the PAIR, never one arm -- dropping one side destroys the
            # pairing that cancels common-mode host drift.
            dropped["below_iteration_gate"] += 1
            continue
        out.append(rec)
    return out, dropped


def ratio_stats(pairs: list[dict], metric: str) -> dict:
    """Paired ratio, aggregated in log space so the interval is symmetric on
    the multiplicative scale the criterion is written in."""
    logs = [math.log(p["rel"][metric] / p["base"][metric]) for p in pairs]
    n = len(logs)
    if n < 2:
        return {"n": n, "ratio": None, "lo": None, "hi": None, "sd_log": None}
    mean = statistics.fmean(logs)
    sd = statistics.stdev(logs)
    # Normal quantile: n is >= 27 by construction, where t and z differ by <2%.
    half = 1.96 * sd / math.sqrt(n)
    return {
        "n": n,
        "ratio": math.exp(mean),
        "lo": math.exp(mean - half),
        "hi": math.exp(mean + half),
        "sd_log": sd,
        "halfwidth_pct": (math.exp(half) - 1) * 100,
    }


def split_by_order(pairs: list[dict], metric: str) -> dict:
    """Paired ratio computed separately over each counterbalance position.

    `order` is the slot the arm occupied inside its pair, 1 or 2. The baseline
    sitting in slot 2 means the CANDIDATE went first, so the labels are read off
    the baseline's slot inverted -- getting this backwards would report a
    position effect as its own mirror image.
    """
    out = {}
    for base_slot, label in ((1, "baseline_first"), (2, "candidate_first")):
        subset = [p for p in pairs if p["base"]["order"] == base_slot]
        sub = ratio_stats(subset, metric)
        out[label] = {"n": sub["n"], "ratio": sub["ratio"]}
    return out


def register(args) -> int:
    """Derive the gate from CALIBRATION pairs only, before any scored rep."""
    pairs, _ = load_pairs(args.csv, scored_only=False)
    if len(pairs) < 2:
        print(f"calibration produced {len(pairs)} usable pairs; need >= 2", file=sys.stderr)
        return 3
    need = {}
    for metric, budget in (("p50", args.p50_budget), ("p99", args.p99_budget)):
        st = ratio_stats(pairs, metric)
        # Target precision: the 95% halfwidth must fit inside a third of the
        # budget, so the interval can land decisively on one side of it.
        target = math.log(1.0 + budget) / 3.0
        n = math.ceil((1.96 * st["sd_log"] / target) ** 2) if st["sd_log"] else args.min_pairs
        need[metric] = {"sd_log_calib": st["sd_log"], "ratio_calib": st["ratio"], "n_required": n}
    pairs_needed = max(args.min_pairs, need["p50"]["n_required"], need["p99"]["n_required"])
    pairs_needed = min(pairs_needed, args.max_pairs)
    min_iters = min(min(p["base"]["iters"], p["rel"]["iters"]) for p in pairs)
    gate = {
        "registered_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "criterion": "NFR.PERF.1",
        "baseline": "v3.5.0 32f135a61fb50c20a044fb4c2347bc1cf8015d89",
        "budgets": {"p50": args.p50_budget, "p99": args.p99_budget},
        "decision_rule": (
            "For each metric, the paired rel/base ratio is aggregated in log space over "
            "pairs and a 95% interval is formed. FAIL if the interval's LOWER bound "
            "exceeds the budget. PASS if its UPPER bound is at or below the budget. "
            "Otherwise INCONCLUSIVE. The overall verdict is FAIL if either metric fails, "
            "else INCONCLUSIVE if either is inconclusive, else PASS."
        ),
        "pairs": pairs_needed,
        "min_requests_per_group_per_rep": 1000,
        "void_gate_min_iterations": int(min_iters * 0.90),
        "calibration": {"pairs_used": len(pairs), "derivation": need},
    }
    with open(args.out, "w") as fh:
        json.dump(gate, fh, indent=2)
        fh.write("\n")
    return 0


def classify(st: dict, budget: float) -> str:
    if st["ratio"] is None:
        return "INCONCLUSIVE"
    bound = 1.0 + budget
    if st["lo"] > bound:
        return "FAIL"
    if st["hi"] <= bound:
        return "PASS"
    return "INCONCLUSIVE"


def verdict(args) -> int:
    gate = json.load(open(args.gate))
    pairs, dropped = load_pairs(
        args.csv, scored_only=True, min_iters=int(gate.get("void_gate_min_iterations", 0))
    )
    budgets = gate["budgets"]
    per_metric, verdicts = {}, []
    for metric in ("p50", "p99"):
        st = ratio_stats(pairs, metric)
        v = classify(st, budgets[metric])
        if st["n"] < gate["pairs"]:
            # Underpowered yields INCONCLUSIVE, never "no effect" -- unless the
            # data already excludes the budget, which no amount of extra power
            # would undo.
            v = "FAIL" if v == "FAIL" else "INCONCLUSIVE"
        # Counterbalance check: the same ratio computed on the pairs that ran
        # the candidate first and on those that ran the baseline first. If the
        # two disagree, the number is position, not version.
        by_order = split_by_order(pairs, metric)
        per_metric[metric] = dict(st, budget=budgets[metric], verdict=v, by_order=by_order)
        verdicts.append(v)
    overall = "FAIL" if "FAIL" in verdicts else ("INCONCLUSIVE" if "INCONCLUSIVE" in verdicts else "PASS")
    out = {
        "criterion": "NFR.PERF.1",
        "scored_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": overall,
        "pairs_scored": len(pairs),
        "pairs_registered": gate["pairs"],
        "pairs_dropped": dropped,
        "iteration_gate": gate.get("void_gate_min_iterations"),
        "gate_registered_utc": gate["registered_utc"],
        "decision_rule": gate["decision_rule"],
        "metrics": per_metric,
        "run_record": json.load(open(args.run_record)) if args.run_record else None,
    }
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(out, fh, indent=2)
            fh.write("\n")
    print(f"NFR.PERF.1 {overall}  ({len(pairs)}/{gate['pairs']} paired reps)")
    print(
        f"  pairs dropped: void={dropped['void']} incomplete={dropped['incomplete']} "
        f"below-iteration-gate={dropped['below_iteration_gate']}"
    )
    for metric in ("p50", "p99"):
        m = per_metric[metric]
        if m["ratio"] is None:
            print(f"  {metric.upper()}: too few pairs to form a ratio")
            continue
        print(
            f"  {metric.upper()}: ratio {m['ratio']:.4f} "
            f"[{m['lo']:.4f}, {m['hi']:.4f}] vs budget {1 + m['budget']:.2f} -> {m['verdict']}"
        )
        cf = m["by_order"]["candidate_first"]
        bf = m["by_order"]["baseline_first"]
        fmt = lambda d: "n/a" if d["ratio"] is None else f"{d['ratio']:.4f} (n={d['n']})"  # noqa: E731
        print(f"    order check: candidate-first {fmt(cf)}  baseline-first {fmt(bf)}")
    return 0


SELFTEST_CSV = """pair,order,arm,sha,p50_ms,p99_ms,reqs,iters,status,reason
1000,1,rel,0c93384,10,20,1200,100,OK,
1000,2,base,32f135a,10,20,1200,100,OK,
1001,1,base,32f135a,10,20,1200,90,OK,
1001,2,rel,0c93384,10,20,1200,100,OK,
1002,1,rel,0c93384,10,20,1200,89,OK,
1002,2,base,32f135a,10,20,1200,100,OK,
1003,1,base,32f135a,10,20,1200,100,OK,
1003,2,rel,0c93384,,,,,VOID,k6-exit-99
1004,1,rel,0c93384,10,20,1200,100,OK,
"""


def selftest() -> int:
    """Exercise the registered iteration gate. Run: `--selftest`.

    The gate decides which pairs reach the verdict, so it gets a check that
    fails if it stops excluding, starts excluding one arm only, or miscounts.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = f"{tmp}/reps.csv"
        with open(path, "w") as fh:
            fh.write(SELFTEST_CSV)

        kept, dropped = load_pairs(path, scored_only=True, min_iters=90)
        survivors = [p["pair"] for p in kept]

        # 1001 sits exactly on the floor and survives: the gate is `<`, not `<=`.
        assert 1001 in survivors, survivors
        # 1002 is one iteration under on the candidate arm only, and the whole
        # pair goes -- the surviving record carries neither of its arms.
        assert 1002 not in survivors, survivors
        # 1000 is clear on both arms.
        assert survivors == [1000, 1001], survivors
        # Each exclusion is counted under its own reason, not pooled.
        assert dropped == {"void": 1, "incomplete": 1, "below_iteration_gate": 1}, dropped

        # The base arm trips the same gate as the candidate arm.
        under_base = SELFTEST_CSV.replace(
            "1001,1,base,32f135a,10,20,1200,90", "1001,1,base,32f135a,10,20,1200,80"
        )
        with open(path, "w") as fh:
            fh.write(under_base)
        kept, dropped = load_pairs(path, scored_only=True, min_iters=90)
        assert [p["pair"] for p in kept] == [1000], kept
        assert dropped["below_iteration_gate"] == 2, dropped

        # min_iters=0 disables the gate, so calibration scoring is unchanged.
        kept, dropped = load_pairs(path, scored_only=True, min_iters=0)
        assert [p["pair"] for p in kept] == [1000, 1001, 1002], kept
        assert dropped["below_iteration_gate"] == 0, dropped

    # The counterbalance labels follow the baseline's SLOT, inverted: a pair
    # whose baseline sat in slot 2 is a pair the candidate opened.
    def mkpair(base_slot: int, rel_p50: float) -> dict:
        return {
            "base": {"p50": 10.0, "order": base_slot},
            "rel": {"p50": rel_p50, "order": 2 if base_slot == 1 else 1},
        }

    split = split_by_order([mkpair(2, 20.0), mkpair(2, 20.0), mkpair(1, 10.0), mkpair(1, 10.0)], "p50")
    assert split["candidate_first"]["n"] == 2, split
    assert abs(split["candidate_first"]["ratio"] - 2.0) < 1e-9, split
    assert abs(split["baseline_first"]["ratio"] - 1.0) < 1e-9, split

    print("selftest OK: iteration gate excludes whole pairs; order labels follow slot")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NFR.PERF.1 paired A/B evaluator")
    ap.add_argument("--read-rep", metavar="SUMMARY")
    ap.add_argument("--samples", metavar="CSV")
    ap.add_argument("--register", action="store_true")
    ap.add_argument("--verdict", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--read-gate", metavar="GATE")
    ap.add_argument("--field")
    ap.add_argument("--csv")
    ap.add_argument("--gate")
    ap.add_argument("--run-record")
    ap.add_argument("--out")
    ap.add_argument("--p50-budget", type=float, default=0.05)
    ap.add_argument("--p99-budget", type=float, default=0.10)
    ap.add_argument("--min-pairs", type=int, default=27)
    ap.add_argument("--max-pairs", type=int, default=60)
    args = ap.parse_args(argv)

    if args.read_rep:
        if not args.samples:
            print("VOID no-samples-argument")
            return 0
        print(read_rep(args.read_rep, args.samples))
        return 0
    if args.selftest:
        return selftest()
    if args.read_gate:
        print(json.load(open(args.read_gate))[args.field])
        return 0
    if args.register:
        return register(args)
    if args.verdict:
        return verdict(args)
    ap.error("one of --read-rep, --register, --verdict, --read-gate, --selftest is required")
    return 64


if __name__ == "__main__":
    sys.exit(main())
