#!/usr/bin/env python3
"""Evaluator for the NFR.WORKLOAD.1 scored run.

Exit status is the verdict. INCONCLUSIVE is a status of its own, never a
string in a report, because a criterion graded from an inconclusive run looks
exactly like a pass in the ledger.

    0  PASS
    1  FAIL
    2  INCONCLUSIVE
    3  VOID

Reads a run directory produced by run_workload.sh:
    <rep>.summary.json   k6 --summary-export for that rep
    <rep>.meta.json      argv, checkout SHA, health version, uptime
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

EXIT_PASS, EXIT_FAIL, EXIT_INCONCLUSIVE, EXIT_VOID = 0, 1, 2, 3

P50_BUDGET = 1.05
P99_BUDGET = 1.10

LEGACY_CELLS = ("A", "B", "C")
REPORT_ONLY_CELLS = ("D", "E")
MEASURED_REPS = (1, 2, 3)


class Void(Exception):
    pass


def load(path: Path):
    if not path.exists():
        raise Void(f"missing required file: {path.name}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        # This is the Amendment 5 failure mode: a summary that shared a file
        # descriptor with another stream and is no longer parseable.
        raise Void(f"unparseable {path.name}: {exc}") from exc


def metric(summary, name, stat):
    metrics = summary.get("metrics") or {}
    if name not in metrics:
        raise Void(f"metric {name} absent from summary")
    value = metrics[name].get(stat)
    if value is None:
        raise Void(f"metric {name} has no {stat}")
    return float(value)


def rate(summary, name):
    metrics = summary.get("metrics") or {}
    if name not in metrics:
        raise Void(f"metric {name} absent from summary")
    node = metrics[name]
    for key in ("rate", "value"):
        if key in node and node[key] is not None:
            return float(node[key])
    raise Void(f"metric {name} has no rate")


def check_rep(run: Path, rep: str, pins: dict) -> dict:
    summary = load(run / f"{rep}.summary.json")
    meta = load(run / f"{rep}.meta.json")

    cell = rep[0]

    # Void 5: exact-string health version. 3.5.0 and 3.5.1 differ only by
    # patch, so a prefix match would accept the wrong binary.
    expected_version = pins["cells"][cell]["health_version"]
    seen_version = meta.get("health_version")
    if seen_version != expected_version:
        raise Void(
            f"{rep}: health version {seen_version!r} != pinned {expected_version!r}"
        )

    # Void 4 in the runner's terms: the argv and checkout SHA must have been
    # written before the arm ran, so a run that died mid-arm still says what
    # it was running.
    for field in ("argv", "checkout_sha"):
        if not meta.get(field):
            raise Void(f"{rep}: meta.{field} was never written")
    expected_sha = pins["cells"][cell]["checkout_sha"]
    if meta["checkout_sha"] != expected_sha:
        raise Void(
            f"{rep}: checkout {meta['checkout_sha']} != pinned {expected_sha}"
        )

    # Void 9: an unpinned load generator invalidates the comparison silently.
    if meta.get("k6_image_digest") != pins["k6_image_digest"]:
        raise Void(f"{rep}: k6 image {meta.get('k6_image_digest')} is not the pin")

    # Void 3: any HTTP error in a measured rep.
    if rate(summary, "http_error_rate") > 0:
        raise Void(f"{rep}: http_error_rate above zero")

    # Void 2: semantic assertions must be perfect, not merely mostly right.
    if rate(summary, "semantic_assertion_rate") < 1.0:
        raise Void(f"{rep}: semantic assertion rate below 100%")

    # Void 4: k6 check pass rate. Read through rate(), which accepts both the
    # "rate" and "value" spellings; k6's --summary-export only ever writes
    # "value", so a direct .get("rate") here is None on every real run and
    # voids every rep before any of them can be graded.
    checks_rate = rate(summary, "checks")
    if checks_rate < 0.99:
        raise Void(f"{rep}: checks pass rate {checks_rate} below 0.99")

    return {
        "rep": rep,
        "p50": metric(summary, "mcp_tools_call_latency", "p(50)"),
        "p99": metric(summary, "mcp_tools_call_latency", "p(99)"),
    }


def pooled(values):
    return statistics.median(values)


def spread(values):
    lo, hi = min(values), max(values)
    return (hi - lo) / lo if lo > 0 else float("inf")


def evaluate(run: Path) -> int:
    pins = load(run / "pins.json")

    for field, value in pins.items():
        if value in (None, "", {}):
            raise Void(f"pins.{field} is empty; an empty pin voids the run")

    cells: dict[str, list[dict]] = {}
    for cell in LEGACY_CELLS + REPORT_ONLY_CELLS:
        cells[cell] = [
            check_rep(run, f"{cell}{n}", pins) for n in MEASURED_REPS
        ]

    report = {"per_rep": cells, "cells": {}}
    for cell, reps in cells.items():
        report["cells"][cell] = {
            "p50": pooled([r["p50"] for r in reps]),
            "p99": pooled([r["p99"] for r in reps]),
            "p50_spread": spread([r["p50"] for r in reps]),
            "p99_spread": spread([r["p99"] for r in reps]),
        }

    a, b, c = (report["cells"][k] for k in LEGACY_CELLS)

    # 3.5.1 is the current upgrade source, 3.5.0 the frozen reference. Holding
    # the budget against whichever legacy arm is faster is the conservative
    # reading.
    base_p50 = min(a["p50"], b["p50"])
    base_p99 = min(a["p99"], b["p99"])
    limit_p50 = P50_BUDGET * base_p50
    limit_p99 = P99_BUDGET * base_p99

    report["baseline"] = {"p50": base_p50, "p99": base_p99}
    report["limits"] = {"p50": limit_p50, "p99": limit_p99}
    report["candidate"] = {"p50": c["p50"], "p99": c["p99"]}

    passes = c["p50"] <= limit_p50 and c["p99"] <= limit_p99

    # A per-rep spread wider than the margin it is being judged against means
    # the run cannot resolve the question, whichever side the pooled number
    # happens to land on.
    margin_p50 = P50_BUDGET - 1.0
    margin_p99 = P99_BUDGET - 1.0
    unstable = [
        f"{cell}.p50 spread {report['cells'][cell]['p50_spread']:.3f} > {margin_p50:.3f}"
        for cell in LEGACY_CELLS
        if report["cells"][cell]["p50_spread"] > margin_p50
    ] + [
        f"{cell}.p99 spread {report['cells'][cell]['p99_spread']:.3f} > {margin_p99:.3f}"
        for cell in LEGACY_CELLS
        if report["cells"][cell]["p99_spread"] > margin_p99
    ]

    if unstable:
        verdict, status = "INCONCLUSIVE", EXIT_INCONCLUSIVE
    elif passes:
        verdict, status = "PASS", EXIT_PASS
    else:
        verdict, status = "FAIL", EXIT_FAIL

    report["unstable"] = unstable
    report["verdict"] = verdict
    report["report_only"] = {
        cell: report["cells"][cell] for cell in REPORT_ONLY_CELLS
    }

    (run / "verdict.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nVERDICT: {verdict}  (exit {status})", file=sys.stderr)
    if unstable:
        print(
            "INCONCLUSIVE: per-rep spread exceeds the budget it is judged "
            "against. This is not a pass and must not be graded as one.",
            file=sys.stderr,
        )
    return status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    try:
        return evaluate(args.run_dir)
    except Void as exc:
        print(f"VERDICT: VOID  (exit {EXIT_VOID})\n  {exc}", file=sys.stderr)
        return EXIT_VOID


if __name__ == "__main__":
    sys.exit(main())
