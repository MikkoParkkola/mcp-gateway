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
import math
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


def finite_number(value):
    """True for a real, finite number. Rejects bool, NaN and the infinities.

    NaN is the one that matters: every comparison against it is False, so a
    NaN load sample slides past `seen >= limit` and an artifact with a NaN
    envelope would disable enforcement without a word. bool is excluded because
    Python makes True an int, and a flag is not a load average.
    """
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def check_envelope(rep: str, meta: dict, pins: dict) -> None:
    """Void the run when a rep was measured on an oversubscribed machine.

    bench-host is shared. A rep whose window ran at loadavg >= the CPU count timed
    the run queue, not the gateway -- observed on 2026-09-21, where a
    three-minute excursion to loadavg 34 on 20 CPUs took tools-call p99 from
    ~3ms to 58.7ms in A2, 75.0ms in B2 and 33.9ms in C2.

    /health moved with it, 3.1ms -> 69ms in the same three reps. /health does no
    routing and no backend round-trip, so the stall is not in the tool path;
    being in the same process, it does not by itself separate host contention
    from a process-wide stall. What separates them is the controlled run: the
    same binary, hand-run with no harness change, at loadavg 34.9-51.1 returned
    health p99 60.01ms and tools p99 59.71ms -- A2's numbers, from CPU scarcity
    alone.

    This voids the RUN, never the rep. Grading the surviving reps would be
    choosing which measurements count after seeing them, which is the failure
    this gate exists to prevent; it is also useless, because the order-statistic
    interval already ignores an extreme value -- dropping A2 moves A.p99's
    half-width from 0.138 to 0.151, WIDER, since n=12 -> 11 steps k from 3 to 2.

    The envelope is read from pins.json, where the runner declares it before any
    rep runs. A run recorded before the pin existed has no envelope key and no
    recorded machine conditions; it is graded as it was, because inventing the
    load numbers it never sampled would be fabricating the evidence. The report
    says which of the two happened, so a legacy grade is never mistaken for an
    enforced one. Once the key IS declared, a rep missing either sample is a
    void: the runner writes load1_end only after k6 returns, so its absence
    means the rep never finished a valid window.
    """
    envelope = pins.get("load_envelope")
    if envelope is None:
        return
    if not isinstance(envelope, dict):
        raise Void(f"pins.load_envelope {envelope!r} must be an object")
    limit = envelope.get("max_load1")
    if not finite_number(limit) or limit <= 0:
        raise Void(f"pins.load_envelope.max_load1 {limit!r} must be a positive number")
    for field in ("load1_start", "load1_end"):
        value = meta.get(field)
        if not finite_number(value) or value < 0:
            raise Void(
                f"{rep}: meta.{field} is {value!r}, but pins.json declares a load "
                f"envelope; a rep with no usable record of its machine conditions "
                f"cannot certify a latency criterion"
            )
    seen = max(meta["load1_start"], meta["load1_end"])
    if seen >= limit:
        raise Void(
            f"{rep}: loadavg {seen:.2f} over the rep window reached the "
            f"{limit:.2f}-CPU envelope; the machine was oversubscribed and this "
            f"rep timed the run queue, not the gateway. Re-run on a quiet "
            f"machine -- do not grade the reps that happened to survive."
        )


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

    check_envelope(rep, meta, pins)

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
        # Reported beside the latencies, never gating. The envelope above is a
        # NECESSARY condition, not a certificate of a quiet machine: a rep
        # measured at loadavg 17.7 of 20 CPUs clears it and still returned p99
        # 20.5ms against a quiet-machine 2.6ms (hand-run on bench-host, 2026-09-21).
        # So when a cell reads INCONCLUSIVE, the conditions it drew are in the
        # same artifact as the width that made it inconclusive.
        "load1_max": (
            max(meta["load1_start"], meta["load1_end"])
            if isinstance(meta.get("load1_end"), (int, float))
            else None
        ),
    }


def pooled(values):
    return statistics.median(values)


CONF = 0.95


def _max_rank(n):
    """Largest k with P(x_(k) <= median <= x_(n-k+1)) >= CONF, else None.

    Coverage is monotone DECREASING in k, so the loop can stop at the first
    rank that breaches the floor. Maximality is the point, not admissibility:
    any smaller k also clears CONF but gives a WIDER interval, and a gate
    built on a too-wide interval reports more coverage than asked for while
    resolving less. For CONF = 0.95 no rank exists below n = 6.
    """
    best = None
    for k in range(1, n // 2 + 1):
        if 1 - 2 * sum(math.comb(n, i) for i in range(k)) / 2**n >= CONF:
            best = k
        else:
            break
    return best


def interval_insufficient(n):
    """True when n reps cannot support a CONF interval at any rank."""
    return _max_rank(n) is None


def median_interval(values):
    """Distribution-free CONF interval for the population median, or None.

    Returns the order-statistic pair (x_(k), x_(n-k+1)), which is
    (sorted[k-1], sorted[n-k]) zero-indexed. Distribution-free because the
    coverage is a binomial tail that does not depend on the population -- the
    t-based first draft measured 85.5% on a bimodal sample.
    """
    n = len(values)
    k = _max_rank(n)
    if k is None:
        return None
    ordered = sorted(values)
    return (ordered[k - 1], ordered[n - k])


def rel_half_width(values):
    """Half the interval width relative to the pooled median.

    Replaces spread(), whose min-to-max range widens with every extra rep and
    so punished the runs that measured hardest. Returns float("inf") when the
    sample cannot support an interval or the centre is non-positive, so an
    unmeasurable cell can never read as stable.
    """
    interval = median_interval(values)
    if interval is None:
        return float("inf")
    centre = pooled(values)
    if centre <= 0:
        return float("inf")
    return (interval[1] - interval[0]) / 2 / centre


def spread(values):
    """Min-to-max range over the smallest rep. Reported, never gating.

    This is the statistic #614 removed from the gate, kept as a diagnostic
    because it is what makes a dirty bench-host run legible: a cell whose range
    blows out while its interval stays tight is a machine-conditions story,
    not a code story. It is a range, so it widens with every added rep -- the
    reason it cannot decide anything, and the reason it is still worth seeing.
    """
    lo, hi = min(values), max(values)
    return (hi - lo) / lo if lo > 0 else float("inf")


def paired_ratios(candidate, baseline):
    """Per-rep candidate/baseline ratio, paired by REP INDEX.

    The ratio is the quantity the budget bounds, and it is the only thing the
    interleaved design can measure without carrying the machine along with it.
    Scoring each cell's absolute values throws the pairing away: on 2026-09-21
    one rep read p99 58.74 (A), 74.97 (B) and 33.90 (C) against a ~3.0 typical
    -- one machine excursion, charged to all three cells at once, which is why
    every unpaired half-width blew out together (A 9.45, B 11.85, C 5.19) while
    the per-rep ratios stayed at 0.3135 and 0.3462, some 30x tighter.

    Pairing is positional: reps[i] of both cells came from the same pass of the
    measured loop. A non-positive denominator yields the inf sentinel rather
    than a ZeroDivisionError, which would leave the process by a route that is
    not one of the four verdicts.
    """
    return [
        (c / b) if b > 0 else float("inf") for c, b in zip(candidate, baseline)
    ]


def jsonable(value):
    """Map the inf sentinel to null on the way out of the process.

    json.dumps writes float("inf") as the bare token Infinity, which RFC 8259
    does not admit; jq, a Go or Rust reader, or a browser JSON.parse rejects
    the whole document, not just the field. The sentinel stays inf in memory
    so every comparison is unchanged -- only the artifact says null.
    """
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def evaluate(run: Path) -> int:
    pins = load(run / "pins.json")

    for field, value in pins.items():
        if value in (None, "", {}):
            raise Void(f"pins.{field} is empty; an empty pin voids the run")

    # The rep numbers are DECLARED in pins.json, never discovered by globbing
    # the directory: a run that died mid-arm leaves fewer files, and that must
    # stay VOID rather than silently regrade as a smaller, insufficient
    # sample. Runs recorded before the pin existed fall back to MEASURED_REPS.
    # The fallback is keyed on the key being ABSENT, not on the value being
    # falsy: `pins.get("reps") or MEASURED_REPS` reads a declared-but-empty
    # sample as "this run predates the pin" and grades it against the default
    # three reps, which is a sample nobody declared. A non-list pin has to be
    # caught here too, or a scalar reaches the loop below as a TypeError.
    measured = pins["reps"] if "reps" in pins else list(MEASURED_REPS)
    if not isinstance(measured, list) or not measured:
        raise Void(f"pins.reps {measured!r} must be a non-empty list of rep ids")

    # A repeated rep id reads the same summary file twice. Six copies of one
    # measurement clear the n>=6 insufficiency floor and, being identical,
    # collapse the interval to zero width -- a single sample would report as a
    # resolved 95% interval. The pin declares the sample, so the pin is where
    # that has to be caught.
    if any(not isinstance(n, int) or isinstance(n, bool) or n < 1 for n in measured):
        raise Void(f"pins.reps {measured} must all be positive integers")
    if len(set(measured)) != len(measured):
        raise Void(f"pins.reps {measured} repeats a rep id; reps must be distinct")

    cells: dict[str, list[dict]] = {}
    for cell in LEGACY_CELLS + REPORT_ONLY_CELLS:
        cells[cell] = [check_rep(run, f"{cell}{n}", pins) for n in measured]

    report = {"per_rep": cells, "cells": {}}
    # Say which of the two gradings this was. A run predating the envelope is
    # graded as it always was, and that is correct -- but a reader comparing it
    # against an enforced run must be able to see that it rests on weaker
    # evidence, without inferring it from an absent key.
    report["load_envelope"] = {
        "enforced": "load_envelope" in pins,
        "max_load1": (pins.get("load_envelope") or {}).get("max_load1"),
    }
    for cell, reps in cells.items():
        loads = [r["load1_max"] for r in reps if r["load1_max"] is not None]
        report["cells"][cell] = {
            "p50": pooled([r["p50"] for r in reps]),
            "p99": pooled([r["p99"] for r in reps]),
            "p50_rel_half_width": rel_half_width([r["p50"] for r in reps]),
            "p99_rel_half_width": rel_half_width([r["p99"] for r in reps]),
            "p50_spread": spread([r["p50"] for r in reps]),
            "p99_spread": spread([r["p99"] for r in reps]),
            # The machine each cell actually drew. With every cell interleaved
            # these should agree; a cell whose window differs from its siblings'
            # is being compared against a different machine, which is what the
            # 2026-09-21 run did to D and E.
            "load1_max": max(loads) if loads else None,
            "load1_median": pooled(loads) if loads else None,
        }

    a, b, c = (report["cells"][k] for k in LEGACY_CELLS)

    # Paired scoring, REPORTED AND GATING NOTHING. The gate's stability check
    # below still reads the unpaired per-cell widths, unchanged: swapping the
    # number a gate decides on is a threshold decision, and a threshold chosen
    # after seeing the data is not a threshold. Both comparisons are kept --
    # C/A and C/B are different ratios (0.3135 and 0.3462 on the 2026-09-21
    # run), and min() over the two cells does not pair coherently per rep.
    # The limit these half-widths belong against is the EXISTING margin for
    # their metric, P50_BUDGET - 1 = 0.05 and P99_BUDGET - 1 = 0.10: the
    # budget bounds the ratio, so the ratio's interval is what has to resolve
    # inside it. Adopting that comparison is an operator decision, not this
    # evaluator's, and no new constant was introduced for it.
    report["paired"] = {}
    for base in ("A", "B"):
        entry = {}
        for name in ("p50", "p99"):
            ratios = paired_ratios(
                [r[name] for r in cells["C"]], [r[name] for r in cells[base]]
            )
            finite = all(math.isfinite(r) for r in ratios)
            interval = median_interval(ratios) if finite else None
            entry[name] = {
                "per_rep_ratio": ratios,
                "median": pooled(ratios) if finite else float("inf"),
                "interval": list(interval) if interval else None,
                "rel_half_width": (
                    rel_half_width(ratios) if finite else float("inf")
                ),
            }
        report["paired"][f"C_over_{base}"] = entry

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

    # An interval half-width wider than the margin it is judged against means
    # the run cannot resolve the question, whichever side the pooled number
    # happens to land on. Too few reps is the same conclusion reached earlier:
    # the interval does not exist, so the cell is unstable by insufficiency
    # and says so, rather than reporting a width nobody can interpret.
    margin_p50 = P50_BUDGET - 1.0
    margin_p99 = P99_BUDGET - 1.0
    unstable = []
    for cell in LEGACY_CELLS:
        n = len(cells[cell])
        if interval_insufficient(n):
            unstable.append(
                f"{cell} insufficient: {n} reps cannot support a "
                f"{CONF:.0%} median interval at any rank"
            )
            continue
        for metric, margin in (("p50", margin_p50), ("p99", margin_p99)):
            width = report["cells"][cell][f"{metric}_rel_half_width"]
            if width > margin:
                unstable.append(
                    f"{cell}.{metric} interval half-width "
                    f"{width:.3f} > {margin:.3f}"
                )

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

    payload = json.dumps(jsonable(report), indent=2, sort_keys=True)
    (run / "verdict.json").write_text(payload)
    print(payload)
    print(f"\nVERDICT: {verdict}  (exit {status})", file=sys.stderr)
    if unstable:
        print(
            "INCONCLUSIVE: the median interval is too wide for the margin it "
            "is judged against, or too few reps to build one at all. This is "
            "not a pass and must not be graded as one.",
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
