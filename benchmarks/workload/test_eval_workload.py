#!/usr/bin/env python3
"""Self-check for eval_workload.py. Proves the four verdicts are distinct.

Run: python3 benchmarks/workload/test_eval_workload.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

EVAL = Path(__file__).resolve().parent / "eval_workload.py"

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
            "http_error_rate": {"rate": http_err},
            "semantic_assertion_rate": {"rate": semantic},
            "checks": {"rate": checks},
        }
    }


def build(run: Path, latencies, **overrides):
    """latencies: {cell: (p50, p99)} applied to all three reps."""
    pins = {
        "k6_image_digest": DIGEST,
        "cells": {
            c: {"health_version": v, "checkout_sha": s} for c, (v, s) in CELLS.items()
        },
    }
    (run / "pins.json").write_text(json.dumps(pins))

    for cell, (p50, p99) in latencies.items():
        for rep in (1, 2, 3):
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


def main() -> None:
    print("eval_workload self-check")

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

    # INCONCLUSIVE: per-rep spread on a legacy arm exceeds the margin, even
    # though the pooled numbers would have passed.
    case(
        "inconclusive/spread",
        FLAT,
        2,
        jitter={"A1": (10.0, 20.0), "A2": (12.0, 20.0), "A3": (10.0, 20.0)},
    )

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

    print("all eval_workload checks passed")


if __name__ == "__main__":
    main()
