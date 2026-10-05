#!/usr/bin/env python3
"""Self-check for the graded cell-order schedule (schedule.py) and its two
enforcers: the runner refuses a graded run off the plan, and the evaluator
voids one whose recorded order is not the plan.

Run: python3 benchmarks/workload/test_schedule.py
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import schedule  # noqa: E402
import test_eval_workload as tev  # noqa: E402

FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")
    if not ok:
        FAILURES.append(name)


def shuffled(seed: int, reps: int) -> list[list[str]]:
    """The diagnostic order: a fresh shuffle per rep, as run_workload.sh draws it."""
    orders = []
    for n in range(1, reps + 1):
        cells = list("ABCDE")
        random.Random(f"{seed}:{n}").shuffle(cells)
        orders.append(cells)
    return orders


def graded_run(run: Path, orders: list[list[str]], **pin_overrides) -> int:
    """A clean 18-rep run (equal latencies) marked graded, with `orders` recorded."""
    tev.build(run, {c: (10.0, 20.0) for c in "ABCDE"}, reps=18)
    pins = json.loads((run / "pins.json").read_text())
    pins.update({"graded": True, "cell_order_seed": str(schedule.GRADED_SEED)})
    pins.update(pin_overrides)
    (run / "pins.json").write_text(json.dumps(pins))
    (run / "cell_order.jsonl").write_text(
        "".join(json.dumps({"rep": n, "order": o}) + "\n" for n, o in enumerate(orders, 1))
    )
    return tev.run_eval(run)


def runner_refusal(env: dict) -> str:
    full = {**os.environ, "K6_IMAGE_DIGEST": "sha256:" + "0" * 64, **env}
    done = subprocess.run(["bash", str(HERE / "run_workload.sh")], env=full,
                          capture_output=True, text=True, timeout=60)
    return done.stderr if done.returncode == 3 else f"exit {done.returncode}: {done.stderr}"


def main() -> int:
    planned = schedule.graded_orders(schedule.GRADED_SEED)
    check("the planned schedule is balanced", schedule.balance_problems(planned) == [],
          str(schedule.balance_problems(planned)))
    for cell in schedule.GATED:
        mean = sum(o.index(cell) + 1 for o in planned) / 18
        check(f"gated cell {cell} averages slot 3.00", mean == 3.0, f"{mean:.2f}")
    # The finding this replaces: the pinned seed's shuffle put C at 2.61.
    old = shuffled(schedule.GRADED_SEED, 18)
    c_mean = sum(o.index("C") + 1 for o in old) / 18
    check("premise: the shuffled order is unbalanced", schedule.balance_problems(old) != []
          and round(c_mean, 2) == 2.61, f"C mean {c_mean:.2f}")
    # Balance holds whatever the seed: only the row order moves.
    check("balance does not depend on the seed",
          all(schedule.balance_problems(schedule.graded_orders(s)) == [] for s in range(1, 200)))
    # A golden copy of the graded plan: an edit to schedule.py, or a change in
    # how random shuffles, must move this list on purpose, never silently.
    golden = ["ACEBD", "ADBEC", "BCDEA", "ABCDE", "BDACE", "DEABC", "BECAD", "CADBE",
              "EBDAC", "DACEB", "DEABC", "ECADB", "EABCD", "CEBDA", "CDBEA", "ABCDE",
              "CDEAB", "DBECA"]
    check("the graded plan is the golden copy", ["".join(o) for o in planned] == golden)
    # The stated carryover limit: slots are balanced, predecessors only partly.
    follows = {(o[i], o[i + 1]) for o in planned for i in range(4)}
    never = {a: [b for b in "ABCDE" if b != a and (a, b) not in follows] for a in "ABCDE"}
    check("each cell has exactly the one successor it never meets",
          never == {"A": ["E"], "B": ["A"], "C": ["B"], "D": ["C"], "E": ["D"]}, str(never))
    cli = subprocess.run([sys.executable, str(HERE / "schedule.py"), str(schedule.GRADED_SEED), "7"],
                         capture_output=True, text=True, check=True).stdout.split()
    check("the CLI prints the planned rep", cli == planned[6], f"{cli} vs {planned[6]}")

    for env, needle in [
        ({"WORKLOAD_GRADED": "1", "WORKLOAD_REPS": "6", "WORKLOAD_SEED": "20261007"}, "WORKLOAD_REPS=18"),
        ({"WORKLOAD_GRADED": "1", "WORKLOAD_REPS": "18", "WORKLOAD_SEED": "1"}, "WORKLOAD_SEED=20261007"),
        ({"WORKLOAD_GRADED": "yes", "WORKLOAD_REPS": "18", "WORKLOAD_SEED": "20261007"}, "must be 0 or 1"),
    ]:
        err = runner_refusal(env)
        check(f"the runner refuses {env}", needle in err, err.strip()[-200:])

    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "planned"
        run.mkdir()
        rc = graded_run(run, planned)
        check("a graded run on the plan is graded (not VOID)", rc != 3, f"rc={rc}")
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "shuffled"
        run.mkdir()
        check("a graded run in the shuffled order is VOID", graded_run(run, old) == 3)
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "seed"
        run.mkdir()
        check("a graded run under another seed is VOID",
              graded_run(run, planned, cell_order_seed="1") == 3)
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "missing"
        run.mkdir()
        graded_run(run, planned)
        (run / "cell_order.jsonl").unlink()
        check("a graded run with no recorded order is VOID", tev.run_eval(run) == 3)

    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "renumbered"
        run.mkdir()
        graded_run(run, planned)
        lines = [json.dumps({"rep": 19 - n, "order": o}) for n, o in enumerate(planned, 1)]
        (run / "cell_order.jsonl").write_text("\n".join(lines) + "\n")
        check("a graded run whose rep ids do not match the plan is VOID", tev.run_eval(run) == 3)
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "diagnostic"
        run.mkdir()
        tev.build(run, {c: (10.0, 20.0) for c in "ABCDE"}, reps=18)
        graded_eval = subprocess.run([sys.executable, str(HERE / "eval_workload.py"), "--graded", str(run)],
                                     capture_output=True, text=True)
        check("--graded voids a diagnostic run", graded_eval.returncode == 3, graded_eval.stderr[-200:])
        plain = subprocess.run([sys.executable, str(HERE / "eval_workload.py"), str(run)],
                               capture_output=True, text=True)
        check("a diagnostic verdict says it is diagnostic",
              json.loads((run / "verdict.json").read_text()).get("mode") == "diagnostic"
              and "DIAGNOSTIC" in plain.stderr, plain.stderr[-200:])
    with tempfile.TemporaryDirectory() as tmp:
        run = Path(tmp) / "used"
        run.mkdir()
        (run / "A1.summary.json").write_text("{}")
        full = {**os.environ, "K6_IMAGE_DIGEST": "sha256:" + "0" * 64, "WORKLOAD_GRADED": "1",
                "WORKLOAD_REPS": "18", "WORKLOAD_SEED": "20261007"}
        done = subprocess.run(["bash", str(HERE / "run_workload.sh"), "measure", str(run)], env=full,
                              capture_output=True, text=True, timeout=60)
        check("the runner refuses a graded measure into a used run dir",
              done.returncode == 3 and "fresh run dir" in done.stderr, done.stderr[-200:])

    print(f"\n{len(FAILURES)} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
