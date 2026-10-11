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
    pins.update({"graded": True, "cell_order_seed": str(schedule.GRADED_SEED),
                 "host_id": schedule.BENCH_HOST_ID,
                 "build_host_ids": {c: schedule.BENCH_HOST_ID for c in "ABC"}})
    pins.update(pin_overrides)
    pins = {k: v for k, v in pins.items() if v is not None}  # None drops a pin
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
        check("a graded run on the plan grades PASS", rc == 0, f"rc={rc}")
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
    # Contract §9: a graded run is built and measured on bench-host. The
    # 2026-10-08 graded run ran on a GitHub-hosted runner and was accepted.
    with tempfile.TemporaryDirectory() as tmp:
        vector = Path(tmp) / "machine-id"
        vector.write_text("0123456789abcdef0123456789abcdef\n")
        check("the host id is the app-specific hash of the machine-id",
              schedule.host_id(vector)
              == "2e326ec7223cf104c8cdd21238903c1c5bcf1b4e68171e469cbede0eb67876a8")
        check("a host with no machine-id has no host id",
              schedule.host_id(vector.with_name("absent")) is None)
    for name, overrides in [
        ("measured on another host", {"host_id": "0" * 64}),
        ("with no recorded host", {"host_id": None}),
        ("with an arm built on another host",
         {"build_host_ids": {"A": schedule.BENCH_HOST_ID, "B": schedule.BENCH_HOST_ID, "C": "0" * 64}}),
        ("with an arm whose build host is unrecorded",
         {"build_host_ids": {"A": schedule.BENCH_HOST_ID, "B": schedule.BENCH_HOST_ID}}),
        ("with no recorded build hosts", {"build_host_ids": None}),
    ]:
        with tempfile.TemporaryDirectory() as tmp:
            check(f"a graded run {name} is VOID", graded_run(Path(tmp), planned, **overrides) == 3)
    with tempfile.TemporaryDirectory() as tmp:
        tev.build(Path(tmp), {c: (10.0, 20.0) for c in "ABCDE"}, reps=18)
        check("a diagnostic run with no host pins still grades", tev.run_eval(Path(tmp)) == 0)

    def graded_runner(tmp: Path, *args: str) -> tuple[subprocess.CompletedProcess, list[str]]:
        """run_workload.sh, graded, with git/cargo/docker as failing stubs that
        leave a mark: no row can check out or build an arm, even while red."""
        stubs = tmp / "stubs"
        stubs.mkdir()
        for tool in ("git", "cargo", "docker"):
            (stubs / tool).write_text(f"#!/bin/sh\ntouch '{stubs}/ran-{tool}'\nexit 97\n")
            (stubs / tool).chmod(0o755)
        env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "ARMS_DIR": str(tmp / "arms"),
               "K6_IMAGE_DIGEST": "sha256:" + "0" * 64, "WORKLOAD_GRADED": "1",
               "WORKLOAD_REPS": "18", "WORKLOAD_SEED": "20261007"}
        done = subprocess.run(["bash", str(HERE / "run_workload.sh"), *args], env=env,
                              capture_output=True, text=True, timeout=60)
        return done, sorted(m.name for m in stubs.glob("ran-*"))

    if schedule.host_id() != schedule.BENCH_HOST_ID:
        with tempfile.TemporaryDirectory() as tmp:
            done, ran = graded_runner(Path(tmp), "build")
            check("the runner refuses a graded build off bench-host, before any build",
                  done.returncode == 3 and "bench-host" in done.stderr and ran == []
                  and not (Path(tmp) / "arms").exists(),
                  f"exit {done.returncode} ran {ran}: {done.stderr[-200:]}")
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "fresh"
            run.mkdir()
            done, ran = graded_runner(Path(tmp), "measure", str(run))
            check("the runner refuses a graded measure off bench-host",
                  done.returncode == 3 and "bench-host" in done.stderr and ran == []
                  and not (run / "pins.json").exists(),
                  f"exit {done.returncode} ran {ran}: {done.stderr[-200:]}")
    else:
        # On bench-host the refusal must not fire: the build proceeds to its
        # first tool, which is a stub.
        with tempfile.TemporaryDirectory() as tmp:
            done, ran = graded_runner(Path(tmp), "build")
            check("on bench-host a graded build passes the host check",
                  "bench-host" not in done.stderr and "ran-git" in ran,
                  f"exit {done.returncode} ran {ran}: {done.stderr[-200:]}")
    for leftover in ("A1.summary.json", "pins.json", "cell_order.jsonl", "verdict.json"):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "used"
            run.mkdir()
            (run / leftover).write_text("{}")
            full = {**os.environ, "K6_IMAGE_DIGEST": "sha256:" + "0" * 64, "WORKLOAD_GRADED": "1",
                    "WORKLOAD_REPS": "18", "WORKLOAD_SEED": "20261007"}
            done = subprocess.run(["bash", str(HERE / "run_workload.sh"), "measure", str(run)], env=full,
                                  capture_output=True, text=True, timeout=60)
            check(f"the runner refuses a graded measure into a dir holding {leftover}",
                  done.returncode == 3 and "fresh run dir" in done.stderr, done.stderr[-200:])

    # Release baselines (MIK-7675): cell A must be v3.5.0 and cell B v3.5.1, by
    # commit, before a verdict reads as the release grade. The fixture SHAs
    # above are placeholders, so every run built so far is a repurposed one.
    release = {"A": ("3.5.0", "32f135a61fb50c20a044fb4c2347bc1cf8015d89"),
               "B": ("3.5.1", "e138680a542b41fa156a94a1ffc9decd9692be77")}

    def eval_both(run: Path) -> tuple[int, str, int, dict]:
        plain = subprocess.run([sys.executable, str(HERE / "eval_workload.py"), str(run)],
                               capture_output=True, text=True)
        report = json.loads((run / "verdict.json").read_text())
        graded_rc = subprocess.run([sys.executable, str(HERE / "eval_workload.py"), "--graded", str(run)],
                                   capture_output=True, text=True).returncode
        return plain.returncode, plain.stderr, graded_rc, report

    def release_run(run: Path, cells: dict) -> tuple[int, str, int, dict]:
        saved = dict(tev.CELLS)
        tev.CELLS.update(cells)
        try:
            graded_run(run, planned)
        finally:
            tev.CELLS.clear()
            tev.CELLS.update(saved)
        return eval_both(run)

    with tempfile.TemporaryDirectory() as tmp:
        rc, err, graded_rc, report = release_run(Path(tmp), release)
        check("verdict.json records every cell's checkout and version",
              report.get("cell_refs") == {c: {"checkout_sha": s, "health_version": v}
                                          for c, (v, s) in {**tev.CELLS, **release}.items()},
              str(report.get("cell_refs")))
        check("release baselines on the plan grade PASS as before", rc == 0 and graded_rc == 0,
              f"rc={rc} graded={graded_rc}")
        check("release baselines read as a release grade",
              report.get("release_grade") is True and "NOT A RELEASE GRADE" not in err, err[-200:])
    for name, cells in (("cell A repurposed", {"B": release["B"]}),
                        ("cell B repurposed", {"A": release["A"]})):
        with tempfile.TemporaryDirectory() as tmp:
            rc, err, graded_rc, report = release_run(Path(tmp), cells)
            check(f"{name}: the verdict itself is unchanged", rc == 0, f"rc={rc}")
            check(f"{name}: labelled not a release grade",
                  report.get("release_grade") is False and "NOT A RELEASE GRADE" in err, err[-200:])
            check(f"{name}: --graded refuses it as VOID", graded_rc == 3, f"graded={graded_rc}")

    ports_rows()
    print(f"\n{len(FAILURES)} failure(s)")
    return 1 if FAILURES else 0


def ports_rows() -> None:
    """Cell ports sit outside the ephemeral range, and a run refuses at second 0
    when they do not (2026-10-11: graded rep C9 voided when a live outgoing
    connection held cell C's port 39422, inside Linux's 32768-60999)."""
    here = Path(__file__).resolve().parent
    ports = getattr(schedule, "CELL_PORTS", {})
    check("every cell has a port", sorted(ports) == list("ABCDE"), str(ports))
    check("every cell port sits below Linux's default ephemeral range (32768)",
          bool(ports) and all(1024 < p < 32768 for p in ports.values()), str(ports))
    check("cell ports are distinct", len(set(ports.values())) == len(ports), str(ports))
    script = (here / "run_workload.sh").read_text()
    stale = [p for p in ("39420", "39421", "39422", "39423", "39424") if p in script]
    check("run_workload.sh names no port of its own (schedule.CELL_PORTS is the one list)",
          not stale, str(stale))

    def ports_clear(range_text: str | None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ip_local_port_range"
            if range_text is not None:
                path.write_text(range_text)
            return subprocess.run(
                [sys.executable, str(here / "schedule.py"), "ports-clear"],
                env={**os.environ, "WORKLOAD_PORT_RANGE_FILE": str(path)},
                capture_output=True, text=True, check=False)

    clear = ports_clear("32768\t60999\n")
    check("ports-clear passes against the default ephemeral range", clear.returncode == 0,
          f"rc={clear.returncode} {clear.stderr[-200:]}")
    covered = ports_clear("20000 30000\n")
    check("ports-clear refuses a range that covers a cell port, naming it",
          covered.returncode == 1 and "ephemeral" in covered.stderr, f"rc={covered.returncode} {covered.stderr[-200:]}")
    unreadable = ports_clear(None)
    check("ports-clear reports an unreadable range apart from a covered one",
          unreadable.returncode == 2, f"rc={unreadable.returncode} {unreadable.stderr[-200:]}")

    # The runner refuses before any rep: no arms, no docker, no config needed.
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "range").write_text("20000 30000\n")
        env = {**os.environ, "WORKLOAD_PORT_RANGE_FILE": str(Path(tmp) / "range"),
               "K6_IMAGE_DIGEST": "sha256:" + "0" * 64, "ARMS_DIR": str(Path(tmp) / "arms")}
        measure = subprocess.run(["bash", str(here / "run_workload.sh"), "measure", str(Path(tmp) / "run")],
                                 env=env, capture_output=True, text=True, check=False, timeout=60)
        check("run_workload.sh measure refuses at second 0 when a cell port is ephemeral",
              measure.returncode == 3 and "ephemeral" in measure.stderr
              and not (Path(tmp) / "run" / "pins.json").exists(),
              f"rc={measure.returncode} {measure.stderr[-300:]}")


if __name__ == "__main__":
    sys.exit(main())
