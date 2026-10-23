# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run CI's cargo-free PR-workflow checks before a push (MIK-8410).

pre-push.sh calls this through scripts/dev/prepush_ci_step.sh. Every listed
line runs in a scratch clone, one clone per worker reset after every command,
slowest first, on a worker count chosen from the CPU count. Each line has its
own hang timeout, and each setup git call its own; a busy machine never fails
a line (MIK-8787). One step backstop guards against hangs, not slowness. A
line that ran and failed is rerun on the merge-base and the result is printed
on its own line; every failure still fails the push.
"""
from __future__ import annotations

import argparse
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

# MIK-8787: a line's verdict must not depend on how busy the machine is. The
# timeouts catch a hang; they never measure speed, and clone setup never counts
# against a line's own timeout. The slowest listed line (99 s) has 9x headroom.
HANG_TIMEOUT_S = 900
SETUP_TIMEOUT_S = 300
# The whole step's hang guard (the ticket's fail-fast: an all-hang run is hours
# long without it). A healthy run is about 4 min; this is not a speed limit.
STEP_BACKSTOP_S = 3600
BASE_BRANCH = "docs/ranking-1-release-line"
TAIL_LINES = 20
# Stubs first on every line's PATH: a listed line never reaches a real Rust
# toolchain on the Mac (X18). Cargo-running checks are CI_ONLY or Spark work.
NO_CARGO = ("cargo", "rustc", "rustup", "rustdoc")


@dataclass
class Line:
    command: str
    seconds: float = 1.0
    direction: str = "closed"
    marker: str = ""
    requires: str = ""


@dataclass
class LineResult:
    command: str
    rc: int
    seconds: float
    log: Path | None = None
    status: str = ""  # "" passed; failed | timeout | setup-timeout | backstop | skipped | missing | crashed
    output: str = ""
    note: str = ""  # one line after the [status] header, e.g. the hang message


@dataclass
class Report:
    rc: int
    failures: list[LineResult] = field(default_factory=list)
    text: str = ""


def parse(text: str) -> Line:
    """One list-file line: command<TAB>seconds<TAB>direction[<TAB>key=value]."""
    command, *rest = text.split("\t")
    line = Line(command=command)
    if rest:
        line.seconds = float(rest[0])
    if len(rest) > 1:
        line.direction = rest[1]
    for extra in rest[2:]:
        key, _, value = extra.partition("=")
        setattr(line, key, value)
    if line.direction not in ("closed", "open"):
        raise ValueError(f"direction must be closed or open, not {line.direction!r}: {text}")
    if line.direction == "open" and not line.marker:
        raise ValueError(f"an open line needs marker=<skip text>: {text}")
    return line


def _git(cwd, *args, timeout=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)


def workers_for(cpus):
    """Lines run at once: a quarter of the CPUs, 2 to 4, so an interactive
    machine stays usable (MIK-8787 GATE.3; no setting)."""
    return min(4, max(2, (cpus or 0) // 4))


def _cap(bound, backstop_at):
    """`bound` seconds, or less if the step backstop comes sooner."""
    return max(min(bound, backstop_at - time.monotonic()), 0.01)


def _past(backstop_at):
    return time.monotonic() >= backstop_at


class SetupTimeout(Exception):
    """A setup git call outlived its own timeout (or the backstop)."""

    def __init__(self, name, seconds):
        super().__init__(f"git {name} timed out after {seconds:g} s (possible hang)")
        self.name = name


def _setup_git(cwd, *args, setup_s, backstop_at):
    try:
        return _git(cwd, *args, timeout=_cap(setup_s, backstop_at))
    except subprocess.TimeoutExpired:
        raise SetupTimeout(args[0], setup_s) from None


def _clone(repo, commit, dest, *, setup_s=SETUP_TIMEOUT_S, backstop_at=float("inf")):
    """A `--shared` clone of `repo` checked out at `commit` (no objects copied)."""
    kw = {"setup_s": setup_s, "backstop_at": backstop_at}
    done = _setup_git(repo, "clone", "-q", "--shared", "--no-checkout", str(repo), str(dest), **kw)
    if done.returncode == 0:
        done = _setup_git(dest, "checkout", "-q", "--detach", commit, **kw)
    if done.returncode != 0:
        raise RuntimeError(f"cannot check out {commit} in a scratch clone: {done.stderr.strip()}")
    return dest


def _reset(clone, *, setup_s=SETUP_TIMEOUT_S, backstop_at=float("inf")):
    """Back to the checked-out commit; a failure raises, and the worker drops the clone."""
    for args in (("reset", "-q", "--hard"), ("clean", "-qfdx")):
        done = _setup_git(clone, *args, setup_s=setup_s, backstop_at=backstop_at)
        if done.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed in {clone}: {done.stderr.strip()}")


def _substitute(command, *, head, merge_base, base_tip, tmp):
    return (
        command.replace("<HEAD>", head)
        .replace("<MERGE_BASE>", merge_base)
        .replace("<BASE_TIP>", base_tip)
        .replace("<TMP>", str(tmp))
    )


def _no_cargo(tmp):
    """Write the failing `cargo`/`rustc`/... stubs under `tmp` (X18). Called once,
    before any worker starts; `_execute` only puts the directory on PATH."""
    stubs = tmp / "no-cargo"
    stubs.mkdir()
    for tool in NO_CARGO:
        stub = stubs / tool
        stub.write_text(
            "#!/bin/sh\n"
            f"echo 'MIK-8410: `{tool}` blocked: pre-push never runs cargo on the Mac; "
            "classify this line CI_ONLY or run it under spark-cargo' >&2\n"
            "exit 97\n"
        )
        stub.chmod(0o755)


def _execute(command, workdir, timeout_s, tmp):
    """(rc, output, timed_out): `command` under bash -o pipefail in its own process group."""
    env = {**os.environ, "TMPDIR": str(tmp), "PATH": f"{tmp / 'no-cargo'}{os.pathsep}{os.environ.get('PATH', '')}"}
    proc = subprocess.Popen(
        ["bash", "-o", "pipefail", "-c", command],
        cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=env, start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=max(timeout_s, 0.01))
        # A passing line's background children die with it, before the reset (X20).
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return proc.returncode, out, False
    except subprocess.TimeoutExpired:
        # The whole group: a command's children die with it (X12).
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        return -9, out or "", True


def yaml_status() -> str:
    """One line naming the PyYAML version, or the install hint (lead ruling: any version)."""
    try:
        import yaml
    except ImportError:
        return "PyYAML is missing: pip install --user pyyaml (CI pins 6.0.2); pre-push installs nothing"
    return f"pyyaml {yaml.__version__} (CI pins 6.0.2)"


def resolve_base_tip(repo, *, remote="origin", branch=BASE_BRANCH, timeout_s=60) -> str:
    """Fetch `branch` (bounded, fail closed) and return its tip SHA (§5.2, G2)."""
    command = f"git fetch --no-tags {remote} {branch}"
    try:
        done = _git(repo, "fetch", "--no-tags", remote, branch, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"`{command}` timed out after {timeout_s} s") from None
    if done.returncode != 0:
        raise RuntimeError(f"`{command}` failed: {done.stderr.strip()}")
    tip = _git(repo, "rev-parse", f"refs/remotes/{remote}/{branch}")
    if tip.returncode != 0:
        tip = _git(repo, "rev-parse", "FETCH_HEAD")
    return tip.stdout.strip()


def _backstop_note(backstop_s, dispatched):
    what = "interrupted by the step backstop" if dispatched else "not dispatched: the step backstop was reached"
    return f"{what} ({backstop_s:g} s; a hang guard, not a speed limit)"


def _pool(lines, *, repo, commit, ctx, tmp, workers, executor, line_timeout_s, setup_s, backstop_at, backstop_s):
    """Run `lines` (already slowest first) on `workers` per-worker clones."""
    work = queue.Queue()
    for index, line in enumerate(lines):
        work.put((index, line))
    results = [None] * len(lines)
    logs = tmp / "logs"
    logs.mkdir(exist_ok=True)
    setup = {"setup_s": setup_s, "backstop_at": backstop_at}

    def worker(n):
        clone = None
        while True:
            try:
                index, line = work.get_nowait()
            except queue.Empty:
                return
            try:
                clone = one(n, index, line, clone)
            except SetupTimeout as err:
                status = "backstop" if _past(backstop_at) else "setup-timeout"
                note = _backstop_note(backstop_s, True) if status == "backstop" else str(err)
                results[index] = LineResult(line.command, -1, 0.0, status=status, note=note)
                clone = None
            except Exception:  # fail closed: a line whose worker raises is a failure (X19)
                results[index] = LineResult(line.command, -1, 0.0, status="crashed", output=traceback.format_exc())
                clone = None  # a crash leaves the clone dirty: the next line gets a fresh one

    def one(n, index, line, clone):
        command = _substitute(line.command, tmp=tmp, **ctx)
        if _past(backstop_at):
            results[index] = LineResult(line.command, -1, 0.0, status="backstop",
                                        note=_backstop_note(backstop_s, False))
            return clone
        if line.requires and _setup_git(repo, "cat-file", "-e", f"{line.requires}^{{commit}}", **setup).returncode != 0:
            results[index] = LineResult(
                line.command, -1, 0.0, status="missing",
                output=f"commit {line.requires} is not in the local object store: git fetch origin {line.requires}",
            )
            return clone
        if clone is None:
            clone = _clone(repo, commit, tmp / f"w{n}-{index:03d}-{commit[:12]}", **setup)
        if _past(backstop_at):  # the backstop expired during setup: never start the command
            results[index] = LineResult(line.command, -1, 0.0, status="backstop",
                                        note=_backstop_note(backstop_s, True))
            return None
        # The line's own timer starts here: setup never counts against it (MIK-8787 GATE.2).
        start = time.monotonic()
        budget = _cap(line_timeout_s, backstop_at)
        if executor is not None:
            rc, out = executor(command, clone, budget)
            timed_out = False
        else:
            rc, out, timed_out = _execute(command, clone, budget, tmp)
        seconds = time.monotonic() - start
        # The log is saved before the reset, so a reset failure cannot lose it.
        log = logs / f"{commit[:12]}-{index:03d}.log"
        log.write_text(out)
        status, note = "", ""
        if timed_out:
            if _past(backstop_at):
                status, note = "backstop", _backstop_note(backstop_s, True)
            else:
                status, note = "timeout", f"timed out after {line_timeout_s:g} s (possible hang)"
        elif rc != 0:
            status = "failed"
        elif line.direction == "open" and line.marker and line.marker in out:
            status = "skipped"
        result = LineResult(line.command, rc, seconds, log, status, out, note)
        results[index] = result
        try:
            _reset(clone, **setup)
        except (RuntimeError, SetupTimeout) as err:
            # The verdict, log and duration stay; the reset failure is noted and
            # the clone dropped. A passing line becomes a failure (X21).
            result.output += f"\nreset failed after the check ran: {err}"
            if not status:
                result.status = "setup-timeout" if isinstance(err, SetupTimeout) else "crashed"
            return None
        return clone

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(max(1, workers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return [r or LineResult(l.command, -1, 0.0, status="crashed", output="no result recorded")
            for r, l in zip(results, lines)]


def _paths_missing_at(command, head_clone, base_clone):
    """Files `command` names that exist at HEAD but not at the base."""
    return [
        word for word in command.replace('"', " ").split()
        if not word.startswith("-") and (head_clone / word).is_file() and not (base_clone / word).exists()
    ]


def _base_rerun(result, line, *, repo, ctx, tmp, n, line_timeout_s, setup_s, backstop_at, backstop_s):
    """One line: the three-way base result (§6.5, G5) as a printed line.

    Only a line that ran and failed on HEAD is rerun; any other status gave no
    verdict to compare (MIK-8787 D6), and the rerun gets its own full timeout."""
    mb, tip = ctx["merge_base"], ctx["base_tip"]
    if result.status != "failed":
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: {result.status}, the check gave no verdict on HEAD; {line.command}"
    if _past(backstop_at):
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: backstop, {_backstop_note(backstop_s, False)}; {line.command}"
    setup = {"setup_s": setup_s, "backstop_at": backstop_at}
    try:
        base = _clone(repo, mb, tmp / f"base{n}", **setup)
        head = _clone(repo, ctx["head"], tmp / f"head{n}", **setup)
    except SetupTimeout as err:
        why = f"backstop, {_backstop_note(backstop_s, True)}" if _past(backstop_at) else f"setup-timeout, {err}"
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: {why}; {line.command}"
    missing = _paths_missing_at(line.command, head, base)
    if missing:
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: {', '.join(missing)} not on the merge-base; {line.command}"
    command = _substitute(line.command, tmp=tmp, **{**ctx, "head": mb})
    if _past(backstop_at):  # expired during the base clones: never start the rerun
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: backstop, {_backstop_note(backstop_s, False)}; {line.command}"
    rc, _, timed_out = _execute(command, base, _cap(line_timeout_s, backstop_at), tmp)
    if timed_out:
        if _past(backstop_at):
            return f"NOT COMPARABLE ON MERGE-BASE {mb}: backstop, {_backstop_note(backstop_s, True)}; {line.command}"
        return f"NOT COMPARABLE ON MERGE-BASE {mb}: timed out on the merge-base (possible hang); {line.command}"
    if rc != 0:
        return f"PRE-EXISTING ON MERGE-BASE {mb}: {line.command}"
    caveat = (
        f"\n  PASSES ON MERGE-BASE {mb}; the base branch has moved to {tip}: "
        "rebase onto it and rerun before treating this as your change"
        if tip != mb else f"\n  PASSES ON MERGE-BASE {mb}: this change broke it"
    )
    return f"FAILS ON HEAD: {line.command}{caveat}"


def run(
    lines,
    *,
    repo,
    head,
    merge_base,
    base_tip,
    workers=None,
    executor=None,
    drift=None,
    line_timeout_s=HANG_TIMEOUT_S,
    setup_timeout_s=SETUP_TIMEOUT_S,
    backstop_s=STEP_BACKSTOP_S,
) -> Report:
    """Run every line; report failures with their base result.

    `lines` use the list-file format: `command<TAB>seconds<TAB>direction` with an
    optional `<TAB>marker=<text>` (open lines) and `<TAB>requires=<sha>`.
    `executor`, `drift` and the timeout arguments are private test seams
    (function arguments, never environment variables); `workers` defaults to
    workers_for(os.cpu_count())."""
    repo = Path(repo)
    if drift is not None:
        found = drift()
        if found:
            return Report(rc=1, text="CI script checks: the drift test failed; no check ran\n" + "\n".join(found))
    workers = workers or workers_for(os.cpu_count())
    parsed = sorted((parse(l) for l in lines), key=lambda l: -l.seconds)
    tmp = Path(tempfile.mkdtemp(prefix="prepush-ci-"))
    _no_cargo(tmp)
    backstop_at = time.monotonic() + backstop_s
    bounds = {"line_timeout_s": line_timeout_s, "setup_s": setup_timeout_s,
              "backstop_at": backstop_at, "backstop_s": backstop_s}
    ctx = {"head": head, "merge_base": merge_base, "base_tip": base_tip}
    results = _pool(parsed, repo=repo, commit=head, ctx=ctx, tmp=tmp, workers=workers,
                    executor=executor, **bounds)
    failures = [r for r in results if r and r.status]
    # Every line's rc and duration, slowest first, so the budget is debuggable (X24).
    per_line = [f"  rc {r.rc} {r.seconds:5.1f} s  {r.command}" for r in results]
    # The slowest lines by measured time keep slowness visible without failing anyone (GATE.6).
    slowest = sorted(results, key=lambda r: -r.seconds)[:5]
    per_line.append(f"CI script checks: {workers} workers; slowest: "
                    + ", ".join(f"{r.command} {r.seconds:.1f} s" for r in slowest))
    if not failures:
        shutil.rmtree(tmp, ignore_errors=True)
        return Report(rc=0, text="\n".join([*per_line, f"CI script checks: {len(results)} passed"]))
    text = [*per_line, f"CI script checks: {len(failures)} of {len(results)} failed (logs kept in {tmp})"]
    for n, result in enumerate(failures):
        line = next(l for l in parsed if l.command == result.command)
        text.append(f"\n[{result.status}] {result.command}" + (f": {result.note}" if result.note else ""))
        if result.log:
            text.append(f"  log: {result.log}")
        text.extend(result.output.splitlines()[-TAIL_LINES:])
        if executor is None and result.status != "skipped":
            text.append(_base_rerun(result, line, repo=repo, ctx=ctx, tmp=tmp, n=n, **bounds))
    return Report(rc=1, failures=failures, text="\n".join(text))


def run_rust(targets, *, cargo, repo, merge_base, base_tip) -> Report:
    """`cargo test --all-features --test …` for the derived targets (§7)."""
    args = [cargo, "test", "--all-features", *[a for t in targets for a in ("--test", t)]]
    done = subprocess.run(args, cwd=repo, capture_output=True, text=True)
    if done.returncode == 0:
        return Report(rc=0, text=f"doc/CLI Rust tests: {len(targets)} targets passed")
    tail = (done.stdout + done.stderr).splitlines()[-TAIL_LINES:]
    # ponytail: no Rust rerun on the merge-base (a fresh clone is a cold Spark
    # build); reported as not comparable instead. Upgrade: a persistent base mirror.
    wt = f"../base-{merge_base[:12]}"
    by_hand = (f"git worktree add --detach {wt} {merge_base} && "
               f"(cd {wt} && CARGO=spark-cargo spark-cargo {' '.join(args[1:])})")
    note = (f"NOT COMPARABLE ON MERGE-BASE {merge_base}: Rust targets are not rerun on the merge-base (cold build)\n"
            f"  to check the merge-base by hand: {by_hand}")
    return Report(rc=1, failures=[LineResult(" ".join(args), done.returncode, 0.0, status="failed")],
                  text="\n".join(["doc/CLI Rust tests failed:", *tail, note]))


def drift_problems(repo) -> list[str]:
    """Every drift problem the push path checks before the pool (§6.1, R3):
    workflow forms against the buckets, and the Rust set against RUST_TARGETS."""
    import test_prepush_ci_checks as drift_test

    return drift_test.problems(repo) + drift_test.rust_drift(repo)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--merge-base", required=True)
    parser.add_argument("--rust", action="store_true", help="run the doc/CLI-reading Rust targets instead")
    args = parser.parse_args(argv)
    status = yaml_status()
    print(status)
    if status.startswith("PyYAML is missing"):
        return 1
    repo = Path(_git(".", "rev-parse", "--show-toplevel").stdout.strip())
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import test_prepush_ci_checks as drift_test

    if args.rust:
        report = run_rust(drift_test.rust_targets(repo), cargo=os.environ.get("CARGO", "cargo"),
                          repo=repo, merge_base=args.merge_base, base_tip=args.merge_base)
        print(report.text)
        return report.rc
    try:
        base_tip = resolve_base_tip(repo)
    except RuntimeError as err:
        print(f"CI script checks: {err}")
        return 1
    lines = [l for l in (repo / "scripts/dev/prepush-ci-checks.txt").read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    start = time.monotonic()
    report = run(lines, repo=repo, head=head, merge_base=args.merge_base, base_tip=base_tip,
                 drift=lambda: drift_problems(repo))
    load = os.getloadavg()[0] if hasattr(os, "getloadavg") else float("nan")
    print(report.text)
    print(f"CI script checks: {time.monotonic() - start:.0f} s wall, load {load:.1f}")
    return report.rc


if __name__ == "__main__":
    raise SystemExit(main())
