#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The int-b shard's "UPGRADING checks on the assembled guide" step must be bounded and say which phase it is in.

On 2026-11-13 two Linux int-b jobs finished their shard suite in 18 to 19 minutes and then sat in this step until the 60 minute
job limit (runs 43340224995 and 43373402677); the step took 8 and 11 minutes in the two healthy runs read. A cancelled job's log is
not kept, so the stall could not be diagnosed. The step now has its own `timeout-minutes` (it fails with its log) and prints a
line before the compile phase and before the run phase of each target, so a timeout shows which one stalled. It prints no
process listing (process arguments can carry secrets); the one thing it may print about processes is a COUNT of the runner
user's processes in each phase line (`ps -u "$(id -u)" -o pid= | wc -l`: pids only, never arguments), because a test child
leaked by the shard suite could hold cargo's build-directory lock ("Blocking waiting for file lock") and look exactly like a
stall: a count that is high at the compile phase points at it.

Rows: the step exists and has a timeout between 15 and 30 minutes (above the slowest healthy run read); its script, read
as executable lines only (a comment counts for nothing), runs in this order: an `echo "phase compile...` line that prints
the process COUNT and `free -m`'s Mem and Swap rows, the `cargo test ... --no-run` compile, an `echo "phase run...` line,
then the test run; and it runs no other `ps`/`pgrep`/`/proc` listing. The keychain job's build step gets the same compile
rows and the same listing ban. `--self-test` runs the checker on fixtures. Standard library only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
STEP = "UPGRADING checks on the assembled guide"
MEMLOG = "scripts/ci/with-memory-log.sh"


def step_block(text: str, name: str = STEP) -> list[str] | None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if re.match(rf"^\s*- name: {re.escape(name)}", line):
            indent = len(line) - len(line.lstrip())
            block = [line]
            for nxt in lines[i + 1:]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                block.append(nxt)
            return block
    return None


COUNT = 'ps -u "$(id -u)" -o pid= | wc -l'
LISTING = re.compile(r"\b(ps|pgrep|pstree|lsof)\b|/proc/|\bjobs\s+-l\b|\btop\b")


def commands(block: list[str]) -> list[str]:
    """The step's `run: |` script as stripped, non-blank lines. The phase lines and the cargo commands count only at
    the start of a line, so one that sits in a comment counts for nothing; the listing ban reads comments too. A
    leading memory-log wrapper (scripts/ci/with-memory-log.sh, which logs numbers only) is read through."""
    run = re.search(r"^\s+run: \|\n(.*)$", "\n".join(block), re.M | re.S)
    script = run.group(1) if run else ""
    return [s.removeprefix(MEMLOG + " ") for s in (l.strip() for l in script.split("\n")) if s]


def phase_problems(cmds: list[str], with_run: bool) -> list[str]:
    """In order: echo `phase compile` (count + Mem and Swap rows), the `--no-run` compile, and with_run: echo
    `phase run`, then the test run. No other process listing anywhere in the script."""
    def at(pred) -> int:
        return next((i for i, c in enumerate(cmds) if pred(c)), -1)

    out = []
    pc = at(lambda c: c.startswith('echo "phase compile'))
    # `--no-run` counts only before a trailing comment.
    build = at(lambda c: c.startswith("cargo test") and "--no-run" in c.partition("#")[0])
    if pc < 0:
        out.append('no `echo "phase compile...` line')
    else:
        if COUNT not in cmds[pc]:
            out.append("the `phase compile` line does not print the runner user's process count")
        mem = cmds[pc].partition("free -m")[2]
        if "Mem" not in mem or "Swap" not in mem:
            out.append("the `phase compile` line does not print `free -m`'s Mem and Swap rows")
    if build < 0:
        out.append("no `cargo test ... --no-run` compile")
    elif 0 <= build < pc:
        out.append("the `phase compile` line comes after the compile")
    if with_run:
        pr = at(lambda c: c.startswith('echo "phase run'))
        test = at(lambda c: c.startswith("cargo test") and "--no-run" not in c.partition("#")[0])
        if pr < 0:
            out.append('no `echo "phase run...` line')
        if test < 0:
            out.append("no test run")
        if build >= 0 and pr >= 0 and test >= 0 and not build < pr < test:
            out.append("not in order: compile, then `phase run`, then the test run")
    if any(LISTING.search(c.replace(COUNT, "")) for c in cmds):
        out.append("the step lists processes (their arguments can print secrets); only the pid count form is allowed")
    return out


def problems(text: str) -> list[str]:
    block = step_block(text)
    if block is None:
        return [f"the step '{STEP}...' is missing"]
    out = []
    m = re.search(r"^\s+timeout-minutes:\s*(\d+)\s*$", "\n".join(block), re.M)
    if not m:
        out.append("no step timeout-minutes (a stall would run to the 60 minute job limit and leave no log)")
    elif not 15 <= int(m.group(1)) <= 30:
        out.append(f"timeout-minutes {m.group(1)} is outside 15..30 (healthy runs took 8 and 11 minutes)")
    return out + phase_problems(commands(block), with_run=True)


KEYCHAIN_STEP = "Build the test binary outside the session"


def keychain_problems(text: str) -> list[str]:
    """The keychain job's build step hung to the job limit once: it prints the same compile phase line."""
    block = step_block(text, KEYCHAIN_STEP)
    if block is None:
        return [f"keychain step '{KEYCHAIN_STEP}' is missing"]
    return [f"keychain step '{KEYCHAIN_STEP}': {p}" for p in phase_problems(commands(block), with_run=False)]


PHASE = """echo "phase compile: $target at $(date -u +%T), runner user processes: $(ps -u "$(id -u)" -o pid= | wc -l), memory MB: $(free -m | awk '/^(Mem|Swap):/ {print $1, $3}')\""""
BUILD = "cargo test --all-features $target --no-run"
RUN_PHASE = 'echo "phase run: $target at $(date -u +%T)"'
TEST = "cargo test --all-features $target 2>&1 | tee x.log"
GOOD = f"""      - name: UPGRADING checks on the assembled guide (suffix)
        if: matrix.shard == 'int-b'
        timeout-minutes: 20
        run: |
          set -euo pipefail
          for target in "--test a" "--lib b"; do
            {PHASE}
            {BUILD}
            {RUN_PHASE}
            {TEST}
          done

  test:
"""
KGOOD = f"""      - name: {KEYCHAIN_STEP}
        run: |
          {PHASE}
          cargo test --all-features --lib --no-run
      - name: next
        run: x
"""


def self_test() -> int:
    def swap(text: str, a: str, b: str) -> str:
        return text.replace(a, "\0").replace(b, a).replace("\0", b)

    cases = [
        ("a bounded, phased step", GOOD, 0),
        ("the cargo lines through the memory log", GOOD.replace(BUILD, MEMLOG + " " + BUILD).replace(TEST, MEMLOG + " " + TEST), 0),
        ("a wrapped run line before the compile", swap(GOOD.replace(TEST, MEMLOG + " " + TEST), BUILD, MEMLOG + " " + TEST), 1),
        ("no timeout", GOOD.replace("        timeout-minutes: 20\n", ""), 1),
        ("a timeout of 60", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 60"), 1),
        ("a timeout of 10, under the slowest healthy run", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 10"), 1),
        ("a timeout of 15", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 15"), 0),
        ("a timeout of 30", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 30"), 0),
        ("no compile phase line", GOOD.replace(PHASE + "\n", ""), 1),
        ("the compile phase line only in a comment", GOOD.replace(PHASE, "# " + PHASE), 1),
        ("no run phase line", GOOD.replace(RUN_PHASE + "\n", ""), 1),
        ("the run phase line only in a comment", GOOD.replace(RUN_PHASE, "# " + RUN_PHASE), 1),
        ("no --no-run", GOOD.replace(" --no-run", ""), 1),
        ("--no-run only in a comment", GOOD.replace(BUILD, "# " + BUILD), 1),
        ("--no-run only in a trailing comment", GOOD.replace(" --no-run", " # --no-run"), 1),
        ("the compile phase line after the compile", swap(GOOD, PHASE, BUILD), 1),
        ("the run phase line after the test run", swap(GOOD, RUN_PHASE, TEST), 1),
        ("the test run before the compile", swap(GOOD, BUILD, TEST), 1),
        ("the run phase line before the compile", swap(GOOD, RUN_PHASE, BUILD), 1),
        ("a process listing", GOOD.replace("set -euo pipefail\n", "set -euo pipefail\n          ps -ef\n"), 1),
        ("a listing with arguments next to the count", GOOD.replace("set -euo pipefail\n", "set -euo pipefail\n          ps -u \"$(id -u)\" -o pid=,args=\n"), 1),
        ("no process count in the compile phase line", GOOD.replace(', runner user processes: $(ps -u "$(id -u)" -o pid= | wc -l)', ""), 1),
        ("no free -m in the compile phase line", GOOD.replace("free -m", "true"), 1),
        ("free -m with the Mem row only", GOOD.replace("(Mem|Swap)", "Mem"), 1),
        ("pgrep instead of the pid count", GOOD.replace('$(ps -u "$(id -u)" -o pid= | wc -l)', "$(pgrep -a cargo)"), 1),
        ("the step missing", GOOD.replace(STEP, "something else"), 1),
        ("the timeout belongs to the next step, not this one", GOOD.replace("        timeout-minutes: 20\n", "").replace("\n  test:\n", "\n      - name: other\n        timeout-minutes: 20\n        run: x\n"), 1),
    ]
    kcases = [
        ("keychain step with the phase line", KGOOD, 0),
        ("keychain build through the memory log", KGOOD.replace("          cargo test", "          " + MEMLOG + " cargo test"), 0),
        ("keychain step without the phase line", KGOOD.replace("phase compile", "phase xx"), 1),
        ("keychain phase line only in a comment", KGOOD.replace(PHASE, "# " + PHASE), 1),
        ("keychain phase line after the build", swap(KGOOD, PHASE, "cargo test --all-features --lib --no-run"), 1),
        ("keychain step without --no-run", KGOOD.replace(" --no-run", ""), 1),
        ("keychain --no-run only in a trailing comment", KGOOD.replace(" --no-run", " # --no-run"), 1),
        ("keychain step without free -m", KGOOD.replace("free -m", "true"), 1),
        ("keychain step with the Mem row only", KGOOD.replace("(Mem|Swap)", "Mem"), 1),
        ("keychain step with ps aux", KGOOD.replace("          cargo test", "          ps aux\n          cargo test"), 1),
        ("keychain step with pgrep -a", KGOOD.replace("          cargo test", "          pgrep -a cargo\n          cargo test"), 1),
        ("keychain step missing", KGOOD.replace(KEYCHAIN_STEP, "other"), 1),
    ]
    wrong = 0
    for check, rows in ((keychain_problems, kcases), (problems, cases)):
        for label, text, want in rows:
            got = len(check(text))
            ok = (got == 0) == (want == 0)
            wrong += not ok
            print(f"{'ok   ' if ok else 'WRONG'} {label}: {got} problem(s), want {'some' if want else 'none'}")
    print(f"self-test: {len(cases) + len(kcases) - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0



def main() -> int:
    text = WORKFLOW.read_text()
    ps = problems(text) + keychain_problems(text)
    for p in ps:
        print(f"::error::ci.yml: step '{STEP}': {p}")
    print(f"int-b upgrading step: {len(ps)} problem(s)")
    return 1 if ps else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
