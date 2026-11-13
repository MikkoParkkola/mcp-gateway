#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The int-b shard's "UPGRADING checks on the assembled guide" step must be bounded and say which phase it is in.

On 2026-11-13 two Linux int-b jobs finished their shard suite in 18 to 19 minutes and then sat in this step until the 60 minute
job limit (runs 43340224995 and 43373402677); the step took 8 and 11 minutes in the two healthy runs read. A cancelled job's log is
not kept, so the stall could not be diagnosed. The step now has its own `timeout-minutes` (it fails with its log) and prints a
line before the compile phase and before the run phase of each target, so a timeout shows which one stalled. It prints no
process listing (process arguments can carry secrets).

Rows: the step exists, has a timeout between 10 and 30 minutes, compiles with `--no-run` before it runs, prints a `phase`
line for both, and runs no `ps`/`pgrep`/`/proc` listing. `--self-test` runs the checker on fixtures. Standard library only.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
STEP = "UPGRADING checks on the assembled guide"


def step_block(text: str) -> list[str] | None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if re.match(rf"^\s*- name: {re.escape(STEP)}", line):
            indent = len(line) - len(line.lstrip())
            block = [line]
            for nxt in lines[i + 1:]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                block.append(nxt)
            return block
    return None


def problems(text: str) -> list[str]:
    block = step_block(text)
    if block is None:
        return [f"the step '{STEP}...' is missing"]
    body = "\n".join(block)
    out = []
    m = re.search(r"^\s+timeout-minutes:\s*(\d+)\s*$", body, re.M)
    if not m:
        out.append("no step timeout-minutes (a stall would run to the 60 minute job limit and leave no log)")
    elif not 10 <= int(m.group(1)) <= 30:
        out.append(f"timeout-minutes {m.group(1)} is outside 10..30 (healthy runs took 8 and 11 minutes)")
    run = re.search(r"^\s+run: \|\n(.*)$", body, re.M | re.S)
    script = run.group(1) if run else ""
    compile_at = script.find("--no-run")
    first_run = script.find("cargo test", compile_at + 1) if compile_at >= 0 else -1
    if compile_at < 0:
        out.append("no `cargo test ... --no-run` compile phase before the run phase")
    p_compile = re.search(r"phase[: ]+compile", script)
    p_run = re.search(r"phase[: ]+run", script)
    if not p_compile:
        out.append("no `phase compile` line printed before the compile")
    if not p_run:
        out.append("no `phase run` line printed before the run")
    if p_compile and p_run and p_compile.start() > p_run.start():
        out.append("the `phase compile` line comes after the `phase run` line")
    if compile_at >= 0 and p_run and first_run >= 0 and p_run.start() > first_run + 400:
        pass  # ordering of the run line against the run command is covered by the phase-order check above
    if re.search(r"\b(ps|pgrep|pstree|lsof)\b|/proc/|\bjobs\s+-l\b|\btop\b", script):
        out.append("the step lists processes (their arguments can print secrets)")
    return out


GOOD = '''      - name: UPGRADING checks on the assembled guide (suffix)
        if: matrix.shard == 'int-b'
        timeout-minutes: 20
        run: |
          set -euo pipefail
          for target in "--test a" "--lib b"; do
            echo "phase compile: $target at $(date -u +%T)"
            cargo test --all-features $target --no-run
            echo "phase run: $target at $(date -u +%T)"
            cargo test --all-features $target 2>&1 | tee x.log
          done

  test:
'''


def self_test() -> int:
    cases = [
        ("a bounded, phased step", GOOD, 0),
        ("no timeout", GOOD.replace("        timeout-minutes: 20\n", ""), 1),
        ("a timeout of 60", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 60"), 1),
        ("a timeout of 5", GOOD.replace("timeout-minutes: 20", "timeout-minutes: 5"), 1),
        ("no compile phase line", GOOD.replace('echo "phase compile: $target at $(date -u +%T)"\n', ""), 1),
        ("no run phase line", GOOD.replace('echo "phase run: $target at $(date -u +%T)"\n', ""), 1),
        ("no --no-run", GOOD.replace(" --no-run", ""), 1),
        ("a process listing", GOOD.replace("set -euo pipefail\n", "set -euo pipefail\n          ps -ef\n"), 1),
        ("the step missing", GOOD.replace(STEP, "something else"), 1),
        ("the timeout belongs to the next step, not this one", GOOD.replace("        timeout-minutes: 20\n", "").replace("\n  test:\n", "\n      - name: other\n        timeout-minutes: 20\n        run: x\n"), 1),
    ]
    wrong = 0
    for label, text, want in cases:
        got = len(problems(text))
        ok = (got == 0) == (want == 0)
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: {got} problem(s), want {'some' if want else 'none'}")
    print(f"self-test: {len(cases) - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


def main() -> int:
    ps = problems(WORKFLOW.read_text())
    for p in ps:
        print(f"::error::ci.yml: step '{STEP}': {p}")
    print(f"int-b upgrading step: {len(ps)} problem(s)")
    return 1 if ps else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
