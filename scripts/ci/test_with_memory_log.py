#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/with-memory-log.sh, run under stubs: a fake `free` on PATH and fake /proc and cgroup
files (MEM_LOG_PROC, MEM_LOG_CGROUP), sampling every second. Standard library only; Linux or macOS with bash 5.

The wrapper runs a command, prints memory samples to stderr while it runs, and exits with the command's own
status. It never limits time (the step's timeout-minutes does) and never prints the command or its arguments.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "ci" / "with-memory-log.sh"
FREE = """#!/bin/sh
echo '               total        used        free      shared  buff/cache   available'
echo 'Mem:           15983        1502        6800          10        7680       14200'
echo 'Swap:          11263          12       11251'
"""


def stubs(tmp: Path, with_free: bool = True, with_proc: bool = True) -> dict[str, str]:
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    # Without free: a stub that fails as a missing command would (the real one is in /usr/bin on Linux).
    (bin_dir / "free").write_text(FREE if with_free else "#!/bin/sh\nexit 127\n")
    (bin_dir / "free").chmod(0o755)
    proc, cg = tmp / "proc", tmp / "cgroup"
    (proc / "pressure").mkdir(parents=True)
    cg.mkdir()
    if with_proc:
        (proc / "pressure" / "memory").write_text(
            "some avg10=1.50 avg60=0.40 avg300=0.10 total=1\nfull avg10=0.75 avg60=0.20 avg300=0.05 total=1\n")
        (proc / "pressure" / "io").write_text("some avg10=2.25 avg60=0.00 avg300=0.00 total=1\n")
        (proc / "loadavg").write_text("3.99 2.00 1.00 5/300 4242\n")
        (cg / "memory.current").write_text(str(9 * 1024 * 1024 * 1024) + "\n")
        (cg / "memory.events").write_text("low 0\nhigh 0\nmax 0\noom 1\noom_kill 2\n")
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env.update(MEM_LOG_EVERY="1", MEM_LOG_PROC=str(proc), MEM_LOG_CGROUP=str(cg))
    return env


def run(cmd: str, env: dict[str, str], timeout: float = 20) -> tuple[int, str, str, float]:
    start = time.monotonic()
    p = subprocess.run(["bash", "-c", cmd], env=env, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr, time.monotonic() - start


def rows() -> list[tuple[str, bool, str]]:
    out = []
    w = str(WRAPPER)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        env = stubs(tmp)
        # W1: start line, >= 2 samples, end line, no trailing sleep.
        rc, so, se, t = run(f"{w} sleep 3", env)
        lines = [l for l in se.splitlines() if l.startswith("memory ")]
        ok = (rc == 0 and len(lines) >= 4 and "start" in lines[0] and "end, exit 0:" in lines[-1] and t < 4.5
              and "Mem total 15983 used 1502 available 14200" in lines[0] and "Swap total 11263 used 12" in lines[0]
              and "pressure mem some 1.50 full 0.75" in lines[0] and "io some 2.25" in lines[0]
              and "load 3.99" in lines[0] and "cgroup MB 9216 oom_kill 2" in lines[0])
        out.append(("W1 a 3 s command: start, samples, end exit 0, numbers parsed, no trailing sleep", ok, se[-400:]))
        # W2: the command's own failure status.
        rc, so, se, t = run(f"{w} bash -c 'exit 3'", env)
        out.append(("W2 exit 3 passes through", rc == 3 and "end, exit 3:" in se.splitlines()[-1], se[-200:]))
        # W3: a signal death is reported as a status, never as a limit.
        rc, so, se, t = run(f"{w} bash -c 'kill -9 $$'", env)
        out.append(("W3 SIGKILL: exit 137, no 'limit' wording", rc == 137 and "end, exit 137" in se and "limit" not in se, se[-200:]))
        # W4: TERM, INT and HUP sent to the wrapper reach the command as TERM; it cleans up its child and exits 42.
        # `set -m` gives the backgrounded wrapper a normal INT (without job control, & ignores INT).
        for sig in ("TERM", "INT", "HUP"):
            marker = tmp / f"child-{sig}"
            cmd = (f"set -m; {w} bash -c 'sleep 30 & c=$!; echo $c > {marker}; "
                   f"trap \"kill $c; exit 42\" TERM; wait $c' & wp=$!; sleep 1.5; kill -{sig} $wp; wait $wp")
            rc, so, se, t = run(cmd, env)
            child = marker.read_text().strip() if marker.exists() else ""
            gone = bool(child) and subprocess.run(["kill", "-0", child], capture_output=True).returncode != 0
            out.append((f"W4 {sig} reaches the command as TERM: exit 42 within 2 s, child gone", rc == 42 and t < 4 and gone, se[-200:]))
        # W6: the command's arguments never reach the wrapper's own output.
        rc, so, se, t = run(f"{w} true sk-SECRET-not-printed", env)
        out.append(("W6 no argv in the wrapper's output", "SECRET" not in se and "SECRET" not in so, se[-200:]))
        # W7: nothing holds the pipe after the command ends, even with a long interval.
        env60 = dict(env, MEM_LOG_EVERY="60")
        rc, so, se, t = run(f"{w} true 2>&1 | cat", env60)
        out.append(("W7 returns within 3 s with a 60 s interval (no sampler left)", rc == 0 and t < 3, f"{t:.1f}s"))
        # W8, W9: the caller shapes keep the failure status.
        rc, so, se, t = run(f"set -o pipefail; {w} false 2>&1 | tee {tmp}/x.log >/dev/null", env)
        out.append(("W8 tee pipeline under pipefail keeps rc 1", rc == 1, ""))
        rc, so, se, t = run(f"bash -euo pipefail -c '{w} false'", env)
        out.append(("W9 bash -euo pipefail -c keeps rc 1", rc == 1, ""))
        # W10: the command's stdout is byte-identical; samples go to stderr only.
        rc, so, se, t = run(f"{w} printf 'a\\nb c\\n'", env)
        out.append(("W10 stdout byte-identical, samples on stderr", so == "a\nb c\n" and "memory " in se, repr(so)))
    with tempfile.TemporaryDirectory() as d:
        env = stubs(Path(d), with_free=False, with_proc=False)
        # W5: missing sources print n/a and never change the status.
        rc, so, se, t = run(f"{w} bash -c 'exit 5'", env)
        out.append(("W5 no free, no /proc files: n/a, rc unchanged", rc == 5 and "n/a" in se and "end, exit 5" in se, se[-300:]))
    return out


def main() -> int:
    if not WRAPPER.is_file():
        print(f"WRONG {WRAPPER.relative_to(ROOT)} is missing")
        return 1
    wrong = 0
    for label, ok, detail in rows():
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}" + ("" if ok else f"\n      {detail!r}"))
    print(f"with-memory-log rows: {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
