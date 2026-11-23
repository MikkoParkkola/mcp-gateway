#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/with-memory-log.sh, run under stubs: a fake `free` on PATH and fake /proc and cgroup
files (MEM_LOG_PROC, MEM_LOG_CGROUP), sampling every second. Standard library only; Linux or macOS with bash 5.

The wrapper runs a command, prints memory samples to stderr while it runs, and exits with the command's own
status. It never limits time (the step's timeout-minutes does) and never prints the command or its arguments.
"""
from __future__ import annotations

import contextlib
import os
import signal
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


# No row asserts "finished within N s" for a success: the machine's load decides how long a start-up takes (a train was refused
# at load 26 by exactly such a bound). A row separates its outcomes by what the wrapper did (a status, a line, a signal that
# arrived) and, where the failure is a wait on a timer or a hang, by a timeout set well under that timer: the wrapper must
# end before it, and a load stretch cannot bring a correct run near it. A hang is rc -1 from run().
def run(cmd: str, env: dict[str, str], timeout: float = 60) -> tuple[int, str, str, float]:
    start = time.monotonic()
    try:
        p = subprocess.run(["bash", "-c", cmd], env=env, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        # A hang is a failed row with its own message, not a crash that hides every later row.
        return -1, "", f"HUNG past {timeout} s", time.monotonic() - start
    return p.returncode, p.stdout, p.stderr, time.monotonic() - start


def rows() -> list[tuple[str, bool, str]]:
    out = []
    w = str(WRAPPER)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        env = stubs(tmp)
        # W1: start line, >= 2 samples, end line. 8 s: under heavy load one sample took about 2 s, and a 3 s command then
        # ended before its second sample. A wrapper that never ends is the hang (rc -1 at the run timeout). W7 is the
        # no-trailing-sampler check.
        rc, so, se, t = run(f"{w} sleep 8", env)
        lines = [l for l in se.splitlines() if l.startswith("memory ")]
        ok = (rc == 0 and len(lines) >= 4 and "start" in lines[0] and "end, exit 0:" in lines[-1]
              and "Mem total 15983 used 1502 available 14200" in lines[0] and "Swap total 11263 used 12" in lines[0]
              and "pressure mem some 1.50 full 0.75" in lines[0] and "io some 2.25" in lines[0]
              and "load 3.99" in lines[0] and "cgroup MB 9216 oom_kill 2" in lines[0])
        out.append(("W1 an 8 s command: start, 2+ samples, end exit 0, numbers parsed", ok, f"rc {rc}, {se[-400:]}"))
        # W2: the command's own failure status.
        rc, so, se, t = run(f"{w} bash -c 'exit 3'", env)
        out.append(("W2 exit 3 passes through", rc == 3 and "end, exit 3:" in se.splitlines()[-1], f"rc {rc}, {se[-200:]}"))
        # W3: a signal death is reported as a status, never as a limit.
        rc, so, se, t = run(f"{w} bash -c 'kill -9 $$'", env)
        out.append(("W3 SIGKILL: exit 137, no 'limit' wording", rc == 137 and "end, exit 137" in se and "limit" not in se,
                    f"rc {rc}, {se[-200:]}"))
        # W4: TERM, INT and HUP sent to the wrapper reach the command as TERM; it cleans up its child and exits 42.
        # `set -m` gives the backgrounded wrapper a normal INT (without job control, & ignores INT). The command sets its
        # trap, then writes its marker; the signal is sent when the marker exists (the command's own "ready" event, not a
        # sleep that load can overtake). A signal that is not forwarded leaves the command in its 120 s wait: a hang at the
        # 60 s timeout, far from a correct run's seconds. The trap waits for the child, so "child gone" holds at exit.
        for sig in ("TERM", "INT", "HUP"):
            marker = tmp / f"child-{sig}"
            cmd = (f"set -m; {w} bash -c 'sleep 120 & c=$!; trap \"kill $c; wait $c; exit 42\" TERM; echo $c > {marker}; wait $c' "
                   f"& wp=$!; while [ ! -s {marker} ]; do kill -0 $wp 2>/dev/null || break; sleep 0.1; done; kill -{sig} $wp; wait $wp")
            rc, so, se, t = run(cmd, env)
            child = marker.read_text().strip() if marker.exists() else ""
            gone = bool(child) and subprocess.run(["kill", "-0", child], capture_output=True).returncode != 0
            out.append((f"W4 {sig} reaches the command as TERM: exit 42, child gone", rc == 42 and gone,
                        f"rc {rc}, {t:.1f}s, child {'gone' if gone else 'still there or never written'}, {se[-200:]}"))
        # W11: a command that ignores the forwarded TERM keeps running and its own later status is the result.
        cmd = (f"set -m; {w} bash -c 'trap \"\" TERM; sleep 2; exit 7' & wp=$!; sleep 0.5; kill -TERM $wp; wait $wp")
        rc, so, se, t = run(cmd, env)
        out.append(("W11 TERM ignored by the command: it finishes, rc 7", rc == 7 and "end, exit 7:" in se and t >= 1.8,
                    f"rc {rc}, {t:.1f}s, {se[-200:]}"))
        # W12: a bad interval falls back to the default (30 s) instead of sampling in a tight loop.
        for bad in ("abc", "00"):
            rc, so, se, t = run(f"{w} sleep 2", dict(env, MEM_LOG_EVERY=bad))
            n = sum(l.startswith("memory ") for l in se.splitlines())
            out.append((f"W12 MEM_LOG_EVERY={bad} falls back to 30 s: start and end lines only", rc == 0 and n == 2,
                        f"rc {rc}, {n} lines"))
        # W6: the command's arguments never reach the wrapper's own output.
        rc, so, se, t = run(f"{w} true sk-SECRET-not-printed", env)
        out.append(("W6 no argv in the wrapper's output", "SECRET" not in se and "SECRET" not in so, se[-200:]))
        # W7: nothing holds the pipe after the command ends, even with a long interval. A sampler left behind holds the
        # pipe for its 60 s interval: the row must end at half of that. The command ends only once the wrapper's sampler
        # nap exists (a `sleep` whose parent is the wrapper, found with ps), so the nap is running when the command ends
        # however slowly the wrapper got there; a command that ends at once never gets a nap started and proves nothing.
        env60 = dict(env, MEM_LOG_EVERY="60")
        waiter = tmp / "w7-waiter.sh"
        waiter.write_text("until ps -A -o ppid=,comm= | awk -v p=$PPID '$1 == p && $2 ~ /sleep$/ { f = 1 } END { exit !f }'; do sleep 0.1; done\n")
        rc, so, se, t = run(f"{w} bash {waiter} 2>&1 | cat", env60, timeout=30)
        out.append(("W7 returns before the 60 s interval ends (no sampler left)", rc == 0, f"rc {rc}, {t:.1f}s"))
        # W8, W9: the caller shapes keep the failure status.
        rc, so, se, t = run(f"set -o pipefail; {w} false 2>&1 | tee {tmp}/x.log >/dev/null", env)
        out.append(("W8 tee pipeline under pipefail keeps rc 1", rc == 1, f"rc {rc}"))
        rc, so, se, t = run(f"bash -euo pipefail -c '{w} false'", env)
        out.append(("W9 bash -euo pipefail -c keeps rc 1", rc == 1, f"rc {rc}"))
        # W10: the command's stdout is byte-identical; samples go to stderr only.
        rc, so, se, t = run(f"{w} printf 'a\\nb c\\n'", env)
        out.append(("W10 stdout byte-identical, samples on stderr", so == "a\nb c\n" and "memory " in se, repr(so)))
    with tempfile.TemporaryDirectory() as d:
        env = stubs(Path(d), with_free=False, with_proc=False)
        # W5: missing sources print n/a and never change the status.
        rc, so, se, t = run(f"{w} bash -c 'exit 5'", env)
        out.append(("W5 no free, no /proc files: n/a, rc unchanged", rc == 5 and "n/a" in se and "end, exit 5" in se,
                    f"rc {rc}, {se[-300:]}"))
    with tempfile.TemporaryDirectory() as d:
        env = stubs(Path(d))
        # W13: a command a signal kills before the wrapper first waits (here, while a slow `free` takes the start
        # sample). bash 5.1 and 5.2 drop such a job from the job table, so `wait -n` never names it; the wrapper must
        # still end with 137, not loop on its sampling timer until the step limit (a hang: rc -1 at the timeout). (bash 5.3
        # keeps the job, so this row turns red on the old wrapper only under bash 5.1 or 5.2.)
        (Path(d) / "bin" / "free").write_text("#!/bin/sh\nsleep 1\n" + FREE.split("\n", 1)[1])
        rc, so, se, t = run(f"{w} bash -c 'kill -9 $$'", env, timeout=60)
        out.append(("W13 a command killed before the first wait: exit 137, no hang",
                    rc == 137 and "end, exit 137" in se, f"rc {rc}, {t:.1f}s, {se[-200:]}"))
    out.extend(gap_rows())
    out.extend(classifier_rows())
    return out


def gap_rows() -> list[tuple[str, bool, str]]:
    """W14, W15: a signal that reaches the wrapper before it has the command's pid is still passed on.

    A BASH_ENV hook places the signal at one exact point from inside the wrapper: a DEBUG trap fires before each
    command, and the hook's $0 guard leaves every other bash alone. W14 sends it just before `cmd=$!` (once per signal
    kind), W15 just after the wrapper's trap line, before the launch. A dropped signal leaves `sleep 120` running and
    the run hits its 30 s timeout; a forwarded one ends the command with TERM at once (exit 143). A hang is the
    expected red only when the hook's own line is in stderr; without it the hook never fired and the row is broken."""
    out = []
    w = str(WRAPPER)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        env = stubs(tmp)
        ver = subprocess.run(["bash", "-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"], env=env,
                             capture_output=True, text=True).stdout.split()
        # Below 5.1 the wrapper execs the command and never reaches the gap.
        old = len(ver) < 2 or (int(ver[0]), int(ver[1])) < (5, 1)
        cases = []
        for sig in ("TERM", "INT", "HUP"):
            said = "hook: " + sig + " now, next is cmd=$!"
            body = ('case $BASH_COMMAND in "cmd=\\$!") trap - DEBUG; echo "hook: ' + sig
                    + ' now, next is $BASH_COMMAND" >&2; kill -' + sig + ' $$ ;; esac')
            cases.append(("W14 " + sig + " between the launch and cmd=$! reaches the command: exit 143", said, body))
        said = "hook: HUP now, the trap is set"
        body = ('if [ -n "${hook_armed-}" ]; then trap - DEBUG; echo "' + said + '" >&2; kill -HUP $$; '
                'else case $BASH_COMMAND in "trap "*" TERM INT HUP") hook_armed=1 ;; esac; fi')
        cases.append(("W15 HUP between the trap line and the launch reaches the command: exit 143", said, body))
        for n, (label, said, body) in enumerate(cases):
            if old:
                out.append((label, True, "skipped: bash older than 5.1"))
                continue
            hook = tmp / f"hook-{n}.sh"
            hook.write_text("case $0 in *with-memory-log.sh) trap '" + body + "' DEBUG ;; esac\n")
            # Its own session, so the whole group can be killed afterwards: run() kills only its direct child, and a
            # `sleep 120` left behind would hold the captured pipes open.
            p = subprocess.Popen([w, "sleep", "120"], env=dict(env, BASH_ENV=str(hook)), cwd=ROOT, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                so, se = p.communicate(timeout=30)
                rc = p.returncode
            except subprocess.TimeoutExpired:
                rc = -1
            # Matched by process group, never by name alone: other runs on the host own sleeps too. Names only, as W7:
            # never a process's arguments. A wrapper that ended has already stopped its own nap, so any sleep still
            # in the group is the command's.
            # The group is killed even if the scan itself fails, so nothing is left holding the pipes.
            try:
                ps = subprocess.run(["ps", "-A", "-o", "pgid=,comm="], capture_output=True, text=True).stdout
                left = any(f[0] == str(p.pid) and f[-1].endswith("sleep")
                           for f in map(str.split, ps.splitlines()) if f)
            finally:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(p.pid, signal.SIGKILL)
            if rc == -1:
                so, se = p.communicate()
                se += "\nHUNG past 30 s"
            lines = se.splitlines()
            ok = (rc == 143 and se.count(said) == 1 and bool(lines) and "end, exit 143" in lines[-1] and not left)
            out.append((label, ok, f"rc {rc}, hook line {se.count(said)}x, "
                                   f"{'a sleep was left' if left else 'no sleep left'}, {se[-200:]}"))
    return out


def classify_hang(record: dict) -> str:
    """A W4 hang record's cause class: the first row of this ordered list that matches. The class names where the cause
    is; it designs no fix. K1 to K6 are named causes; K7 to K10 are not (K7 and K8 are snapshots of one moment, K9 has
    two stories a snapshot cannot tell apart), and neither is K0, a capture that failed."""
    r6 = record.get("R6")
    if (any(record.get(f) is None for f in ("R1", "R2", "R3", "R4", "R5", "R7", "R8", "R9"))
            or (record["linux"] and r6 is None)
            or (r6 is not None and any(r6[w]["identity"] == "not confirmed" for w in ("wrapper", "command")))):
        return "K0"
    # A stopped process that is only a fellow member of the wrapper's group selects nothing.
    if any(p["state"].startswith("T") for p in record["R7"] if p["role"] != "group"):
        return "K1"
    if not record["R1"]["written"]:
        return "K2"
    if not record["R2"]["reached"]:
        return "K3"
    if record["R2"]["status"] != 0:
        return "K4"
    if record["R3"]["trap_ran"]:
        return "K5"
    if r6 is None:
        return "K6 to K9, not separable here"
    w, c = r6["wrapper"], r6["command"]
    w_alive, c_alive = w["identity"] == "confirmed", c["identity"] == "confirmed"
    sig, term = _bit(record["signal"]), _bit("TERM")
    # Pending is the union of the thread's set and the process's. A blocked set alone selects nothing: a signal that is
    # blocked need never have been sent.
    if w_alive and w["ign"] & sig:
        return "K6"
    if w_alive and (w["pnd"] | w["shd"]) & sig:
        return "K7"
    if c_alive and (c["pnd"] | c["shd"]) & term:
        return "K8"
    # K8 above already took a command holding TERM.
    if w_alive and w["cgt"] & sig and not (w["pnd"] | w["shd"]):
        return "K9"
    return "K10"


def _bit(sig: str) -> int:
    """The mask bit /proc/PID/status uses for a signal: bit n-1 for signal n."""
    return 1 << (signal.Signals["SIG" + sig].value - 1)


def _canned(sig: str = "INT") -> dict:
    """A complete Linux record that meets none of the classes K0 to K9, so it is K10: the marker was written, the kill
    returned 0, the trap did not run, and the wrapper and the command are alive, confirmed, stopped neither, and neither
    ignore, catch nor hold any signal."""
    def proc() -> dict:
        return {"identity": "confirmed", "state": "S", "ign": 0, "cgt": 0, "blk": 0, "pnd": 0, "shd": 0}
    return {
        "signal": sig, "linux": True,
        "R1": {"written": True, "child": 1003, "command": 1002},
        "R2": {"reached": True, "status": 0},
        "R3": {"trap_ran": False},
        "R4": {"running": True, "status": None},
        "R5": {"pid": 1001, "group": 1001},
        "R6": {"wrapper": proc(), "command": proc()},
        "R7": [{"pid": p, "ppid": pp, "pgid": 1001, "state": "S", "etime": "00:10", "comm": c, "role": r}
               for p, pp, c, r in ((1001, 1000, "bash", "wrapper"), (1002, 1001, "bash", "command"),
                                   (1003, 1002, "sleep", "sleeper"), (1004, 1001, "sleep", "descendant"))]
               + [{"pid": 1005, "ppid": 1, "pgid": 1001, "state": "S", "etime": "00:10", "comm": "sh", "role": "group"}],
        "R8": {"stdout": "", "stderr": "memory 00:00:00 start: ..."},
        "R9": {"load_start": 21.0, "load_limit": 22.0, "to_marker": 0.5, "to_kill": 0.6},
    }


def _role(record: dict, role: str) -> dict:
    return next(p for p in record["R7"] if p["role"] == role)


# One setter per class row of the ordered list: each makes the canned record meet that row's condition. "K7p" and "K8p"
# put the signal in the process-wide pending set instead of the thread's.
_MEETS = {
    "K0": lambda r: r.update(R9=None),
    "K1": lambda r: _role(r, "wrapper").update(state="T"),
    "K2": lambda r: r["R1"].update(written=False, child=None, command=None),
    "K3": lambda r: r["R2"].update(reached=False, status=None),
    "K4": lambda r: r["R2"].update(status=1),
    "K5": lambda r: r["R3"].update(trap_ran=True),
    "K6": lambda r: r["R6"]["wrapper"].update(ign=_bit(r["signal"])),
    "K7": lambda r: r["R6"]["wrapper"].update(pnd=_bit(r["signal"])),
    "K7p": lambda r: r["R6"]["wrapper"].update(shd=_bit(r["signal"])),
    "K8": lambda r: r["R6"]["command"].update(pnd=_bit("TERM")),
    "K8p": lambda r: r["R6"]["command"].update(shd=_bit("TERM")),
    "K9": lambda r: r["R6"]["wrapper"].update(cgt=_bit(r["signal"])),
}
# Pairs no real record can meet together: a kill status needs the kill line (K3, K4); a caught signal is neither
# ignored (K6) nor, for K9, pending anywhere (K7, K8).
_EXCLUSIVE = {("K3", "K4"), ("K6", "K9"), ("K7", "K9"), ("K7p", "K9"), ("K8", "K9"), ("K8p", "K9")}


def _met(*classes: str) -> dict:
    record = _canned()
    for c in reversed(classes):  # the upper class last, so it is the one surely met
        _MEETS[c](record)
    return record


def classifier_rows() -> list[tuple[str, bool, str]]:
    """W16: the ordered list of classes, on canned records only (no timing)."""
    order = list(_MEETS)
    checks = [(c, (c,), c[:2]) for c in order] + [("K10", (), "K10")]
    # Every pair of rows a record can meet together, neighbours or not, must print the upper row.
    checks += [(f"{a}+{b}", (a, b), a[:2]) for i, a in enumerate(order) for b in order[i + 1:]
               if a[:2] != b[:2] and (a, b) not in _EXCLUSIVE]
    wrong = []
    for name, classes, want in checks:
        got = classify_hang(_met(*classes))
        if got != want:
            wrong.append(f"{name}: {got}, want {want}")
    out = [("W16 each class row, and each pair of rows met together, prints the upper class",
            not wrong, f"{len(wrong)} of {len(checks)} wrong: " + "; ".join(wrong))]
    # Facts that must select nothing: a stopped process that is only a member of the wrapper's group, and a signal
    # that is only blocked.
    quiet = _canned()
    _role(quiet, "group").update(state="T")
    quiet["R6"]["wrapper"].update(blk=_bit("INT"))
    quiet["R6"]["command"].update(blk=_bit("TERM"))
    got = classify_hang(quiet)
    out.append(("W16 a stopped group member and a blocked signal select nothing", got == "K10", f"got {got}"))
    # A process that has exited is a complete R6 answer, not a missing one, and its sets are n/a: a dead wrapper whose
    # last sets ignored and held the signal, beside a dead command that held TERM, is neither K0 nor K6 to K9.
    gone = _canned()
    sig = _bit(gone["signal"])
    gone["R6"]["wrapper"].update(identity="dead", ign=sig, pnd=sig, cgt=sig)
    gone["R6"]["command"].update(identity="dead", pnd=_bit("TERM"))
    got = classify_hang(gone)
    out.append(("W16 dead processes are an answer: not K0, and their sets select nothing", got == "K10", f"got {got}"))
    # K9 needs the wrapper to hold nothing pending, not merely not the signal sent.
    other = _met("K9")
    other["R6"]["wrapper"].update(shd=_bit("CHLD"))
    got = classify_hang(other)
    out.append(("W16 a caught signal beside another pending one is not K9", got == "K10", f"got {got}"))
    # The K0 forms: a fact missing, R6 missing on Linux, the wrapper's or the command's identity not confirmed.
    k0 = []
    for fact in ("R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"):
        r = _canned()
        r[fact] = None
        k0.append((fact + " missing", r))
    for who in ("wrapper", "command"):
        r = _canned()
        r["R6"][who] = {"identity": "not confirmed"}
        k0.append((who + " identity not confirmed", r))
    bad = [f"{n}: {got}" for n, r in k0 if (got := classify_hang(r)) != "K0"]
    out.append(("W16 every K0 form prints K0", not bad, "; ".join(bad)))
    # Off Linux R6 is n/a: K0 to K5 are still told apart, rows 7 to 10 are one answer.
    off = []
    for c, want in (("K5", "K5"), (None, "K6 to K9, not separable here")):
        r = _met(c) if c else _canned()
        r.update(linux=False, R6=None)
        if (got := classify_hang(r)) != want:
            off.append(f"{c or 'none'}: {got}, want {want}")
    out.append(("W16 off Linux: R6 n/a is not K0, and K6 to K9 are one answer", not off, "; ".join(off)))
    return out


def summary(results: list[tuple[str, bool, str]]) -> str:
    """The script's last line: the count of wrong rows, then each one's label and detail (cut to 200 characters, ending
    "..." when cut). A caller that keeps only the tail of the output (the kit's cheap stage keeps 12 lines) still learns
    which row failed and what it saw."""
    wrong = []
    for label, ok, detail in results:
        if not ok:
            flat = " ".join(detail.split())
            seen = flat if len(flat) <= 200 else flat[:197] + "..."
            wrong.append(f"{label} [{seen}]" if seen else label)
    return f"with-memory-log rows: {len(wrong)} wrong" + (": " + " | ".join(wrong) if wrong else "")


def main() -> int:
    if not WRAPPER.is_file():
        print(f"WRONG {WRAPPER.relative_to(ROOT)} is missing")
        return 1
    results = rows()
    for label, ok, detail in results:
        print(f"{'ok   ' if ok else 'WRONG'} {label}" + ("" if ok else f"\n      {detail!r}"))
    print(summary(results))
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
