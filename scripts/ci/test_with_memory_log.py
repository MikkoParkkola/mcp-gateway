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
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NamedTuple

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


class W4Files(NamedTuple):
    """The files a W4 run's shells write: the marker (sleeper's pid, command's pid), R5, R2 before and after, R3."""
    marker: Path
    wrapper: Path
    pre: Path
    post: Path
    trap: Path


LINUX = sys.platform.startswith("linux")


def run_w4(cmd: str, env: dict[str, str], sig: str, files: W4Files,
           timeout: float = 60) -> tuple[int, str, str, float, dict | None]:
    """run() for W4, holding the outer shell itself: on a hang the record is taken before anything is killed (the
    outer shell's state at the limit needs the process; run() cannot give it). Then, as run() does, only the outer
    shell is killed: nothing the row did not start is signalled, and the leftovers end with the command's sleep."""
    clock = Clock()
    load_start = real_load()
    start = time.monotonic()
    p = subprocess.Popen(["bash", "-c", cmd], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
    try:
        so, se = p.communicate(timeout=timeout)
        return p.returncode, so.decode(errors="replace"), se.decode(errors="replace"), time.monotonic() - start, None
    except subprocess.TimeoutExpired as e:
        record = hang_record(sig, files, p, clock, load_start, e.stdout, e.stderr)
        # Printed at once, above the summary, so a later crash or a cancelled run still keeps it.
        print(f"W4 hang record, class {classify_hang(record)}: {json.dumps(record, sort_keys=True)}", flush=True)
        p.kill()
        p.wait()
        for pipe in (p.stdout, p.stderr):
            pipe.close()
        return -1, "", f"HUNG past {timeout} s", time.monotonic() - start, record


def real_load() -> float | None:
    """The host's 1-minute load: the real /proc/loadavg (never the rows' stub), or the OS's figure off Linux."""
    with contextlib.suppress(OSError, ValueError, IndexError):
        return float(Path("/proc/loadavg").read_text().split()[0]) if LINUX else os.getloadavg()[0]
    return None


class Clock:
    """The row's start on the system's time since boot, in clock ticks (the unit /proc gives a start time in), and
    the one offset that puts a file's wall-clock time on that same clock (D2)."""
    def __init__(self) -> None:
        self.tick = os.sysconf("SC_CLK_TCK")
        self.wall = time.time()
        boot = time.clock_gettime(time.CLOCK_BOOTTIME) if LINUX else 0.0
        self.offset = self.wall - boot
        self.start_ticks = boot * self.tick

    def ticks_at(self, path: Path) -> float | None:
        with contextlib.suppress(OSError):
            return (path.stat().st_mtime - self.offset) * self.tick
        return None

    def since_start(self, path: Path) -> float | None:
        with contextlib.suppress(OSError):
            return round(path.stat().st_mtime - self.wall, 3)
        return None


def _mask(status: str, key: str) -> int:
    line = next(l for l in status.splitlines() if l.startswith(key + ":"))
    return int(line.split()[1], 16)


def _exited(handle: int) -> bool:
    """A pidfd reads as ready once its process has exited."""
    poll = select.poll()
    poll.register(handle, select.POLLIN)
    return bool(poll.poll(0))


def bound_read(pid: int, parents: set[int], low: float, high: float, held: dict[int, int]) -> dict:
    """R6 for one pid, kept only if it names the row's own process (Linux). A handle that names this one process is
    taken first; the facts are read; then the handle says whether that process is still the same live one. Its start
    time must lie between the row's start and the moment its pid was written (one tick either way), and its parent
    must be one of `parents`. A process gone is "dead", a complete answer; anything else is "not confirmed". A
    confirmed pid's handle is left open in `held`, so the caller can ask again after reading R7; the caller closes it."""
    try:
        handle = os.pidfd_open(pid)
    except ProcessLookupError:
        return {"identity": "dead"}
    except OSError:
        return {"identity": "not confirmed"}
    try:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            status = Path(f"/proc/{pid}/status").read_text()
        except OSError:
            stat = status = None
        if _exited(handle):
            return {"identity": "dead"}
        if stat is None or status is None:  # alive, but its facts could not be read
            return {"identity": "not confirmed"}
        fields = stat.rsplit(")", 1)[1].split()  # after the name: state, ppid, pgrp, ...; starttime is field 22
        state, ppid, started = fields[0], int(fields[1]), int(fields[19])
        if not (low - 1 <= started <= high + 1) or ppid not in parents:
            return {"identity": "not confirmed"}
        held[pid] = handle
        return {"identity": "confirmed", "state": state,
                **{k: _mask(status, f) for k, f in (("ign", "SigIgn"), ("cgt", "SigCgt"), ("blk", "SigBlk"),
                                                     ("pnd", "SigPnd"), ("shd", "ShdPnd"))}}
    finally:
        if held.get(pid) != handle:
            os.close(handle)


def orphan_adopter(excluded: set[int | None]) -> int | None:
    """The process that adopts this row's orphans, measured (D3): a short sleep whose shell has exited, read for its
    new parent. It shares the row's ancestry, and no shell between is a subreaper, so the row's orphans go there too.
    Never one of `excluded` (this Python and the pids the run itself started): those give None."""
    with contextlib.suppress(OSError, ValueError, IndexError):
        sh = subprocess.run(["sh", "-c", "sleep 2 >/dev/null 2>&1 & echo $!"], capture_output=True, text=True)
        orphan = int(sh.stdout.split()[0])
        adopter = int(Path(f"/proc/{orphan}/stat").read_text().rsplit(")", 1)[1].split()[1])
        return None if adopter in excluded | {os.getpid()} else adopter
    return None


def _pids(path: Path) -> list[int] | None:
    with contextlib.suppress(OSError, ValueError):
        return [int(x) for x in path.read_text().split()]
    return None


def _ps() -> str | None:
    """One ps snapshot for R7: pid, parent, group, state, elapsed time and program name. Never a process's
    arguments. None when ps failed or could not be started at all, so either is a missing R7."""
    try:
        ps = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid=,stat=,etime=,comm="],
                            capture_output=True, text=True)
    except OSError:
        return None
    return ps.stdout if ps.returncode == 0 else None


def _select(ps: str | None, roles: dict[int, str], wrapper: int | None, group_private: bool, group: int | None,
            refused: set[int]) -> list[dict] | None:
    """R7 from one ps snapshot: the named pids, every descendant of the wrapper, and, only when the wrapper's group
    is the row's own, every other member of that group. A pid in `refused` (one whose identity was not confirmed, or
    whose process is gone and whose number may be reused) is never listed, by any route. None when ps gave no table:
    a missing R7, not an empty one."""
    if ps is None:
        return None
    table = {}
    for line in ps.splitlines():
        f = line.split(None, 5)
        if len(f) == 6:
            table[int(f[0])] = {"pid": int(f[0]), "ppid": int(f[1]), "pgid": int(f[2]), "state": f[3],
                                "etime": f[4], "comm": f[5]}
    if not table:
        return None
    found = {pid: role for pid, role in roles.items() if pid not in refused}
    if wrapper is not None:
        # Walked apart from the roles: a named command or sleeper is walked through, keeping its role.
        visited, frontier = {wrapper}, [wrapper]
        while frontier:
            parent = frontier.pop()
            for pid, row in table.items():
                if row["ppid"] == parent and pid not in visited and pid not in refused:
                    visited.add(pid)
                    found.setdefault(pid, "descendant")
                    frontier.append(pid)
    if group_private and group is not None:
        for pid, row in table.items():
            if row["pgid"] == group and pid not in refused:
                found.setdefault(pid, "group")
    return [dict(table[pid], role=role) for pid, role in sorted(found.items()) if pid in table]


def hang_record(sig: str, files: W4Files, outer: subprocess.Popen, clock: Clock, load_start: float | None,
                stdout: bytes | None, stderr: bytes | None) -> dict:
    """The facts R1 to R9 of a W4 hang, read before anything is killed and only read: nothing is signalled."""
    outer_rc = outer.poll()
    marker = _pids(files.marker)
    written = bool(marker)
    sleeper, command = (marker + [None, None])[:2] if written else (None, None)
    r5 = None
    with contextlib.suppress(OSError, ValueError, IndexError):
        parts = files.wrapper.read_text().split()
        wrapper_pid = int(parts[0])
        # The stat line read by the outer shell: after "(name)", state then ppid then pgrp.
        tail = files.wrapper.read_text().rsplit(")", 1)
        group = int(tail[1].split()[2]) if len(tail) == 2 else None
        r5 = {"pid": wrapper_pid, "group": group}
    post = (_pids(files.post) or [None])[0]  # an empty file: kill's status not yet written
    reached = files.pre.exists()
    r2 = {"reached": reached, "status": post} if (not reached or post is not None) else None
    record = {
        "signal": sig, "linux": LINUX,
        "R1": {"written": written, "child": sleeper, "command": command},
        "R2": r2,
        "R3": {"trap_ran": files.trap.exists()},
        "R4": {"running": outer_rc is None, "status": outer_rc},
        "R5": r5,
        "R6": None,
        "R8": {"stdout": (stdout or b"").decode(errors="replace"), "stderr": (stderr or b"").decode(errors="replace")},
        "R9": {"load_start": load_start, "load_limit": real_load(), "to_marker": clock.since_start(files.marker),
               "to_kill": clock.since_start(files.pre)},
    }
    wrapper = r5["pid"] if r5 else None
    roles = {pid: role for pid, role in ((wrapper, "wrapper"), (command, "command"), (sleeper, "sleeper")) if pid}
    if LINUX and r5:
        adopter = orphan_adopter({outer.pid, wrapper, command, sleeper})
        adopters = {adopter} if adopter is not None else set()
        low = clock.start_ticks
        held: dict[int, int] = {}
        try:
            w = bound_read(wrapper, {outer.pid} | (adopters if outer_rc is not None else set()), low,
                           clock.ticks_at(files.wrapper) or low, held)
            c = {"identity": "dead"} if command is None else bound_read(
                command, {wrapper} | (adopters if w["identity"] == "dead" else set()), low,
                clock.ticks_at(files.marker) or low, held)
            s = {"identity": "dead"} if sleeper is None else bound_read(
                sleeper, {command} | (adopters if c["identity"] == "dead" else set()), low,
                clock.ticks_at(files.marker) or low, held)
            ps = _ps()
            # A confirmed process that has exited by now may have lost its number to another process before the
            # snapshot: its number is dropped from R7. One still alive here was alive throughout the snapshot.
            gone = sorted(pid for pid, handle in held.items() if _exited(handle))
        finally:
            for handle in held.values():
                os.close(handle)
        record["R6"] = {"wrapper": w, "command": c}
        record["adopter"] = adopter
        if gone:
            # Checked once the snapshot is taken: these exited before, during or just after it.
            record["gone_at_recheck"] = gone
        # No fact is kept from a pid whose identity is not confirmed, nor from a dead one's number, which the system
        # may already have handed to another process.
        refused = set(gone)
        for pid, seen in ((wrapper, w), (command, c), (sleeper, s)):
            if pid and seen["identity"] != "confirmed":
                refused.add(pid)
                if seen["identity"] == "not confirmed":
                    record.setdefault("not_confirmed", []).append(pid)
        record["R7"] = _select(ps, roles, wrapper if wrapper not in refused else None,
                               r5["group"] == wrapper, r5["group"], refused)
    else:
        record["R7"] = _select(_ps(), roles, wrapper, bool(r5) and r5["group"] == wrapper,
                               r5["group"] if r5 else None, set())
    return record


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
        # The marker holds the sleeper's pid and the command's own. For a hang's record (hang_record) the shells also
        # write four small files, by redirection only (no process): the wrapper's pid and /proc stat line just after
        # the launch (R5), one file just before the kill and one after it holding kill's status (R2), and one as the
        # command's trap starts (R3).
        for sig in ("TERM", "INT", "HUP"):
            marker = tmp / f"child-{sig}"
            files = W4Files(marker, *(tmp / f"w4-{sig}-{n}" for n in ("wrapper", "pre", "post", "trap")))
            cmd = (f"set -m; {w} bash -c 'sleep 120 & c=$!; trap \": > {files.trap}; kill $c; wait $c; exit 42\" TERM; "
                   f"echo $c $$ > {marker}; wait $c' "
                   f"& wp=$!; st=; read -r st 2>/dev/null < /proc/$wp/stat; echo \"$wp $st\" > {files.wrapper}; "
                   f"while [ ! -s {marker} ]; do kill -0 $wp 2>/dev/null || break; sleep 0.1; done; "
                   f": > {files.pre}; kill -{sig} $wp; echo $? > {files.post}; wait $wp")
            rc, so, se, t, record = run_w4(cmd, env, sig, files)
            child = marker.read_text().split()[0] if marker.exists() and marker.read_text().split() else ""
            gone = bool(child) and subprocess.run(["kill", "-0", child], capture_output=True).returncode != 0
            hung = f", class {classify_hang(record)}" if record else ""
            out.append((f"W4 {sig} reaches the command as TERM: exit 42, child gone", rc == 42 and gone,
                        f"rc {rc}, {t:.1f}s, child {'gone' if gone else 'still there or never written'}{hung}, "
                        f"{se[-200:]}"))
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
    out.extend(adopter_rows())
    return out


def adopter_rows() -> list[tuple[str, bool, str]]:
    """W17: the measured adopter of orphans is never a pid the run itself started (D3). Linux only: read from /proc.
    The same measurement is taken twice, the second time with the first answer excluded; it must then give None."""
    label = "W17 the measured orphan adopter is refused when it is one of the run's own pids"
    if not LINUX:
        return [(label, True, "skipped: not Linux")]
    seen = orphan_adopter(set())
    refused = orphan_adopter({seen})
    out = [(label, seen is not None and refused is None, f"measured {seen}, with it excluded {refused}")]
    # This Python is never the adopter, unasked: a child Python that makes itself the adopter of its orphans (Linux
    # prctl 36, the child subreaper flag) must still get None. It prints prctl's status, then the measurement.
    # The child loads this very file by its path, so a changed copy of it is the code the row judges.
    code = ("import ctypes, importlib.util as u, sys; s = u.spec_from_file_location('rows', sys.argv[1]); "
            "t = u.module_from_spec(s); s.loader.exec_module(t); "
            "print(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0), t.orphan_adopter(set()))")
    own = subprocess.run([sys.executable, "-c", code, str(Path(__file__).resolve())],
                         capture_output=True, text=True, timeout=30)
    out.append(("W17 this Python, made the adopter of its own orphans, is refused too", own.stdout.split() == ["0", "None"],
                f"rc {own.returncode}, {own.stdout.strip()!r}, {own.stderr[-200:]}"))
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
            or (record["linux"] and record["R5"]["group"] is None)  # D1: only off Linux is the group n/a
            or (r6 is not None and any(r6[w]["identity"] == "not confirmed" for w in ("wrapper", "command")))
            or _r9_incomplete(record)):
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


def _r9_incomplete(record: dict) -> bool:
    """R9 lacks a fact it must hold: either load, the marker's time when the marker was written, or the kill's time
    when the kill line was reached. A time is n/a only for an event that did not happen."""
    r9 = record["R9"]
    return (r9["load_start"] is None or r9["load_limit"] is None
            or (record["R1"]["written"] and r9["to_marker"] is None)
            or (record["R2"]["reached"] and r9["to_kill"] is None))


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
# ignored (K6) nor, for K9, pending in the wrapper (K7). The command's pending TERM (K8) can sit beside K9's wrapper,
# so that pair is checked: only the order keeps it K8.
_EXCLUSIVE = {("K3", "K4"), ("K6", "K9"), ("K7", "K9"), ("K7p", "K9")}


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
    r = _canned()
    r["R5"]["group"] = None
    k0.append(("R5 group missing on Linux", r))
    # R9's own facts: a load missing, or a time missing for an event that happened.
    for key in ("load_start", "load_limit", "to_marker", "to_kill"):
        r = _canned()
        r["R9"][key] = None
        k0.append(("R9 " + key + " missing", r))
    bad = [f"{n}: {got}" for n, r in k0 if (got := classify_hang(r)) != "K0"]
    out.append(("W16 every K0 form prints K0", not bad, "; ".join(bad)))
    # A time is n/a for an event that did not happen: no marker (K2), no kill line (K3); neither is K0.
    na = []
    for c, key in (("K2", "to_marker"), ("K3", "to_kill")):
        r = _met(c)
        r["R9"][key] = None
        if (got := classify_hang(r)) != c:
            na.append(f"{c} with {key} n/a: {got}")
    out.append(("W16 a time for an event that did not happen may be n/a", not na, "; ".join(na)))
    # R7 on a canned ps table: the walk goes through the named command to its stopped child outside the group (so the
    # record is K1), a lone member of the private group is listed, and a refused pid is listed by no route (as the
    # sleeper, as a descendant, or as a group member). No table at all is a missing R7.
    ps = "\n".join(" ".join(map(str, f)) for f in (
        (1001, 1000, 1001, "S", "00:10", "bash"), (1002, 1001, 1001, "S", "00:10", "bash"),
        (1003, 1002, 1001, "S", "00:10", "sleep"), (1006, 1002, 2000, "T", "00:10", "sleep"),
        (1007, 1, 1001, "S", "00:10", "sh"), (1008, 1002, 1001, "S", "00:10", "sleep"),
        (1009, 1, 1001, "S", "00:10", "sh")))
    listed = _select(ps, {1001: "wrapper", 1002: "command", 1003: "sleeper"}, 1001, True, 1001, {1003, 1008, 1009})
    roles = {p["pid"]: p["role"] for p in listed or []}
    want = {1001: "wrapper", 1002: "command", 1006: "descendant", 1007: "group"}
    stopped = _canned()
    stopped["R7"] = listed
    got = classify_hang(stopped) if listed else None
    out.append(("W16 R7 walks through the command, lists the group, never a refused pid; no table is missing",
                roles == want and got == "K1" and _select("", {}, None, False, None, set()) is None,
                f"roles {roles}, want {want}; class {got}"))
    # Off Linux R6 is n/a: K0 to K5 are still told apart, rows 7 to 10 are one answer.
    off = []
    for c, want in (("K5", "K5"), (None, "K6 to K9, not separable here")):
        r = _met(c) if c else _canned()
        r.update(linux=False, R6=None)
        r["R5"]["group"] = None  # n/a off Linux, never K0 there
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
