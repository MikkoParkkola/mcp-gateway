#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""obtain-lib: take a macOS lib test binary that another job of this run built (option E).

  obtain_lib.py <leg> <dest>    leg: lib-b | int; dest: the folder the binary is downloaded into

Polls this run's artifacts and jobs every 20 s. The first producer of the leg (PRODUCERS, in order) whose artifact is
present is downloaded into <dest> (emptied first), made executable, checked to be an arm64 Mach-O, and listed under a
120 s timeout; a failed download, wrong architecture, failed or empty list drops that producer. Writes found,
producer, reason (found | none-left | deadline | misconfigured), local_build (int: true only on none-left before
LOCAL_BUILD_BY), tests, list and binary (the downloaded file) to GITHUB_OUTPUT, and one summary line. Every deadline
is epoch seconds from JOB_START, the job's first step's `date +%s`. The producers' conclusions are never read: a
completed producer without its artifact after one re-read is absent, whatever its conclusion.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

MIN = 60
# Producer -> (job name in this run, artifact name).
JOBS = {"xbuild": ("macOS lib test binary (cross-built)", "macos-lib-xbuild"),
        "lib-b": ("macOS shard lib-b", "macos-lib-tests")}
# Leg -> producers, in preference order.
PRODUCERS = {"lib-b": ["xbuild"], "int": ["xbuild", "lib-b"]}
GRACE = 10 * MIN                                       # a queued or absent producer, from JOB_START
# A running producer, from its own started_at: the Intel job's timeout; lib-b's wait (75), build (120), upload (5)
# and int's download (3).
RUN_LIMIT = {"xbuild": 65 * MIN, "lib-b": (75 + 120 + 5 + 3) * MIN}
CAP = {"lib-b": 75 * MIN, "int": 210 * MIN}            # the leg's wait, from JOB_START (255 less the later steps)
LOCAL_BUILD_BY = 100 * MIN                             # int builds lib-a itself only on none-left before this
REREAD = 60                                            # a completed producer is re-read once after this
# Every poll costs 2-3 REST calls on the repository's shared GITHUB_TOKEN budget (1000 an hour): 30 s keeps a lib-b
# wait of 45 min near 180 calls.
POLL = 30
FETCH_TRIES = 3                                        # a producer whose artifact is there is dropped after 3 failures
ARM64_MACHO = bytes.fromhex("cffaedfe0c000001")        # MH_MAGIC_64, CPU_TYPE_ARM64, little-endian


class Misconfigured(Exception):
    """A 401, 403 or 404 on this run's own endpoints: the step itself is wrong, so retrying cannot help."""


def gh_json(path: str, run=subprocess.run):
    """One `gh api` call, parsed. 401, 404 and a 403 that is not a rate limit raise Misconfigured; anything else,
    rate limits included (GitHub answers them 403 or 429), raises RuntimeError, which the poll retries."""
    p = run(["gh", "api", path], capture_output=True, text=True)
    if p.returncode:
        err = p.stderr.strip()[:300]
        denied = "HTTP 403" in err and "rate limit" not in err.lower()
        if denied or "HTTP 401" in err or "HTTP 404" in err:
            raise Misconfigured(f"gh api {path.split('?')[0]}: {err}")
        raise RuntimeError(f"gh api {path.split('?')[0]} exited {p.returncode}: {err}")
    return json.loads(p.stdout)


def fetch(producer: str, dest: str, repo: str, run_id: str, run=subprocess.run):
    """Download and check one producer's binary. Returns (binary, tests, list sha256) or raises RuntimeError."""
    artifact = JOBS[producer][1]
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest)
    p = run(["gh", "run", "download", run_id, "--repo", repo, "-n", artifact, "-D", dest],
            capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"download of {artifact} failed: {p.stderr.strip()[:200]}")
    files = [os.path.join(dest, f) for f in os.listdir(dest) if os.path.isfile(os.path.join(dest, f))]
    if len(files) != 1:
        raise RuntimeError(f"{artifact} holds {len(files)} files, not one binary")
    binary = files[0]
    with open(binary, "rb") as f:
        if f.read(8) != ARM64_MACHO:
            raise RuntimeError(f"{artifact} is not an arm64 Mach-O")
    os.chmod(binary, 0o755)
    try:
        p = run([binary, "--list", "--format", "terse"], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{artifact}: --list ran past 120 s")
    tests = [line for line in p.stdout.splitlines() if line.endswith(": test")]
    if p.returncode or not tests:
        raise RuntimeError(f"{artifact}: --list exited {p.returncode} with {len(tests)} tests")
    return binary, len(tests), hashlib.sha256("\n".join(tests).encode()).hexdigest()


def epoch(stamp):
    """GitHub's ISO time as epoch seconds; None for a job not started."""
    if not stamp:
        return None
    from datetime import datetime
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()


def snapshot(repo: str, run_id: str, attempt: str, artifacts: list, gh=gh_json):
    """(those of `artifacts` present in this run, {job name: (status, started_at epoch)} for this attempt). Each
    artifact is asked for by name; a jobs page shorter than the attempt's job count raises RuntimeError (retried), so
    a producer past the first page never reads as absent (a train's attempt held 68 jobs on 2026-11-16)."""
    names = set()
    for artifact in artifacts:
        arts = gh(f"repos/{repo}/actions/runs/{run_id}/artifacts?name={artifact}")
        names |= {a["name"] for a in arts.get("artifacts", []) if a.get("name") == artifact and not a.get("expired")}
    jobs = gh(f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    listed = jobs.get("jobs", [])
    if jobs.get("total_count", 0) > len(listed):
        raise RuntimeError(f"jobs page holds {len(listed)} of {jobs.get('total_count')} jobs")
    return names, {j["name"]: (j.get("status"), epoch(j.get("started_at"))) for j in listed}


def skipped(mode: str, leg: str) -> set:
    """The producers a dispatch rehearsal (MACOS_LIB_REHEARSE_FALLBACK) skips for this leg; an unknown mode raises."""
    return {"none": set(), "xbuild": {"xbuild"}, "all": set(JOBS),
            "compare": {"xbuild"} if leg == "lib-b" else set()}[mode]


def result(leg: str, producer, reason: str, waited: float, tests: int = 0, sha: str = "", why: str = "",
           binary: str = "") -> dict:
    local = leg == "int" and reason == "none-left" and waited < LOCAL_BUILD_BY
    return {"found": "true" if producer else "false", "producer": producer or "none", "reason": reason,
            "local_build": "true" if local else "false", "tests": str(tests), "list": sha, "binary": binary,
            "waited": str(int(waited)), "why": why}


def obtain(leg: str, producers: list, job_start: float, look, get, clock, sleep, warn=print) -> dict:
    """The poll loop. look() gives snapshot(); get(producer) gives fetch()'s triple or raises RuntimeError."""
    alive, done_at, failed = list(producers), {}, {}
    while True:
        now = clock()
        if now - job_start >= CAP[leg]:
            return result(leg, None, "deadline", now - job_start)
        try:
            names, state = look()
        except Misconfigured as e:
            return result(leg, None, "misconfigured", now - job_start, why=str(e))
        except (RuntimeError, OSError, ValueError, KeyError) as e:
            warn(f"::warning::obtain-lib: {e}; polling again")
            sleep(POLL)
            continue
        for p in list(alive):
            job, artifact = JOBS[p]
            if artifact in names:
                try:
                    binary, tests, sha = get(p)
                    return result(leg, p, "found", clock() - job_start, tests, sha, binary=binary)
                except (RuntimeError, OSError) as e:
                    # A download can fail once and work on the next poll; a wrong binary fails every time.
                    failed[p] = failed.get(p, 0) + 1
                    warn(f"::warning::obtain-lib: {p} fetch failed ({failed[p]} of {FETCH_TRIES}): {e}")
                    if failed[p] >= FETCH_TRIES:
                        alive.remove(p)
                    continue
            status, started = state.get(job, (None, None))
            if status == "completed":
                if now - done_at.setdefault(p, now) >= REREAD:
                    alive.remove(p)
            elif status == "in_progress":
                if started is not None and now - started >= RUN_LIMIT[p]:
                    alive.remove(p)
            elif now - job_start >= GRACE:
                alive.remove(p)
        if not alive:
            return result(leg, None, "none-left", now - job_start)
        sleep(POLL)


def write(out: dict, leg: str) -> None:
    """GITHUB_OUTPUT keys and the fixed summary line."""
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write("".join(f"{k}={out[k]}\n" for k in ("found", "producer", "reason", "local_build", "tests", "list",
                                                    "binary")))
    line = (f"obtain-lib: leg={leg} producer={out['producer']} reason={out['reason']} waited={out['waited']} "
            f"tests={out['tests']} list={out['list']}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(line + "\n")
    print(line if out["found"] == "true" else f"::warning::{line} {out['why']}".rstrip())


def main(argv: list) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) != 3 or argv[1] not in PRODUCERS:
        print(__doc__, file=sys.stderr)
        return 2
    leg, dest = argv[1], argv[2]
    repo, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    attempt, job_start = os.environ.get("GITHUB_RUN_ATTEMPT", "1"), float(os.environ["JOB_START"])
    mode = os.environ.get("MACOS_LIB_REHEARSE_FALLBACK", "none")
    # Rehearsal (dispatch): xbuild skips the cross-built producer; all skips every producer; compare has lib-b build
    # natively, so int can fetch both binaries and compare their lists.
    producers = [p for p in PRODUCERS[leg] if p not in skipped(mode, leg)]

    def look(ps):
        return lambda: snapshot(repo, run_id, attempt, [JOBS[p][1] for p in ps])
    if mode == "compare" and leg == "int":
        # Both binaries (xbuild's into dest, lib-b's beside it); their lists must match; non-advisory.
        where = {"xbuild": dest, "lib-b": f"{dest}-native"}
        got = {p: obtain(leg, [p], job_start, look([p]), lambda q: fetch(q, where[q], repo, run_id), time.time,
                         time.sleep)
               for p in PRODUCERS[leg]}
        shas = {p: o["list"] for p, o in got.items()}
        print(f"obtain-lib compare: {shas}")
        if len(set(shas.values())) != 1 or any(o["found"] != "true" for o in got.values()):
            print("::error::obtain-lib compare: the cross-built and native lists differ or one is missing")
            return 1
        write(got["xbuild"], leg)
        return 0
    out = obtain(leg, producers, job_start, look(producers), lambda p: fetch(p, dest, repo, run_id), time.time,
                 time.sleep)
    write(out, leg)
    return 0


def self_test() -> int:
    """Rows on a fake epoch clock (design section 8 and the r3 final amendment)."""
    import tempfile
    t0 = 1_000_000.0
    xb, lb = JOBS["xbuild"], JOBS["lib-b"]

    def case(leg, scenario, get=None, producers=None):
        t = [t0]
        return obtain(leg, PRODUCERS[leg] if producers is None else producers, t0, lambda: scenario(t[0] - t0),
                      get or (lambda p: ("bin", 7, f"sha-{p}")), lambda: t[0],
                      lambda s: t.__setitem__(0, t[0] + s), warn=lambda m: None)

    def snap(arts=(), x=None, b=None):  # x, b: (status, started minutes after JOB_START) for xbuild, lib-b
        jobs = {n: (s, t0 + m * MIN) for n, sm in ((xb[0], x), (lb[0], b)) if sm for s, m in [sm]}
        return set(arts), jobs

    rows = 0

    def check(name, got, **want):
        nonlocal rows
        bad = {k: (got[k], v) for k, v in want.items() if got[k] != v}
        assert not bad, f"{name}: {bad}"
        rows += 1

    check("present first", case("lib-b", lambda s: snap([xb[1]], x=("in_progress", 0))),
          producer="xbuild", reason="found", waited="0", binary="bin")
    check("first done without artifact, second found",
          case("int", lambda s: snap([lb[1]] if s >= 300 else [], x=("completed", 0), b=("in_progress", 0))),
          producer="lib-b", reason="found", waited="300")
    check("both absent", case("int", lambda s: snap()), reason="none-left", waited="600", local_build="true")
    check("deadline while running", case("lib-b", lambda s: snap(x=("in_progress", 20))),
          reason="deadline", waited="4500", found="false", local_build="false")

    def denied(s):
        raise Misconfigured("HTTP 401")
    check("401 fails fast", case("int", denied), reason="misconfigured", waited="0")
    calls = [0]

    def blip(s):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("HTTP 502")
        return snap([xb[1]], x=("completed", 0))
    check("transient then success", case("lib-b", blip), producer="xbuild", waited="30")

    def bad_xbuild(p):
        if p == "xbuild":
            raise RuntimeError("download failed")
        return "bin", 7, "sha-lib-b"
    check("a failed fetch falls through", case("int", lambda s: snap([xb[1], lb[1]], x=("completed", 0),
                                                                      b=("completed", 0)), get=bad_xbuild),
          producer="lib-b")
    check("artifact 30 s after completion", case("lib-b", lambda s: snap([xb[1]] if s >= 30 else [],
                                                                         x=("completed", 0))),
          producer="xbuild", waited="30")
    # A download that fails twice is tried again; the third failure drops the producer.
    tries = [0]

    def flaky(p):
        tries[0] += 1
        if tries[0] < 3:
            raise RuntimeError("download failed")
        return "bin", 7, "sha-xbuild"
    check("download fails twice, then works", case("lib-b", lambda s: snap([xb[1]], x=("completed", 0)), get=flaky),
          producer="xbuild", waited="60")

    def broken(p):
        raise RuntimeError("not an arm64 Mach-O")
    check("third failed fetch drops the producer", case("lib-b", lambda s: snap([xb[1]], x=("completed", 0)),
                                                        get=broken), reason="none-left", waited="60")
    # gh_json: rate limits (403 or 429) are retried; a plain 403, 401 or 404 is a misconfigured step.
    for err, kind in [("HTTP 403: API rate limit exceeded for installation", RuntimeError),
                      ("HTTP 403: You have exceeded a secondary rate limit", RuntimeError),
                      ("HTTP 429: Too Many Requests", RuntimeError), ("HTTP 502: Bad Gateway", RuntimeError),
                      ("HTTP 403: Resource not accessible by integration", Misconfigured),
                      ("HTTP 401: Bad credentials", Misconfigured), ("HTTP 404: Not Found", Misconfigured)]:
        try:
            gh_json("repos/o/r/x", run=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", err))
        except Exception as e:  # noqa: BLE001 - the row checks which class
            assert type(e) is kind, f"{err}: {type(e).__name__}, want {kind.__name__}"
            rows += 1
        else:
            raise AssertionError(f"{err} returned")
    # snapshot: each artifact asked for by name; a short jobs page raises (retried), never reads as absent.
    asked = []

    def fake_gh(path, total=2):
        asked.append(path)
        if "/artifacts?" in path:
            return {"artifacts": [{"name": path.split("name=")[1]}, {"name": "other"}]}
        return {"total_count": total, "jobs": [{"name": xb[0], "status": "queued"}, {"name": lb[0]}]}
    names, jobs = snapshot("o/r", "9", "1", ["macos-lib-xbuild"], gh=fake_gh)
    assert names == {"macos-lib-xbuild"} and set(jobs) == {xb[0], lb[0]}, (names, jobs)
    assert asked[0] == "repos/o/r/actions/runs/9/artifacts?name=macos-lib-xbuild", asked
    try:
        snapshot("o/r", "9", "1", [], gh=lambda p: fake_gh(p, total=101))
    except RuntimeError:
        rows += 2
    else:
        raise AssertionError("a truncated jobs page was accepted")
    check("queued past grace", case("lib-b", lambda s: snap(x=("queued", 0))), reason="none-left", waited="600")
    check("int waits for a running lib-b past 100 min, no local build",
          case("int", lambda s: snap(b=("in_progress", 0) if s < 9000 else ("completed", 0))),
          reason="none-left", waited="9060", local_build="false")
    check("rehearsal all: nothing to wait for", case("int", lambda s: snap(), producers=[]),
          reason="none-left", waited="0", local_build="true")
    # int waits for a running lib-b until lib-b's start + 203 min (12180 s): lib-b's 75-min wait, 120-min build,
    # 5-min upload and int's 3-min download. Literal seconds: a row built from RUN_LIMIT passes with any value.
    check("lib-b dropped at its start + 203 min, not before",
          case("int", lambda s: snap(x=("completed", 0), b=("in_progress", 0))),
          reason="none-left", waited="12180", local_build="false")
    # Rehearsal skips: compare has lib-b build natively and leaves int both producers.
    assert skipped("none", "int") == set() and skipped("xbuild", "int") == {"xbuild"}
    assert skipped("all", "int") == {"xbuild", "lib-b"}
    assert skipped("compare", "lib-b") == {"xbuild"} and skipped("compare", "int") == set()
    try:
        skipped("true", "int")  # the old boolean input's value
    except KeyError:
        rows += 1
    else:
        raise AssertionError("an unknown rehearsal mode was accepted")

    # fetch(): the download argv, an emptied dest, the architecture, the list.
    with tempfile.TemporaryDirectory() as d:
        dest = os.path.join(d, "lib")

        def fake(content=ARM64_MACHO + b"x", dl_rc=0, list_rc=0, listing="a: test\nb: test\n", log=None):
            def run(argv, **kw):
                if log is not None:
                    log.append(argv)
                if argv[:3] == ["gh", "run", "download"]:
                    if not dl_rc:
                        with open(os.path.join(argv[argv.index("-D") + 1], "lib-bin"), "wb") as f:
                            f.write(content)
                    return subprocess.CompletedProcess(argv, dl_rc, "", "boom" if dl_rc else "")
                return subprocess.CompletedProcess(argv, list_rc, listing, "")
            return run
        os.makedirs(dest)
        open(os.path.join(dest, "stale"), "w").close()
        log = []
        _, n, _ = fetch("xbuild", dest, "o/r", "77", run=fake(log=log))
        assert n == 2 and os.listdir(dest) == ["lib-bin"], (n, os.listdir(dest))
        assert log[0] == ["gh", "run", "download", "77", "--repo", "o/r", "-n", "macos-lib-xbuild", "-D", dest], log
        rows += 1
        for name, kw in [("download failure", {"dl_rc": 1}), ("wrong architecture", {"content": b"\x7fELF" * 2}),
                         ("failed list", {"list_rc": 1}), ("empty list", {"listing": ""})]:
            try:
                fetch("xbuild", dest, "o/r", "77", run=fake(**kw))
            except RuntimeError:
                rows += 1
                continue
            raise AssertionError(f"{name} was accepted")
    print(f"obtain-lib self-test: {rows} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
