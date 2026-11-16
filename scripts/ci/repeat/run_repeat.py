#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Re-run one filtered lib test on the binary CI already built.

The branch is the commit under test plus ONE commit that adds
`.repeat/spec.json`. That commit may also add `.github/workflows/repeat.yml`,
and only when that blob is byte-identical to the release line (a head older
than the workflow lacks it, and the push trigger needs it):

  sha       40-hex parent of this commit (CI must have finished for it)
  filter    libtest filter, 1..200 of [A-Za-z0-9_:]
  runs      how many times to repeat, 1..50
  parallel  copies of each repeat, 1..4
  exact     pass --exact to libtest when true

Modes: `plan` (refuse a bad branch, print the spec, write valid=true),
`fetch --out DIR` (download that sha's linux-lib-tests artifact from the
newest finished CI run for the sha; the binary is kept 1 day), `run
--binary BIN --out DIR` (repeat the filter; compiles nothing),
`--self-test`. Standard library only.

Exit: plan 0 or 2; fetch 0 or 4; run 0 when every repeat passed, 1 when one
failed (including a copy that exited non-zero with no harness summary) or the
run stopped early (incomplete), 3 when a finished run had a repeat that
executed no tests (void, nothing to judge). A finished run prints
`repeat: <passed>/<runs>`. An early stop prints
`repeat: <passed>/<runs> (INCOMPLETE after <k> runs)`.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SPEC_PATH = ".repeat/spec.json"
WORKFLOW_BLOB = ".github/workflows/repeat.yml"
RELEASE_LINE = "docs/ranking-1-release-line"
WORKFLOW_MISMATCH = "repeat.yml differs from the release line; copy it byte-identical"
REF_RE = re.compile(r"^refs/heads/throwaway/repeat-.+")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FILTER_RE = re.compile(r"^[A-Za-z0-9_:]{1,200}$")
KEYS = ("sha", "filter", "runs", "parallel", "exact")
RESULT_RE = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored\b", re.M)
RUNNING_RE = re.compile(r"^running \d+ tests?\b")
TAIL_LINES = 40
COPY_OUTPUT_LINES = 400
COPY_TIMEOUT = 1200
# After a timeout kill, the second read. A setsid grandchild can hold the pipes.
POST_KILL_READ = 10
RUN_BUDGET = 300 * 60
ARTIFACT = "linux-lib-tests"
RUNS_MAX = 50
PARALLEL_MAX = 4


class PlanError(Exception):
    """The branch cannot be repeated; plan exits 2 and writes nothing."""


def git(*args: str) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise PlanError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def prebuilt_shape() -> tuple[list[str], str, str]:
    """Linux lib tail of shard_tests.run_prebuilt: skips, BY_BINARY, LIB_TARGET.

    The checkout under test is never searched. shard_tests.py beside this file
    is tried first: the workflow copies both reviewed files into one directory.
    The repo-layout path, scripts/ci/shard_tests.py two directories up, is used
    only when that sibling is absent (local tests).
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "shard_tests.py",
        here.parent.parent / "shard_tests.py",
    ]
    path = next((c for c in candidates if c.is_file()), None)
    if path is None:
        raise RuntimeError("shard_tests.py is absent")
    spec = importlib.util.spec_from_file_location("shard_tests_repeat", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.SKIPS["linux"]), mod.BY_BINARY, mod.LIB_TARGET


def spec_error(data: object) -> str | None:
    """Why `data` is not a repeat spec, or None. The text names the bad field."""
    if not isinstance(data, dict):
        return "spec must be a JSON object"
    missing = [key for key in KEYS if key not in data]
    if missing:
        return "missing " + ", ".join(missing)
    unknown = [key for key in data if key not in KEYS]
    if unknown:
        return "unknown key " + ", ".join(unknown)
    sha, filt, runs, parallel, exact = (data[key] for key in KEYS)
    if not isinstance(sha, str) or SHA_RE.fullmatch(sha) is None:
        return "sha must be 40 hex characters, the parent commit"
    # A leading dash is a flag, not a test name. Refused on its own so a later
    # widening of the charset cannot start passing options through to libtest.
    if isinstance(filt, str) and filt.startswith("-"):
        return "filter must not start with a dash"
    if not isinstance(filt, str) or FILTER_RE.fullmatch(filt) is None:
        return "filter must be 1..200 characters of letters, digits, underscore or colon"
    if not _count(runs, RUNS_MAX):
        return f"runs must be an integer from 1 to {RUNS_MAX}"
    if not _count(parallel, PARALLEL_MAX):
        return f"parallel must be an integer from 1 to {PARALLEL_MAX}"
    if not isinstance(exact, bool):
        return "exact must be a boolean"
    return None


def _count(value: object, upper: int) -> bool:
    """True for an int in 1..upper. Bool is an int in Python and is rejected."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= upper


def load_spec() -> dict:
    """The spec on this commit, or PlanError.

    The commit adds the spec. It may also add the repeat workflow; plan then
    requires that blob to match the release line. Anything else is refused.
    """
    ref = os.environ.get("GITHUB_REF", "")
    if REF_RE.fullmatch(ref) is None:
        raise PlanError(f"GITHUB_REF must be refs/heads/throwaway/repeat-<name>, got {ref or 'unset'}")
    files = [ln for ln in git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines() if ln]
    extra = [path for path in files if path not in (SPEC_PATH, WORKFLOW_BLOB)]
    if SPEC_PATH not in files:
        raise PlanError(f"spec is absent: {SPEC_PATH}")
    if extra:
        raise PlanError(f"repeat commit must add only {SPEC_PATH}, found " + ", ".join(extra))
    try:
        data = json.loads(git("show", f"HEAD:{SPEC_PATH}"))
    except json.JSONDecodeError:
        raise PlanError("spec must be a JSON object") from None
    error = spec_error(data)
    if error:
        raise PlanError(error)
    parent = git("rev-parse", "HEAD^").strip()
    if data["sha"] != parent:
        raise PlanError("sha is not the parent commit, the commit under test")
    return data


def lib_argv(spec: dict, skips: list[str]) -> list[str]:
    """Positional filter, --exact when asked, then the Linux skips run_prebuilt appends."""
    args = [spec["filter"]]
    if spec["exact"]:
        args.append("--exact")
    args.extend(skips)
    return args


def judge(exit_code: int, text: str) -> tuple[int, str]:
    """(tests_run, kind). tests_run is passed+failed from the harness summary.

    A non-zero exit with no `test result:` summary is a failure: the copy
    crashed, was killed (OOM is 137), or failed to load. Void stays an exit of
    0 with no summary, or a summary that executed nothing (`running 0 tests`).
    A non-zero exit with tests executed is a failure.
    """
    found = list(RESULT_RE.finditer(text))
    if not found:
        if exit_code != 0:
            return 0, "fail"
        return 0, "void"
    status, passed_s, failed_s, _ignored = found[-1].groups()
    tests_run = int(passed_s) + int(failed_s)
    if tests_run == 0:
        return 0, "void"
    if exit_code == 0 and status == "ok" and int(failed_s) == 0:
        return tests_run, "pass"
    return tests_run, "fail"


def failure_tail(text: str) -> str:
    """Last 40 lines of the first failing copy. Long enough to keep the summary."""
    return "\n".join(text.splitlines()[-TAIL_LINES:])


def fetch_release_line() -> None:
    """Fetch the release-line tip into FETCH_HEAD.

    `--depth=1` only when the checkout is already shallow (a CI checkout). In a
    full clone it would shallow the object store, and a local run shares that
    store with every worktree. A fetch that fails because the caller already
    fetched the line is tolerated when that ref still resolves.
    """
    shallow = git("rev-parse", "--is-shallow-repository").strip() == "true"
    depth = ["--depth=1"] if shallow else []
    proc = subprocess.run(
        ["git", "fetch", "--quiet", *depth, "origin", RELEASE_LINE],
        capture_output=True, text=True)
    if proc.returncode == 0:
        return
    ref = os.environ.get("REPEAT_RELEASE_REF", "FETCH_HEAD").strip() or "FETCH_HEAD"
    try:
        git("rev-parse", "--verify", "--quiet", ref)
    except PlanError:
        detail = proc.stderr.strip() or f"git fetch origin {RELEASE_LINE} failed"
        raise PlanError(detail) from None


def release_treeish() -> str:
    """Commit whose repeat.yml is the reviewed copy.

    REPEAT_RELEASE_TREEISH names it directly (tests; no network).
    REPEAT_RELEASE_REF names a ref the caller already fetched (default
    FETCH_HEAD when the variable is unset and this function fetches).
    """
    named = os.environ.get("REPEAT_RELEASE_TREEISH", "").strip()
    if named:
        return named
    if "REPEAT_RELEASE_REF" in os.environ:
        return os.environ["REPEAT_RELEASE_REF"].strip() or "FETCH_HEAD"
    fetch_release_line()
    return "FETCH_HEAD"


def _blob(treeish: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", f"{treeish}:{path}"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def require_reviewed_workflow() -> None:
    """HEAD's repeat.yml must be the release-line blob. A missing file differs."""
    treeish = release_treeish()
    head = _blob("HEAD", WORKFLOW_BLOB)
    reviewed = _blob(treeish, WORKFLOW_BLOB)
    if head is None or reviewed is None or head != reviewed:
        raise PlanError(WORKFLOW_MISMATCH)


def cmd_plan() -> int:
    try:
        spec = load_spec()
        require_reviewed_workflow()
    except PlanError as exc:
        print(exc, file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(spec) + "\n")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write("valid=true\n")
    return 0


def _fetch_die(message: str) -> int:
    """One line, exit 4. gh's own text stays captured so it cannot add a second."""
    print(message, file=sys.stderr)
    return 4


def _env_int(name: str, default: int) -> int:
    """Test override. Unset keeps the module constant."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


def cmd_fetch(out: Path) -> int:
    try:
        spec = load_spec()
    except PlanError as exc:
        return _fetch_die(str(exc))
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    url = f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={spec['sha']}&per_page=20"
    listed = subprocess.run(["gh", "api", url], capture_output=True, text=True)
    if listed.returncode != 0:
        return _fetch_die("no CI run: the run list failed")
    try:
        payload = json.loads(listed.stdout)
    except json.JSONDecodeError:
        return _fetch_die("no CI run: the run list was not JSON")
    runs = payload.get("workflow_runs") or []
    # The list is queried by sha, and still filtered: a run for another sha must not block this one.
    matched = [run for run in runs if isinstance(run, dict) and run.get("head_sha") == spec["sha"]]
    if not matched:
        return _fetch_die("no CI run for this sha")
    newest = max(matched, key=lambda run: (str(run.get("created_at") or ""), int(run.get("id") or 0)))
    # Only the newest run matters. An older finished run is not a substitute for one still going.
    if newest.get("status") != "completed":
        return _fetch_die("CI for this sha is not finished; wait for it to complete")
    out.mkdir(parents=True, exist_ok=True)
    # Conclusion is not required to be success: a red run can still have uploaded the binary.
    # A file already in OUT is from an earlier attempt. Drop it before gh runs so a
    # failed download cannot leave that stale binary looking new.
    binary = out / "lib-tests"
    binary.unlink(missing_ok=True)
    downloaded = subprocess.run(
        ["gh", "run", "download", str(newest["id"]), "--dir", str(out), "--name", ARTIFACT],
        capture_output=True, text=True)
    # Both: gh must exit 0, and lib-tests must be on disk. Either miss is the 1-day window.
    if downloaded.returncode != 0 or not binary.is_file():
        binary.unlink(missing_ok=True)
        return _fetch_die("the lib test binary is kept 1 day and the download failed")
    binary.chmod(0o755)  # an artifact round trip drops the exec bit, as run_prebuilt restores
    (out / "source-run-id.txt").write_text(f"{newest['id']}\n", encoding="utf-8")
    return 0


def _source_run_id(binary: Path) -> str | None:
    """CI run the binary came from. A test may set the env; fetch writes the file beside the binary."""
    chosen = os.environ.get("REPEAT_SOURCE_RUN_ID")
    if chosen is not None and chosen.strip():
        return chosen.strip()
    path = binary.parent / "source-run-id.txt"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    return text or None


def _runner() -> str:
    """Hosted runner identity. RUNNER_NAME, else RUNNER_OS-RUNNER_ARCH, else empty."""
    name = os.environ.get("RUNNER_NAME", "").strip()
    if name:
        return name
    system = os.environ.get("RUNNER_OS", "").strip()
    arch = os.environ.get("RUNNER_ARCH", "").strip()
    if system and arch:
        return f"{system}-{arch}"
    return ""


def _payload(spec: dict, iterations: list[dict], tail: str | None, incomplete: bool, source_id: str | None) -> dict:
    passed = sum(1 for it in iterations if it["result"] == "pass")
    void = sum(1 for it in iterations if it["result"] == "void")
    completed = len(iterations)
    # Denominator is the spec's runs. A partial file must not read as N of N.
    payload = {
        "passed": passed,
        "total": completed,
        "void": void,
        "verdict": f"{passed}/{spec['runs']}",
        "completed": completed,
        "incomplete": incomplete,
        "artifact": ARTIFACT,
        "runner": _runner(),
        "spec": spec,
        "iterations": iterations,
    }
    if source_id is not None:
        payload["source_run_id"] = source_id
    if tail is not None:
        payload["first_failure_tail"] = tail
    return payload


def _write_results(out: Path, payload: dict) -> None:
    """Atomically publish results.json. A killed runner keeps the previous iteration."""
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "results.json"
    tmp = out / ".results.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, dest)


def _write_summary(prior: str, iterations: list[dict], passed: int, spec_runs: int, incomplete: bool) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    done = len(iterations)
    rows = ["| iteration | copies | result |", "| --- | --- | --- |"]
    rows += [f"| {it['n']} | {len(it['copies'])} | {it['result']} |" for it in iterations]
    rows.append("")
    if incomplete:
        rows.append(f"INCOMPLETE: {done} of {spec_runs} runs executed")
    rows.append(f"Verdict: {passed}/{spec_runs}")
    path = Path(summary)
    body = prior + "\n".join(rows) + "\n"
    tmp = path.with_name(path.name + ".repeat-tmp")
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, path)


class _Capture:
    """Last 400 lines plus the harness summary lines. The rest is discarded."""

    def __init__(self) -> None:
        self.tail: deque[str] = deque(maxlen=COPY_OUTPUT_LINES)
        self.result: str | None = None
        self.running: str | None = None
        self.lock = threading.Lock()

    def add_many(self, lines: list[str]) -> None:
        if not lines:
            return
        with self.lock:
            for line in lines:
                if line.startswith("test result:") and RESULT_RE.match(line):
                    self.result = line
                elif line.startswith("running ") and RUNNING_RE.match(line):
                    self.running = line
            self.tail.extend(lines)

    def snapshot(self) -> tuple[list[str], str | None, str | None]:
        with self.lock:
            return list(self.tail), self.result, self.running


def _close_pipes(proc: subprocess.Popen) -> None:
    for stream in (proc.stdout, proc.stderr):
        if stream is None or stream.closed:
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _read_pipe(stream, state: _Capture, stop: threading.Event) -> None:
    """One stream. Line at a time; a stop or a closed pipe ends the read."""
    fd = stream.fileno()
    os.set_blocking(fd, False)
    pending = b""
    eof = False
    while not stop.is_set() and not eof:
        try:
            ready, _, _ = select.select([fd], [], [], 0.2)
        except (OSError, ValueError):
            break
        if not ready:
            continue
        while not stop.is_set():
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                break
            except OSError:
                eof = True
                break
            if not chunk:
                eof = True
                break
            pending += chunk
            *lines, pending = pending.split(b"\n")
            if lines:
                state.add_many([raw.decode("utf-8", "replace").rstrip("\r") for raw in lines])
    if pending:
        state.add_many([pending.decode("utf-8", "replace").rstrip("\r")])


def _join_readers(threads: list[threading.Thread], timeout: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    return all(not thread.is_alive() for thread in threads)


def _as_text(data: str | bytes | None) -> str:
    if not data:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def _fold(state: _Capture, data: str | bytes | None) -> None:
    text = _as_text(data)
    if text:
        state.add_many(text.splitlines())


def _judge_text(lines: list[str], result: str | None, running: str | None) -> str:
    """Tail plus any summary line that scrolled out of it. judge uses the last match."""
    body = list(lines)
    if running and running not in body:
        body.insert(0, running)
    if result:
        matches = [line for line in body if RESULT_RE.match(line)]
        if not matches or matches[-1] != result:
            body.append(result)
    return "\n".join(body)


def _blocking(proc: subprocess.Popen) -> None:
    for stream in (proc.stdout, proc.stderr):
        if stream is None or stream.closed:
            continue
        try:
            os.set_blocking(stream.fileno(), True)
        except (OSError, ValueError):
            pass


def _one_copy(binary: str, args: list[str], repo: Path, by_binary: str, lib_target: str) -> dict:
    """One libtest invocation, with the temp dir run_prebuilt gives a Linux lib binary.

    cwd is inherited: the process is already in the repo, and passing cwd= leaves
    Python's posix_spawn path. The copy runs in its own session so a timeout can
    kill the whole group. A reader thread per stream keeps the last 400 lines and
    the `test result:` / `running N tests` lines; judge sees that, not the whole
    run. After a timeout kill the second communicate waits at most 10s, then the
    pipes are closed and whatever was already read is kept. The temp root is
    removed when the copy ends.
    """
    root = tempfile.mkdtemp(prefix="shard-tmp-")
    try:
        tmpdir = os.path.join(root, by_binary, lib_target)
        os.makedirs(tmpdir)
        env = os.environ.copy()
        env["CARGO_MANIFEST_DIR"] = str(repo)
        env["TMPDIR"] = tmpdir
        limit = _env_int("REPEAT_COPY_TIMEOUT_S", COPY_TIMEOUT)
        proc = subprocess.Popen(
            [binary, *args],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        state = _Capture()
        stop = threading.Event()
        threads = []
        for stream in (proc.stdout, proc.stderr):
            if stream is None:
                continue
            thread = threading.Thread(target=_read_pipe, args=(stream, state, stop), daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + limit
        try:
            proc.wait(timeout=limit)
            exited = True
        except subprocess.TimeoutExpired:
            exited = False
        readers_done = _join_readers(threads, max(0.0, deadline - time.monotonic())) if exited else False
        timed_out = not exited or not readers_done
        if timed_out:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Readers own the pipes until they stop. Then one bounded communicate.
            stop.set()
            _join_readers(threads, 1)
            _blocking(proc)
            try:
                extra_out, extra_err = proc.communicate(timeout=POST_KILL_READ)
            except subprocess.TimeoutExpired as exc:
                extra_out, extra_err = exc.stdout, exc.stderr
                _close_pipes(proc)
            _fold(state, extra_out)
            _fold(state, extra_err)
            if proc.poll() is None:
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        else:
            stop.set()
            _close_pipes(proc)
        lines, result, running = state.snapshot()
        if timed_out:
            lines.append(f"TIMEOUT after {limit} s")
            lines = lines[-COPY_OUTPUT_LINES:]
        exit_code = proc.returncode if proc.returncode is not None else -signal.SIGKILL
        tests_run, kind = judge(exit_code, _judge_text(lines, result, running))
        if timed_out:
            kind = "fail"
        return {"exit": exit_code, "tests_run": tests_run, "kind": kind, "output": "\n".join(lines)}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def cmd_run(binary: Path, out: Path) -> int:
    try:
        spec = load_spec()
    except PlanError as exc:
        print(exc, file=sys.stderr)
        return 2
    skips, by_binary, lib_target = prebuilt_shape()
    os.chmod(binary, 0o755)
    repo = Path.cwd()
    args = lib_argv(spec, skips)
    iterations: list[dict] = []
    tail = None
    budget = _env_int("REPEAT_RUN_BUDGET_S", RUN_BUDGET)
    started = time.monotonic()
    incomplete = False
    source_id = _source_run_id(binary)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    prior = ""
    if summary:
        summary_path = Path(summary)
        if summary_path.is_file():
            prior = summary_path.read_text(encoding="utf-8")
            if prior and not prior.endswith("\n"):
                prior += "\n"

    def publish(is_incomplete: bool) -> None:
        payload = _payload(spec, iterations, tail, is_incomplete, source_id)
        _write_results(out, payload)
        _write_summary(prior, iterations, payload["passed"], spec["runs"], is_incomplete)

    # Repeats are sequential so repeat N is N copies later. Copies inside one repeat overlap.
    for number in range(1, spec["runs"] + 1):
        # Stop starting iterations once the budget is exceeded. One already running finishes.
        if time.monotonic() - started > budget:
            incomplete = True
            break
        with ThreadPoolExecutor(max_workers=spec["parallel"]) as pool:
            copies = list(pool.map(
                lambda _i: _one_copy(str(binary), args, repo, by_binary, lib_target),
                range(spec["parallel"])))
        # A crash beside a void copy is a failure. Void only if nothing failed.
        kinds = [copy["kind"] for copy in copies]
        if "fail" in kinds:
            result = "fail"
        elif "void" in kinds:
            result = "void"
        else:
            result = "pass"
        if tail is None:
            failed = next((copy for copy in copies if copy["kind"] == "fail"), None)
            if failed is not None:
                tail = failure_tail(failed["output"])
        iterations.append({
            "n": number,
            "result": result,
            "copies": [{"exit": copy["exit"], "tests_run": copy["tests_run"]} for copy in copies],
        })
        # A file written before the last spec run is a partial result.
        publish(number != spec["runs"])
    if incomplete:
        publish(True)
    passed = sum(1 for it in iterations if it["result"] == "pass")
    void = sum(1 for it in iterations if it["result"] == "void")
    done = len(iterations)
    spec_runs = spec["runs"]
    # Denominator is the spec. A budget or kill stop must not read as N of N.
    if incomplete:
        print(f"repeat: {passed}/{spec_runs} (INCOMPLETE after {done} runs)")
    else:
        print(f"repeat: {passed}/{spec_runs}")
    if tail:
        print(tail)
    if incomplete:
        return 1
    # A failure outranks void at run level too, as it does inside an iteration.
    if done - passed - void:
        return 1
    if void:
        return 3
    return 0


def self_test() -> int:
    """Classifier, tail and spec rules on canned inputs. No git, no network."""
    problems = []
    red = "\n".join([f"FAIL {i:02d}" for i in range(1, 51)] + [
        "running 1 test",
        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out",
    ])
    lines = failure_tail(red).splitlines()
    if len(lines) != 40 or "FAIL 50" not in lines or "FAIL 01" in lines or not any(
            line.startswith("test result: FAILED") for line in lines):
        problems.append(f"tail {lines[:1]!r}..{lines[-1:]!r} ({len(lines)})")
    ok = "running 1 test\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
    empty = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out\n"
    bare = "running 3 tests\ntest something ... ok\n"
    if judge(0, ok) != (1, "pass") or judge(0, empty) != (0, "void") or judge(0, bare) != (0, "void"):
        problems.append(f"judge ok={judge(0, ok)} empty={judge(0, empty)} bare={judge(0, bare)}")
    if judge(137, "killed\n") != (0, "fail") or judge(1, "load error\n") != (0, "fail"):
        problems.append(f"crash was not a failure: 137={judge(137, 'killed')} 1={judge(1, 'load error')}")
    if judge(1, red)[1] != "fail":
        problems.append("a FAILED summary was not a failure")
    good = {"sha": "a" * 40, "filter": "gateway::foo_1", "runs": 3, "parallel": 2, "exact": True}
    if spec_error(good) is not None:
        problems.append(f"good spec refused: {spec_error(good)}")
    refused = [
        ([], "object"),
        ({**good, "sha": "abc"}, "sha"),
        ({k: v for k, v in good.items() if k != "filter"}, "filter"),
        ({**good, "filter": ""}, "filter"),
        ({**good, "filter": "a" * 201}, "filter"),
        ({**good, "filter": "foo-bar"}, "filter"),
        ({**good, "filter": "a;b"}, "filter"),
        ({**good, "filter": "a$b"}, "filter"),
        ({**good, "filter": "a b"}, "filter"),
        ({**good, "filter": "-x"}, "dash"),
        ({**good, "runs": 0}, "runs"),
        ({**good, "runs": 51}, "runs"),
        ({**good, "parallel": 5}, "parallel"),
        ({**good, "exact": 1}, "exact"),
        ({**good, "bonus": 1}, "bonus"),
    ]
    for data, needle in refused:
        message = spec_error(data) or ""
        if needle not in message:
            problems.append(f"{needle}: {message!r}")
    if REF_RE.fullmatch("refs/heads/throwaway/repeat-demo") is None or REF_RE.fullmatch("refs/heads/main"):
        problems.append("ref regex misclassified")
    skips, by_binary, lib_target = prebuilt_shape()
    argv = lib_argv(good, skips)
    if argv != ["gateway::foo_1", "--exact", *skips] or by_binary != "by-binary" or lib_target != "mcp_gateway":
        problems.append(f"prebuilt shape {argv!r} {by_binary}/{lib_target}")
    for problem in problems:
        print(f"self-test: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["plan", "fetch", "run"], nargs="?")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--binary", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.mode == "plan":
        return cmd_plan()
    if args.mode == "fetch":
        if args.out is None:
            ap.error("fetch needs --out")
        return cmd_fetch(args.out)
    if args.mode == "run":
        if args.binary is None or args.out is None:
            ap.error("run needs --binary and --out")
        return cmd_run(args.binary, args.out)
    ap.error("need plan, fetch --out, run --binary --out, or --self-test")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
