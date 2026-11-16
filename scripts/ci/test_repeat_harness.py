#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""RED checks for hosted repeat evidence.

The repeat job never compiles. It re-runs the lib test binary CI already
built. Each check prints PASS or FAIL; the process exits 1 if any fail.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "repeat" / "run_repeat.py"
WORKFLOW = ROOT / ".github" / "workflows" / "repeat.yml"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
SWAP = ROOT / "scripts" / "ci" / "check_swap_jobs.py"
REF_OK = "refs/heads/throwaway/repeat-demo"
REF_RE = re.compile(r"\bGITHUB_REF\b|\bref\b")
ABSENT = "scripts/ci/repeat/run_repeat.py is absent"


def run_py(args: list[str], cwd: Path, env: dict, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], cwd=cwd, env=env,
        capture_output=True, text=True, timeout=timeout)


def git(repo: Path, env: dict, hooks: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={hooks}", *args],
        cwd=repo, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def git_env(cfg: Path) -> dict:
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(cfg),
               GIT_AUTHOR_NAME="Repeat Test", GIT_AUTHOR_EMAIL="repeat@example.com",
               GIT_COMMITTER_NAME="Repeat Test", GIT_COMMITTER_EMAIL="repeat@example.com")
    return env


def init_repo(repo: Path, env: dict, hooks: Path) -> str:
    repo.mkdir()
    git(repo, env, hooks, "init", "-q", "-b", "main")
    (repo / "README").write_text("base\n")
    git(repo, env, hooks, "add", "README")
    git(repo, env, hooks, "commit", "-q", "-m", "base")
    return git(repo, env, hooks, "rev-parse", "HEAD")


def commit_overlay(repo: Path, env: dict, hooks: Path, content: str | None, extra: tuple[str, ...] = ()) -> None:
    if content is not None:
        (repo / ".repeat").mkdir(exist_ok=True)
        (repo / ".repeat" / "spec.json").write_text(content)
        git(repo, env, hooks, "add", "-A", ".repeat")
    for rel in extra:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n")
        git(repo, env, hooks, "add", "-A", "--", rel)
    git(repo, env, hooks, "commit", "-q", "--allow-empty", "-m", "repeat")


def base_spec(sha: str) -> dict:
    return {"sha": sha, "filter": "gateway::foo_1", "runs": 3, "parallel": 2, "exact": True}


def script_env(cfg: Path, ref: str, **extra: str) -> dict:
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(cfg), GITHUB_REF=ref)
    env.pop("GITHUB_OUTPUT", None)
    env.pop("GITHUB_STEP_SUMMARY", None)
    env.update(extra)
    return env


def combined(proc: subprocess.CompletedProcess[str]) -> str:
    return proc.stdout + proc.stderr


def nonempty_lines(proc: subprocess.CompletedProcess[str]) -> list[str]:
    return [line for line in combined(proc).splitlines() if line.strip()]


def write_exe(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def linux_shape() -> tuple[list[str], str, str]:
    """Invocation tail run_prebuilt uses for a Linux lib binary, minus the filter."""
    path = ROOT / "scripts" / "ci" / "shard_tests.py"
    spec = importlib.util.spec_from_file_location("shard_tests_repeat", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return list(mod.SKIPS["linux"]), mod.BY_BINARY, mod.LIB_TARGET


def compiler_fakes(bindir: Path, marker: Path) -> None:
    body = f"#!/bin/sh\necho invoked >> {marker}\nexit 1\n"
    for name in ("cargo", "rustc"):
        write_exe(bindir / name, body)


def test_self_test() -> None:
    if not SCRIPT.is_file():
        raise AssertionError(ABSENT)
    proc = run_py(["--self-test"], ROOT, os.environ.copy(), 120)
    if proc.returncode != 0:
        raise AssertionError(f"--self-test exited {proc.returncode}: {combined(proc)[-500:]}")


def test_plan() -> None:
    if not SCRIPT.is_file():
        raise AssertionError(ABSENT)
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="repeat-plan-") as raw:
        tmp, hooks = Path(raw), Path(raw) / "hooks"
        hooks.mkdir()
        cfg = tmp / "gitconfig"
        cfg.write_text("")
        env = git_env(cfg)

        repo = tmp / "good"
        sha = init_repo(repo, env, hooks)
        spec = base_spec(sha)
        commit_overlay(repo, env, hooks, json.dumps(spec) + "\n")
        out = repo / "output"
        proc = run_py(["plan"], repo, script_env(cfg, REF_OK, GITHUB_OUTPUT=str(out)), 30)
        line = proc.stdout.strip()
        try:
            got = json.loads(line)
        except json.JSONDecodeError:
            got = None
        if proc.returncode != 0 or "\n" in line or got != spec:
            problems.append(f"good spec: rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}")
        elif not out.is_file() or "valid=true" not in out.read_text().splitlines():
            problems.append(f"good spec did not write valid=true ({out.read_text()!r})" if out.is_file() else
                            "good spec did not write GITHUB_OUTPUT")

        def refuse(name: str, needle: str, *, overlay: dict | None = None, drop: tuple[str, ...] = (),
                   raw_text: str | None = None, extra: tuple[str, ...] = (), missing: bool = False,
                   ref: str = REF_OK) -> None:
            case = tmp / name
            parent = init_repo(case, env, hooks)
            body = base_spec(parent)
            for key in drop:
                del body[key]
            if overlay:
                body.update(overlay)
            if missing:
                commit_overlay(case, env, hooks, None)
            elif raw_text is not None:
                commit_overlay(case, env, hooks, raw_text, extra)
            else:
                commit_overlay(case, env, hooks, json.dumps(body) + "\n", extra)
            output = case / "output"
            ran = run_py(["plan"], case, script_env(cfg, ref, GITHUB_OUTPUT=str(output)), 30)
            text = combined(ran)
            bad = []
            if ran.returncode != 2:
                bad.append(f"rc={ran.returncode}")
            if needle == "GITHUB_REF":
                if not REF_RE.search(text):
                    bad.append("message does not name GITHUB_REF")
            elif needle not in text:
                bad.append(f"message does not name {needle!r}")
            if output.is_file() and "valid=true" in output.read_text().splitlines():
                bad.append("wrote valid=true")
            if bad:
                problems.append(f"{name}: {', '.join(bad)}: {text.strip()[:300]!r}")

        refuse("missing", "spec", missing=True)
        refuse("not-object", "object", raw_text="[]\n")
        refuse("bad-sha", "sha", overlay={"sha": "abc"})
        refuse("filter-missing", "filter", drop=("filter",))
        refuse("filter-empty", "filter", overlay={"filter": ""})
        refuse("filter-long", "filter", overlay={"filter": "a" * 201})
        refuse("filter-chars", "filter", overlay={"filter": "foo-bar"})
        refuse("runs-0", "runs", overlay={"runs": 0})
        refuse("runs-51", "runs", overlay={"runs": 51})
        refuse("parallel-5", "parallel", overlay={"parallel": 5})
        refuse("exact-type", "exact", overlay={"exact": 1})
        refuse("extra-key", "bonus", overlay={"bonus": 1})
        refuse("bad-ref", "GITHUB_REF", ref="refs/heads/main")
        refuse("head-mismatch", "sha", overlay={"sha": "c" * 40})
        refuse("outside", "src/x", extra=("src/x",))
    if problems:
        raise AssertionError("\n".join(problems))


def gh_script() -> str:
    return """#!/bin/sh
printf '%s\\n' "$*" >> "$GH_FAKE_LOG"
found=
for a in "$@"; do
  case "$a" in
    *workflows/ci.yml/runs*) found=1 ;;
  esac
done
if [ -n "$found" ]; then
  if [ -n "$GH_FAKE_LIST_FAIL" ]; then
    echo "run list failed" >&2
    exit 1
  fi
  cat "$GH_FAKE_RUNS"
  exit 0
fi
if [ "$1" = "run" ] && [ "$2" = "download" ]; then
  shift 2
  run_id=
  dest=
  name=
  while [ $# -gt 0 ]; do
    case "$1" in
      -D|--dir) dest=$2; shift 2 ;;
      -n|--name) name=$2; shift 2 ;;
      *) run_id=$1; shift ;;
    esac
  done
  if [ "$name" != "linux-lib-tests" ]; then
    echo "download must request --name linux-lib-tests" >&2
    exit 1
  fi
  printf '%s\\n' "$run_id" >> "$GH_FAKE_IDS"
  if [ -n "$GH_FAKE_DOWNLOAD_FAIL" ]; then
    echo "artifact expired" >&2
    exit 1
  fi
  mkdir -p "$dest"
  if [ -n "$GH_FAKE_DOWNLOAD_EMPTY" ]; then
    exit 0
  fi
  printf '%s\\n' 'REPEAT-ARTIFACT' > "$dest/lib-tests"
  chmod 644 "$dest/lib-tests"
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 99
"""


def test_fetch() -> None:
    if not SCRIPT.is_file():
        raise AssertionError(ABSENT)
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="repeat-fetch-") as raw:
        tmp, hooks = Path(raw), Path(raw) / "hooks"
        hooks.mkdir()
        cfg = tmp / "gitconfig"
        cfg.write_text("")
        env = git_env(cfg)
        bindir = tmp / "bin"
        marker = tmp / "compiled"
        compiler_fakes(bindir, marker)
        write_exe(bindir / "gh", gh_script())
        repo = tmp / "repo"
        sha = init_repo(repo, env, hooks)
        spec = base_spec(sha)
        commit_overlay(repo, env, hooks, json.dumps(spec) + "\n")
        log, ids, runs_path = tmp / "gh.log", tmp / "ids", tmp / "runs.json"

        def fetch(name: str, payload: dict, out: Path, *, download_fail: bool = False,
                  list_fail: bool = False, download_empty: bool = False,
                  raw_runs: str | None = None) -> subprocess.CompletedProcess[str]:
            runs_path.write_text(raw_runs if raw_runs is not None else json.dumps(payload))
            log.write_text("")
            ids.write_text("")
            marker.unlink(missing_ok=True)
            penv = script_env(cfg, REF_OK, GITHUB_REPOSITORY="acme/widgets",
                              GH_FAKE_LOG=str(log), GH_FAKE_RUNS=str(runs_path), GH_FAKE_IDS=str(ids),
                              PATH=f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
            if download_fail:
                penv["GH_FAKE_DOWNLOAD_FAIL"] = "1"
            if list_fail:
                penv["GH_FAKE_LIST_FAIL"] = "1"
            if download_empty:
                penv["GH_FAKE_DOWNLOAD_EMPTY"] = "1"
            return run_py(["fetch", "--out", str(out)], repo, penv, 30)

        def compiled(name: str) -> None:
            if marker.exists():
                problems.append(f"{name}: cargo or rustc was invoked")

        completed = {
            "total_count": 2,
            "workflow_runs": [
                {"id": 10, "head_sha": sha, "status": "completed", "conclusion": "success",
                 "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:10:00Z"},
                {"id": 20, "head_sha": sha, "status": "completed", "conclusion": "success",
                 "created_at": "2026-11-16T00:00:00Z", "updated_at": "2026-11-16T00:10:00Z"},
            ],
        }
        out = tmp / "out-ok"
        proc = fetch("found", completed, out)
        compiled("found")
        binary = out / "lib-tests"
        logged = log.read_text()
        if proc.returncode != 0 or not binary.is_file() or binary.read_text() != "REPEAT-ARTIFACT\n":
            problems.append(f"found: rc={proc.returncode} file={binary.is_file()} {combined(proc)[:300]!r}")
        elif not (binary.stat().st_mode & 0o111):
            problems.append("found: lib-tests is not executable")
        elif ids.read_text().split() != ["20"]:
            problems.append(f"found: downloaded run ids {ids.read_text()!r}, want 20")
        elif (out / "source-run-id.txt").read_text().strip() != "20":
            problems.append(f"found: source-run-id.txt {(out / 'source-run-id.txt').read_text()!r}")
        elif "workflows/ci.yml/runs" not in logged or f"head_sha={sha}" not in logged or "per_page=20" not in logged:
            problems.append(f"found: gh was not asked for the ci.yml runs of the sha: {logged!r}")
        elif "--name" not in logged or "linux-lib-tests" not in logged:
            problems.append(f"found: download was not asked for --name linux-lib-tests: {logged!r}")

        def refused(name: str, payload: dict, phrase: str, *, download_fail: bool = False,
                    list_fail: bool = False, download_empty: bool = False,
                    raw_runs: str | None = None) -> None:
            ran = fetch(name, payload, tmp / f"out-{name}", download_fail=download_fail,
                        list_fail=list_fail, download_empty=download_empty, raw_runs=raw_runs)
            compiled(name)
            lines = nonempty_lines(ran)
            if ran.returncode != 4 or len(lines) != 1 or phrase not in lines[0]:
                problems.append(f"{name}: rc={ran.returncode} lines={lines!r}")

        refused("no-run", {"total_count": 0, "workflow_runs": []}, "no CI run")
        refused("list-fail", {}, "run list failed", list_fail=True)
        refused("not-json", {}, "not JSON", raw_runs="not-json")
        refused("in-progress", {"total_count": 1, "workflow_runs": [
            {"id": 5, "head_sha": sha, "status": "in_progress", "created_at": "2026-11-16T00:00:00Z"}]}, "wait")
        refused("newest-in-progress", {"total_count": 2, "workflow_runs": [
            {"id": 1, "head_sha": sha, "status": "completed", "conclusion": "success",
             "created_at": "2026-11-01T00:00:00Z"},
            {"id": 2, "head_sha": sha, "status": "in_progress",
             "created_at": "2026-11-16T00:00:00Z"},
        ]}, "wait")
        if ids.read_text().strip():
            problems.append(f"newest-in-progress: downloaded {ids.read_text()!r} instead of waiting")
        refused("expired", {"total_count": 1, "workflow_runs": [
            {"id": 30, "head_sha": sha, "status": "completed", "conclusion": "success",
             "created_at": "2026-11-16T00:00:00Z"}]}, "1 day", download_fail=True)
        refused("empty-download", {"total_count": 1, "workflow_runs": [
            {"id": 31, "head_sha": sha, "status": "completed", "conclusion": "success",
             "created_at": "2026-11-16T00:00:00Z"}]}, "1 day", download_empty=True)

        failed_run = {"total_count": 1, "workflow_runs": [
            {"id": 40, "head_sha": sha, "status": "completed", "conclusion": "failure",
             "created_at": "2026-11-16T00:00:00Z"},
        ]}
        failed_out = tmp / "out-failed-run"
        proc = fetch("failed-run", failed_run, failed_out)
        compiled("failed-run")
        if proc.returncode != 0 or not (failed_out / "lib-tests").is_file():
            problems.append(f"failed-run: rc={proc.returncode} {combined(proc)[:300]!r}")
        elif ids.read_text().split() != ["40"] or (failed_out / "source-run-id.txt").read_text().strip() != "40":
            problems.append(f"failed-run: ids {ids.read_text()!r}")

        other = "b" * 40
        other_out = tmp / "out-other-sha"
        proc = fetch("other-sha", {"total_count": 2, "workflow_runs": [
            {"id": 7, "head_sha": other, "status": "in_progress",
             "created_at": "2026-11-01T00:00:00Z"},
            {"id": 8, "head_sha": sha, "status": "completed", "conclusion": "success",
             "created_at": "2026-11-16T00:00:00Z"},
        ]}, other_out)
        compiled("other-sha")
        if proc.returncode != 0 or ids.read_text().split() != ["8"] or not (other_out / "lib-tests").is_file():
            problems.append(f"other-sha: rc={proc.returncode} ids={ids.read_text()!r} {combined(proc)[:300]!r}")
    if problems:
        raise AssertionError("\n".join(problems))


def test_run() -> None:
    if not SCRIPT.is_file():
        raise AssertionError(ABSENT)
    skips, by_binary, lib_target = linux_shape()
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="repeat-run-") as raw:
        tmp, hooks = Path(raw), Path(raw) / "hooks"
        hooks.mkdir()
        cfg = tmp / "gitconfig"
        cfg.write_text("")
        env = git_env(cfg)
        bindir = tmp / "bin"
        marker = tmp / "compiled"
        compiler_fakes(bindir, marker)
        record = tmp / "record"

        def repo_for(name: str, spec: dict) -> Path:
            repo = tmp / name
            sha = init_repo(repo, env, hooks)
            spec["sha"] = sha
            commit_overlay(repo, env, hooks, json.dumps(spec) + "\n")
            return repo

        def penv(**extra: str) -> dict:
            base = script_env(cfg, REF_OK, PATH=f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
            base.update(extra)
            return base

        # All copies pass: 3 iterations, 2 copies each, --exact, prebuilt invocation shape.
        pass_spec = {"filter": "pass_case", "runs": 3, "parallel": 2, "exact": True}
        pass_repo = repo_for("pass", pass_spec)
        record.mkdir()
        write_exe(tmp / "pass-bin", f"""#!/bin/sh
dir="$RECORD_DIR"
while ! mkdir "$dir/lock" 2>/dev/null; do sleep 0.01; done
n=0
if [ -f "$dir/n" ]; then n=$(cat "$dir/n"); fi
n=$((n + 1))
printf '%s\\n' "$n" > "$dir/n"
rmdir "$dir/lock"
printf '%s\\n' "$PWD" > "$dir/$n.cwd"
printf '%s\\n' "$CARGO_MANIFEST_DIR" > "$dir/$n.manifest"
printf '%s\\n' "$TMPDIR" > "$dir/$n.tmp"
printf '%s\\n' "$@" > "$dir/$n.args"
printf '%s\\n' "running 1 test"
printf '%s\\n' "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
exit 0
""")
        summary = tmp / "summary.md"
        summary.write_text("")
        out = tmp / "pass-out"
        (tmp / "source-run-id.txt").write_text("4242\n")
        proc = run_py(["run", "--binary", str(tmp / "pass-bin"), "--out", str(out)], pass_repo,
                      penv(RECORD_DIR=str(record), GITHUB_STEP_SUMMARY=str(summary)), 30)
        if marker.exists():
            problems.append("pass: cargo or rustc was invoked")
        try:
            data = json.loads((out / "results.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            data = None
            problems.append(f"pass: no results.json ({exc})")
        if proc.returncode != 0 or "repeat: 3/3" not in proc.stdout:
            problems.append(f"pass: rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}")
        if isinstance(data, dict):
            if data.get("passed") != 3 or data.get("total") != 3 or data.get("void") != 0:
                problems.append(f"pass: totals {data.get('passed')}/{data.get('total')} void={data.get('void')}")
            if data.get("incomplete") is not False:
                problems.append(f"pass: incomplete {data.get('incomplete')!r}")
            if data.get("source_run_id") != "4242":
                problems.append(f"pass: source_run_id {data.get('source_run_id')!r}")
            if data.get("spec") != pass_spec:
                problems.append(f"pass: spec {data.get('spec')!r}")
            iters = data.get("iterations")
            if (not isinstance(iters, list) or len(iters) != 3 or
                    any(it.get("n") != i or len(it.get("copies") or []) != 2 for i, it in enumerate(iters, start=1)) or
                    any(copy.get("exit") != 0 or copy.get("tests_run") != 1
                        for it in iters for copy in it.get("copies") or [])):
                problems.append(f"pass: iterations {iters!r}")
            if not isinstance(data.get("verdict"), str) or not data.get("verdict"):
                problems.append(f"pass: verdict {data.get('verdict')!r}")
        args = sorted(record.glob("*.args"))
        want = ["pass_case", "--exact", *skips]
        if len(args) != 6 or any(path.read_text().splitlines() != want for path in args):
            seen = {path.name: path.read_text().splitlines() for path in args}
            problems.append(f"pass: argv records {seen!r}, want 6 of {want!r}")
        for path in record.glob("*.cwd"):
            if Path(path.read_text().strip()).resolve() != pass_repo.resolve():
                problems.append(f"pass: cwd {path.read_text().strip()!r}")
        for path in record.glob("*.manifest"):
            if Path(path.read_text().strip()).resolve() != pass_repo.resolve():
                problems.append(f"pass: CARGO_MANIFEST_DIR {path.read_text().strip()!r}")
        for path in record.glob("*.tmp"):
            tmpdir = Path(path.read_text().strip())
            if tmpdir.name != lib_target or tmpdir.parent.name != by_binary or tmpdir.exists():
                problems.append(f"pass: TMPDIR {tmpdir} exists={tmpdir.exists()}")
        if "|" not in summary.read_text():
            problems.append("pass: GITHUB_STEP_SUMMARY has no markdown table")
        (tmp / "source-run-id.txt").unlink()

        # The binary fails only on its second invocation. One copy per iteration, so iteration 2 fails.
        fail_spec = {"filter": "fail_case", "runs": 3, "parallel": 1, "exact": False}
        fail_repo = repo_for("fail", fail_spec)
        count = tmp / "count"
        write_exe(tmp / "fail-bin", """#!/bin/sh
dir="$COUNT_DIR"
mkdir -p "$dir"
while ! mkdir "$dir/lock" 2>/dev/null; do sleep 0.01; done
n=0
if [ -f "$dir/n" ]; then n=$(cat "$dir/n"); fi
n=$((n + 1))
printf '%s\\n' "$n" > "$dir/n"
rmdir "$dir/lock"
if [ "$n" -eq 2 ]; then
  i=1
  while [ "$i" -le 50 ]; do
    printf 'FAIL %02d\\n' "$i"
    i=$((i + 1))
  done
  printf '%s\\n' "running 1 test"
  printf '%s\\n' "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out"
  exit 1
fi
printf '%s\\n' "running 1 test"
printf '%s\\n' "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
exit 0
""")
        fail_out = tmp / "fail-out"
        proc = run_py(["run", "--binary", str(tmp / "fail-bin"), "--out", str(fail_out)], fail_repo,
                      penv(COUNT_DIR=str(count)), 30)
        if marker.exists():
            problems.append("fail: cargo or rustc was invoked")
        try:
            data = json.loads((fail_out / "results.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            data = None
            problems.append(f"fail: no results.json ({exc})")
        if proc.returncode != 1 or "repeat: 2/3" not in proc.stdout:
            problems.append(f"fail: rc={proc.returncode} stdout={proc.stdout[-400:]!r}")
        if isinstance(data, dict):
            if data.get("passed") != 2 or data.get("total") != 3 or data.get("void") != 0:
                problems.append(f"fail: totals {data.get('passed')}/{data.get('total')} void={data.get('void')}")
            tail = data.get("first_failure_tail")
            lines = tail.splitlines() if isinstance(tail, str) else [str(item) for item in tail] if isinstance(tail, list) else []
            if len(lines) != 40 or "FAIL 50" not in lines or "FAIL 01" in lines or not any(
                    line.startswith("test result: FAILED") for line in lines):
                problems.append(f"fail: first_failure_tail {lines[:2]!r}..{lines[-2:]!r} ({len(lines)} lines)")
            elif "FAIL 50" not in proc.stdout:
                problems.append("fail: first_failure_tail was not printed")

        def once(name: str, body: str, spec: dict, code: int, totals: tuple[int, int, int], tests_run: int) -> None:
            marker.unlink(missing_ok=True)
            write_exe(tmp / f"{name}-bin", body)
            repo = repo_for(name, spec)
            dest = tmp / f"{name}-out"
            ran = run_py(["run", "--binary", str(tmp / f"{name}-bin"), "--out", str(dest)], repo, penv(), 30)
            if marker.exists():
                problems.append(f"{name}: cargo or rustc was invoked")
            try:
                got = json.loads((dest / "results.json").read_text())
            except (OSError, json.JSONDecodeError) as exc:
                problems.append(f"{name}: no results.json ({exc})")
                return
            passed, total, void = totals
            if ran.returncode != code or f"repeat: {passed}/{total}" not in ran.stdout:
                problems.append(f"{name}: rc={ran.returncode} stdout={ran.stdout!r} stderr={ran.stderr!r}")
            if got.get("passed") != passed or got.get("total") != total or got.get("void") != void:
                problems.append(f"{name}: totals {got.get('passed')}/{got.get('total')} void={got.get('void')}")
            copies = (got.get("iterations") or [{}])[0].get("copies") or [{}]
            if not copies or copies[0].get("tests_run") != tests_run:
                problems.append(f"{name}: tests_run {copies!r}")

        once("void", """#!/bin/sh
printf '%s\\n' "running 0 tests"
printf '%s\\n' "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"
exit 0
""", {"filter": "void_case", "runs": 1, "parallel": 1, "exact": False}, 3, (0, 1, 1), 0)
        once("no-result", """#!/bin/sh
printf '%s\\n' "running 3 tests"
printf '%s\\n' "test something ... ok"
exit 0
""", {"filter": "none_case", "runs": 1, "parallel": 1, "exact": False}, 3, (0, 1, 1), 0)

        sleep_spec = {"filter": "sleep_case", "runs": 1, "parallel": 2, "exact": False}
        sleep_repo = repo_for("sleep", sleep_spec)
        stamp = tmp / "overlap.log"
        write_exe(tmp / "sleep-bin", """#!/usr/bin/env python3
import os
import time
path = os.environ["STAMP_FILE"]
def stamp(word):
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        os.write(fd, f"{word} {time.time()}\\n".encode())
    finally:
        os.close(fd)
stamp("start")
time.sleep(1)
stamp("end")
print("running 1 test")
print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out")
""")
        proc = run_py(["run", "--binary", str(tmp / "sleep-bin"), "--out", str(tmp / "sleep-out")],
                      sleep_repo, penv(STAMP_FILE=str(stamp)), 20)
        events = []
        for line in stamp.read_text().splitlines() if stamp.is_file() else []:
            kind, _, raw = line.partition(" ")
            if kind in ("start", "end") and raw:
                events.append((kind, float(raw)))
        starts = [when for kind, when in events if kind == "start"]
        ends = [when for kind, when in events if kind == "end"]
        overlapped = len(starts) == 2 and len(ends) == 2 and min(ends) > max(starts)
        if proc.returncode != 0 or not overlapped:
            problems.append(
                f"sleep: rc={proc.returncode} events={events!r} stderr={proc.stderr!r}")
        else:
            try:
                got = json.loads((tmp / "sleep-out" / "results.json").read_text())
            except (OSError, json.JSONDecodeError) as exc:
                problems.append(f"sleep: no results.json ({exc})")
            else:
                copies = (got.get("iterations") or [{}])[0].get("copies") or []
                if got.get("passed") != 1 or len(copies) != 2:
                    problems.append(f"sleep: passed={got.get('passed')} copies={len(copies)}")

        timeout_spec = {"filter": "timeout_case", "runs": 1, "parallel": 1, "exact": False}
        timeout_repo = repo_for("timeout", timeout_spec)
        write_exe(tmp / "timeout-bin", """#!/bin/sh
sleep 30
printf '%s\\n' "running 1 test"
printf '%s\\n' "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
exit 0
""")
        timeout_out = tmp / "timeout-out" / "results.json"
        started = time.monotonic()
        proc = run_py(["run", "--binary", str(tmp / "timeout-bin"), "--out", str(tmp / "timeout-out")],
                      timeout_repo, penv(REPEAT_COPY_TIMEOUT_S="1"), 20)
        elapsed = time.monotonic() - started
        if proc.returncode != 1 or elapsed >= 5 or not timeout_out.is_file():
            problems.append(
                f"timeout: rc={proc.returncode} elapsed={elapsed:.2f}s file={timeout_out.is_file()} "
                f"stderr={proc.stderr!r}")
        else:
            got = json.loads(timeout_out.read_text())
            tail = got.get("first_failure_tail") or ""
            iteration = (got.get("iterations") or [{}])[0]
            if "TIMEOUT" not in tail or iteration.get("result") != "fail":
                problems.append(f"timeout: result={iteration.get('result')!r} tail={tail!r}")

        budget_spec = {"filter": "budget_case", "runs": 5, "parallel": 1, "exact": False}
        budget_repo = repo_for("budget", budget_spec)
        write_exe(tmp / "budget-bin", """#!/bin/sh
sleep 1.2
printf '%s\\n' "running 1 test"
printf '%s\\n' "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
exit 0
""")
        budget_out = tmp / "budget-out" / "results.json"
        proc = run_py(["run", "--binary", str(tmp / "budget-bin"), "--out", str(tmp / "budget-out")],
                      budget_repo, penv(REPEAT_RUN_BUDGET_S="1", REPEAT_SOURCE_RUN_ID="77"), 30)
        if not budget_out.is_file():
            problems.append(f"budget: no results.json rc={proc.returncode} stderr={proc.stderr!r}")
        else:
            got = json.loads(budget_out.read_text())
            iters = got.get("iterations") or []
            if (proc.returncode != 1 or got.get("incomplete") is not True or len(iters) != 1
                    or got.get("total") != 1 or got.get("verdict") != "1/1"
                    or "repeat: 1/1" not in proc.stdout or got.get("source_run_id") != "77"):
                problems.append(
                    f"budget: rc={proc.returncode} incomplete={got.get('incomplete')!r} "
                    f"total={got.get('total')} verdict={got.get('verdict')!r} "
                    f"source={got.get('source_run_id')!r} stdout={proc.stdout!r}")
    if problems:
        raise AssertionError("\n".join(problems))


def step_strings(node: object):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from step_strings(key)
            yield from step_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from step_strings(value)


def has_fetch_depth(node: object) -> bool:
    if isinstance(node, dict):
        return node.get("fetch-depth") == 2 or any(has_fetch_depth(value) for value in node.values())
    if isinstance(node, list):
        return any(has_fetch_depth(value) for value in node)
    return False


def test_workflow() -> None:
    if not WORKFLOW.is_file():
        raise AssertionError(".github/workflows/repeat.yml is absent")
    doc = yaml.safe_load(WORKFLOW.read_text()) or {}
    problems: list[str] = []
    trigger = doc.get(True) or doc.get("on") or {}
    if set(trigger) != {"push"} or (trigger.get("push") or {}).get("branches") != ["throwaway/repeat-*"]:
        problems.append(f"trigger {trigger!r}")
    if "pull_request" in trigger or "workflow_dispatch" in trigger:
        problems.append("pull_request or workflow_dispatch is set")
    jobs = doc.get("jobs") or {}
    job = jobs.get("linux-hosted")
    if not isinstance(job, dict):
        raise AssertionError("job linux-hosted is absent; " + "; ".join(problems))
    if job.get("runs-on") != "ubuntu-latest":
        problems.append(f"runs-on {job.get('runs-on')!r}")
    conc = {}
    if isinstance(doc.get("concurrency"), dict):
        conc.update(doc["concurrency"])
    if isinstance(job.get("concurrency"), dict):
        conc.update(job["concurrency"])
    if (conc.get("group") != "repeat-linux-hosted" or conc.get("cancel-in-progress") is not False
            or conc.get("queue") != "max"):
        problems.append(f"concurrency {conc!r}")
    if not isinstance(job.get("timeout-minutes"), int) or job.get("timeout-minutes") <= 0:
        problems.append(f"timeout-minutes {job.get('timeout-minutes')!r}")
    perms = job["permissions"] if "permissions" in job else doc.get("permissions")
    if perms != {"contents": "read", "actions": "read"}:
        problems.append(f"permissions {perms!r}")
    blob = "\n".join(step_strings(job.get("steps") or []))
    folded = blob.lower()
    for word in ("cargo", "rustc", "rust-toolchain", "rust-cache", "add-swap", "swapon", "mkswap"):
        if word in folded:
            problems.append(f"step text contains {word}")
    for path in ("scripts/ci/repeat/run_repeat.py", "scripts/ci/shard_tests.py"):
        shown = f"git show FETCH_HEAD:{path}"
        if shown not in blob or not re.search(re.escape(shown) + r"\s*>\s*[\"']?\$RUNNER_TEMP/", blob):
            problems.append(f"{path} is not fetched with git show FETCH_HEAD into RUNNER_TEMP")
    if "docs/ranking-1-release-line" not in blob:
        problems.append("release line is not fetched")
    if not has_fetch_depth(job.get("steps") or []):
        problems.append("checkout fetch-depth is not 2")
    run_steps = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        text = step.get("run")
        if isinstance(text, str) and re.search(r"run_repeat\.py['\"]?\s+run\b", text):
            run_steps.append(text)
    if len(run_steps) != 1:
        problems.append(f"expected one run_repeat.py run step, found {len(run_steps)}")
    else:
        text = run_steps[0]
        checkout_script = "with-memory-log.sh" in text or re.search(r"(^|[\s\"'])scripts/", text)
        if checkout_script or "RUNNER_TEMP" not in text:
            problems.append(
                "run step must use only the fetched files from RUNNER_TEMP, "
                "not a script from the checkout under test")
    token_ok = False

    def walk(node: object) -> None:
        nonlocal token_ok
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "GH_TOKEN" and "github.token" in str(value):
                    token_ok = True
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(job)
    if not token_ok:
        problems.append("GH_TOKEN is not set from github.token")
    if problems:
        raise AssertionError("\n".join(problems))


def test_swap_jobs() -> None:
    proc = subprocess.run([sys.executable, str(SWAP)], cwd=ROOT, capture_output=True, text=True)
    text = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise AssertionError(f"check_swap_jobs.py exited {proc.returncode}: {text[-400:]}")
    if "repeat.yml" in text:
        raise AssertionError(f"check_swap_jobs.py mentions repeat.yml: {text[-400:]}")


def test_contributing() -> None:
    text = CONTRIBUTING.read_text()
    missing = [literal for literal in ("throwaway/repeat-", ".repeat/spec.json", "1 day") if literal not in text]
    if missing:
        raise AssertionError("CONTRIBUTING.md lacks " + ", ".join(missing))


CHECKS = [test_self_test, test_plan, test_fetch, test_run, test_workflow, test_swap_jobs, test_contributing]


def main() -> int:
    failed = 0
    for fn in CHECKS:
        try:
            fn()
        except Exception as exc:
            print(f"FAIL {fn.__name__}: {exc}")
            failed += 1
        else:
            print(f"PASS {fn.__name__}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
