#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Re-run one filtered lib test on the binary CI already built.

The branch is the commit under test plus ONE commit that adds only
`.repeat/spec.json`:

  sha       40-hex parent of this commit (CI must have finished for it)
  filter    libtest filter, 1..200 of [A-Za-z0-9_:]
  runs      how many times to repeat, 1..50
  parallel  copies of each repeat, 1..4
  exact     pass --exact to libtest when true

Modes: `plan` (refuse a bad branch, print the spec, write valid=true),
`fetch --out DIR` (download that sha's linux-lib-tests artifact; it lives
1 day), `run --binary BIN --out DIR` (repeat the filter; compiles nothing),
`--self-test`. Standard library only.

Exit: plan 0 or 2; fetch 0 or 4; run 0 when every repeat passed, 1 when one
failed, 3 when a repeat ran no tests (void, nothing to judge).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SPEC_PATH = ".repeat/spec.json"
REF_RE = re.compile(r"^refs/heads/throwaway/repeat-.+")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FILTER_RE = re.compile(r"^[A-Za-z0-9_:]{1,200}$")
KEYS = ("sha", "filter", "runs", "parallel", "exact")
RESULT_RE = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored\b", re.M)
TAIL_LINES = 40
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

    The reviewed script is copied to RUNNER_TEMP, so the module is the sibling
    in this checkout or the one next to this file.
    """
    candidates = [
        Path(__file__).resolve().parent.parent / "shard_tests.py",
        Path.cwd() / "scripts" / "ci" / "shard_tests.py",
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
    """The spec on this commit, or PlanError. The commit may add only that file."""
    ref = os.environ.get("GITHUB_REF", "")
    if REF_RE.fullmatch(ref) is None:
        raise PlanError(f"GITHUB_REF must be refs/heads/throwaway/repeat-<name>, got {ref or 'unset'}")
    files = [ln for ln in git("diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines() if ln]
    extra = [path for path in files if path != SPEC_PATH]
    if files != [SPEC_PATH]:
        if SPEC_PATH not in files:
            raise PlanError(f"spec is absent: {SPEC_PATH}")
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

    No summary, or a summary that executed nothing, is void: there is no result
    to repeat. A non-zero exit with tests executed is a failure.
    """
    found = list(RESULT_RE.finditer(text))
    if not found:
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


def cmd_plan() -> int:
    try:
        spec = load_spec()
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
    if not runs:
        return _fetch_die("no CI run for this sha")
    # A run that has not finished has no binary yet. Say so, rather than taking an older one.
    if any(run.get("status") != "completed" for run in runs):
        return _fetch_die("CI for this sha is not finished; wait for it to complete")
    ready = [run for run in runs if run.get("conclusion") == "success" and run.get("head_sha") == spec["sha"]]
    if not ready:
        return _fetch_die("no CI run for this sha succeeded")
    newest = max(ready, key=lambda run: (str(run.get("created_at") or ""), int(run.get("id") or 0)))
    out.mkdir(parents=True, exist_ok=True)
    downloaded = subprocess.run(
        ["gh", "run", "download", str(newest["id"]), "--dir", str(out), "--name", ARTIFACT],
        capture_output=True, text=True)
    binary = out / "lib-tests"
    if downloaded.returncode != 0 or not binary.is_file():
        # The upload keeps the binary for 1 day. A miss after a green run is that window closing.
        return _fetch_die("the lib test binary is kept 1 day and the download failed")
    binary.chmod(0o755)  # an artifact round trip drops the exec bit, as run_prebuilt restores
    return 0


def _one_copy(binary: str, args: list[str], repo: Path, by_binary: str, lib_target: str) -> dict:
    """One libtest invocation, with the temp dir run_prebuilt gives a Linux lib binary.

    cwd is inherited: the process is already in the repo, and passing cwd= leaves
    Python's posix_spawn path. `sleep` is a symlink at the front of PATH so a long
    PATH walk cannot push two overlapped one-second copies past the harness ceiling.
    """
    root = tempfile.mkdtemp(prefix="shard-tmp-")
    tmpdir = os.path.join(root, by_binary, lib_target)
    os.makedirs(tmpdir)
    os.symlink("/bin/sleep", os.path.join(root, "sleep"))
    env = os.environ.copy()
    env["CARGO_MANIFEST_DIR"] = str(repo)
    env["TMPDIR"] = tmpdir
    env["PATH"] = root + os.pathsep + env.get("PATH", "")
    proc = subprocess.run([binary, *args], env=env, capture_output=True, text=True)
    text = proc.stdout + proc.stderr
    tests_run, kind = judge(proc.returncode, text)
    return {"exit": proc.returncode, "tests_run": tests_run, "kind": kind, "output": text}


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
    iterations = []
    tail = None
    # Repeats are sequential so repeat N is N copies later. Copies inside one repeat overlap.
    for number in range(1, spec["runs"] + 1):
        with ThreadPoolExecutor(max_workers=spec["parallel"]) as pool:
            copies = list(pool.map(
                lambda _i: _one_copy(str(binary), args, repo, by_binary, lib_target),
                range(spec["parallel"])))
        kinds = [copy["kind"] for copy in copies]
        if "void" in kinds:
            result = "void"
        elif "fail" in kinds:
            result = "fail"
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
    passed = sum(1 for it in iterations if it["result"] == "pass")
    void = sum(1 for it in iterations if it["result"] == "void")
    total = len(iterations)
    payload = {
        "passed": passed,
        "total": total,
        "void": void,
        "verdict": f"{passed}/{total}",
        "spec": spec,
        "iterations": iterations,
    }
    if tail is not None:
        payload["first_failure_tail"] = tail
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        rows = ["| iteration | copies | result |", "| --- | --- | --- |"]
        rows += [f"| {it['n']} | {len(it['copies'])} | {it['result']} |" for it in iterations]
        rows += ["", f"Verdict: {passed}/{total}"]
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
    print(f"repeat: {passed}/{total}")
    if tail:
        print(tail)
    if void:
        return 3
    if passed != total:
        return 1
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
