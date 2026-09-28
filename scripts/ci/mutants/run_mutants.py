#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Batched mutation-proof runner for `throwaway/mutants-<pr>` branches.

The branch is a source head plus ONE commit that adds `.mutants/`:
  .mutants/manifest.tsv   first line: head_sha<TAB><40-hex sha>
                          rows: id<TAB>platform<TAB>patch file<TAB>cargo test args...
                          (args = rest of the line, split on spaces; `#` lines ignored)
  .mutants/<patch files>  applied with `git apply`, one row at a time

Every mutant is classified from what cargo printed, never from an exit code alone:
  RED       exit != 0 and the harness printed `test result: FAILED`
  SURVIVED  exit 0 and at least one test executed (passed + failed; ignored excluded)
  VOID      could not be judged: apply, compile, compile-timeout, timeout, no-tests,
            or a baseline that was red, timed out or ran nothing
  ERROR     anything else (a crash with no harness summary, or exit 0 beside a FAILED
            summary); the job fails

Modes: `plan` (integrity checks, writes has_linux/has_windows to $GITHUB_OUTPUT),
`run --platform linux|windows`, `--self-test` (classifier on canned outputs).
Standard library only; runs on Linux and on Windows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

RELEASE_LINE = "docs/ranking-1-release-line"
REF_RE = re.compile(r"^refs/heads/throwaway/mutants-[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PLATFORMS = ("linux", "windows")
MUTANTS_DIR = ".mutants"
# Where the batch's manifest and patches live, and the head it proves. The
# throwaway path uses MUTANTS_DIR and HEAD^; PR mode (`--source pr`) sets both
# from the pull request (.mutants/<number>/ and the PR head SHA).
_batch = {"dir": MUTANTS_DIR, "head": None}
# The harness may ride along in the batch commit (a source head older than it
# lacks it) only when it is byte-identical to the reviewed copy.
HARNESS = (".github/workflows/mutants.yml", "scripts/ci/mutants/run_mutants.py")
COMPILE_LIMIT = 30 * 60
TEST_LIMIT = 20 * 60
EVIDENCE_LINES = 15
SUMMARY_RE = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored")
EVIDENCE_RE = re.compile(r"^---- .* stdout ----$|panicked at|assertion|^thread '.*' panicked|left:|right:")


@dataclass
class Row:
    id: str
    platform: str
    patch: str
    args: list[str]


@dataclass
class Outcome:
    exit: int | None
    output: str
    timed_out: bool


@dataclass
class Verdict:
    result: str
    detail: str
    executed: int = 0
    evidence: list[str] = field(default_factory=list)


class Abort(Exception):
    """The batch cannot be trusted; fail the run before (or instead of) classifying."""


class ProcessLeak(Abort):
    """A test process survived its row; the tree must not be touched while it runs."""


def git(*args: str, check: bool = True) -> str:
    done = subprocess.run(["git", *args], capture_output=True, text=True, errors="replace")
    if check and done.returncode != 0:
        raise Abort(f"git {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout.strip()


def parse_manifest(text: str) -> tuple[str, list[Row]]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        raise Abort("manifest is empty")
    head = lines[0].split("\t")
    if len(head) != 2 or head[0] != "head_sha" or not SHA_RE.match(head[1]):
        raise Abort("manifest line 1 must be head_sha<TAB><40-hex sha>")
    rows, seen = [], set()
    for n, line in enumerate(lines[1:], start=2):
        parts = line.split("\t", 3)
        if len(parts) != 4 or not parts[3].strip():
            raise Abort(f"manifest line {n}: want id, platform, patch, cargo test args")
        rid, platform, patch, args = (p.strip() for p in parts)
        if not re.fullmatch(r"[A-Za-z0-9._-]+", rid):
            raise Abort(f"manifest line {n}: bad id {rid!r}")
        if rid in seen:
            raise Abort(f"manifest line {n}: duplicate id {rid!r}")
        if platform not in PLATFORMS:
            raise Abort(f"manifest line {n}: platform must be one of {PLATFORMS}")
        if "/" in patch or "\\" in patch or patch.startswith("."):
            raise Abort(f"manifest line {n}: patch must be a plain file name in {MUTANTS_DIR}/")
        seen.add(rid)
        rows.append(Row(rid, platform, patch, args.split()))
    if not rows:
        raise Abort("manifest has no rows")
    return head[1], rows


def summarise(output: str) -> tuple[int, bool]:
    """Executed tests (passed + failed) and whether any suite reported FAILED."""
    executed, failed = 0, False
    for line in output.splitlines():
        m = SUMMARY_RE.match(line.strip())
        if m:
            executed += int(m.group(2)) + int(m.group(3))
            failed = failed or m.group(1) == "FAILED"
    return executed, failed


def evidence(output: str) -> list[str]:
    return [ln.rstrip() for ln in output.splitlines() if EVIDENCE_RE.search(ln)][:EVIDENCE_LINES]


FAILED_TEST_RE = re.compile(r"^test (.+) \.\.\. FAILED$")
SECTION_RE = re.compile(r"^---- (.+) stdout ----$")
DOCTEST_NAME_RE = re.compile(r" - (.* )?\(line \d+\)$")


def doctest_compile_failure(output: str) -> bool:
    """True when every failing test is a doctest whose own failure section carries
    rustdoc's compile marker: `--no-run` does not build doctests, so that is a
    compile failure, not a kill. One doctest assertion failure beside it is a kill."""
    failing = [m.group(1) for m in map(FAILED_TEST_RE.match, output.splitlines()) if m]
    if not failing or not all(DOCTEST_NAME_RE.search(n) for n in failing):
        return False
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        m = SECTION_RE.match(line)
        if m:
            current = sections.setdefault(m.group(1), [])
        elif line.startswith("failures:") or line.startswith("test result:"):
            current = None
        elif current is not None:
            current.append(line)
    return all("Couldn't compile the test." in "\n".join(sections.get(n, [])) for n in failing)


def classify_test(run: Outcome) -> Verdict:
    """Classifies a mutant's test run. A timeout is judged by the wrapper's flag,
    whatever exit code the killed process left (124, 137, 1, ...)."""
    executed, failed = summarise(run.output)
    if run.timed_out:
        return Verdict("VOID", "timeout", executed)
    if run.exit != 0 and failed:
        if doctest_compile_failure(run.output):
            return Verdict("VOID", "doctest-compile", executed)
        return Verdict("RED", "named test failed", executed, evidence(run.output))
    if run.exit == 0 and failed:
        # The harness and the exit code disagree; neither verdict can be trusted.
        return Verdict("ERROR", "exit 0 with a FAILED test summary", executed)
    if run.exit == 0 and executed >= 1:
        return Verdict("SURVIVED", "tests passed on the mutant", executed)
    if run.exit == 0:
        return Verdict("VOID", "no-tests", executed)
    return Verdict("ERROR", f"exit {run.exit} without a failed test summary", executed)


def classify_baseline(run: Outcome) -> Verdict | None:
    """None when the clean head is a usable baseline, else the VOID every row using it gets."""
    executed, _ = summarise(run.output)
    if run.timed_out:
        return Verdict("VOID", "baseline-timeout", executed)
    if run.exit != 0:
        return Verdict("VOID", "baseline-red", executed, evidence(run.output))
    if executed == 0:
        return Verdict("VOID", "baseline-no-tests", executed)
    return None


def run_cmd(cmd: list[str], limit: int, log: Path) -> Outcome:
    """Runs cmd in its own process group; on timeout kills the whole tree and waits
    for it, so no test process outlives its row (or locks files on Windows)."""
    kw: dict = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as buf:
        proc = subprocess.Popen(cmd, stdout=buf, stderr=subprocess.STDOUT, **kw)
        timed_out = False
        try:
            proc.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        leaked = os.name != "nt" and not group_gone(proc.pid)
        buf.seek(0)
        output = buf.read()
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(f"$ {' '.join(cmd)}\n{output}", encoding="utf-8")
    finally:
        # A failed log write must not turn a leak into a plain error: that
        # would let the caller revert the tree under a live test process.
        if leaked:
            raise ProcessLeak(f"a process of `{' '.join(cmd)}` survived SIGKILL for 10 s; see {log}")
    return Outcome(proc.returncode, output, timed_out)


def group_gone(pgid: int) -> bool:
    """Kills what is left of the group (a test that spawned a server, say) and
    waits up to 10 s for it to be empty."""
    try:
        os.killpg(pgid, signal.SIGKILL)
        for _ in range(100):
            os.killpg(pgid, 0)
            time.sleep(0.1)
    except ProcessLookupError:
        return True
    return False


def reverting(action):
    """Runs action, then reverts the tree -- unless a test process is still alive,
    in which case the tree is left alone and the batch aborts."""
    try:
        result = action()
    except ProcessLeak:
        raise
    except BaseException:
        revert()
        raise
    revert()
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan() -> list[Row]:
    """Integrity checks shared by `plan` and `run`. Any failure aborts the batch."""
    ref = os.environ.get("GITHUB_REF", "")
    if not REF_RE.match(ref):
        raise Abort(f"ref {ref!r} is not refs/heads/throwaway/mutants-<pr>")
    manifest = Path(MUTANTS_DIR, "manifest.tsv")
    if not manifest.is_file():
        raise Abort(f"{manifest} is missing")
    head_sha, rows = parse_manifest(manifest.read_text(encoding="utf-8"))
    parent = git("rev-parse", "HEAD^")
    if parent != head_sha:
        raise Abort(f"manifest head_sha {head_sha} is not the batch commit's parent {parent}")
    changed = [p for p in git("diff", "--name-only", "HEAD^", "HEAD").splitlines() if p]
    stray = [p for p in changed if not p.startswith(MUTANTS_DIR + "/") and p not in HARNESS]
    if stray:
        raise Abort(f"the batch commit may only add {MUTANTS_DIR}/ (and the harness); it also changes {stray}")
    # The harness that runs must be the reviewed one, whichever commit brought
    # it: the batch commit, or the source head itself (which may have edited it).
    git("fetch", "--quiet", "--depth=1", "origin", RELEASE_LINE)
    for path in HARNESS:
        if git("rev-parse", f"HEAD:{path}") != git("rev-parse", f"FETCH_HEAD:{path}", check=False):
            raise Abort(f"{path} differs from the reviewed copy on {RELEASE_LINE}")
    for row in rows:
        if not Path(MUTANTS_DIR, row.patch).is_file():
            raise Abort(f"row {row.id}: patch {row.patch} is missing")
    return rows


def header(rows: list[Row]) -> dict:
    manifest = Path(_batch["dir"], "manifest.tsv")
    return {
        "head_sha": _batch["head"] or git("rev-parse", "HEAD^"),
        "batch_sha": _batch["head"] or git("rev-parse", "HEAD"),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "runner": os.environ.get("RUNNER_NAME", ""),
        "manifest_sha256": sha256(manifest),
        "patch_sha256": {r.id: sha256(Path(_batch["dir"], r.patch)) for r in rows},
        "rustc": subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.strip(),
    }


def revert() -> None:
    git("reset", "--quiet", "--hard", "HEAD")
    git("clean", "-fdxq", "-e", "target", "-e", "mutants-out")


def judge(row: Row, cargo: list[str], logs: Path) -> Verdict:
    applied = subprocess.run(["git", "apply", str(Path(_batch["dir"], row.patch))], capture_output=True, text=True)
    if applied.returncode != 0:
        return Verdict("VOID", "apply")
    build = run_cmd([*cargo, "--no-run"], COMPILE_LIMIT, logs / f"{row.id}-compile.log")
    if build.timed_out:
        return Verdict("VOID", "compile-timeout")
    if build.exit != 0:
        return Verdict("VOID", "compile")
    return classify_test(run_cmd([*cargo, *row.args], TEST_LIMIT, logs / f"{row.id}.log"))


def run(platform: str, out: Path, source: str = "throwaway") -> int:
    planned = plan_pr() if source == "pr" else plan()
    rows = [r for r in planned if r.platform == platform]
    skipped = [r.id for r in planned if r.platform != platform]
    if source == "pr" and skipped:
        print(f"skipped {len(skipped)} {'/'.join(sorted({r.platform for r in planned} - {platform}))} row(s) "
              f"in PR mode (they run on the throwaway path): {skipped}", flush=True)
    meta = header(rows)
    logs = out / "logs"
    cargo = ["cargo", "test", "--all-features"]
    base = run_cmd([*cargo, "--no-run"], COMPILE_LIMIT, logs / "baseline-compile.log")
    if base.timed_out or base.exit != 0:
        raise Abort("the clean head does not compile; nothing can be classified")
    baselines: dict[tuple[str, ...], Verdict | None] = {}
    results = []
    for row in rows:
        key = tuple(row.args)
        if key not in baselines:
            n = len(baselines)
            baselines[key] = reverting(lambda: classify_baseline(
                run_cmd([*cargo, *row.args], TEST_LIMIT, logs / f"baseline-{n}.log")))
        verdict = baselines[key]
        if verdict is None:
            verdict = reverting(lambda: judge(row, cargo, logs))
        results.append({"id": row.id, "platform": platform, "args": " ".join(row.args), **verdict.__dict__})
        print(f"{row.id}: {verdict.result} ({verdict.detail})", flush=True)
    write_outputs(out, platform, meta, results)
    if source == "pr":
        errors = pr_batch_errors(results, read_expect(Path(_batch["dir"])))
        for e in errors:
            print(f"::error::{e}", file=sys.stderr)
        return 1 if errors else 0
    return 1 if any(r["result"] == "ERROR" for r in results) else 0


def write_outputs(out: Path, platform: str, meta: dict, results: list[dict]) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / f"mutants-{platform}.json").write_text(json.dumps({**meta, "results": results}, indent=2), encoding="utf-8")
    tsv = [f"# head_sha {meta['head_sha']} batch_sha {meta['batch_sha']} run {meta['run_id']} runner {meta['runner']}",
           "id\tplatform\tresult\tdetail\texecuted\targs"]
    tsv += [f"{r['id']}\t{platform}\t{r['result']}\t{r['detail']}\t{r['executed']}\t{r['args']}" for r in results]
    (out / f"mutants-{platform}.tsv").write_text("\n".join(tsv) + "\n", encoding="utf-8")
    md = [f"### Mutants ({platform}) at `{meta['head_sha']}`", "",
          "| id | result | detail | executed | args | evidence |", "|---|---|---|---|---|---|"]
    for r in results:
        ev = "<br>".join(e.replace("|", "\\|").replace("`", "'") for e in r["evidence"][:3])
        md.append(f"| {r['id']} | {r['result']} | {r['detail']} | {r['executed']} | `{r['args']}` | {ev} |")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n".join(md) + "\n")



# ---------------------------------------------------------------------------
# In-PR evidence (evidence.yml): the red-first check and PR-mode mutant
# batches. Both read their inputs from GitHub-provided SHAs in the
# environment, never from the tree's own claims, and both fail closed.

FILTER_RE = re.compile(r"^[A-Za-z0-9_:-]+$")
MAX_FILTERS = 20


def env_sha(name: str) -> str:
    value = os.environ.get(name, "")
    if not SHA_RE.match(value):
        raise Abort(f"{name} is not a 40-hex commit SHA: {value!r}")
    return value


def parse_filters(value: str) -> list[str]:
    """`Red-first: a::b, c::d` -> exact test names; data only, never shell text."""
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        raise Abort("the Red-first: trailer names no test")
    if len(items) > MAX_FILTERS:
        raise Abort(f"the Red-first: trailer names {len(items)} tests; at most {MAX_FILTERS}")
    bad = [v for v in items if not FILTER_RE.match(v)]
    if bad:
        raise Abort(f"Red-first: test names may use only [A-Za-z0-9_:-]; rejected {bad}")
    return items


def find_red_first(base: str, head: str) -> tuple[str, list[str]]:
    """The newest of the PR's own commits (first parent only: commits merged in
    from the base are not the PR's) that carries a Red-first: trailer."""
    for sha in git("rev-list", "--first-parent", f"{base}..{head}").split():
        value = git("log", "-1", "--format=%(trailers:key=Red-first,valueonly,separator=%x2C)", sha).strip()
        if value:
            return sha, parse_filters(value)
    raise Abort("no commit of this pull request carries a Red-first: trailer")


def judge_red(run: Outcome) -> Verdict:
    """Before the fix the named test must fail on its own assertion."""
    v = classify_test(run)
    if v.result == "RED" and v.executed == 1:
        return v
    if v.result == "RED":
        return Verdict("FAIL", f"{v.executed} tests ran; the name must select exactly one", v.executed)
    return Verdict("FAIL", f"not red before the fix: {v.result} ({v.detail})", v.executed, v.evidence)


def judge_green(run: Outcome) -> Verdict:
    """At the PR head the same test must pass, and be the only one selected."""
    v = classify_test(run)
    if v.result == "SURVIVED" and v.executed == 1:
        return Verdict("PASS", "passes at the head", 1)
    return Verdict("FAIL", f"not green at the head: {v.result} ({v.detail}, {v.executed} ran)", v.executed, v.evidence)


def redfirst(out: Path) -> int:
    base, head = env_sha("BASE_SHA"), env_sha("HEAD_SHA")
    red, filters = find_red_first(base, head)
    changed = git("diff", "--name-only", f"{red}^", red).splitlines()
    logs = out / "logs"
    cargo = ["cargo", "test", "--all-features"]
    results = []
    for phase, commit, judge_fn in (("red", red, judge_red), ("head", head, judge_green)):
        git("checkout", "--quiet", "--detach", commit)
        build = run_cmd([*cargo, "--no-run"], COMPILE_LIMIT, logs / f"{phase}-compile.log")
        for name in filters:
            if build.timed_out or build.exit != 0:
                # A compile error is never red: it proves nothing about the test.
                verdict = Verdict("FAIL", f"{phase} commit does not compile")
            else:
                verdict = judge_fn(run_cmd([*cargo, name, "--", "--exact"], TEST_LIMIT, logs / f"{phase}-{name}.log"))
            results.append({"phase": phase, "commit": commit, "test": name, **verdict.__dict__})
            print(f"{phase} {name}: {verdict.result} ({verdict.detail})", flush=True)
    meta = {"base_sha": base, "head_sha": head, "red_sha": red, "red_changed_files": changed,
            "run_id": os.environ.get("GITHUB_RUN_ID", ""), "harness": os.environ.get("HARNESS_REF", "")}
    out.mkdir(parents=True, exist_ok=True)
    (out / "red-first.json").write_text(json.dumps({**meta, "results": results}, indent=2), encoding="utf-8")
    ok = all(r["result"] in ("RED", "PASS") for r in results)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Red-first at `{red}` -> head `{head}`: {'proven' if ok else 'NOT proven'}\n\n")
            f.write("| phase | test | result | detail |\n|---|---|---|---|\n")
            for r in results:
                f.write(f"| {r['phase']} | `{r['test']}` | {r['result']} | {r['detail'].replace('|', '/')} |\n")
    return 0 if ok else 1


def plan_pr() -> list[Row]:
    """PR mode: the manifest sits at .mutants/<PR number>/ in the PR itself, it
    names a commit the PR head descends from (a manifest cannot name the
    commit that carries it), and the checkout is exactly the PR head."""
    number = os.environ.get("PR_NUMBER", "")
    if not number.isdigit():
        raise Abort(f"PR_NUMBER is not a pull request number: {number!r}")
    head = env_sha("HEAD_SHA")
    if git("rev-parse", "HEAD") != head:
        raise Abort("the checkout is not the pull request head")
    folder = Path(MUTANTS_DIR, number)
    manifest = folder / "manifest.tsv"
    if not manifest.is_file():
        raise Abort(f"{manifest} is missing (the manifest lives under the PR's own number)")
    head_sha, rows = parse_manifest(manifest.read_text(encoding="utf-8"))
    if subprocess.run(["git", "merge-base", "--is-ancestor", head_sha, head], capture_output=True).returncode != 0:
        raise Abort(f"manifest head_sha {head_sha} is not an ancestor of the PR head {head}")
    for row in rows:
        if not (folder / row.patch).is_file():
            raise Abort(f"row {row.id}: patch {row.patch} is missing from {folder}")
    _batch.update(dir=str(folder), head=head)
    return rows


def read_expect(folder: Path) -> dict[str, str] | None:
    path = folder / "expect.tsv"
    if not path.is_file():
        return None
    out = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2 or parts[1].strip() not in ("RED", "SURVIVED"):
            raise Abort(f"{path} line {n}: want id<TAB>RED|SURVIVED")
        out[parts[0].strip()] = parts[1].strip()
    return out


def pr_batch_errors(results: list[dict], expect: dict[str, str] | None) -> list[str]:
    """PR mode fails on any ERROR, on a batch with no RED row, and (when an
    expect file is present) on a SURVIVED row not declared SURVIVED."""
    errors = [f"{r['id']}: ERROR ({r['detail']})" for r in results if r["result"] == "ERROR"]
    if not any(r["result"] == "RED" for r in results):
        errors.append("no mutant was killed (zero RED rows)")
    if expect is not None:
        errors += [f"{r['id']}: SURVIVED but not declared SURVIVED in expect.tsv"
                   for r in results if r["result"] == "SURVIVED" and expect.get(r["id"]) != "SURVIVED"]
    return errors


def evidence_self_test() -> list[str]:
    """Cases for the in-PR evidence modes: filters, red/green judging, the
    trailer walk over a real temporary repository, PR-mode planning and the
    PR batch verdict."""
    errs: list[str] = []
    for value, ok in (("a::b", True), ("a::b, c-d::e_f", True), ("", False), ("a b", False),
                      ("x;rm", False), ("$(id)", False), (",".join(["t"] * 21), False)):
        try:
            parse_filters(value)
            got = True
        except Abort:
            got = False
        if got != ok:
            errs.append(f"filters {value[:20]!r}: accepted={got}, expected {ok}")
    one_red = ("running 1 test\ntest t ... FAILED\n\n---- t stdout ----\nassertion `left == right` failed\n\n"
               "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n")
    two_red = one_red.replace("0 passed; 1 failed", "0 passed; 2 failed")
    one_ok = "running 1 test\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
    none = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
    for name, got, want in (
        ("red: one failing test", judge_red(Outcome(101, one_red, False)), "RED"),
        ("red: two tests selected", judge_red(Outcome(101, two_red, False)), "FAIL"),
        ("red: already passes", judge_red(Outcome(0, one_ok, False)), "FAIL"),
        ("red: selects nothing", judge_red(Outcome(0, none, False)), "FAIL"),
        ("red: timeout", judge_red(Outcome(137, one_red, True)), "FAIL"),
        ("head: passes", judge_green(Outcome(0, one_ok, False)), "PASS"),
        ("head: still fails", judge_green(Outcome(101, one_red, False)), "FAIL"),
        ("head: selects nothing", judge_green(Outcome(0, none, False)), "FAIL"),
        ("head: two tests selected", judge_green(Outcome(0, one_ok.replace("1 passed", "2 passed"), False)), "FAIL"),
    ):
        if got.result != want:
            errs.append(f"{name}: {got.result}, expected {want}")
    rows = [{"id": "k", "result": "RED", "detail": ""}, {"id": "n", "result": "SURVIVED", "detail": ""}]
    for name, results, expect, want_fail in (
        ("killed + declared survivor", rows, {"n": "SURVIVED"}, False),
        ("killed + survivor, no expect file", rows, None, False),
        ("undeclared survivor", rows, {"k": "RED"}, True),
        ("nothing killed", rows[1:], None, True),
        ("an ERROR row", rows + [{"id": "e", "result": "ERROR", "detail": "crash"}], None, True),
    ):
        if bool(pr_batch_errors(results, expect)) != want_fail:
            errs.append(f"PR batch {name}: failed={not want_fail}, expected {want_fail}")
    errs += walk_check()
    return errs


def walk_check() -> list[str]:
    """find_red_first and plan_pr over a real temporary repository."""
    errs: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp, "r")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

        def g(*args) -> str:
            done = subprocess.run(["git", *args], cwd=repo, env=env, capture_output=True, text=True)
            if done.returncode != 0:
                raise Abort(f"fixture `git {' '.join(args)}` failed: {done.stderr.strip()}")
            return done.stdout.strip()

        def commit(msg: str) -> str:
            g("commit", "-q", "--allow-empty", "-m", msg)
            return g("rev-parse", "HEAD")

        here, saved = os.getcwd(), dict(os.environ)
        try:
            repo.mkdir()
            g("init", "-q", "-b", "base")
            b1 = commit("b1")
            g("checkout", "-q", "-b", "pr")
            p1 = commit("p1\n\nRed-first: a::t1")
            commit("p2 fix")
            g("checkout", "-q", "base")
            b2 = commit("b2\n\nRed-first: base::not_ours")
            g("checkout", "-q", "pr")
            g("merge", "-q", "--no-edit", "base")
            head = commit("p3")
            os.chdir(repo)
            os.environ.clear()
            os.environ.update(env)
            # BASE_SHA older than the merged-in b2: only a first-parent walk skips b2's trailer.
            cases = (("own trailer behind a merged-in base trailer", b1, head, p1, ["a::t1"]),
                     ("diverged base (base tip includes b2)", b2, head, p1, ["a::t1"]))
            for name, base, tip, want_sha, want_filters in cases:
                try:
                    got = find_red_first(base, tip)
                    if got != (want_sha, want_filters):
                        errs.append(f"walk {name}: {got}, expected {(want_sha, want_filters)}")
                except Abort as exc:
                    errs.append(f"walk {name}: {exc}")
            p4 = commit("p4\n\nRed-first: a::t2, a::t3")
            if find_red_first(b2, p4) != (p4, ["a::t2", "a::t3"]):
                errs.append("walk: the newest trailer is not the one picked")
            g("checkout", "-q", "-b", "none", b2)
            bare = commit("no trailer")
            try:
                find_red_first(b2, bare)
                errs.append("walk: a PR without a trailer passed")
            except Abort:
                pass
            # PR mode: manifest under the PR number, naming an ancestor of the head.
            g("checkout", "-q", "pr")
            folder = repo / MUTANTS_DIR / "7"
            folder.mkdir(parents=True)
            (folder / "m.patch").write_text("x\n")
            (folder / "manifest.tsv").write_text(f"head_sha\t{p1}\nk\tlinux\tm.patch\ta::t1\n")
            g("add", "-A")
            tip = commit("mutants")
            os.environ.update(PR_NUMBER="7", HEAD_SHA=tip)
            try:
                if [r.id for r in plan_pr()] != ["k"]:
                    errs.append("plan_pr: rows not read")
            except Abort as exc:
                errs.append(f"plan_pr on a valid batch: {exc}")
            (folder / "manifest.tsv").write_text(f"head_sha\t{'0' * 40}\nk\tlinux\tm.patch\ta::t1\n")
            g("add", "-A")
            tip = commit("bad head")
            os.environ["HEAD_SHA"] = tip
            try:
                plan_pr()
                errs.append("plan_pr: a manifest naming a non-ancestor passed")
            except Abort:
                pass
            os.environ["PR_NUMBER"] = "8"
            try:
                plan_pr()
                errs.append("plan_pr: a missing .mutants/<number>/ manifest passed")
            except Abort:
                pass
        except Abort as exc:
            errs.append(str(exc))
        finally:
            os.chdir(here)
            os.environ.clear()
            os.environ.update(saved)
            _batch.update(dir=MUTANTS_DIR, head=None)
    return errs


def self_test() -> int:
    ok = "running 3 tests\ntest a ... ok\n\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n"
    empty = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out\n"
    ignored = "running 2 tests\n\ntest result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out\n"
    red = ("running 1 test\ntest t ... FAILED\n\nfailures:\n\n---- t stdout ----\n"
           "thread 't' panicked at src/x.rs:9:5:\nassertion `left == right` failed\n  left: 1\n right: 2\n\n"
           "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out\n")
    doc_compile = ("running 1 test\ntest src/lib.rs - (line 3) ... FAILED\n\nfailures:\n\n"
                   "---- src/lib.rs - (line 3) stdout ----\nerror: expected one of `.`, `;`\n"
                   "Couldn't compile the test.\n\n"
                   "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
    doc_red = ("running 1 test\ntest src/lib.rs - add (line 3) ... FAILED\n\nfailures:\n\n"
               "---- src/lib.rs - add (line 3) stdout ----\nassertion `left == right` failed\n\n"
               "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
    crash = "running 1 test\nerror: test failed, to rerun pass `--lib`\nprocess didn't exit successfully (signal: 11, SIGSEGV)\n"
    cases = [
        ("killed mutant", classify_test(Outcome(101, empty + red, False)), "RED"),
        ("surviving mutant", classify_test(Outcome(0, ok + empty, False)), "SURVIVED"),
        ("filter matches nothing", classify_test(Outcome(0, empty, False)), "VOID"),
        ("only ignored tests", classify_test(Outcome(0, ignored, False)), "VOID"),
        ("crash without summary", classify_test(Outcome(101, crash, False)), "ERROR"),
        ("timeout after failure output, exit 124", classify_test(Outcome(124, red, True)), "VOID"),
        ("timeout, SIGKILL exit 137", classify_test(Outcome(137, ok, True)), "VOID"),
        ("timeout, killed by signal", classify_test(Outcome(-9, "", True)), "VOID"),
        ("FAILED summary but exit 0", classify_test(Outcome(0, red, False)), "ERROR"),
        ("doctest does not compile", classify_test(Outcome(101, doc_compile, False)), "VOID"),
        ("doctest assertion fails", classify_test(Outcome(101, doc_red, False)), "RED"),
        ("doctest compile error with an error code", classify_test(Outcome(101, doc_compile.replace(
            "error: expected one of `.`, `;`", "error[E0308]: mismatched types").replace(
            "src/lib.rs - (line 3)", "src/lib.rs - add (line 3)"), False)), "VOID"),
        ("doctest compile failure beside a real failure", classify_test(Outcome(101, doc_compile + red, False)), "RED"),
        ("doctest compile failure beside a doctest assertion", classify_test(Outcome(101, doc_compile.replace(
            "test result: FAILED", "test src/lib.rs - sub (line 9) ... FAILED\n\n"
            "---- src/lib.rs - sub (line 9) stdout ----\nassertion `left == right` failed\n\ntest result: FAILED"), False)), "RED"),
        ("red baseline", classify_baseline(Outcome(101, red, False)), "VOID"),
        ("baseline runs nothing", classify_baseline(Outcome(0, ignored, False)), "VOID"),
        ("baseline timeout", classify_baseline(Outcome(137, "", True)), "VOID"),
        ("usable baseline", classify_baseline(Outcome(0, ok, False)), None),
    ]
    rc = 0
    for name, got, want in cases:
        result = got.result if got is not None else None
        if result != want:
            print(f"self-test: {name}: expected {want}, got {result}", file=sys.stderr)
            rc = 1
    if not any("assertion" in line for line in classify_test(Outcome(101, red, False)).evidence):
        print("self-test: RED evidence lost the assertion text", file=sys.stderr)
        rc = 1
    sha = "a" * 40
    good = f"head_sha\t{sha}\n# note\nm1\tlinux\tm1.patch\t--lib foo::bar -- --exact\n"
    if [r.args for r in parse_manifest(good)[1]] != [["--lib", "foo::bar", "--", "--exact"]]:
        print("self-test: manifest args not parsed as the line remainder", file=sys.stderr)
        rc = 1
    bad = {
        "duplicate id": good + "m1\tlinux\tm2.patch\tx\n",
        "unlisted platform": f"head_sha\t{sha}\nm1\tmacos\tm1.patch\tx\n",
        "patch outside the mutants dir": f"head_sha\t{sha}\nm1\tlinux\tsub/x.patch\tx\n",
        "no args": f"head_sha\t{sha}\nm1\tlinux\tm1.patch\t \n",
        "short sha": "head_sha\tabc\nm1\tlinux\tm1.patch\tx\n",
        "no rows": f"head_sha\t{sha}\n",
    }
    for name, text in bad.items():
        try:
            parse_manifest(text)
        except Abort:
            continue
        print(f"self-test: manifest with {name} was accepted", file=sys.stderr)
        rc = 1
    refs_ok = ["refs/heads/throwaway/mutants-1473"]
    refs_bad = ["refs/heads/throwaway-mutants-1", "refs/heads/throwaway/mutantsX",
                "refs/heads/throwaway/mutants-1/x", "refs/tags/throwaway/mutants-1"]
    for ref in refs_ok + refs_bad:
        if bool(REF_RE.match(ref)) != (ref in refs_ok):
            print(f"self-test: ref {ref} misclassified", file=sys.stderr)
            rc = 1
    for err in evidence_self_test():
        print(f"self-test: evidence: {err}", file=sys.stderr)
        rc = 1
    if rc == 0:
        total = len(cases) + 2 + len(bad) + len(refs_ok) + len(refs_bad)
        print(f"self-test: {total} classifier, manifest and ref cases, plus the in-PR evidence cases, as expected")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["plan", "run", "redfirst"], nargs="?")
    ap.add_argument("--source", choices=["throwaway", "pr"], default="throwaway")
    ap.add_argument("--platform", choices=PLATFORMS)
    ap.add_argument("--out", type=Path, default=Path("mutants-out"))
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    try:
        if a.mode == "plan":
            rows = plan()
            lines = [f"has_{p}={'true' if any(r.platform == p for r in rows) else 'false'}" for p in PLATFORMS]
            print("\n".join(lines))
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            return 0
        if a.mode == "run" and a.platform:
            return run(a.platform, a.out, a.source)
        if a.mode == "redfirst":
            return redfirst(a.out)
        ap.error("need plan, run --platform P [--source pr], redfirst, or --self-test")
    except Abort as exc:
        print(f"::error::mutant batch aborted: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
