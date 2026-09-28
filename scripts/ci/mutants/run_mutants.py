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
    fetch_release_line()
    for path in HARNESS:
        if git("rev-parse", f"HEAD:{path}") != git("rev-parse", f"FETCH_HEAD:{path}", check=False):
            raise Abort(f"{path} differs from the reviewed copy on {RELEASE_LINE}")
    for row in rows:
        if not Path(MUTANTS_DIR, row.patch).is_file():
            raise Abort(f"row {row.id}: patch {row.patch} is missing")
    return rows


def fetch_release_line() -> None:
    """Fetches the release-line tip into FETCH_HEAD. `--depth=1` only in a
    checkout that is already shallow (a CI checkout): in a full clone it would
    make the object store shallow, and a local run shares that store with every
    worktree of the repository, breaking their merge-bases."""
    depth = []
    git("fetch", "--quiet", *depth, "origin", RELEASE_LINE)


def fetch_check() -> list[str]:
    """Runs fetch_release_line in a full clone and in a shallow clone of a
    throwaway origin: the full clone must stay full (a local run shares the
    developer's object store), and both must resolve FETCH_HEAD."""
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        origin, full, shallow = (Path(tmp, n) for n in ("origin", "full", "shallow"))
        # Isolated from the caller's git setup: no inherited GIT_DIR, no global
        # or system config (signing, hooks, url rewrites).
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

        def run(*args, cwd=None):
            done = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
            if done.returncode != 0:
                raise Abort(f"fixture `{' '.join(args)}` failed: {done.stderr.strip()}")

        try:
            run("git", "init", "-q", "-b", RELEASE_LINE, str(origin))
            for n in (1, 2):
                run("git", "commit", "-q", "--allow-empty", "-m", f"c{n}", cwd=origin)
            url = origin.as_uri()
            run("git", "clone", "-q", url, str(full))
            run("git", "clone", "-q", "--depth=1", url, str(shallow))
            # A new tip after cloning: a depth-1 fetch brings 1 commit of history,
            # a plain fetch into the shallow clone would bring 2 (tip + old tip).
            run("git", "commit", "-q", "--allow-empty", "-m", "c3", cwd=origin)
        except Abort as exc:
            return [str(exc)]
        here = os.getcwd()
        for clone, want, history in ((full, "false", "3"), (shallow, "true", "1")):
            os.chdir(clone)
            try:
                fetch_release_line()
                if git("rev-parse", "--is-shallow-repository") != want:
                    errors.append(f"{clone.name} clone: shallow={want!r} expected after the fetch")
                if git("rev-list", "--count", "FETCH_HEAD") != history:
                    errors.append(f"{clone.name} clone: FETCH_HEAD history is not {history} commit(s)")
            except Abort as exc:
                errors.append(f"{clone.name} clone: {exc}")
            finally:
                os.chdir(here)
    return errors


def header(rows: list[Row]) -> dict:
    manifest = Path(MUTANTS_DIR, "manifest.tsv")
    return {
        "head_sha": git("rev-parse", "HEAD^"),
        "batch_sha": git("rev-parse", "HEAD"),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "runner": os.environ.get("RUNNER_NAME", ""),
        "manifest_sha256": sha256(manifest),
        "patch_sha256": {r.id: sha256(Path(MUTANTS_DIR, r.patch)) for r in rows},
        "rustc": subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.strip(),
    }


def revert() -> None:
    git("reset", "--quiet", "--hard", "HEAD")
    git("clean", "-fdxq", "-e", "target", "-e", "mutants-out")


def judge(row: Row, cargo: list[str], logs: Path) -> Verdict:
    applied = subprocess.run(["git", "apply", str(Path(MUTANTS_DIR, row.patch))], capture_output=True, text=True)
    if applied.returncode != 0:
        return Verdict("VOID", "apply")
    build = run_cmd([*cargo, "--no-run"], COMPILE_LIMIT, logs / f"{row.id}-compile.log")
    if build.timed_out:
        return Verdict("VOID", "compile-timeout")
    if build.exit != 0:
        return Verdict("VOID", "compile")
    return classify_test(run_cmd([*cargo, *row.args], TEST_LIMIT, logs / f"{row.id}.log"))


def run(platform: str, out: Path) -> int:
    rows = [r for r in plan() if r.platform == platform]
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
    for err in fetch_check():
        print(f"self-test: release-line fetch: {err}", file=sys.stderr)
        rc = 1
    if rc == 0:
        total = len(cases) + 2 + len(bad) + len(refs_ok) + len(refs_bad) + 2
        print(f"self-test: {total} classifier, manifest and ref cases as expected")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["plan", "run"], nargs="?")
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
            return run(a.platform, a.out)
        ap.error("need plan, run --platform P, or --self-test")
    except Abort as exc:
        print(f"::error::mutant batch aborted: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
