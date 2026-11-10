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
HARNESS = (".github/workflows/mutants.yml", "scripts/ci/mutants/run_mutants.py",
           ".github/actions/add-swap/action.yml")
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


def run_cmd(cmd: list[str], limit: int, log: Path, env: dict | None = None) -> Outcome:
    """Runs cmd in its own process group; on timeout kills the whole tree and waits
    for it, so no test process outlives its row (or locks files on Windows)."""
    kw: dict = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as buf:
        proc = subprocess.Popen(cmd, stdout=buf, stderr=subprocess.STDOUT, env=env, **kw)
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
    depth = ["--depth=1"] if git("rev-parse", "--is-shallow-repository") == "true" else []
    git("fetch", "--quiet", *depth, "origin", RELEASE_LINE)


FETCH_CASES = 2  # full clone, shallow clone


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

        def fixture_git(*args, cwd=None):
            done = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)
            if done.returncode != 0:
                raise Abort(f"fixture `git {' '.join(args)}` failed: {done.stderr.strip()}")

        try:
            fixture_git("init", "-q", "-b", RELEASE_LINE, str(origin))
            for n in (1, 2):
                fixture_git("commit", "-q", "--allow-empty", "-m", f"c{n}", cwd=origin)
            url = origin.as_uri()
            fixture_git("clone", "-q", url, str(full))
            fixture_git("clone", "-q", "--depth=1", url, str(shallow))
            # A new tip after cloning: a depth-1 fetch brings 1 commit of history,
            # a plain fetch into the shallow clone would bring 2 (tip + old tip).
            fixture_git("commit", "-q", "--allow-empty", "-m", "c3", cwd=origin)
        except Abort as exc:
            return [str(exc)]
        # fetch_release_line runs through the module's git(), which reads the
        # process environment: give it the same isolated one for the duration.
        here, saved = os.getcwd(), dict(os.environ)
        os.environ.clear()
        os.environ.update(env)
        try:
            for clone, want, history in ((full, "false", "3"), (shallow, "true", "1")):
                os.chdir(clone)
                try:
                    fetch_release_line()
                    got = git("rev-parse", "--is-shallow-repository")
                    if got != want:
                        errors.append(f"{clone.name} clone: shallow={got!r} after the fetch, expected {want!r}")
                    got = git("rev-list", "--count", "FETCH_HEAD")
                    if got != history:
                        errors.append(f"{clone.name} clone: FETCH_HEAD history {got} commit(s), expected {history}")
                except Abort as exc:
                    errors.append(f"{clone.name} clone: {exc}")
                finally:
                    os.chdir(here)
        finally:
            os.environ.clear()
            os.environ.update(saved)
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


# ---------------------------------------------------------------------------
# Schemata mode: every mutant of a batch in ONE `--cfg mutants` build.
#
# A batch carries `.mutants/schemata.tsv` instead of a patch manifest. The
# source wraps each mutated expression in `mutant!("ID", mutated, original)`
# (src/mutant.rs); one all-targets build with `--cfg mutants` carries them
# all, and each test process switches on at most one through
# MCP_GATEWAY_MUTANT. Each expected row runs by exact name, alone.
#
# Spec:   #features <cargo features>          (optional, once)
#         #mutant <ID> [multi=<n>]            (one per mutant)
#         <executable>\t<exact test name>\t<file:line>   (its rows)
#
# The verdicts are stricter than patch mode's: a row only counts as killed if
# it FAILED and panicked at the file:line its spec names, and anything
# unclear is ERROR, never VOID. The table, checked in order:
#   baseline failed, or the build failed    -> run refused (exit 1)
#   output unparseable, a row missing or reported twice, a timeout, an abort
#   or signal, a panic elsewhere             -> ERROR
#   every row ran and one PASSED             -> SURVIVED
#   every row FAILED at its spec location    -> KILLED
# Exit 0 only when the baseline passed and every spec mutant has exactly one
# verdict and it is KILLED; refusals before any run exit 2.
# ---------------------------------------------------------------------------

SCHEMATA_SPEC = "schemata.tsv"
MUTANT_ENV = "MCP_GATEWAY_MUTANT"
# Exists only in a `--cfg mutants` build: the proof the cfg took (V1).
CFG_PROBE = "mutant::mutants_build::only_the_named_site_switches_on"
# The gateway library's test executable, by target name: a workspace build also
# produces other libraries' test executables (crates/gateway-core), and the
# probe and the site listing live only in this one.
LIB_TARGET = "mcp_gateway"
MUTANT_HEAD_RE = re.compile(r"^#mutant\s+([A-Za-z0-9._-]+)(?:\s+multi=([1-9][0-9]*))?\s*$")
LOCATION_RE = re.compile(r"^[^\s:]+\.rs:[1-9][0-9]*$")
SITE_LINE_RE = re.compile(r"^MUTANT-SITE (\S+) (\S+):(\d+)$")
RECORD_RE = re.compile(r"^test (.+?) \.\.\.(?: (.*))?$")
RESULT_RE = re.compile(r"^(ok|FAILED|ignored)(?:, .*)?$")


def records(output: str) -> list[tuple[str, str]]:
    """libtest's per-test records, (name, ok|FAILED|ignored), in order.

    A line written straight to stderr while a test runs can land between
    `test NAME ... ` and its result in the merged output, glued after the
    prefix or on lines of its own. Then the record ends at the next line that
    is a result word alone; lines between are noise. A prefix no result
    follows yields no record (libtest-record-parse family)."""
    found: list[tuple[str, str]] = []
    held: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if held is not None and (r := RESULT_RE.match(line)):
            found.append((held, r.group(1)))
            held = None
            continue
        m = RECORD_RE.match(line)
        if not m:
            continue
        r = RESULT_RE.match(m.group(2) or "")
        if r:
            found.append((m.group(1), r.group(1)))
            held = None
        else:
            held = m.group(1)
    return found
PANIC_RE = re.compile(r"^thread '([^']+)'(?: \(\d+\))? panicked at ([^:\s]+):(\d+):\d+:")


class BaselineRefused(Exception):
    """The all-off baseline did not pass every expected row: no verdicts (exit 1)."""


@dataclass
class SpecRow:
    executable: str
    test: str
    location: str


@dataclass
class SpecMutant:
    id: str
    multi: int
    rows: list[SpecRow]


def parse_spec(text: str) -> tuple[str | None, dict[str, SpecMutant]]:
    """The features line and the mutants, in order. Any malformed line refuses."""
    features: str | None = None
    mutants: dict[str, SpecMutant] = {}
    current: SpecMutant | None = None
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.startswith("#features"):
            if features is not None or mutants:
                raise Abort(f"spec line {n}: #features must come once, first")
            features = line[len("#features"):].strip()
            continue
        if line.startswith("#mutant"):
            m = MUTANT_HEAD_RE.match(line)
            if not m:
                raise Abort(f"spec line {n}: want `#mutant <ID> [multi=<n>]`")
            if m.group(1) in mutants:
                raise Abort(f"spec line {n}: mutant {m.group(1)} declared twice")
            current = SpecMutant(m.group(1), int(m.group(2) or 1), [])
            mutants[current.id] = current
            continue
        if line.startswith("#"):
            continue
        if current is None:
            raise Abort(f"spec line {n}: a row before any #mutant header")
        parts = line.split("\t")
        if len(parts) != 3 or not all(p.strip() for p in parts):
            raise Abort(f"spec line {n}: want executable, exact test name, file:line")
        exe, test, loc = (p.strip() for p in parts)
        if not LOCATION_RE.match(loc):
            raise Abort(f"spec line {n}: location {loc!r} is not file.rs:line")
        current.rows.append(SpecRow(exe, test, loc))
    if not mutants:
        raise Abort("the spec names no mutants")
    empty = [m.id for m in mutants.values() if not m.rows]
    if empty:
        raise Abort(f"mutants with no expected rows: {', '.join(empty)}")
    return features, mutants


def parse_sites(listing: str) -> list[tuple[str, str]]:
    """(id, path:line) per site from the library's site-listing test; refuses an
    incomplete listing (no completion marker)."""
    if "MUTANT-SITES-DONE" not in listing:
        raise Abort("the site listing did not complete")
    sites = []
    for line in listing.splitlines():
        m = SITE_LINE_RE.match(line.strip())
        if m:
            sites.append((m.group(1), f"{m.group(2)}:{m.group(3)}"))
    return sites


def reconcile(mutants: dict[str, SpecMutant], sites: list[tuple[str, str]]) -> None:
    """The spec's IDs must equal the source's site IDs, each with its count."""
    counts: dict[str, int] = {}
    for sid, _ in sites:
        counts[sid] = counts.get(sid, 0) + 1
    unknown = sorted(set(mutants) - set(counts))
    missing = sorted(set(counts) - set(mutants))
    if unknown:
        raise Abort(f"spec IDs no site carries: {', '.join(unknown)}")
    if missing:
        raise Abort(f"site IDs the spec does not name: {', '.join(missing)}")
    wrong = [f"{i} ({counts[i]} sites, spec says {m.multi})" for i, m in mutants.items() if counts[i] != m.multi]
    if wrong:
        raise Abort(f"site counts differ from the spec: {'; '.join(wrong)}")


def check_public_text(text: str, patterns: list[re.Pattern]) -> None:
    """The spec rides on a public branch: no private content in it (U5)."""
    for p in patterns:
        m = p.search(text)
        if m:
            raise Abort(f"the spec carries private content ({m.group(0).strip()!r}); keep ids and names out")


def classify_row(outcome: Outcome, test: str, location: str) -> str:
    """PASSED, FAILED_AT_SPEC, or ERROR:<why> for one exact-name row run."""
    if outcome.timed_out:
        return "ERROR:timeout"
    reports = [result for name, result in records(outcome.output) if name == test]
    if outcome.exit is None or outcome.exit < 0 or outcome.exit in (134, 137):
        return "ERROR:abort or signal"
    summaries = [m.groups() for line in outcome.output.splitlines() if (m := SUMMARY_RE.match(line.strip()))]
    if not summaries:
        return "ERROR:no result line"
    if not reports:
        return "ERROR:row did not run"
    if len(reports) > 1:
        return "ERROR:row reported twice"
    if reports[0] not in ("ok", "FAILED"):
        return f"ERROR:row {reports[0]}"
    # A split record can be completed by a stray result word on stderr, so the
    # record must agree with the exit code and with a summary of exactly this
    # one test (libtest-record-parse family).
    want = ("ok", "1", "0") if reports[0] == "ok" else ("FAILED", "0", "1")
    if (outcome.exit == 0) != (reports[0] == "ok") or want not in [g[:3] for g in summaries]:
        return "ERROR:record disagrees with the exit code or summary"
    if reports[0] == "ok":
        return "PASSED"
    panics = [f"{m.group(2)}:{m.group(3)}" for line in outcome.output.splitlines()
              if (m := PANIC_RE.match(line.strip())) and m.group(1) == test]
    if location in panics:
        return "FAILED_AT_SPEC"
    return f"ERROR:panicked at {', '.join(panics) or 'no location'}, spec {location}"


def mutant_verdict(row_results: list[str]) -> str:
    """The verdict table, in order: ERROR, then SURVIVED, then KILLED."""
    if any(r.startswith("ERROR") for r in row_results):
        return "ERROR"
    if any(r == "PASSED" for r in row_results):
        return "SURVIVED"
    return "KILLED"


def check_baseline(row_results: dict[str, str]) -> None:
    """Every expected row must pass with no mutant on, or the batch is refused."""
    bad = [f"{name}: {r}" for name, r in row_results.items() if r != "PASSED"]
    if bad:
        raise BaselineRefused("the baseline did not pass: " + "; ".join(bad))


def schemata_exit(mutants: dict[str, SpecMutant], verdicts: list[tuple[str, str]]) -> int:
    """Exit 0 only when every spec mutant has exactly one verdict and it is KILLED."""
    seen: dict[str, int] = {}
    for mid, _ in verdicts:
        seen[mid] = seen.get(mid, 0) + 1
    if set(seen) != set(mutants) or any(c != 1 for c in seen.values()):
        return 1
    return 0 if all(v == "KILLED" for _, v in verdicts) else 1


def hygiene_patterns() -> list[re.Pattern]:
    """The repository's private-content patterns, from the release line's copy
    (the ticket-id and reviewer-name rules), as Python regexes."""
    text = git("show", "FETCH_HEAD:scripts/dev/public-hygiene-patterns.sh")
    posix = {"[:alnum:]": "A-Za-z0-9", "[:alpha:]": "A-Za-z", "[:space:]": r"\s", "[:digit:]": "0-9"}
    found = []
    for name in ("ticket_id_regex", "reviewer_regex"):
        m = re.search(rf"^{name}='(.*)'$", text, re.MULTILINE)
        if not m:
            raise Abort(f"public-hygiene-patterns.sh on {RELEASE_LINE} has no {name}")
        expr = m.group(1)
        for k, v in posix.items():
            expr = expr.replace(k, v)
        found.append(re.compile(expr, re.IGNORECASE if name == "reviewer_regex" else 0))
    return found


def plan_schemata() -> tuple[str | None, dict[str, SpecMutant]]:
    """The schemata batch's integrity checks; any failure refuses (exit 2)."""
    ref = os.environ.get("GITHUB_REF", "")
    if not REF_RE.match(ref):
        raise Abort(f"ref {ref!r} is not refs/heads/throwaway/mutants-<pr>")
    spec_path = Path(MUTANTS_DIR, SCHEMATA_SPEC)
    text = spec_path.read_text(encoding="utf-8")
    head_line, _, rest = text.lstrip().partition("\n")
    head = head_line.split("\t")
    if len(head) != 2 or head[0] != "head_sha" or not SHA_RE.match(head[1]):
        raise Abort(f"{spec_path} line 1 must be head_sha<TAB><40-hex sha>")
    if git("rev-parse", "HEAD^") != head[1]:
        raise Abort(f"spec head_sha {head[1]} is not the batch commit's parent")
    changed = [p for p in git("diff", "--name-only", "HEAD^", "HEAD").splitlines() if p]
    stray = [p for p in changed if not p.startswith(MUTANTS_DIR + "/") and p not in HARNESS]
    if stray:
        raise Abort(f"the batch commit may only add {MUTANTS_DIR}/ (and the harness); it also changes {stray}")
    fetch_release_line()
    for path in HARNESS:
        if git("rev-parse", f"HEAD:{path}") != git("rev-parse", f"FETCH_HEAD:{path}", check=False):
            raise Abort(f"{path} differs from the reviewed copy on {RELEASE_LINE}")
    check_public_text(text, hygiene_patterns())
    return parse_spec(rest)


def build_schemata(features: str | None, logs: Path) -> dict[str, dict]:
    """One `--cfg mutants` build of every test target. Returns target name ->
    {path, sha256, kinds}. A failed build refuses the run and names its sites."""
    env = dict(os.environ)
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " --cfg mutants").strip()
    env.pop(MUTANT_ENV, None)
    feats = ["--features", features] if features else ["--all-features"]
    cmd = ["cargo", "test", "--workspace", "--all-targets", "--no-run", "--message-format=json",
           "--target-dir", "target/mutants-cfg", *feats]
    built = run_cmd(cmd, COMPILE_LIMIT, logs / "schemata-build.log", env)
    if built.timed_out or built.exit != 0:
        sites = sorted(set(re.findall(r"-->\s+(\S+\.rs:\d+)", built.output)))
        raise BaselineRefused(f"the --cfg mutants build failed at {sites or 'an unknown site'}; "
                              "move those mutants to the patch flow and rerun the rest")
    artifacts: dict[str, dict] = {}
    for line in built.output.splitlines():
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") == "compiler-artifact" and msg.get("executable") and msg["profile"].get("test"):
            path = Path(msg["executable"])
            artifacts[msg["target"]["name"]] = {"path": str(path), "sha256": sha256(path),
                                                "kinds": msg["target"]["kind"]}
    return artifacts


def run_row(exe: str, test: str, mutant: str | None, logs: Path, tag: str) -> tuple[Outcome, float, list[str]]:
    env = dict(os.environ)
    env.pop(MUTANT_ENV, None)
    if mutant is not None:
        env[MUTANT_ENV] = mutant
    cmd = [exe, "--exact", test, "--test-threads=1"]
    start = time.monotonic()
    outcome = run_cmd(cmd, TEST_LIMIT, logs / f"{tag}.log", env)
    return outcome, round(time.monotonic() - start, 2), cmd


def run_schemata(out: Path) -> int:
    features, mutants = plan_schemata()
    return execute_schemata(features, mutants, out)


def library_executable(artifacts: dict[str, dict]) -> dict:
    """The gateway library's test executable, picked by target name."""
    lib = artifacts.get(LIB_TARGET)
    if lib is None or "lib" not in lib["kinds"]:
        libs = sorted(name for name, a in artifacts.items() if "lib" in a["kinds"])
        raise Abort(f"the build produced no {LIB_TARGET} library test executable (libraries: {libs})")
    return lib


def execute_schemata(features: str | None, mutants: dict[str, SpecMutant], out: Path) -> int:
    """Build, prove the cfg, reconcile, baseline, then each mutant (after plan)."""
    logs = out / "logs"
    artifacts = build_schemata(features, logs)
    named = sorted({r.executable for m in mutants.values() for r in m.rows})
    absent = [e for e in named if e not in artifacts]
    if absent:
        raise Abort(f"spec executables the build did not produce: {absent}")
    lib = library_executable(artifacts)
    listed = run_cmd([lib["path"], "--list", "--format", "terse"], TEST_LIMIT, logs / "list.log")
    if f"{CFG_PROBE}: test" not in listed.output.splitlines():
        raise Abort("the build has no --cfg mutants (the probe test is absent); check RUSTFLAGS")
    env = dict(os.environ, MCP_GATEWAY_MUTANT_LIST="1")
    env.pop(MUTANT_ENV, None)
    listing = run_cmd([lib["path"], "--exact", "mutant_scan::tests::list_mutant_sites", "--nocapture"],
                      TEST_LIMIT, logs / "sites.log", env)
    reconcile(mutants, parse_sites(listing.output))
    print(f"{len(mutants)} mutants to run", flush=True)
    records: list[dict] = []
    baseline: dict[str, str] = {}
    rows = [(m, r) for m in mutants.values() for r in m.rows]
    for i, (m, r) in enumerate(rows):
        outcome, secs, cmd = run_row(artifacts[r.executable]["path"], r.test, None, logs, f"baseline-{i}")
        baseline[r.test] = classify_row(outcome, r.test, r.location)
        records.append({"mutant": "baseline", "test": r.test, "command": cmd, "exit": outcome.exit,
                        "seconds": secs, "result": baseline[r.test], "log": f"logs/baseline-{i}.log"})
    check_baseline(baseline)
    verdicts: list[tuple[str, str]] = []
    for m in mutants.values():
        results = []
        for j, r in enumerate(m.rows):
            outcome, secs, cmd = run_row(artifacts[r.executable]["path"], r.test, m.id, logs, f"{m.id}-{j}")
            res = classify_row(outcome, r.test, r.location)
            results.append(res)
            records.append({"mutant": m.id, "test": r.test, "command": cmd, "exit": outcome.exit,
                            "seconds": secs, "result": res, "location": r.location,
                            "executable_sha256": artifacts[r.executable]["sha256"], "log": f"logs/{m.id}-{j}.log"})
        verdicts.append((m.id, mutant_verdict(results)))
        print(f"{m.id}: {verdicts[-1][1]} ({'; '.join(results)})", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    (out / "mutants-schemata.json").write_text(json.dumps({
        "head_sha": git("rev-parse", "HEAD^", check=False), "batch_sha": git("rev-parse", "HEAD", check=False),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""), "queue_wait_seconds": os.environ.get("MUTANTS_QUEUE_WAIT", ""),
        "executables": artifacts, "verdicts": dict(verdicts), "rows": records}, indent=2), encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Mutants (schemata)\n\n| id | verdict |\n|---|---|\n")
            f.write("".join(f"| {i} | {v} |\n" for i, v in verdicts))
            f.write(f"\nqueue wait: {os.environ.get('MUTANTS_QUEUE_WAIT', 'unknown')} s\n")
    return schemata_exit(mutants, verdicts)


def schemata_self_test() -> tuple[int, list[str]]:
    """(cases run, failures) for the schemata mode's decisions (R1-R30)."""
    def out(test: str, status: str, panic: str | None = None, extra: str = "") -> str:
        lines = ["running 1 test", f"test {test} ... {status}", ""]
        if status == "FAILED":
            lines += ["failures:", "", f"---- {test} stdout ----"]
            if panic:
                lines.append(f"thread '{test}' (1234) panicked at {panic}:5:")
            lines += ["assertion `left == right` failed", ""]
        p, f = (1, 0) if status == "ok" else (0, 1)
        res = "ok" if status == "ok" else "FAILED"
        lines.append(f"test result: {res}. {p} passed; {f} failed; 0 ignored; 0 measured; 9 filtered out")
        return "\n".join(lines) + "\n" + extra

    t, loc = "m::t1", "src/x.rs:9"
    spec_ok = f"#mutant A\nlib\t{t}\t{loc}\n#mutant B multi=2\nlib\tm::t2\tsrc/y.rs:4\nlib\tm::t3\tsrc/y.rs:7\n"
    sites_ok = [("A", "src/x.rs:3"), ("B", "src/y.rs:1"), ("B", "src/y.rs:2")]
    failures: list[str] = []
    n = 0

    def refuses(name: str, fn) -> None:
        nonlocal n
        n += 1
        try:
            fn()
        except Abort:
            return
        failures.append(f"{name}: not refused")

    def expect(name: str, got, want) -> None:
        nonlocal n
        n += 1
        if got != want:
            failures.append(f"{name}: expected {want!r}, got {got!r}")

    refuses("R1 empty spec", lambda: parse_spec("\n#features x\n"))
    other_lib = {"path": "core", "sha256": "", "kinds": ["lib"]}
    gateway_lib = {"path": "gw", "sha256": "", "kinds": ["lib"]}
    expect("R28 the gateway library is picked by name, not the first library",
           library_executable({"gateway_core": other_lib, LIB_TARGET: gateway_lib})["path"], "gw")
    refuses("R29 a build without the gateway library", lambda: library_executable({"gateway_core": other_lib}))
    refuses("R30 an mcp_gateway target that is not a library",
            lambda: library_executable({LIB_TARGET: {"path": "gw", "sha256": "", "kinds": ["test"]}}))
    refuses("R2 a mutant with no rows", lambda: parse_spec("#mutant A\n#mutant B\nlib\tt\tsrc/x.rs:1\n"))
    _, ms = parse_spec(spec_ok)
    refuses("R3 a spec ID no site carries", lambda: reconcile({**ms, "Z": SpecMutant("Z", 1, [])}, sites_ok))
    refuses("R4 a site ID the spec omits", lambda: reconcile(ms, sites_ok + [("C", "src/z.rs:1")]))
    refuses("R5 a mutant declared twice", lambda: parse_spec("#mutant A\nlib\tt\tsrc/x.rs:1\n#mutant A\nlib\tt\tsrc/x.rs:1\n"))
    refuses("R6 two sites, no multi", lambda: reconcile(ms, sites_ok + [("A", "src/q.rs:8")]))
    refuses("R7 multi=2 with three sites", lambda: reconcile(ms, sites_ok + [("B", "src/y.rs:3")]))
    refuses("R8 a nested duplicate site", lambda: reconcile(ms, sites_ok + [("A", "src/m.rs:2")]))
    refuses("a row with a bad location", lambda: parse_spec("#mutant A\nlib\tt\tx.rs\n"))
    refuses("a row before any header", lambda: parse_spec("lib\tt\tsrc/x.rs:1\n#mutant A\n"))
    refuses("an incomplete site listing", lambda: parse_sites("MUTANT-SITE A src/x.rs:3\n"))
    expect("reconciled spec", reconcile(ms, sites_ok), None)
    expect("site listing parsed", parse_sites("noise\nMUTANT-SITE A src/x.rs:3\nMUTANT-SITES-DONE\n"),
           [("A", "src/x.rs:3")])
    n += 1
    try:
        check_baseline({t: classify_row(Outcome(101, out(t, "FAILED", "src/x.rs:9"), False), t, loc)})
        failures.append("R10/R24 a failing baseline row was accepted")
    except BaselineRefused:
        pass
    for name, outcome in [("R25 baseline timeout", Outcome(None, "", True)),
                          ("R26 baseline ran no test", Outcome(0, "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n", False)),
                          ("R27 baseline row twice", Outcome(0, out(t, "ok") + out(t, "ok"), False))]:
        n += 1
        try:
            check_baseline({t: classify_row(outcome, t, loc)})
            failures.append(f"{name}: accepted")
        except BaselineRefused:
            pass
    expect("baseline passes", check_baseline({t: classify_row(Outcome(0, out(t, "ok"), False), t, loc)}), None)
    killed = classify_row(Outcome(101, out(t, "FAILED", "src/x.rs:9"), False), t, loc)
    expect("R11 failed at the spec location", killed, "FAILED_AT_SPEC")
    expect("R11 KILLED", mutant_verdict([killed]), "KILLED")
    expect("R12 one row passed", mutant_verdict([killed, classify_row(Outcome(0, out(t, "ok"), False), t, loc)]), "SURVIVED")
    expect("R13 panicked elsewhere", mutant_verdict([classify_row(Outcome(101, out(t, "FAILED", "src/x.rs:10"), False), t, loc)]), "ERROR")
    expect("R14 the row did not run", classify_row(Outcome(0, out("m::other", "ok"), False), t, loc), "ERROR:row did not run")
    expect("R15 the row reported twice", classify_row(Outcome(101, out(t, "FAILED", "src/x.rs:9") * 2, False), t, loc), "ERROR:row reported twice")
    expect("R16 aborted, exit 134", mutant_verdict([classify_row(Outcome(134, f"running 1 test\ntest {t} ... ", False), t, loc)]), "ERROR")
    expect("R16 no result line", classify_row(Outcome(101, f"running 1 test\ntest {t} ... FAILED\n", False), t, loc), "ERROR:no result line")
    expect("R17 timeout is never KILLED", mutant_verdict([classify_row(Outcome(124, out(t, "FAILED", "src/x.rs:9"), True), t, loc)]), "ERROR")
    expect("R18 all killed exits 0", schemata_exit(ms, [("A", "KILLED"), ("B", "KILLED")]), 0)
    expect("R18 a missing verdict exits 1", schemata_exit(ms, [("A", "KILLED")]), 1)
    expect("R18 a duplicated verdict exits 1", schemata_exit(ms, [("A", "KILLED"), ("A", "KILLED"), ("B", "KILLED")]), 1)
    expect("R18 an extra verdict exits 1", schemata_exit(ms, [("A", "KILLED"), ("B", "KILLED"), ("C", "KILLED")]), 1)
    expect("R12 a survivor exits 1", schemata_exit(ms, [("A", "KILLED"), ("B", "SURVIVED")]), 1)
    b2 = classify_row(Outcome(101, out("m::t2", "FAILED", "src/y.rs:4"), False), "m::t2", "src/y.rs:4")
    b3 = classify_row(Outcome(101, out("m::t3", "FAILED", "src/y.rs:7"), False), "m::t3", "src/y.rs:7")
    b3ok = classify_row(Outcome(0, out("m::t3", "ok"), False), "m::t3", "src/y.rs:7")
    expect("R19 multi=2, both sites' rows fail", mutant_verdict([b2, b3]), "KILLED")
    expect("R19 multi=2, one site's rows pass", mutant_verdict([b2, b3ok]), "SURVIVED")
    priv = [re.compile(r"(^|[^A-Za-z0-9])MIK-[0-9]+")]
    refuses("R22 a ticket id in the spec", lambda: check_public_text("#mutant A\n# see MI" "K-1234\n", priv))
    expect("R22 a clean spec", check_public_text(spec_ok, priv), None)
    # R31-R35: a line written straight to stderr while a row runs can land
    # between libtest's `test NAME ... ` and its result (fixtures/libtest).
    fx = Path(__file__).resolve().parent / "fixtures" / "libtest"
    h12 = "gateway::server::test_seams::health_start_tests::h12_both_files_are_saved_before_serving_and_the_stop_is_clean"
    meter = ("gateway::router::stored_read_account_tests::http_nonce_alloc::"
             "a_refused_meta_call_costs_its_parse_plus_a_fixed_cap")
    for name, file, exit_code, test, want in [
        ("R31 a stderr line glued after the prefix, then ok", "midline-stderr.txt", 0, h12, "PASSED"),
        ("R32 forwarded measurement lines, then ok", "alloc-meter-one-thread.txt", 0, meter, "PASSED"),
        ("R33 a stderr line, then FAILED at the spec line", "failed-after-noise.txt", 101, "m::row_that_fails",
         "FAILED_AT_SPEC"),
        ("R34 a caught panic printed by a passing row", "panic-in-passing-test.txt", 0,
         "m::passes_after_a_caught_panic", "PASSED"),
        ("R35 a filter that matched nothing", "zero-match.txt", 0, h12, "ERROR:row did not run"),
    ]:
        text = (fx / file).read_text(encoding="utf-8")
        expect(name, classify_row(Outcome(exit_code, text, False), test, "src/x.rs:9"), want)
    for name, file, exit_code, want in [
        ("R37 a stray ok line before the real FAILED is no pass", "stray-ok-before-failed.txt", 101,
         "ERROR:record disagrees with the exit code or summary"),
        ("R38 a stray FAILED line before the real ok is no kill", "stray-failed-before-ok.txt", 0,
         "ERROR:record disagrees with the exit code or summary"),
    ]:
        text = (fx / file).read_text(encoding="utf-8")
        expect(name, classify_row(Outcome(exit_code, text, False), "m::row_with_noise", "src/x.rs:9"), want)
    expect("R36 a held prefix with no result stays unrun",
           classify_row(Outcome(0, f"running 1 test\ntest {t} ... noise\n\ntest result: ok. 1 passed; 0 failed;"
                                   " 0 ignored; 0 measured; 9 filtered out\n", False), t, loc),
           "ERROR:row did not run")
    return n, failures


FAKE_TEST_BINARY = r'''#!/usr/bin/env python3
"""A stand-in libtest executable: answers from a scripted table."""
import json, os, subprocess, sys, time
table = json.load(open(os.environ["FAKE_TABLE"]))
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as f:
    f.write(json.dumps({"args": args, "mutant": os.environ.get("MCP_GATEWAY_MUTANT")}) + "\n")
if args[:1] == ["--list"]:
    if not table.get("no_probe"):
        print("mutant::mutants_build::only_the_named_site_switches_on: test")
    print("m::t1: test")
    sys.exit(0)
if "--exact" not in args:
    # libtest without --exact: the name is a substring filter, so the sibling
    # m::t10 runs beside m::t1.
    flt = next(a for a in args if not a.startswith("-"))
    names = [n for n in ("m::t1", "m::t10") if flt in n]
    mutant = os.environ.get("MCP_GATEWAY_MUTANT") or "base"
    print(f"running {len(names)} tests")
    failed = 0
    for name in names:
        row = table["rows"].get(mutant + " " + name, {"status": "ok"})
        print(f"test {name} ... {row['status']}")
        if row["status"] == "FAILED":
            failed += 1
            print(f"thread '{name}' (7) panicked at {row['panic']}:5:")
    print(f"test result: {'FAILED' if failed else 'ok'}. {len(names) - failed} passed; {failed} failed; 0 ignored; 0 measured; 3 filtered out")
    sys.exit(101 if failed else 0)
test = args[args.index("--exact") + 1]
if test == "mutant_scan::tests::list_mutant_sites":
    for site in table["sites"]:
        print("MUTANT-SITE " + site)
    print("MUTANT-SITES-DONE")
    sys.exit(0)
key = (os.environ.get("MCP_GATEWAY_MUTANT") or "base") + " " + test
row = table["rows"].get(key, {"status": "ok"})
if row["status"] == "hang":
    child = subprocess.Popen(["sleep", "60"])
    open(os.environ["FAKE_CHILD"], "w").write(str(child.pid))
    time.sleep(60)
print("running 1 test")
print(f"test {test} ... {row['status']}")
if row["status"] == "FAILED":
    print(f"thread '{test}' (7) panicked at {row['panic']}:5:")
    print(f"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out")
    sys.exit(101)
print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out")
'''

FAKE_CARGO = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_CALLS"], "a") as f:
    f.write(json.dumps({"cargo": sys.argv[1:], "rustflags": os.environ.get("RUSTFLAGS", ""),
                        "mutant": os.environ.get("MCP_GATEWAY_MUTANT")}) + "\n")
exe = os.environ["FAKE_EXE"]
for name, kind in (("mcp_gateway", ["lib"]), ("itest", ["test"])):
    print(json.dumps({"reason": "compiler-artifact", "executable": exe, "profile": {"test": True},
                      "target": {"name": name, "kind": kind}}))
'''


def schemata_driver_self_test() -> tuple[int, list[str]]:
    """(cases run, failures) for the driver (D1-D3, D6-D9, R9, R23), with a fake
    cargo and a fake test executable on PATH."""
    global TEST_LIMIT
    failures: list[str] = []
    n = 0
    saved_path, saved_limit = os.environ.get("PATH", ""), TEST_LIMIT
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        exe, cargo = d / "fake-test", d / "cargo"
        exe.write_text(FAKE_TEST_BINARY)
        cargo.write_text(FAKE_CARGO)
        for f in (exe, cargo):
            f.chmod(0o755)
        os.environ.update(PATH=f"{d}{os.pathsep}{saved_path}", FAKE_EXE=str(exe),
                          FAKE_CALLS=str(d / "calls"), FAKE_TABLE=str(d / "table.json"),
                          FAKE_CHILD=str(d / "child.pid"), RUSTFLAGS="--cap-lints=warn")
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        _, ms = parse_spec("#mutant A\nmcp_gateway\tm::t1\tsrc/x.rs:9\n")

        def run(table: dict, mutants=ms) -> tuple[int | str, list[dict]]:
            (d / "calls").write_text("")
            (d / "table.json").write_text(json.dumps(table))
            try:
                rc: int | str = execute_schemata(None, mutants, d / "out")
            except BaselineRefused:
                rc = "refused"
            except Abort:
                rc = "aborted"
            calls = [json.loads(l) for l in (d / "calls").read_text().splitlines()]
            return rc, calls

        def expect(name: str, got, want) -> None:
            nonlocal n
            n += 1
            if got != want:
                failures.append(f"{name}: expected {want!r}, got {got!r}")

        killed = {"sites": ["A src/x.rs:3"], "rows": {"A m::t1": {"status": "FAILED", "panic": "src/x.rs:9"}}}
        try:
            rc, calls = run(killed)
            expect("a killed mutant exits 0", rc, 0)
            builds = [c for c in calls if "cargo" in c]
            expect("D1 one build for the batch", len(builds), 1)
            expect("D1 the build carries --cfg mutants and the workflow's flags",
                   builds[0]["rustflags"] if builds else None, "--cap-lints=warn --cfg mutants")
            expect("D1 the build has its own target dir",
                   "target/mutants-cfg" in (builds[0]["cargo"] if builds else []), True)
            runs = [c for c in calls if "m::t1" in c.get("args", [])]
            expect("D3 the baseline runs with no mutant on", [c["mutant"] for c in runs], [None, "A"])
            expect("D2 each row runs alone by exact name", [c["args"] for c in runs],
                   [["--exact", "m::t1", "--test-threads=1"]] * 2)
            sibling = {**killed, "rows": {"A m::t10": {"status": "FAILED", "panic": "src/x.rs:9"}}}
            rc, calls = run(sibling)
            expect("D2b a substring sibling's failure does not kill the mutant", rc, 1)
            sib_runs = [c for c in calls if c.get("mutant") == "A" and "--exact" in c.get("args", [])]
            expect("D2b the mutant's row ran by exact name", [c["args"][1] for c in sib_runs], ["m::t1"])
            rc, calls = run({**killed, "rows": {"base m::t1": {"status": "FAILED", "panic": "src/x.rs:9"}}})
            expect("D7 a failed baseline refuses (exit 1)", rc, "refused")
            expect("D7 no mutant runs after a failed baseline",
                   [c for c in calls if c.get("mutant") == "A"], [])
            rc, _ = run({**killed, "rows": {}})
            expect("D8 a surviving mutant exits 1", rc, 1)
            rc, _ = run({**killed, "no_probe": True})
            expect("R23 a build without --cfg mutants is refused", rc, "aborted")
            _, ms_absent = parse_spec("#mutant A\nnot_built\tm::t1\tsrc/x.rs:9\n")
            rc, _ = run(killed, ms_absent)
            expect("R9 an executable the build did not produce is refused", rc, "aborted")
            rc, _ = run({**killed, "sites": ["B src/x.rs:3"]})
            expect("D6 a spec that does not reconcile refuses before any row", rc, "aborted")
            TEST_LIMIT = 2
            rc, _ = run({**killed, "rows": {"A m::t1": {"status": "hang"}}})
            expect("D9 a hung row is ERROR and exits 1", rc, 1)
            pid_file = d / "child.pid"
            expect("D9 the hung row started its child", pid_file.is_file(), True)
            alive = None
            if pid_file.is_file():
                try:
                    os.kill(int(pid_file.read_text()), 0)
                    alive = True
                except ProcessLookupError:
                    alive = False
            expect("D9 the hung row's child process is killed too", alive, False)
        finally:
            TEST_LIMIT = saved_limit
            os.environ["PATH"] = saved_path
    return n, failures


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
    schemata_cases, schemata_failures = schemata_self_test()
    driver_cases, driver_failures = schemata_driver_self_test() if os.name != "nt" else (0, [])
    schemata_cases += driver_cases
    schemata_failures += driver_failures
    for failure in schemata_failures:
        print(f"self-test: schemata: {failure}", file=sys.stderr)
        rc = 1
    if rc == 0:
        total = len(cases) + 2 + len(bad) + len(refs_ok) + len(refs_bad) + FETCH_CASES + schemata_cases
        print(f"self-test: {total} classifier, manifest, ref and release-line fetch cases as expected")
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
        schemata = Path(MUTANTS_DIR, SCHEMATA_SPEC).is_file()
        if a.mode == "plan" and schemata:
            plan_schemata()
            lines = ["has_linux=true", "has_windows=false"]
            print("\n".join(lines))
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            return 0
        if a.mode == "run" and schemata:
            if a.platform != "linux":
                raise Abort("schemata batches run on linux only")
            return run_schemata(a.out)
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
    except BaselineRefused as exc:
        print(f"::error::mutant batch refused: {exc}", file=sys.stderr)
        return 1
    except Abort as exc:
        print(f"::error::mutant batch aborted: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
