#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every Linux-hosted job that compiles the library's test binary adds swap first.

That compile is one rustc of about 15.4 GB on a runner with 16 GB of RAM and
3 GB of swap: measured, it leaves a few hundred MB free and fills the swap,
and a run that tips over loses its runner (exit 143, "shutdown signal"). The
shared action `.github/actions/add-swap` adds 8 GB and fails unless total swap
reaches 10 GB.

This check reads every workflow and refuses:
  - a Linux-hosted job that runs a library-test build with no add-swap step
    before its first such step;
  - an add-swap step whose `if:` is not one of ALLOWED_CONDITIONS (a condition
    that skips a library matrix row would leave that row without swap);
  - a Linux-hosted job that runs the memory tripwire unless an add-swap step
    without `if:` comes before its first `run:` step and the tripwire comes
    after every other `run:` command (no build detection: position decides),
    since the tripwire fails closed with no active swap and counts the whole
    job's swap-out, and some runner images come with none;
  - a hand-copied swap script (`swapon`/`mkswap` in a workflow `run:`), which
    could drift from the shared action;
  - an in-scope job list that differs from EXPECTED (a job that starts or stops
    building the library must be named here on purpose).

`--self-test` runs the classifier on fixtures. Standard library plus PyYAML,
as the other workflow checks.
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

import yaml

ACTION = "./.github/actions/add-swap"
WORKFLOWS = Path(".github/workflows")
CARGO_CONFIG = Path(".cargo/config.toml")

# A library-test build: `cargo test`, `cargo llvm-cov` or `cargo bench` (the
# library's own bench harness compiles it with cfg(test)) that is not a
# single-target, doc-only or binary-only run; `cargo build` with `--tests`,
# `--all-targets` or `--benches`; and the repo's wrapper scripts around one.
# `cargo check` and `cargo clippy` stay out: check-only, they peak under the
# memory tripwire's limit, so they are not the build the lib test split removes.
CARGO_RE = re.compile(r"\bcargo\s+(test|llvm-cov|bench)\b([^\n|;&]*)")
BUILD_TESTS = re.compile(r"\bcargo\s+build\b[^\n|;&]*\s--(tests|all-targets|benches)\b")
SINGLE_TARGET = re.compile(r"--(test|bin|doc|example|bench)\b")
# Where cargo's own arguments end: SINGLE_TARGET reads only those, so a test binary's --test-threads is not one.
TEST_ARGS = re.compile(r"\s--(?:\s|$)")
# The & of a redirection (2>&1, <&0, &>file): part of one command, not a separator, so the matchers above may cross it.
REDIRECT_AMP = re.compile(r"(?<=[<>])&|&(?=>)")
LLVM_COV_NO_COMPILE = re.compile(r"^\s*(clean|report)\b")
WRAPPERS = (
    re.compile(r"scripts/ci/shard_tests\.py\s+run\s+linux\b"),
    # The shared lib test binary: `export-lib` compiles it once for the run.
    re.compile(r"scripts/ci/shard_tests\.py\s+export-lib\b"),
    # The Linux lib test binary in parts: the helper compiles each part through export-lib.
    re.compile(r"scripts/ci/lib-parts\.sh\s+(export|cov|run)\b"),
    re.compile(r"scripts/ci/coverage_shards\.py\s+run\b"),
    re.compile(r"scripts/ci/packaged-tests\.sh\s+(build|run)\b"),
    # The mutant harness, run from the repo or from the copy mutants.yml takes
    # off the release line into $RUNNER_TEMP.
    re.compile(r"run_mutants\.py\"?\s+run\b"),
)
COPIED_SWAP = re.compile(r"\b(swapon|mkswap)\b")

# The one condition an add-swap step may carry. Gating it to the library coverage parts went: the integration parts
# run the memory tripwire too, and it needs active swap on every leg (train 64a: an int part on an image with none).
ALLOWED_CONDITIONS = {
    # A step shared with a self-hosted twin job (mutants.yml keeps its hosted
    # and trusted Linux jobs identical): it runs on every hosted run.
    "runner.environment == 'github-hosted'",
}

# Jobs that go through a wrapper above but compile no library test binary,
# with the measurement that puts them out of scope.
EXEMPT = {
    ("coverage-probe.yml", "linux-sdk"): "builds one integration test; measured peak 6.5 GB",
    ("feature-combos.yml", "release-test-compile"): "cargo check only, no test binary; measured peak 12.96 GB",
}

# The jobs in scope, by workflow file and job id. A change to this set is a
# change to which jobs carry the library compile, reviewed as such.
EXPECTED = {
    ("ci.yml", "linux-lib-build"),
    ("ci.yml", "package-tests"),
    ("ci.yml", "test-shards"),
    ("ci.yml", "test-throwaway-hosted"),
    ("coverage-probe.yml", "linux-part"),
    ("maps-live-smoke.yml", "gateway"),
    ("mutants.yml", "linux-hosted"),
    ("packaged-suite.yml", "packaged-suite"),
    ("release.yml", "verify"),
}

# The lib test split (SPLIT.6): every in-scope job builds the library tests through scripts/ci/lib-parts.sh, so each
# compile is one part, never the whole binary, or it is listed here with why. Shrink-only: the stage B jobs keep the
# whole build until stage B converts them.
HELPER = "scripts/ci/lib-parts.sh"
WHOLE_BUILD_ALLOWED = {
    ("ci.yml", "test-throwaway-hosted"): "stage B: the throwaway full-test job",
    ("mutants.yml", "linux-hosted"): "stage B: mutant batches",
    ("ci.yml", "test-shards"): "builds the integration targets only (int-a, int-b): no lib test target",
}


# The packaged crate's build builds by part inside the unpacked crate, where the helper is not shipped: it counts as
# through the helper while its script's build mode holds that shape (packaged_build_problems).
PACKAGED_BUILD = "scripts/ci/packaged-tests.sh build"
# Its run mode (the post-merge packaged suite) runs the suite through the helper from the unpacked crate: it counts as
# through the helper while that mode holds one helper `run` call and no other build (packaged_run_problems).
PACKAGED_RUN = "scripts/ci/packaged-tests.sh run"
RUN_HELPER = re.compile(r'^"?\$root/scripts/ci/lib-parts\.sh"?\s+run\b')
TRIPWIRE = "scripts/ci/memory-tripwire.sh"
PACKAGED_SCRIPT = Path("scripts/ci/packaged-tests.sh")
# Matched at the start of a command: a part call is the command itself, not text inside an echo or another command.
PART_CALL = re.compile(r"""MCP_GATEWAY_TEST_PART="\$k"\s+cargo\s+test\b.*\s--lib\b""")
REST_CALL = re.compile(r"""cargo\s+test\b.*\s--test\s+'\*'""")
SELECTS_LIB = re.compile(r"\s--(lib|tests|all-targets|benches)\b")
PART_LOOP = re.compile(r'\bfor\s+k\s+in\s+\$\(seq\s+1\s+"\$n"\)\s*;?\s*do\b(.*?)^\s*done\b', re.S | re.M)
# The packaged build's one assignment of n (one shell command each): read from the build script, nothing else.
N_READ = ("n=\"$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)"
          "[[:space:]]*;.*/\\1/p' scripts/dev/test-parts-build.rs)\"")
# Reads of n are an allow-list: $n, and ${n} with a non-assigning operator (:- - :+ + :? ?). READ_N blanks those; any
# other mention of n left (n=, ((--n)), let n, read n, -n, an option cluster ending in n such as -vn, ${n:=1}) counts
# as naming n, and the packaged block may name n in one command only: the canonical read below, placed before the
# part loop. A false count refuses the block, the strict direction.
# Non-goals: the census guards against accidental drift in reviewed workflows and scripts, not deliberate
# obfuscation. Dynamically built variable names (printf -v with a computed name), eval, and command or function
# shadowing are out of scope.
READ_N = re.compile(r"\$n(?!\w)|\$\{n(?=\}|:?[-+?])")
BARE_N = re.compile(r"(?<!\w)n(?!\w)|(?<![\w-])-[A-Za-z]+n(?!\w)")


def packaged_build_problems(text: str) -> list[str]:
    """Why the packaged crate's `build` mode does not build the lib tests one part at a time, or nothing: every
    `cargo test` there is either one part (`--lib` with MCP_GATEWAY_TEST_PART set) or the other targets only
    (`--test '*'`, no `--lib`/`--tests`/`--all-targets`/`--benches`), and there is one of each."""
    start = text.find('elif [ "$mode" = build ]')
    if start < 0:
        return ["packaged-tests.sh has no build mode"]
    block = text[start:].split("\nelse", 1)[0]
    # Each shell command, not each line: a whole build chained after a part call, or a `cargo build --tests`, counts.
    commands = run_commands(block)
    calls = [cmd for cmd in commands if re.search(r"\bcargo\s+test\b", cmd) or builds_library(cmd)]
    out = [f"`{c}` is neither one part nor the other targets" for c in calls
           if not PART_CALL.match(c) and not (REST_CALL.search(c) and not SELECTS_LIB.search(c))]
    if not any(PART_CALL.match(c) for c in calls):
        out.append("the build mode builds no part")
    if not any(REST_CALL.search(c) and not SELECTS_LIB.search(c) for c in calls):
        out.append("the build mode builds no non-lib test target")
    # Every part: the part builds sit inside a loop over 1..N, and the block names n bare exactly once, in the build
    # script's read (BARE_N), so a shortened loop, a rewritten n or a part built outside the loop cannot pass.
    writes = [cmd for cmd in commands for _ in BARE_N.finditer(READ_N.sub("", cmd))]
    loop = PART_LOOP.search(block)
    outside = block[:loop.start()] + block[loop.end():] if loop else block
    # One command names n, and a canonical read sits before the loop, so that command is the read and runs first.
    if (not loop or len(writes) != 1
            or not any(" ".join(cmd.split()) == N_READ for cmd in run_commands(block[:loop.start()]))
            or any(PART_CALL.match(cmd) for cmd in run_commands(outside))
            or not all(PART_CALL.match(cmd) for cmd in run_commands(loop.group(1)))):
        out.append('the parts are not all built inside `for k in $(seq 1 "$n")` with n written only by its read '
                   "from scripts/dev/test-parts-build.rs")
    return out


def packaged_run_problems(text: str) -> list[str]:
    """Why the packaged crate's `run` mode does not run the suite through the helper, or nothing: judged per command,
    it calls `lib-parts.sh run` exactly once and builds no test target any other way."""
    start = text.find('elif [ "$mode" = build ]')
    tail = text[start:].split("\nelse", 1) if start >= 0 else []
    if len(tail) < 2:
        return ["packaged-tests.sh has no run mode after its build mode"]
    commands = run_commands(tail[1].split("\nfi", 1)[0])
    helper = [cmd for cmd in commands if RUN_HELPER.match(cmd)]
    out = [] if len(helper) == 1 else [f"the run mode calls the helper's run {len(helper)} times, not once"]
    return out + [f"`{cmd}` builds tests outside the helper" for cmd in commands
                  if not RUN_HELPER.match(cmd) and (re.search(r"\bcargo\s+test\b", cmd) or builds_library(cmd))]


def shell_commands(line: str) -> list[str] | None:
    """The commands on one shell line (continuations already joined), each its original text, split at `;`, `&`,
    `&&`, `||`, `|` and `|&` outside quotes, as bash reads them: single quotes take everything literally, double
    quotes honour a backslash, an unquoted backslash escapes the next character, a quote glued to a word stays in
    that word, and `#` starts a comment only at the start of a word. `&` in a redirection (`2>&1`, `&>file`) is not a
    separator. None when a quote is left open. A guard against a whole build coming back by accident, not a shell
    parser: command substitution and eval are not looked into."""
    out: list[str] = []
    buf: list[str] = []
    quote = ""
    word_start = True
    redirect = False  # the last character was an unquoted, unescaped < or >, so a following & is part of it
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            buf.append(c)
            if quote == '"' and c == "\\" and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 1
            elif c == quote:
                quote = ""
        elif c == "\\" and i + 1 < len(line):
            buf += [c, line[i + 1]]
            i += 1
            word_start = redirect = False
        elif c in "'\"":
            quote = c
            buf.append(c)
            word_start = redirect = False
        elif c == "#" and word_start:
            break
        elif c in ";&|" and not (c == "&" and (redirect or line[i + 1:i + 2] == ">")):
            out += ["".join(buf).strip()] if "".join(buf).strip() else []
            buf = []
            while i + 1 < len(line) and line[i + 1] in ";&|":
                i += 1
            word_start, redirect = True, False
        else:
            buf.append(c)
            word_start, redirect = c.isspace(), c in "<>"
        i += 1
    if quote:
        return None
    return out + (["".join(buf).strip()] if "".join(buf).strip() else [])


def run_lines(run: str) -> list[tuple[str, list[str] | None]]:
    """Each line of a `run:` script, continuations joined, with its shell commands (None when a quote is left open).
    The one place the census paths read a script into commands, so they cannot drift apart."""
    lines, cur = [], ""
    for physical in run.split("\n"):
        cur += physical
        if continues(cur):
            cur = cur[:-1] + " "
            continue
        lines.append(cur)
        cur = ""
    lines += [cur] if cur else []
    return [(line, shell_commands(line)) for line in lines]


def continues(line: str) -> bool:
    """Whether the line goes on to the next one, as bash reads it: it ends in a backslash that is not itself escaped,
    not inside single quotes and not inside a comment (bash ends a comment at the newline)."""
    quote, word_start, i = "", True, 0
    while i < len(line):
        c = line[i]
        if quote:
            if quote == '"' and c == "\\":
                if i + 1 == len(line):
                    return True
                i += 1
            elif c == quote:
                quote = ""
        elif c == "\\":
            if i + 1 == len(line):
                return True
            i += 1
            word_start = False
        elif c in "'\"":
            quote, word_start = c, False
        elif c == "#" and word_start:
            return False
        else:
            word_start = c.isspace() or c in ";&|"
        i += 1
    return False


def run_commands(run: str) -> list[str]:
    """Every shell command of a `run:` script; a line with an open quote counts as one command, judged whole. A
    comment-only line has no command."""
    return [cmd for line, cmds in run_lines(run) for cmd in (cmds if cmds is not None else [line])]


def step_builds(step: dict, aliases: dict[str, str] | None = None) -> bool:
    """Whether a step builds the library tests, judged per shell command as builds_through does."""
    return any(builds_library(cmd, aliases) for cmd in run_commands(str(step.get("run", ""))))


def builds_through(job: dict, marks: tuple[str, ...], aliases: dict[str, str] | None = None) -> bool:
    """Whether every command in `job` that builds the library tests goes through one of `marks`, judged per shell
    command (shell_commands), so a helper call cannot vouch for a whole build beside it in the same job, step or
    line. A line that does not tokenize and builds the library counts as not through."""
    builds: list[str] = []
    for step in job.get("steps", []):
        if not isinstance(step, dict):
            continue
        for line, commands in run_lines(str(step.get("run", ""))):
            if commands is None:
                if builds_library(line, aliases):
                    return False
                continue
            builds += [cmd for cmd in commands if builds_library(cmd, aliases)]
    return bool(builds) and all(any(m in cmd for m in marks) for cmd in builds)


def census(jobs_in_scope: dict, packaged_by_part: bool, packaged_run_by_part: bool = False) -> list[str]:
    """SPLIT.6: an in-scope job outside WHOLE_BUILD_ALLOWED builds through the helper (or is the packaged build while
    `packaged_by_part`); every allowance names a job still in scope that still does not."""
    problems = []
    marks = (HELPER,) + ((PACKAGED_BUILD,) if packaged_by_part else ()) + ((PACKAGED_RUN,) if packaged_run_by_part else ())
    through = {key for key, job in jobs_in_scope.items() if builds_through(job, marks)}
    for key in sorted(set(jobs_in_scope) - through - set(WHOLE_BUILD_ALLOWED)):
        problems.append(f"{key[0]}:{key[1]} builds the library tests without {HELPER}, so the whole lib test binary")
    for key in sorted(set(WHOLE_BUILD_ALLOWED) - (set(jobs_in_scope) - through)):
        problems.append(f"{key[0]}:{key[1]} is allowed a whole build but no longer has one; delete its row")
    # A job that builds by part ends with the swap-out tripwire, after its last build step and run even after a failed
    # or timed-out step; one placed before the build would measure nothing.
    for key in sorted(through):
        steps = [s for s in jobs_in_scope[key].get("steps", []) if isinstance(s, dict)]
        last_build = max((i for i, s in enumerate(steps) if step_builds(s)), default=-1)
        if not any(runs_tripwire(s)
                   and str(s.get("if", "")).strip() == "always()"
                   for s in steps[last_build + 1:]):
            problems.append(f"{key[0]}:{key[1]} builds by part with no `if: always()` step running {TRIPWIRE} "
                            "after its last build step")
    return problems


def alias_text(table: dict) -> dict[str, str]:
    """A cargo `[alias]` table as name -> expansion text (cargo takes a string or a list of words)."""
    return {name: value if isinstance(value, str) else " ".join(value) for name, value in table.items()}


def repo_aliases() -> dict[str, str]:
    """The repo's own cargo aliases, from `[alias]` in .cargo/config.toml."""
    if not CARGO_CONFIG.is_file():
        return {}
    return alias_text(tomllib.loads(CARGO_CONFIG.read_text(encoding="utf-8")).get("alias", {}))


def builds_library(run: str, aliases: dict[str, str] | None = None) -> bool:
    """Whether a `run:` script compiles the library's test binary. A repo alias is read as what it expands to."""
    for name, expansion in (repo_aliases() if aliases is None else aliases).items():
        run = re.sub(rf"\bcargo\s+{re.escape(name)}\b", lambda _, e=expansion: f"cargo {e}", run)
    run = REDIRECT_AMP.sub("", run)
    if BUILD_TESTS.search(run):
        return True
    for m in CARGO_RE.finditer(run):
        sub, args = m.group(1), m.group(2)
        if sub == "llvm-cov" and LLVM_COV_NO_COMPILE.match(args):
            continue
        if SINGLE_TARGET.search(TEST_ARGS.split(args, 1)[0]):
            continue
        return True
    return any(w.search(run) for w in WRAPPERS)


def linux_hosted(job: dict) -> bool:
    runs_on = job.get("runs-on", "")
    return "ubuntu" in (" ".join(runs_on) if isinstance(runs_on, list) else str(runs_on))


def runs_tripwire(step: dict) -> bool:
    return (run_commands(str(step.get("run", ""))) or [""])[0].startswith(TRIPWIRE)


def tripwire_swap_problems(name: str, steps: list) -> list[str]:
    """The tripwire counts swap-out since boot and fails closed when none is active. So in its job the unconditional
    add-swap step comes before every shell step, and the tripwire after every other one. Position alone decides,
    whatever a step compiles: a build the library match misses still runs between the two."""
    shell = [i for i, s in enumerate(steps) if "run" in s]
    trips = [i for i in shell if runs_tripwire(steps[i])]
    if not trips:
        return []
    found = []
    if not any(s.get("uses") == ACTION and "if" not in s for s in steps[:shell[0]]):
        found.append(f"{name}: needs an {ACTION} step without `if:` before step {shell[0]}, its first shell step, "
                     f"since the memory tripwire (step {trips[0]}) fails closed on a runner image that has no swap")
    later = [i for i in shell if i > trips[-1] and not runs_tripwire(steps[i])]
    if later:
        found.append(f"{name}: its memory tripwire (step {trips[-1]}) is not the job's last shell step: step "
                     f"{later[0]} runs after it, and its swap-out goes uncounted")
    elif any(not c.startswith(TRIPWIRE) for c in run_commands(str(steps[trips[-1]].get("run", "")))[1:]):
        found.append(f"{name}: step {trips[-1]} runs another command after the memory tripwire in the same step, "
                     "and that command's swap-out goes uncounted")
    return found


def check_job(name: str, job: dict) -> tuple[bool, list[str]]:
    """(in scope, problems) for one job."""
    problems: list[str] = []
    steps = job.get("steps") or []
    for i, step in enumerate(steps):
        if COPIED_SWAP.search(str(step.get("run", ""))):
            problems.append(f"{name}: step {i} copies a swap script; use {ACTION}")
    if not linux_hosted(job):
        return False, problems
    first_build = next((i for i, s in enumerate(steps) if step_builds(s)), None)
    problems += tripwire_swap_problems(name, steps)
    if first_build is None:
        return False, problems
    swap = next((i for i, s in enumerate(steps) if s.get("uses") == ACTION), None)
    if swap is None:
        problems.append(f"{name}: builds the library tests (step {first_build}) with no {ACTION} step")
    elif swap > first_build:
        problems.append(f"{name}: {ACTION} (step {swap}) comes after the library build (step {first_build})")
    else:
        cond = steps[swap].get("if")
        if cond is not None and str(cond).strip() not in ALLOWED_CONDITIONS:
            problems.append(f"{name}: {ACTION} runs only if `{cond}`, which may skip a library row")
    return True, problems


# Every library build line in scope runs through the memory log, and every such step carries its own
# timeout-minutes, so a stalled build ends while the runner is alive and the step keeps its log (a job cancelled at
# its own limit keeps none). Limits come from measured healthy durations; a step with no measurement yet logs
# only, named here per step. Its limit must not be set until it is measured.
MEMLOG = "scripts/ci/with-memory-log.sh"
# The same wrapper as the mutants jobs run it: fetched from the release line into $RUNNER_TEMP, never the checkout's.
MEMLOG_FETCHED = 'bash "$RUNNER_TEMP/with-memory-log.sh"'
LOG_ONLY = {
    # A healthy lib-b run took 52 min on 2026-11-13: no limit until the shard suite's tail is measured.
    ("ci.yml", "test-shards", "Shard suite"),
    ("ci.yml", "test-throwaway-hosted", "Run the tests"),
    ("packaged-suite.yml", "packaged-suite", "Run the tests from the packaged crate"),
    ("mutants.yml", "linux-hosted", "Run the linux rows"),
    ("release.yml", "verify", "Test"),
}
# Minutes kept free of step limits in each job: setup, cache, swap and post steps measured at 3 min or less.
RESERVE = 10
JOB_DEFAULT = 360  # GitHub's job limit when timeout-minutes is unset


def whole_step_wrapped(run: str) -> bool:
    """Whether the step is ONE command run through the memory log, its script in a single-quoted `bash -c` body that
    ends the step (the keychain steps: `with-memory-log.sh dbus-run-session -- bash -euo pipefail -c '...'`). Then
    every build line inside it is wrapped. Anything after the closing quote, or a second quote inside, is not."""
    text = run.strip()
    if not text.startswith(MEMLOG + " ") or not text.endswith("'"):
        return False
    first = text.find("'")
    return first < len(text) - 1 and "'" not in text[first + 1:-1]


# What may stand between the start of a command and the build it runs, for the build to count as wrapped: an
# optional loop/branch keyword, the wrapper as the command's first word, an optional interpreter, and the start of
# the build's own word when the match begins inside it (`"$RUNNER_TEMP/run_mutants.py`). No `(` or backtick.
WRAPPED_PREFIX = re.compile(
    r"\s*(?:(?:do|then|else)\s+)?(?:(?:\./)?" + re.escape(MEMLOG) + "|" + re.escape(MEMLOG_FETCHED) + ")"
    r"\s+(?:(?:python3?|bash|sh)\s+)?[\w$./{}\"'-]*")
# Characters that end one command and start another (or a substitution's): a build's command starts after the
# last of them.
COMMAND_BREAKS = "\n;&|(`"


def unwrapped_builds(run: str) -> list[str]:
    """Every library build in `run` that does not run through the wrapper. Fail closed, not a shell parser: after
    joining backslash continuations and dropping comment lines, each occurrence of a build (CARGO_RE, WRAPPERS) is
    wrapped only when the text from the start of its command (after the last newline, `;`, `&`, `|`, `(` or
    backtick) to the build is exactly WRAPPED_PREFIX. Anything else counts as bare: a build on the line after a
    mention of the wrapper, after `VAR=`, inside `$( )` or backticks, or in an echo's text (so a phase line must
    not spell out `cargo test`)."""
    text = "\n".join(line for line, _ in run_lines(run) if not line.lstrip().startswith("#"))
    starts = []
    for m in CARGO_RE.finditer(text):
        if m.group(1) == "llvm-cov" and LLVM_COV_NO_COMPILE.match(m.group(2)):
            continue
        if not SINGLE_TARGET.search(TEST_ARGS.split(m.group(2), 1)[0]):
            starts.append(m.start())
    starts += [m.start() for w in WRAPPERS for m in w.finditer(text)]
    bare = []
    for s in sorted(starts):
        command_start = max(text.rfind(c, 0, s) for c in COMMAND_BREAKS) + 1
        if not WRAPPED_PREFIX.fullmatch(text[command_start:s]):
            bare.append(text[s:s + 80].split("\n")[0])
    return bare


def memlog_problems(file: str, name: str, job: dict) -> list[str]:
    """Problems with the memory log and the step limits of one in-scope job."""
    problems: list[str] = []
    limit_total = 0
    for i, step in enumerate(job.get("steps") or []):
        label = step.get("name", f"step {i}")
        limit = step.get("timeout-minutes")
        # Every step's own limit counts against the job's, build or not: they all run before the job limit.
        if isinstance(limit, int):
            limit_total += limit
        run = str(step.get("run", ""))
        if not step_builds(step):
            continue
        bare = [] if whole_step_wrapped(run) else unwrapped_builds(run)
        if bare:
            problems.append(f"{file}:{name}: '{label}' builds the library without {MEMLOG}: {bare[0][:80]}")
        if (file, name, label) in LOG_ONLY:
            if limit is not None:
                problems.append(f"{file}:{name}: '{label}' is log-only (not measured yet) but sets timeout-minutes")
        elif not isinstance(limit, int):
            problems.append(f"{file}:{name}: '{label}' builds the library with no timeout-minutes of its own")
    job_limit = job.get("timeout-minutes", JOB_DEFAULT)
    if not isinstance(job_limit, int):
        problems.append(f"{file}:{name}: job timeout-minutes is not a number")
    elif limit_total + RESERVE >= job_limit:
        problems.append(f"{file}:{name}: step limits {limit_total} + {RESERVE} reserve must stay under the job's {job_limit}")
    return problems


def check_workflow(file: str, doc: dict, seen: dict | None = None) -> tuple[set[tuple[str, str]], list[str]]:
    scope: set[tuple[str, str]] = set()
    problems: list[str] = []
    for name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if (file, name) in EXEMPT:
            continue
        in_scope, found = check_job(f"{file}:{name}", job)
        problems += found
        if in_scope:
            scope.add((file, name))
            if seen is not None:
                seen[(file, name)] = job
            problems += memlog_problems(file, name, job)
    return scope, problems


def main(packaged_script: Path = PACKAGED_SCRIPT) -> int:
    scope: set[tuple[str, str]] = set()
    problems: list[str] = []
    seen: dict = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        s, p = check_workflow(path.name, yaml.safe_load(path.read_text(encoding="utf-8")) or {}, seen)
        scope |= s
        problems += p
    text = packaged_script.read_text(encoding="utf-8")
    problems += census(seen, packaged_by_part=not packaged_build_problems(text),
                       packaged_run_by_part=not packaged_run_problems(text))
    for missing in sorted(EXPECTED - scope):
        problems.append(f"{missing[0]}:{missing[1]} is listed in EXPECTED but builds no library tests")
    for extra in sorted(scope - EXPECTED):
        problems.append(f"{extra[0]}:{extra[1]} builds the library tests but is not in EXPECTED")
    for p in problems:
        print(f"::error::{p}")
    print(f"{len(scope)} jobs build the library tests; {len(problems)} problems")
    return 1 if problems else 0


def action_script() -> str:
    """The run block of the add-swap action's only step."""
    doc = yaml.safe_load(Path(".github/actions/add-swap/action.yml").read_text())
    return doc["runs"]["steps"][0]["run"]


def run_action(before_mb: int, after_mb: int) -> int:
    """Exit status of the action's script on a runner whose total swap is before_mb until swapon, then after_mb.
    sudo, fallocate, chmod, mkswap and swapon are stubs; `free` answers from a counter: its first call (before the
    swap file is made) reports before_mb, later calls after_mb."""
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp)
        for name in ("fallocate", "chmod", "mkswap", "swapon"):
            (fake / name).write_text("#!/bin/sh\nexit 0\n")
        (fake / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
        (fake / "free").write_text(
            "#!/bin/sh\n"
            f'n=$(cat "{tmp}/calls" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "{tmp}/calls"\n'
            f'if [ "$n" -eq 1 ]; then m={before_mb}; else m={after_mb}; fi\n'
            'echo "              total        used        free"; echo "Mem:          15983         891       14431"\n'
            'echo "Swap:         $m           0       $m"\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"}
        return subprocess.run(["bash", "-c", action_script()], env=env, capture_output=True, text=True).returncode


def each_in_its_own(words: tuple, problems: list[str]) -> bool:
    """Every word found in a different problem, so one merged message cannot stand for two."""
    left = list(problems)
    for word in words:
        hit = next((p for p in left if word in p), None)
        if hit is None:
            return False
        left.remove(hit)
    return True


def self_test() -> int:
    def job(*steps: dict, runs_on: str = "ubuntu-latest") -> dict:
        return {"runs-on": runs_on, "steps": list(steps)}

    def step(run: str, **fields) -> dict:
        return {"run": run, **fields}

    swap = {"uses": ACTION}
    tw = step(f"{TRIPWIRE} 2048 \"$RUNNER_TEMP/memory-trend.txt\"", **{"if": "always()"})
    # Train 64a: an integration coverage part drew a runner image with no swap, and its tripwire failed closed.
    lib_only_swap = {**swap, "if": "startsWith(matrix.part, 'lib-')"}
    cov_part = step("python3 scripts/ci/coverage_shards.py run 4 \"$PART\"")
    full = step("cargo test --all-features")
    itest = step("cargo test --test public_claims_validation")  # out of scope: no library build
    cases = [
        ("a library test build with no swap step", job({"run": "cargo test --all-features --lib --no-run"}), True, 1),
        ("a build continued between cargo and test, no swap step",
         job({"run": "cargo \\\n  test --all-features --lib --no-run"}), True, 1),
        ("swap after the build", job({"run": "cargo test --all-features"}, swap), True, 1),
        ("swap before the build", job(swap, {"run": "cargo test --all-features"}), True, 0),
        ("a copied swap script", job({"run": "sudo swapon /swapfile"}, {"run": "cargo test"}), True, 2),
        ("a single integration target is out of scope", job({"run": "cargo test --test public_claims_validation"}), False, 0),
        ("a binary build is out of scope", job({"run": "cargo build --locked --bin mcp-gateway"}), False, 0),
        ("llvm-cov clean and report do not compile", job({"run": "cargo llvm-cov clean --workspace\ncargo llvm-cov report -v"}), False, 0),
        ("the Linux shard wrapper builds the library", job({"run": "python3 scripts/ci/shard_tests.py run linux lib-a"}), True, 1),
        ("packaged-tests.sh build", job({"run": "scripts/ci/packaged-tests.sh build"}), True, 1),
        ("packaged-tests.sh run", job({"run": "scripts/ci/packaged-tests.sh run"}), True, 1),
        ("the mutant harness copied to the runner temp", job({"run": 'python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o'}), True, 1),
        ("the mutant harness plan step does not compile", job({"run": 'python3 "$RUNNER_TEMP/run_mutants.py" plan'}), False, 0),
        ("the repo's mutant runner path", job({"run": "python3 scripts/ci/mutants/run_mutants.py run --platform linux"}), True, 1),
        ("swap gated to lib parts leaves the int parts with none", job(lib_only_swap, cov_part), True, 1),
        ("tripwire job, swap gated to lib parts", job(lib_only_swap, cov_part, tw), True, ("needs an", "runs only if")),
        ("tripwire job, swap on hosted runners only", job({**swap, "if": "runner.environment == 'github-hosted'"}, full, tw), True, ("needs an",)),
        ("tripwire job, unconditional swap before the build", job(swap, full, tw), True, 0),
        ("tripwire job, no library build and no swap", job(itest, tw), False, ("needs an",)),
        ("tripwire job, swap only after the build", job(full, swap, tw), True, ("needs an", "comes after the library build")),
        ("tripwire job, no library build, swap first", job(swap, tw), False, 0),
        ("tripwire job, tripwire before the build it should measure", job(swap, tw, full), True, ("not the job's last",)),
        ("tripwire job, swap after an integration build", job(itest, swap, tw), False, ("needs an",)),
        ("tripwire job, an integration build after the tripwire", job(swap, tw, itest), False, ("not the job's last",)),
        ("tripwire job, an upload step after it", job(swap, full, tw, {"uses": "actions/upload-artifact@v7"}), True, 0),
        ("tripwire job, two tripwire steps, the second last", job(swap, full, tw, tw), True, 0),
        ("tripwire job, a shell step before add-swap", job(step("echo setup"), swap, full, tw), True, ("needs an",)),
        ("tripwire job, a build in the tripwire's own step",
         job(swap, full, step(f"{TRIPWIRE} 2048 t\ncargo test --all-features", **{"if": "always()"})), True,
         ("in the same step",)),
        ("hosted-only swap shared with a self-hosted twin", job({**swap, "if": "runner.environment == 'github-hosted'"}, {"run": "cargo test --all-features"}), True, 0),
        ("coverage parts gated to one lib part", job({**swap, "if": "matrix.part == 'lib-a'"}, {"run": "python3 scripts/ci/coverage_shards.py run 4 \"$PART\""}), True, 1),
        ("macOS is out of scope", job({"run": "cargo test --all-features"}, runs_on="macos-15"), False, 0),
        ("cargo bench compiles the library's own bench harness", job({"run": "cargo bench --all-features --no-run"}), True, 1),
        ("a named bench target never selects the library", job({"run": "cargo bench --bench token_savings --no-run"}), False, 0),
        ("cargo build --tests compiles the library tests", job({"run": "cargo build --all-features --tests"}), True, 1),
        ("cargo build --benches selects the library's bench harness", job({"run": "cargo build --benches"}), True, 1),
        ("a check-only build is out of scope", job({"run": "cargo check --all-targets"}), False, 0),
    ]
    # The repo's own cargo aliases expand before the match.
    alias_cases = [
        ("an alias for cargo test --lib", {"wl": "test --lib"}, "cargo wl --no-run", True),
        ("a list-form alias", {"wl": ["test", "--lib"]}, "cargo wl", True),
        ("an alias for a release build", {"rel": "build --release"}, "cargo rel", False),
    ]
    wrong = 0
    for label, table, run, want in alias_cases:
        got = builds_library(run, alias_text(table))
        wrong += got != want
        print(f"{'ok   ' if got == want else 'WRONG'} alias, {label}: library build {got}")
    # The action must prove that OUR swap file took, whatever swap the runner image brings: runners differ (3 GB already
    # there, 11263 MB total; or none, 8191 MB total, which the old absolute 10 GB floor failed on 2026-11-12).
    for label, before, after, want_rc in (
        ("a runner with 3 GB of swap already there: 3072 -> 11263", 3072, 11263, 0),
        ("a runner with no swap: 0 -> 8191 (the file took)", 0, 8191, 0),
        ("swapon did nothing on a runner with 3 GB: 3072 -> 3072", 3072, 3072, 1),
        ("swapon did nothing on a runner with none: 0 -> 0", 0, 0, 1),
        ("only part of the file took: 0 -> 4096", 0, 4096, 1),
        ("just under the file's size: 0 -> 7999", 0, 7999, 1),
    ):
        rc = run_action(before, after)
        ok = (rc == 0) == (want_rc == 0)
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} add-swap action, {label}: exit {rc}")
    for label, j, want_scope, want_problems in cases:
        in_scope, problems = check_job("fixture", j)
        if isinstance(want_problems, tuple):  # one word per expected problem, each found in its own message
            ok = (in_scope == want_scope and len(problems) == len(want_problems)
                  and each_in_its_own(want_problems, problems))
        else:
            ok = in_scope == want_scope and len(problems) == want_problems
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: in scope {in_scope}, problems {problems}")
    for label, file, name, j, want_bad in memlog_cases():
        problems = memlog_problems(file, name, j)
        ok = bool(problems) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} memory log, {label}: problems {problems}")
    tripwire = {"if": "always()", "run": "scripts/ci/memory-tripwire.sh 2048 \"$RUNNER_TEMP/memory-trend.txt\""}
    helper_build = {"run": "scripts/ci/with-memory-log.sh scripts/ci/lib-parts.sh export 1 out"}
    helper_job = {"steps": [helper_build, tripwire]}
    whole_job = {"steps": [{"run": "cargo test --all-features --lib --no-run"}]}
    packaged_job = {"steps": [{"run": "scripts/ci/with-memory-log.sh scripts/ci/packaged-tests.sh build"}, tripwire]}
    allowed = {key: {"steps": []} for key in WHOLE_BUILD_ALLOWED}
    census_cases = [
        ("a new job building the whole binary", {**allowed, ("ci.yml", "new"): whole_job}, True, True),
        ("a new job building through the helper", {**allowed, ("ci.yml", "new"): helper_job}, False, True),
        ("a helper job without the tripwire", {**allowed, ("ci.yml", "new"): {"steps": [helper_build]}}, True, True),
        ("a helper job whose tripwire skips after a failure",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, {**tripwire, "if": "success()"}]}}, True, True),
        ("a helper job with a whole build in another step",
         {**allowed, ("ci.yml", "new"): {"steps": helper_job["steps"] + whole_job["steps"]}}, True, True),
        ("a helper job with a whole build on another line of the same step",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"] + "\n" + whole_job["steps"][0]["run"]},
                                                   tripwire]}}, True, True),
        *[(f"a helper job with a whole build after {sep.strip()!r} on the same line",
           {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"] + sep + whole_job["steps"][0]["run"]},
                                                     tripwire]}}, True, True)
          for sep in ("; ", " && ", " || ", " | ", " & ")],
        ("a quoted # before a whole build on the helper's next line",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"] + '\necho " #"; '
                                                           + whole_job["steps"][0]["run"]}, tripwire]}}, True, True),
        ("an unbalanced quote on a line that builds the library, beside a clean helper step",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, {"run": 'echo "x; ' + whole_job["steps"][0]["run"]},
                                                   tripwire]}}, True, True),
        ("an in-word # before a whole build on the helper's next line",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"] + "\necho a#b; "
                                                           + whole_job["steps"][0]["run"]}, tripwire]}}, True, True),
        ("a quote glued to a word before a whole build on the helper's next line",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"] + '\necho x" #"; '
                                                           + whole_job["steps"][0]["run"]}, tripwire]}}, True, True),
        ("a whole build with a redirect before --lib, beside the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": helper_build["run"]
                                                           + "; cargo test --all-features 2>&1 --lib --no-run"},
                                                   tripwire]}}, True, True),
        ("a whole build whose trailing comment names the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": whole_job["steps"][0]["run"] + "  # scripts/ci/lib-parts.sh"},
                                                   tripwire]}}, True, True),
        ("a helper job whose tripwire runs before the build",
         {**allowed, ("ci.yml", "new"): {"steps": [tripwire, helper_build]}}, True, True),
        # The tripwire counts only as a command that runs it: not a comment, not an echo of its path.
        ("a helper job whose tripwire is commented out",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, {**tripwire, "run": "# " + tripwire["run"]}]}},
         True, True),
        ("a helper job whose tripwire is only echoed",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, {**tripwire, "run": "echo " + tripwire["run"]}]}},
         True, True),
        ("a helper job whose tripwire is behind ||",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, {**tripwire, "run": "true || " + tripwire["run"]}]}},
         True, True),
        # Placement reads each command as the census does: a build named only in a comment is not a later build step.
        ("a step after the tripwire that names a build only in a comment",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, tripwire,
                                                   {"run": "echo done  # cargo test --all-features --lib --no-run"}]}},
         False, True),
        ("a comment-only step after the tripwire that names a build",
         {**allowed, ("ci.yml", "new"): {"steps": [helper_build, tripwire,
                                                   {"run": "# cargo test --all-features --lib --no-run"}]}},
         False, True),
        ("a whole build after an escaped > and &, on the helper's line",
         {**allowed, ("ci.yml", "new"): {"steps": [
             {"run": "scripts/ci/lib-parts.sh export 1 out \\>& cargo test --all-features --lib --no-run"},
             tripwire]}}, True, True),
        ("a cargo build with 2>&1 before --tests, beside the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [
             helper_build, {"run": "scripts/ci/with-memory-log.sh cargo build --all-features 2>&1 --tests"},
             tripwire]}}, True, True),
        # A test binary's own flags after `--` (--test-threads) do not make the build a single-target one.
        ("a whole build with --test-threads after --, beside the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [
             helper_build, {"run": "cargo test --all-features --lib 2>&1 -- --test-threads=1"}, tripwire]}}, True, True),
        # bash ends a comment at the newline: a backslash at the end of a comment does not continue the line.
        ("a whole build on the line after a comment ending in a backslash, beside the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [
             helper_build, {"run": "# build the lib tests \\\ncargo test --all-features --lib --no-run"},
             tripwire]}}, True, True),
        ("a new job calling export-lib itself, without the helper",
         {**allowed, ("ci.yml", "new"): {"steps": [{"run": "python3 scripts/ci/shard_tests.py export-lib out"}]}}, True, True),
        ("an allowed job converted but still listed",
         {**allowed, ("ci.yml", "test-throwaway-hosted"): helper_job}, True, True),
        ("the allowance as it stands", allowed, False, True),
        ("the packaged-crate build, its script building by part",
         {**allowed, ("ci.yml", "package-tests"): packaged_job}, False, True),
        ("the packaged-crate build, its script building the whole binary",
         {**allowed, ("ci.yml", "package-tests"): packaged_job}, True, False),
    ]
    for label, jobs, want_bad, by_part in census_cases:
        found = census(jobs, packaged_by_part=by_part)
        ok = bool(found) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} census, {label}: problems {found}")
    part = 'MCP_GATEWAY_TEST_PART="$k" cargo test --all-features --locked --lib --no-run'
    rest = "cargo test --all-features --locked --no-run --test '*' --bins --examples"
    # The canonical read, as packaged-tests.sh writes it (continued onto a second line).
    n_line = ("  n=\"$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)"
              "[[:space:]]*;.*/\\1/p' \\\n    scripts/dev/test-parts-build.rs)\"\n")
    shape = ('elif [ "$mode" = build ]; then\n' + n_line + '  for k in $(seq 1 "$n"); do\n    {}\n  done\n  {}\nelse\n'
             '  cargo test --all-features\nfi\n')
    packaged_cases = [
        ("by part, then the other targets", shape.format(part, rest), False),
        ("today's whole build", 'elif [ "$mode" = build ]; then\n  cargo test --all-features --locked --no-run\nelse\nfi\n', True),
        ("--tests selects the lib again", shape.format(part, rest.replace("--test '*'", "--tests")), True),
        ("a part without its variable", shape.format(part.replace('MCP_GATEWAY_TEST_PART="$k" ', ""), rest), True),
        ("parts only, the other targets never built", shape.format(part, "true"), True),
        # One rule each: every other case also trips a second rule, so these keep each rule's own failure seen.
        ("a whole build beside the parts and the other targets",
         shape.format(part, rest + "\n  cargo test --all-features --locked --no-run"), True),
        ("a second other-targets call that also selects the lib",
         shape.format(part, rest + "\n  " + rest.replace("--bins", "--lib --bins")), True),
        ("the other targets only, no part", shape.format("true", rest), True),
        ("a fixed list of parts, not 1..N", shape.format(part, rest).replace('$(seq 1 "$n")', "1 2"), True),
        ("N not read from the build script", shape.format(part, rest).replace(n_line, "  n=2\n"), True),
        ("n overridden after it is read", shape.format(part, rest).replace(n_line, n_line + "  n=2\n"), True),
        ("n overridden after a separator", shape.format(part, rest).replace(n_line, n_line + "  true; n=2\n"), True),
        ("n overridden after a quoted # glued to a word",
         shape.format(part, rest).replace(n_line, n_line + '  true; msg=x" #"; n=2\n'), True),
        ("n overridden inside a one-line if", shape.format(part, rest).replace(n_line, n_line + "  if true; then n=2; fi\n"), True),
        # One row per word that can stand before an assignment, and per way to assign n besides `n=` first.
        ("n overridden in an if condition", shape.format(part, rest).replace(n_line, n_line + "  if n=2; then :; fi\n"), True),
        ("n overridden in a while condition",
         shape.format(part, rest).replace(n_line, n_line + "  while n=2; do break; done\n"), True),
        ("n overridden in an until condition",
         shape.format(part, rest).replace(n_line, n_line + "  until n=2; do :; done\n"), True),
        ("n overridden after do", shape.format(part, rest).replace(n_line, n_line + "  for x in 1; do n=2; done\n"), True),
        ("n overridden after else",
         shape.format(part, rest).replace(n_line, n_line + "  if false; then :; else n=2; fi\n"), True),
        ("n overridden after elif",
         shape.format(part, rest).replace(n_line, n_line + "  if false; then :; elif n=2; then :; fi\n"), True),
        ("n overridden in a brace group", shape.format(part, rest).replace(n_line, n_line + "  { n=2; }\n"), True),
        ("n overridden after !", shape.format(part, rest).replace(n_line, n_line + "  ! n=2\n"), True),
        ("n overridden after time -p", shape.format(part, rest).replace(n_line, n_line + "  time -p n=2\n"), True),
        ("n overridden as a second assignment word", shape.format(part, rest).replace(n_line, n_line + "  x=1 n=2\n"), True),
        ("n overridden by export beside another name",
         shape.format(part, rest).replace(n_line, n_line + "  export a=1 n=2\n"), True),
        ("n appended to", shape.format(part, rest).replace(n_line, n_line + "  n+=1\n"), True),
        ("n overridden through its first element", shape.format(part, rest).replace(n_line, n_line + "  n[0]=2\n"), True),
        ("n as a for loop's variable", shape.format(part, rest).replace(n_line, n_line + "  for n in 2; do :; done\n"), True),
        ("n as a select loop's variable",
         shape.format(part, rest).replace(n_line, n_line + "  select n in 2; do break; done\n"), True),
        ("n overridden in a case arm",
         shape.format(part, rest).replace(n_line, n_line + '  case "$x" in y) n=2;; esac\n'), True),
        ("n overridden in a case arm on its own line",
         shape.format(part, rest).replace(n_line, n_line + '  case "$x" in\n    y) n=2 ;;\n  esac\n'), True),
        # The rule is a whitelist: the bare word n (not $n or ${n}) appears in one command only, the build script's
        # read. So every other way bash has to write n is refused without being listed.
        ("n written by arithmetic", shape.format(part, rest).replace(n_line, n_line + "  ((n=2))\n"), True),
        ("n written by let", shape.format(part, rest).replace(n_line, n_line + "  let n=2\n"), True),
        ("n written by read", shape.format(part, rest).replace(n_line, n_line + "  read -r n <<< 2\n"), True),
        ("n overridden in a case arm after a command substitution head",
         shape.format(part, rest).replace(n_line, n_line + '  case $(cat mode) in y) n=2;; esac\n'), True),
        ("n overridden in a case arm with a bracket pattern",
         shape.format(part, rest).replace(n_line, n_line + '  case "$mode" in buil[d\\(]) n=2;; esac\n'), True),
        ("n read as ${n}, ${n:-1} and named in a comment",
         shape.format(part, rest).replace(n_line, n_line + '  # n comes from the build script\n'
                                                   '  : "${n:-1}"\n  echo "parts: ${n}"\n'), False),
        # Only $n and the non-assigning ${n...} forms are reads; anything else that names n counts, even a flag.
        ("n decremented by arithmetic", shape.format(part, rest).replace(n_line, n_line + "  ((--n))\n"), True),
        ("n written by printf -v glued to its option", shape.format(part, rest).replace(n_line, n_line + "  printf -vn 1\n"),
         True),
        ("n written by read -a glued to its option",
         shape.format(part, rest).replace(n_line, n_line + "  read -an <<< 1\n"), True),
        ("n assigned by ${n:=1}", shape.format(part, rest).replace(n_line, n_line + '  : "${n:=1}"\n'), True),
        ("n assigned by ${n=1}", shape.format(part, rest).replace(n_line, n_line + '  : "${n=1}"\n'), True),
        ("a -n flag names n too (strict)", shape.format(part, rest).replace(n_line, n_line + '  [ -n "$x" ] || true\n'),
         True),
        # One mention of n, so only the canonical-read rule can refuse it.
        ("the read prints a constant", shape.format(part, rest).replace(
            n_line, "  n=\"$(sed 's/.*/2/;q' scripts/dev/test-parts-build.rs)\"\n"), True),
        # The read must come before the loop, or the loop runs on whatever n held before the block.
        ("the canonical read after the part loop",
         shape.format(part, rest).replace(n_line, "").replace("  done\n", "  done\n" + n_line, 1), True),
        # The loop's body is a whitelist too: only the part call, so nothing can cut the loop short.
        ("a break after the first part build", shape.format(part + "\n    break", rest), True),
        ("the part call only echoed in the loop", shape.format("echo " + part, rest), True),
        # Each command is judged, not each line: a whole build chained after a part call, or a cargo build of the tests.
        ("a whole build chained after the part call on its line",
         shape.format(part + "; cargo test --all-features --locked --no-run", rest), True),
        ("a cargo build of the tests in the build block",
         shape.format(part, rest + "\n  cargo build --all-features --locked --tests"), True),
        ("a part built outside the loop", shape.format(part, rest + "\n  " + part), True),
        ("a part built outside the loop, continued before --lib",
         shape.format(part, rest + '\n  MCP_GATEWAY_TEST_PART="$k" cargo test --all-features --locked \\\n    --lib --no-run'),
         True),
    ]
    for label, text, want_bad in packaged_cases:
        found = packaged_build_problems(text)
        ok = bool(found) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} packaged build, {label}: problems {found}")
    # The packaged run mode (the post-merge packaged suite): one helper `run` call, judged per command, nothing else.
    helper_run = '  "$root/scripts/ci/lib-parts.sh" run --all-features --locked -- \\\n    --skip a \\\n    --skip b\n'
    run_shape = shape.format(part, rest).replace("else\n  cargo test --all-features\nfi\n", "else\n{}fi\n")
    run_cases = [
        ("today's whole cargo test", shape.format(part, rest), True),
        ("the helper call and a stray cargo test", run_shape.format(helper_run + "  cargo test --all-features\n"), True),
        ("a build chained on the helper call's line", run_shape.format(helper_run.replace("--skip b\n", "--skip b; cargo test\n")),
         True),
        ("the helper call only", run_shape.format(helper_run), False),
        ("no helper call and no build", run_shape.format("  true\n"), True),
        ("two helper calls", run_shape.format(helper_run + helper_run), True),
        ("a build continued across lines beside the helper call",
         run_shape.format(helper_run + "  cargo \\\n    test --all-features\n"), True),
    ]
    for label, text, want_bad in run_cases:
        found = packaged_run_problems(text)
        ok = bool(found) == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} packaged run, {label}: problems {found}")
    run_step = {"run": "scripts/ci/with-memory-log.sh scripts/ci/lib-parts.sh run --all-features -- --skip x"}
    packaged_run_job = {"steps": [{"run": "scripts/ci/with-memory-log.sh scripts/ci/packaged-tests.sh run"}, tripwire]}
    placement = "no `if: always()` step running"
    run_census = [
        ("a job through the helper's run, tripwire after it", {("release.yml", "v"): {"steps": [run_step, tripwire]}}, True,
         False, ""),
        # The placement rows name their reason: without the run mode known as a build, these jobs fail for another one.
        ("the tripwire before the run step", {("release.yml", "v"): {"steps": [tripwire, run_step]}}, True, True, placement),
        ("the tripwire without if: always()",
         {("release.yml", "v"): {"steps": [run_step, {**tripwire, "if": "success()"}]}}, True, True, placement),
        ("the tripwire before a later run step",
         {("release.yml", "v"): {"steps": [run_step, tripwire, run_step]}}, True, True, placement),
        ("the packaged suite while its run mode goes through the helper", {("packaged-suite.yml", "p"): packaged_run_job},
         True, False, ""),
        ("the packaged suite while its run mode builds whole", {("packaged-suite.yml", "p"): packaged_run_job}, False, True,
         "builds the library tests without"),
    ]
    for label, jobs, run_by_part, want_bad, reason in run_census:
        found = census({**allowed, **jobs}, packaged_by_part=True, packaged_run_by_part=run_by_part)
        ok = bool(found) == want_bad and (not reason or any(reason in p for p in found))
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} census, run mode: {label}: problems {found}")
    # The scanner itself, as bash splits a line into commands.
    split_cases = [
        ("a; b", ["a", "b"]),
        ("a && b || c | d & e", ["a", "b", "c", "d", "e"]),
        ("a |& b", ["a", "b"]),
        ('echo " #"; b', ['echo " #"', "b"]),
        ("echo ' # '; b", ["echo ' # '", "b"]),
        ('echo x" #"; b', ['echo x" #"', "b"]),
        ("echo a#b; b", ["echo a#b", "b"]),
        ("a # c; b", ["a"]),
        ("cargo test 2>&1 --lib", ["cargo test 2>&1 --lib"]),
        ("a &>log; b", ["a &>log", "b"]),
        ("echo a >&2; b", ["echo a >&2", "b"]),
        # An escaped > is a literal character, so the & after it separates.
        ("echo a \\>& b", ["echo a \\>", "b"]),
        # A redirection's target ends the redirection: an escape or a quote after > leaves the next & a separator.
        ("echo x >\\a& b", ["echo x >\\a", "b"]),
        ('echo x >"a"& b', ['echo x >"a"', "b"]),
        ("echo \\; b", ["echo \\; b"]),
        ('echo "a\\"; b"; c', ['echo "a\\"; b"', "c"]),
        ("echo 'a\\'; b", ["echo 'a\\'", "b"]),
        ('echo "it\'s"; b', ['echo "it\'s"', "b"]),
        ("echo \\'; b", ["echo \\'", "b"]),
        ("a;# c", ["a"]),
        ('echo "open', None),
    ]
    for line, want in split_cases:
        got = shell_commands(line)
        wrong += got != want
        print(f"{'ok   ' if got == want else 'WRONG'} shell commands of {line!r}: {got}")
    # main() judges the packaged job by the script it reads: a whole build there makes that job a census problem.
    # Its ::error:: lines are captured, so this expected failure raises no annotation.
    with tempfile.TemporaryDirectory() as tmp:
        whole = Path(tmp) / "packaged-tests.sh"
        whole.write_text('elif [ "$mode" = build ]; then\n  cargo test --all-features --locked --no-run\nelse\nfi\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(whole)
    ok = rc == 1 and "ci.yml:package-tests builds the library tests without" in out.getvalue()
    wrong += not ok
    print(f"{'ok   ' if ok else 'WRONG'} main, a whole build in the packaged script: exit {rc}")
    # Coverage split C1-C3: the census reads the helper's cov mode as a build by part.
    cov_line = 'scripts/ci/with-memory-log.sh scripts/ci/lib-parts.sh cov "$COVERAGE_PARTS" "$PART"'
    cov_job = job(swap, step(cov_line), step("scripts/ci/memory-tripwire.sh", **{"if": "always()"}))

    def c1() -> None:
        in_scope, problems = check_job("fixture:cov", cov_job)
        found = census({**allowed, ("fixture.yml", "cov"): cov_job}, packaged_by_part=True)
        assert in_scope, "cov helper command is not counted as a library build"
        assert builds_through(cov_job, (HELPER,)), "cov build is not recognized as through the helper"
        assert not problems and not found, (problems, found)

    def c2() -> None:
        direct = job(swap, step('scripts/ci/with-memory-log.sh python3 scripts/ci/coverage_shards.py run '
                                '"$COVERAGE_PARTS" "$PART"'),
                     step("scripts/ci/memory-tripwire.sh", **{"if": "always()"}))
        found = census({**allowed, ("coverage-probe.yml", "linux-part"): direct}, packaged_by_part=True)
        want = "coverage-probe.yml:linux-part builds the library tests without scripts/ci/lib-parts.sh"
        assert any(want in problem for problem in found), f"direct coverage build not rejected: {found}"

    def c3() -> None:
        no_tripwire = job(swap, step(cov_line))
        found = census({**allowed, ("fixture.yml", "cov"): no_tripwire}, packaged_by_part=True)
        want = "no `if: always()` step running scripts/ci/memory-tripwire.sh"
        assert any(want in problem for problem in found), f"missing cov tripwire not diagnosed: {found}"

    cov_cases = (("C1 cov helper counted", c1), ("C2 direct coverage forbidden", c2),
                 ("C3 cov tripwire required", c3))
    for label, test in cov_cases:
        try:
            test()
        except AssertionError as error:
            wrong += 1
            print(f"WRONG {label}: {error}")
        else:
            print(f"ok   {label}")
    # The summary comes last, so a failing row never prints after it.
    total = (len(cases) + len(alias_cases) + 6 + len(memlog_cases()) + len(census_cases) + len(packaged_cases)
             + len(run_cases) + len(run_census) + len(split_cases) + 1 + len(cov_cases))
    print(f"self-test: {total - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


def memlog_cases() -> list[tuple[str, str, str, dict, bool]]:
    """(label, workflow, job id, job, problems expected) for memlog_problems, from the real step shapes."""
    w = MEMLOG + " "

    def job(*steps: dict, limit: int | None = 60) -> dict:
        return {"runs-on": "ubuntu-latest", "steps": list(steps), **({"timeout-minutes": limit} if limit else {})}

    def step(run: str, limit: int | None = 20, name: str = "Build") -> dict:
        return {"name": name, "run": run, **({"timeout-minutes": limit} if limit else {})}

    feature = ("cargo test --all-targets --no-run --config profile.dev.debug-assertions=false \\\n"
               "  --config profile.test.debug-assertions=false")
    loop = ('for target in "--test a" "--lib b"; do\n  echo "phase compile"\n  cargo test --all-features $target --no-run\n'
            '  echo "phase run"\n  cargo test --all-features $target 2>&1 | tee "$RUNNER_TEMP/a.log"\ndone')
    dbus = ("dbus-run-session -- bash -euo pipefail -c '\n  printf \"ci\" | gnome-keyring-daemon --unlock > /dev/null\n"
            "  cargo test --all-features --lib -- --ignored --exact a15 2>&1 | tee \"$RUNNER_TEMP/a15.log\"\n'")
    cov = 'set -o pipefail\ncargo llvm-cov clean --workspace\npython3 scripts/ci/coverage_shards.py run "$P" "$PART" 2>&1 | tee run.log'
    return [
        ("C1 a bare library build", "ci.yml", "j", job(step("cargo test --all-features --lib --no-run")), True),
        ("C2 a wrapped build with a limit", "ci.yml", "j", job(step(w + "cargo test --all-features --lib --no-run")), False),
        ("C3 the wrapper only in a comment above", "ci.yml", "j",
         job(step(f"# {w}cargo test\ncargo test --all-features --lib --no-run")), True),
        ("C3b the wrapper only in a trailing comment", "ci.yml", "j",
         job(step(f"cargo test --all-features --lib --no-run # {w}")), True),
        # The census's own line reading: bash ends a comment at the newline, and flags after `--` are the test binary's.
        ("C3c a bare build on the line after a comment ending in a backslash", "ci.yml", "j",
         job(step(f"# {w}\\\ncargo test --all-features --lib --no-run")), True),
        ("C3d a bare build with --test-threads after --", "ci.yml", "j",
         job(step("cargo test --all-features --lib -- --test-threads=1")), True),
        ("C3e a bare build continued after `cargo \\`", "ci.yml", "j",
         job(step("cargo \\\n  test --all-features --lib --no-run")), True),
        ("C4 limits + reserve under the job limit", "ci.yml", "j",
         job(step(w + "cargo test --lib", 25), step(w + "cargo test --lib", 5), step(w + "cargo test --lib", 5), limit=50), False),
        ("C4b limits + reserve equal to the job limit", "ci.yml", "j",
         job(step(w + "cargo test --lib", 25), step(w + "cargo test --lib", 5), step(w + "cargo test --lib", 5), limit=45), True),
        ("C5 no job limit counts as 360", "ci.yml", "j", job(step(w + "cargo test --lib", 340), limit=None), False),
        ("C5b no job limit, steps past 360", "ci.yml", "j", job(step(w + "cargo test --lib", 351), limit=None), True),
        ("C6 a build step with no limit of its own", "ci.yml", "j", job(step(w + "cargo test --lib", None)), True),
        ("C7 a log-only step with no limit", "ci.yml", "test-shards",
         job(step(w + "python3 scripts/ci/shard_tests.py run linux lib-a", None, "Shard suite")), False),
        ("C7b a log-only step that sets a limit", "ci.yml", "test-shards",
         job(step(w + "python3 scripts/ci/shard_tests.py run linux lib-a", 30, "Shard suite")), True),
        ("C8 two build lines, one wrapped", "ci.yml", "j", job(step(w + "cargo test --lib --no-run\ncargo test --lib")), True),
        ("C12 an echo spelling out cargo test counts as a bare build (fail closed)", "ci.yml", "j",
         job(step(f'echo "phase compile: cargo test --lib --no-run at $(date -u +%T)"\n{w}cargo test --all-features --lib --no-run')), True),
        ("C12 the real phase line: names no build, its substitutions run ps, wc and free", "ci.yml", "j",
         job(step('echo "phase compile: the lib test binary at $(date -u +%T), n: $(ps -u "$(id -u)" -o pid= | wc -l), '
                  "m: $(free -m | awk '/^Mem:/ {print $3}')\"\n" + w + "cargo test --all-features --lib --no-run")), False),
        ("C13 a wrapped first command, then a bare build after &&", "ci.yml", "j", job(step(w + "true && cargo test --all-features --lib")), True),
        ("C13 a bare build after ;", "ci.yml", "j", job(step(w + "cargo test --lib --no-run; cargo test --lib")), True),
        ("C13 echo, then a bare build after &&", "ci.yml", "j", job(step("echo start && cargo test --all-features --lib")), True),
        ("C13 an echo whose substitution builds", "ci.yml", "j", job(step('echo "$(cargo test --all-features --lib)"')), True),
        ("C13 a wrapped build piped to tee", "ci.yml", "j", job(step(w + 'cargo test --all-features --lib 2>&1 | tee "$RUNNER_TEMP/x.log"')), False),
        ("C15 a backtick build in an echo", "ci.yml", "j", job(step("echo `cargo test --all-features --lib`")), True),
        ("C15 a build backgrounded after &", "ci.yml", "j", job(step("echo start & cargo test --all-features --lib")), True),
        ("C15 a build in a substitution passed to the wrapper", "ci.yml", "j", job(step(w + 'true "$(cargo test --all-features --lib)"')), True),
        ("C15 a one-line loop running the wrapper", "ci.yml", "j",
         job(step(f"for t in a b; do {w}cargo test --all-features --lib $t; done")), False),
        ("C15 the wrapper on a continued line", "ci.yml", "j", job(step(w + "\\\n  cargo test --all-features --lib --no-run")), False),
        ("C15 the mutant harness through the wrapper", "m.yml", "j",
         job(step(w + 'python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o')), False),
        # The mutants jobs fetch the wrapper from the release line, like the runner, and run that copy.
        ("C15b the mutant harness through the release line's fetched wrapper", "m.yml", "j",
         job(step(f'{MEMLOG_FETCHED} python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o')), False),
        ("C15c another fetched script is not the wrapper", "m.yml", "j",
         job(step('bash "$RUNNER_TEMP/other.sh" python3 "$RUNNER_TEMP/run_mutants.py" run --platform linux --out o')), True),
        ("C16 a comment naming cargo test is not a build", "ci.yml", "j",
         job(step(f"# cargo test --all-features --lib runs below\n{w}cargo test --all-features --lib --no-run")), False),
        ("C16 a bare single-target run beside a wrapped library build", "ci.yml", "j",
         job(step(f"{w}cargo test --all-features --lib --no-run\ncargo test --all-features --test one_target")), False),
        ("C17 the wrapper named on the line before a bare build", "ci.yml", "j",
         job(step(f"ls -l {MEMLOG}\ncargo test --all-features --lib")), True),
        ("C17 the wrapper as an assignment's value", "ci.yml", "j", job(step(f"VAR={MEMLOG} cargo test --all-features --lib")), True),
        ("C17 a substitution glued to the wrapper's argument", "ci.yml", "j", job(step(w + '"$(cargo test --all-features --lib)"')), True),
        ("C17 the wrapper after && before a bare build", "ci.yml", "j", job(step(f"test -x {MEMLOG} && cargo test --all-features --lib")), True),
        ("C18 a wrapped build inside a subshell", "ci.yml", "j", job(step(f"({w}cargo test --all-features --lib)")), False),
        ("C18 a wrapped build after a backgrounded command", "ci.yml", "j", job(step(f"sleep 1 & {w}cargo test --all-features --lib")), False),
        ("C18 a wrapped build after &&", "ci.yml", "j", job(step(f"true && {w}cargo test --all-features --lib")), False),
        ("C14 a non-build step's limit counts against the job", "ci.yml", "j",
         job({"name": "Setup", "run": "true", "timeout-minutes": 30}, step(w + "cargo test --lib", 25), limit=60), True),
        ("C11 feature-combos continuation, wrapped", "f.yml", "j", job(step(w + feature)), False),
        ("C11 feature-combos continuation, bare", "f.yml", "j", job(step(feature)), True),
        ("C11 UPGRADING loop, both cargo lines wrapped", "ci.yml", "j",
         job(step(loop.replace("  cargo test", "  " + w + "cargo test"))), False),
        ("C11 UPGRADING loop, the run line bare", "ci.yml", "j",
         job(step(loop.replace("  cargo test --all-features $target --no-run", f"  {w}cargo test --all-features $target --no-run"))), True),
        ("C11 keychain dbus script, inner cargo wrapped", "ci.yml", "j", job(step(dbus.replace("  cargo test", "  " + w + "cargo test"), 5)), False),
        ("C11 keychain dbus script, the whole command wrapped", "ci.yml", "j", job(step(w + dbus, 5)), False),
        ("C11 whole command wrapped, then a bare build after it", "ci.yml", "j",
         job(step(w + dbus + "\ncargo test --all-features --lib", 5)), True),
        ("C11 whole command wrapped, but its body has a second quote", "ci.yml", "j",
         job(step(w + dbus.replace("--exact a15", "--exact 'a15'"), 5)), True),
        ("C11 keychain dbus script, bare", "ci.yml", "j", job(step(dbus, 5)), True),
        ("C11 coverage tee pipeline, wrapped", "c.yml", "j", job(step(cov.replace("python3 scripts", w + "python3 scripts"), 70), limit=180), False),
        ("C11 coverage tee pipeline, bare", "c.yml", "j", job(step(cov, 70), limit=180), True),
    ]


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main())
