#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of an OS test job (MIK-8482).

The Tests, Windows check and macOS check suites run as shards. Each shard is
a plain `cargo test` over a subset of test targets. The shards of one OS are
exact complements of the command that job ran before sharding:

- the library is split by a libtest filter and the matching `--skip` (Windows
  cuts it by module filters into four lib legs, each skipping the filters of
  the legs before it), or run whole in one shard (macOS). Filters match substrings of
  the test path, so a module filter also takes its nested paths;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`) where the OS runs a single integration shard.

`scripts/ci/test_os_shards.py` holds the table below to that rule. Each shard
also fails when it selects fewer tests than its floor, so a filter that
quietly stops matching cannot read as green. A floor that drops because tests
were deleted is lowered in the same diff, where review sees it.

  shard_tests.py run <os> <shard>    run it (exit 1 on failure or under floor)
  shard_tests.py export-lib <dir>    build the lib test binary and copy it to <dir>
  shard_tests.py run-prebuilt <os> <shard> <binary>
                                     run a SHARED_BUILD shard from that binary
  shard_tests.py run-prebuilt-parts <os> <leg> --build <dir>
                                     build and run a PARTS leg's lib test parts one at a time
  shard_tests.py with-home -- <cmd>...
                                     run <cmd> in a private gateway home, removed afterwards
  shard_tests.py export-home <file>  make a private gateway home for the rest of a CI job and
                                     append its variables to <file> ($GITHUB_ENV)
  shard_tests.py --self-test         check the counter against fixed logs
"""
from __future__ import annotations

import contextlib
import io
import glob
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_union  # noqa: E402  the one parser of the part count N

SDK = "a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result"
BURST = "mik_7479_full_burst"
# Each skip names the job that runs the test in full, and its ticket:
#   SDK: job `task-sdk-recovery`, MIK-7534.
#   BURST: workflow mrtr7b-full-burst.yml, MIK-7479 (Windows: MIK-7644).
SKIPS = {
    "linux": ["--skip", SDK, "--skip", BURST],
    "macos": ["--skip", SDK, "--skip", BURST],
    "windows": ["--skip", BURST],
}
LIB_SPLIT = "gateway::"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIB_BINARY = "lib-tests"
GLOB_A, GLOB_B, GLOB_ALL = "[a-l]*", "[!a-l]*", "*"
BASE = ["test", "--all-features", "--no-fail-fast"]

# (step, cargo args after `cargo test --all-features --no-fail-fast`,
#  libtest args before the OS skips, floor of selected tests)
_LIB_A = ("suite", ["--lib"], [LIB_SPLIT])
_LIB_B = ("suite", ["--lib"], ["--skip", LIB_SPLIT])
# Windows runs its library from one shared exe in four legs, so a leg costs setup only, not a
# compile. gateway:: is cut in two (router and server first, then the rest of it), security::
# runs on its own, and lib-b takes whatever is left. Each leg skips the filters of the legs
# before it (the cascade test_os_shards.py checks), so every library test runs in exactly one.
_WIN_FIRST = ["gateway::router::", "gateway::server::"]
_WIN_SKIP_FIRST = [x for f in _WIN_FIRST for x in ("--skip", f)]
_WIN_LIB_A = ("suite", ["--lib"], list(_WIN_FIRST))
_WIN_LIB_D = ("suite", ["--lib"], [LIB_SPLIT, *_WIN_SKIP_FIRST])
_WIN_LIB_C = ("suite", ["--lib"], ["security::", *_WIN_SKIP_FIRST, "--skip", LIB_SPLIT])
_WIN_LIB_B = ("suite", ["--lib"], [*_WIN_SKIP_FIRST, "--skip", LIB_SPLIT, "--skip", "security::"])
# The binary's own unit tests (599 of them) moved into the library behind `cli::run`: the
# `--bins` selection of every int shard dropped by 597 (the binary keeps 2), and the library
# shards gained them. Linux int-a measured 1063 before (run 42963873558), so 466 after, at the
# same ~78% floor ratio: 365. Windows int-a measured 970 before (so at least 373 after): 295.
# macOS int (floor 2205 under ~2250) loses the same 597 or fewer: 1600. The lib floors only
# rise in practice (the moved tests land in lib-b, or lib-c for transport::/events:: paths).
SHARDS: dict[str, dict[str, list[tuple[str, list[str], list[str], int]]]] = {
    # Floors: the selections measured by the MIK-8482 probe (run 39135535466).
    "linux": {
        "lib-a": [(*_LIB_A, 5353)],
        "lib-b": [(*_LIB_B, 6941)],
        "int-a": [("suite", ["--bins", "--test", GLOB_A], [], 365)],
        "int-b": [("suite", ["--test", GLOB_B], [], 1371), ("doc", ["--doc"], [], 55)],
    },
    "windows": {
        # Floors: 0.575 of each leg's count replayed over run 45007740526's 20,327 names
        # (the lowest selected-to-floor proportion among the former legs).
        "lib-a": [(*_WIN_LIB_A, 2528)],
        "lib-d": [(*_WIN_LIB_D, 2861)],
        "lib-c": [(*_WIN_LIB_C, 1086)],
        "lib-b": [(*_WIN_LIB_B, 5211)],
        "int-a": [("suite", ["--bins", "--test", GLOB_A], [], 295)],
        "int-b": [("suite", ["--test", GLOB_B], [], 1238)],
    },
    # macOS builds the lib test parts, never the whole binary (it swapped the 3-core, 7 GB runner): `lib-b`
    # builds and runs parts 1-4 one at a time, `int` runs its suite and `int-lib` builds and runs part 5 in the
    # same job. PARTS is the one source of which leg takes which part; the workflow names the leg only.
    "macos": {
        "lib-b": [("parts", ["--lib"], [], 0)],
        "int": [("suite", ["--bins", "--test", GLOB_ALL], [], 1600), ("doc", ["--doc"], [], 55)],
        "int-lib": [("parts", ["--lib"], [], 0)],
    },
}
# Which lib test parts each part-building leg builds and runs (`run-prebuilt-parts <os> <leg> --build`).
PARTS = {"macos": {"lib-b": (1, 2, 3, 4), "int-lib": (5,)}}
# The macOS part counts the floors come from (each part's list less the macOS skips), with the run they were read
# from: the E1 dispatch run at 0a3037aecd, both legs' per-part notices. Each leg's floor is its parts' sum, 2% under.
MACOS_PART_COUNTS = {"run": "44460056220 (E1, macOS, 0a3037aecd)", 1: 3827, 2: 3700, 3: 4526, 4: 5157, 5: 3615}


def part_count() -> int:
    """N, from the build script that declares it (lib_union.py's parser)."""
    return lib_union.part_count(Path(ROOT, lib_union.BUILD_SCRIPT))


def leg_parts(os_kind: str, leg: str, solo: bool = False) -> tuple[int, ...]:
    """The parts LEG builds; lib-b in the os-sensitive solo lane (it runs alone) takes every part."""
    if solo and leg == "lib-b":
        return tuple(range(1, part_count() + 1))
    return PARTS[os_kind][leg]


for _leg, _parts in PARTS["macos"].items():
    SHARDS["macos"][_leg] = [("parts", ["--lib"], [], sum(MACOS_PART_COUNTS[k] for k in _parts) * 98 // 100)]
# Shards that are matrix legs of their own but compile nothing: they run from the lib test binary one job
# of the run builds and shares (ci.yml's linux-lib-build, `export-lib`), under the same guards as `run`.
SHARED_BUILD = {"linux": ("lib-a", "lib-b"), "windows": ("lib-a", "lib-b", "lib-c", "lib-d")}
# The lib test binary's folder under BY_BINARY, as the cargo runner names it (`mcp_gateway-<hash>`, hash dropped).
LIB_TARGET = "mcp_gateway"
# Built, not run: the default `cargo test` target set compiles examples, and
# Windows' former `cargo test --no-run` did too.
EXAMPLES = {"linux": "int-b", "macos": "int", "windows": "int-b"}
# Windows printed every test's output (`--show-output`) before sharding.
OUTPUT = {"windows": ["--show-output"]}

# A test leaves nothing in the temp directory. The Linux shards run
# cargo with TMPDIR set to a fresh private directory and fail on any entry left
# there that KNOWN_LEFTOVERS does not allow. The list holds only what a pending
# fix removes, each as (pattern on the entry name, pattern every file inside it
# must match, most allowed, why). An entry is matched by its contents too, so
# a leftover from any other source fails even when its folder name is generic.
# It may only shrink: the self-test holds each entry and count to
# LEFTOVER_CEILING. Empty since the late audit writes were fixed: the audit
# high-water mark they left in a plain temp dir no longer appears in any lib or
# int shard.
TMP_GUARDED = {"linux"}
KNOWN_LEFTOVERS: list[tuple[str, str, int, str]] = []
# Written out, not derived from the list above: an entry added there and not
# here, or a count raised past its ceiling, fails the self-test, so the list
# can only lose entries.
LEFTOVER_CEILING: dict[tuple[str, str], int] = {}

HEADER = re.compile(r"^\s*(Running|Doc-tests) ")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RUNNING = re.compile(r"^running (\d+) tests?$")
RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")
# test_dir_keep.rs report_unkept: "<kind> at <path> is in a temp dir no test kept; created by <test>",
# on raw stderr, so it can start mid-line. The kind is read, never listed: a new writer's kind fails too.
# The path runs to the report's fixed suffix, so a path with spaces is read whole.
# The kind is one or two lowercase words (every writer's kind is), and the path holds no " at ", so lowercase
# words or an earlier " at " that raw stderr put before the report on the same line are not read into either.
UNKEPT = re.compile(r"\b([a-z]+(?: [a-z]+)?) at ((?:(?! at ).)+?) is in a temp dir no test kept; created by (\S+)")


def unkept(lines: list[str]) -> list[str]:
    """One failure per distinct unkept-dir report in a step's output, whatever its kind."""
    return list(dict.fromkeys(
        f"unkept temp dir: {m.group(1)} at {m.group(2)}; created by {m.group(3)}"
        for line in lines for m in UNKEPT.finditer(line)))


def selected(lines: list[str]) -> int:
    """Tests libtest selected, one `running N` per test binary.

    Only the first `running N` after each `Running`/`Doc-tests` header
    counts. A test that re-runs its own binary as a child with inherited
    stdout (transparency_log_lease_tests.rs) prints a further `running 1
    test`, which is the child's, not another selected test.

    Rustdoc is the exception: it runs merged doctests and standalone ones as
    two batches under one `Doc-tests` header (`running 51`, then `running 4`).
    Inside a doctest section each `test result:` re-arms the count. Doctests
    spawn no libtest children, so nothing else can print there.
    """
    total, armed, doc = 0, False, False
    for line in lines:
        m = HEADER.match(line)
        if m:
            armed, doc = True, m.group(1) == "Doc-tests"
            continue
        m = RUNNING.match(line.strip())
        if m and armed:
            total += int(m.group(1))
            armed = False
        elif doc and RESULT.search(line):
            armed = True
    return total


def cargo(
    args: list[str],
    program: tuple[str, ...] = ("cargo",),
    env: dict[str, str] | None = None,
) -> tuple[int, list[str]]:
    """Run cargo with output mirrored to this job's log.

    Bytes are mirrored as they arrive and decoded (UTF-8, lossy) only for
    counting. Decoding through the locale and writing text back died on
    Windows: cp1252 turned an output byte into U+FFFD, which cp1252 stdout
    cannot encode (#3944, Windows int-a).
    """
    p = subprocess.Popen(
        [*program, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
    )
    lines = []
    assert p.stdout is not None
    out = sys.stdout.buffer
    for raw in p.stdout:
        out.write(raw)
        out.flush()
        # ci.yml sets CARGO_TERM_COLOR=always: match on the text, not the escapes.
        lines.append(ANSI.sub("", raw.decode("utf-8", "replace").rstrip("\r\n")))
    return p.wait(), lines


def leftovers(tmp: str) -> dict[str, str]:
    """Every entry left in a shard's TMPDIR, by name, with its path. An entry a test binary left in
    its own BY_BINARY/<binary> folder is named `<binary>/<entry>`; an empty binary folder is no
    leftover. The runner itself is not one. Everything else at the top is checked as it is."""
    out = {}
    for name in os.listdir(tmp):
        path = os.path.join(tmp, name)
        if name == RUNNER_NAME:
            continue
        if name == BY_BINARY and os.path.isdir(path) and not os.path.islink(path):
            for binary in os.listdir(path):
                folder = os.path.join(path, binary)
                if not os.path.isdir(folder) or os.path.islink(folder):
                    out[f"{BY_BINARY}/{binary}"] = folder
                    continue
                for entry in os.listdir(folder):
                    out[f"{binary}/{entry}"] = os.path.join(folder, entry)
            continue
        out[name] = path
    return out


def unexpected(entries: dict[str, list[str]],
               known: list[tuple[str, str, int, str]] = KNOWN_LEFTOVERS) -> list[str]:
    """The entries `known` does not allow. An entry is allowed when its name
    matches, it holds at least one file and every file matches, each known
    source up to its count. `entries` maps each name to the files under it."""
    used: dict[tuple[str, str], int] = {}
    bad = []
    for name in sorted(entries):
        files = entries[name]
        for pattern, holds, most, _why in known:
            key = (pattern, holds)
            if (re.fullmatch(pattern, name.rsplit("/", 1)[-1]) and files
                    and all(re.fullmatch(holds, f) for f in files)
                    and used.get(key, 0) < most):
                used[key] = used.get(key, 0) + 1
                break
        else:
            bad.append(name)
    return bad


def files_in(path: str) -> list[str]:
    """The files under a leftover folder, relative and `/`-separated; none for
    a plain file or an unreadable folder, which no known source matches."""
    if not os.path.isdir(path):
        return []
    try:
        # A link to a folder is not walked into: it counts as a file of its
        # own, so it matches no known source.
        return sorted(os.path.relpath(os.path.join(root, f), path).replace(os.sep, "/")
                      for root, dirs, fs in os.walk(path, onerror=_raise)
                      for f in [*fs, *(d for d in dirs if os.path.islink(os.path.join(root, d)))])
    except OSError:
        return []


def _raise(error: OSError) -> None:
    raise error


def contents(path: str, most: int | None = 3) -> str:
    """The files under a leftover entry, with sizes, so a guard failure names
    the writer instead of a random folder name: the first `most`, or all of
    them when `most` is None."""
    try:
        if not os.path.isdir(path):
            return f"{os.lstat(path).st_size}B"
        files = [os.path.join(root, f) for root, _dirs, fs in os.walk(path) for f in fs]
        found = sorted(f"{os.path.relpath(f, path)} {os.lstat(f).st_size}B" for f in files)
    except OSError as error:
        return f"unreadable: {error}"
    if most is None:
        most = len(found)
    shown = ", ".join(found[:most]) or "empty"
    return shown + (f", +{len(found) - most} more" if len(found) > most else "")


def make_home(parent: str) -> dict[str, str]:
    """A fresh, empty gateway home made in `parent`, given as the three variables that send test binaries to it:
    the override itself, and the config and data dirs the library resolves beneath it."""
    home = os.path.join(parent, f"shard-home-{secrets.token_hex(8)}")
    # Only the owner may enter it on POSIX. Windows gets a plain mkdir that inherits the account's temp-dir ACL:
    # the 0o700 form (the one mkdtemp uses) writes a protected DACL with an OWNER RIGHTS entry, and the gateway
    # rejects a lock dir writable by any SID beyond the user, SYSTEM and Administrators, so auth-on starts broke.
    os.mkdir(home, 0o777 if os.name == "nt" else 0o700)
    return {
        "MCP_GATEWAY_TEST_HOME_DIR": home,
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "MCP_GATEWAY_CONFIG_DIR": os.path.join(home, ".mcp-gateway"),
    }


@contextlib.contextmanager
def private_home(base: dict[str, str] | None, tmp: str | None):
    """A gateway home of the shard's own for its test binaries, on every OS: without one, every
    shard on a host shares the account's vault lock and data dir. Made beside the shard's TMPDIR
    (not inside it, so the leftover check never reads it) and removed after the shard, also when a
    step fails. The config and data dirs the lib resolves are set beneath it."""
    values = make_home(os.path.dirname(tmp) if tmp else tempfile.gettempdir())
    home = values["MCP_GATEWAY_TEST_HOME_DIR"]
    env = dict(os.environ if base is None else base)
    env.update(values)
    # A test that skips for a missing tool or right fails here: a feature's only check must not pass by not running.
    # Every shard runs through this home, the packaged-crate suite's included (lib-parts.sh re-runs itself under
    # `with-home`); a file the package leaves out on purpose skips there through test_wait::skip_unshipped.
    env.setdefault("TESTS_REQUIRE_ALL", "1")
    try:
        yield env
    finally:
        try:
            shutil.rmtree(home)
        except OSError as error:
            # Not a shard failure, but never silent: a kept home is state the next run must not see.
            print(f"::warning::could not remove the shard's gateway home {home}: {error}")


def run(os_kind: str, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    failed = run_steps(os_kind, shard, program)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


def with_home(cmd: list[str]) -> int:
    """Run a test command outside the shards (a workflow step, lib-parts.sh run) in a private
    gateway home of its own, the same as a shard's, and hand back its exit code."""
    with private_home(None, None) as env:
        return subprocess.run(cmd, env=env).returncode


def export_home(env_file: str) -> int:
    """For a CI step whose command stays as written: make a gateway home for the rest of the job in RUNNER_TEMP
    (which the runner empties at the start and end of every job) and append its variables to `env_file`
    ($GITHUB_ENV), so the job's later steps run their tests in it."""
    values = make_home(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    with open(env_file, "a", encoding="utf-8") as f:
        f.writelines(f"{key}={value}\n" for key, value in values.items())
    return 0


RUNNER_NAME = ".shard-runner.sh"
BY_BINARY = "by-binary"


# One shared TMPDIR cannot say which test binary left an entry. Every test binary starts through
# this runner instead, with TMPDIR set to BY_BINARY/<target> (cargo's `-<hash>` suffix dropped), so
# a leftover is reported under the binary that left it. A gateway a test spawns inherits that TMPDIR.
RUNNER_SH = """#!/bin/sh
b=${1##*/}
b=${b%-*}
d="$TMPDIR/by-binary/$b"
mkdir -p "$d" || exit 1
TMPDIR=$d exec "$@"
"""


def write_runner(tmp: str) -> str:
    """Write the cargo runner into `tmp` and return its path."""
    path = os.path.join(tmp, RUNNER_NAME)
    with open(path, "w") as f:
        f.write(RUNNER_SH.replace("by-binary", BY_BINARY))
    os.chmod(path, 0o755)
    return path


def runner_config(path: str) -> list[str]:
    """Cargo arguments that start each test binary, on any host triple, through `path`."""
    return ["--config", f"target.'cfg(all())'.runner=['{path}']"]


def run_steps(os_kind: str, shard: str, program: tuple[str, ...] = ("cargo",)) -> list[str]:
    if any(step == "parts" for step, _, _, _ in SHARDS[os_kind][shard]):
        # Never a whole `cargo test --lib`: the leg's parts are built one at a time.
        return [f"{shard} builds lib test parts; run it with run-prebuilt-parts {os_kind} {shard} --build <dir>"]
    failed = []
    tmp = tempfile.mkdtemp(prefix="shard-tmp-") if os_kind in TMP_GUARDED else None
    runner = runner_config(write_runner(tmp)) if tmp else []
    with private_home({**os.environ, "TMPDIR": tmp} if tmp else None, tmp) as env:
        for step, cargo_args, test_args, floor in SHARDS[os_kind][shard]:
            rc, lines = cargo(
                [*runner, *BASE, *cargo_args, "--", *test_args, *OUTPUT.get(os_kind, []), *SKIPS[os_kind]],
                program,
                env,
            )
            n = selected(lines)
            results = [tuple(map(int, m.groups())) for m in map(RESULT.search, lines) if m]
            print(f"::notice::{os_kind} {shard} {step}: selected {n} (floor {floor}), "
                  f"passed {sum(r[0] for r in results)}, failed {sum(r[1] for r in results)}, "
                  f"ignored {sum(r[2] for r in results)}, rc {rc}")
            if rc != 0:
                failed.append(f"{step}: cargo exited {rc}")
            if n < floor:
                failed.append(f"{step}: selected {n} tests, below the floor of {floor}")
            # One failure per distinct report, even when two steps print the same one.
            failed += [u for u in unkept(lines) if u not in failed]
        if EXAMPLES.get(os_kind) == shard:
            rc, _ = cargo(["build", "--all-features", "--examples"], program, env)
            if rc != 0:
                failed.append(f"examples: cargo build exited {rc}")
    if tmp:
        failed += tmp_problems(os_kind, shard, tmp)
    return failed


def tmp_problems(os_kind: str, shard: str, tmp: str) -> list[str]:
    """The TMPDIR guard's verdict on a shard's private `tmp` (then removed): one failure per entry a test
    left there that KNOWN_LEFTOVERS does not allow."""
    paths = leftovers(tmp)
    bad = unexpected({name: files_in(path) for name, path in paths.items()})
    # Tolerated entries are printed too: which ones count against the
    # allowance is only sort order, so the cause can sit in either list.
    for name in sorted(set(paths) - set(bad)):
        print(f"::notice::{os_kind} {shard} tolerated in TMPDIR: {name} "
              f"({contents(paths[name])})")
    # A failure lists every file: the writer may be named by the last one.
    failed = [f"left in TMPDIR: {name} ({contents(paths[name], None)})" for name in bad]
    shutil.rmtree(tmp, ignore_errors=True)
    return failed


def self_test() -> int:
    lease = [
        "     Running unittests src/lib.rs (target/debug/deps/mcp_gateway-1)",
        "", "running 6941 tests",
        "test a ... ok", "running 1 test", "test lease_child_process ... ok",
        "running 1 test", "running 1 test",
        "test result: ok. 6941 passed; 0 failed; 0 ignored; 0 measured",
        "     Running tests/x.rs (target/debug/deps/x-2)", "running 0 tests",
        "   Doc-tests mcp_gateway", "running 55 tests",
    ]
    assert selected(lease) == 6996, selected(lease)
    # The child's own result line must not re-arm the count outside doctests.
    child = ["     Running unittests src/lib.rs (x)", "running 2 tests", "running 1 test",
             "test result: ok. 1 passed; 0 failed; 0 ignored", "running 1 test",
             "test result: ok. 2 passed; 0 failed; 0 ignored"]
    assert selected(child) == 2, selected(child)
    # Rustdoc's two batches under one header (probe run 39135535466, Linux int-b).
    rustdoc = ["   Doc-tests mcp_gateway", "running 51 tests",
               "test result: ok. 41 passed; 0 failed; 10 ignored; 0 measured; 0 filtered out",
               "running 4 tests",
               "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"]
    assert selected(rustdoc) == 55, selected(rustdoc)
    # libtest-record-parse: a line written straight to stderr mid-test can split
    # a `test NAME ... RESULT` record (scripts/ci/mutants/fixtures/libtest).
    # Floors read `running N` and `test result:` lines, which libtest writes
    # before and after the tests, so the shared fixtures must count exactly.
    fx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants", "fixtures", "libtest")
    for name, running, passed in [("midline-stderr.txt", 1, 1), ("alloc-meter-one-thread.txt", 1, 1),
                                  ("failed-after-noise.txt", 1, 0), ("panic-in-passing-test.txt", 1, 1),
                                  ("zero-match.txt", 0, 0)]:
        lines = ["     Running unittests src/lib.rs (x)",
                 *open(os.path.join(fx, name), encoding="utf-8").read().splitlines()]
        assert selected(lines) == running, (name, selected(lines))
        got = [int(m.group(1)) for m in map(RESULT.search, lines) if m]
        assert got == [passed], (name, got)
    # #3944: a byte cp1252 cannot map, mirrored to a strict cp1252 stdout as
    # on the Windows runner. The mirror must not raise, and the line counts.
    import io
    sink = io.BytesIO()
    real = sys.stdout
    sys.stdout = wrapper = io.TextIOWrapper(sink, encoding="cp1252", errors="strict")
    try:
        emit = "import sys; sys.stdout.buffer.write(b'     Running x\\r\\nrunning 3 tests \\x81\\r\\n')"
        rc, lines = cargo([], program=(sys.executable, "-c", emit))
    finally:
        sys.stdout = real
        wrapper.flush()
        wrapper.detach()  # keep `sink` open for the assertions below
    assert rc == 0 and b"\x81" in sink.getvalue(), (rc, sink.getvalue())
    assert lines == ["     Running x", "running 3 tests �"], lines
    colored = "\x1b[1m\x1b[92m     Running\x1b[0m tests/y.rs (target/debug/deps/y-3)"
    assert selected([ANSI.sub("", colored), "running 4 tests"]) == 4
    assert selected(["running 3 tests"]) == 0, "a count with no header is a child's"
    for os_kind, shards in SHARDS.items():
        for name, steps in shards.items():
            assert steps and all(floor > 0 for *_, floor in steps), (os_kind, name)
    # The TMPDIR guard. A planted test that leaks one file turns a
    # guarded shard red on that file alone, and the same run without the leak
    # stays green. The fake cargo clears the shard's floor.
    fake = (sys.executable, "-c", (
        "import os\n"
        "print('     Running unittests src/lib.rs (x)')\n"
        "print('running 99999 tests')\n"
        "print('test result: ok. 99999 passed; 0 failed; 0 ignored')\n"
        "if os.environ.get('PLANT_LEAK'):\n"
        "    open(os.path.join(os.environ['TMPDIR'], '.tmpAbC123.hwm'), 'w').close()\n"
        "if os.environ.get('PLANT_UNKEPT'):\n"
        "    import sys\n"
        "    sys.stderr.write('shutdown save at /tmp/.tmpZz9Yy8/s.json is in a temp dir no test kept;'\n"
        "                     ' created by a::b::row\\n')\n"
    ))
    os.environ["PLANT_LEAK"] = "1"
    try:
        planted = run_steps("linux", "lib-a", fake)
    finally:
        del os.environ["PLANT_LEAK"]
    assert planted == ["left in TMPDIR: .tmpAbC123.hwm (0B)"], planted
    with tempfile.TemporaryDirectory() as leftover:
        os.makedirs(os.path.join(leftover, "tasks"))
        for name in ("task-a.json", "task-b.json", "task-c.json", "task-d.json"):
            with open(os.path.join(leftover, "tasks", name), "w") as f:
                f.write("{}")
        shown = contents(leftover)
        assert shown == (f"{os.path.join('tasks', 'task-a.json')} 2B, "
                         f"{os.path.join('tasks', 'task-b.json')} 2B, "
                         f"{os.path.join('tasks', 'task-c.json')} 2B, +1 more"), shown
        # A failing entry lists every file, so the last one can name the writer.
        assert contents(leftover, None).endswith(
            f"{os.path.join('tasks', 'task-d.json')} 2B"), contents(leftover, None)
    assert run_steps("linux", "lib-a", fake) == [], "the control run must stay green"
    # K6 on a cargo shard's run path: a report a test printed (raw stderr, merged into the step's
    # output) fails the shard once, by its test, beside the control run above that stays green.
    os.environ["PLANT_UNKEPT"] = "1"
    try:
        reported = run_steps("linux", "lib-a", fake)
    finally:
        del os.environ["PLANT_UNKEPT"]
    assert reported == ["unkept temp dir: shutdown save at /tmp/.tmpZz9Yy8/s.json; created by a::b::row"], \
        f"a cargo shard whose test printed an unkept report did not fail on it: {reported}"
    assert unexpected({"a": ["x"], "b": ["x"]}, [("[ab]", "x", 1, "one allowed")]) == ["b"], \
        "the count bounds a source"
    assert all(n <= LEFTOVER_CEILING.get((p, h), 0) for p, h, n, _ in KNOWN_LEFTOVERS), \
        "KNOWN_LEFTOVERS may only shrink"
    hwm = ["audit.jsonl.hwm"]
    # KNOWN_LEFTOVERS is empty, so the matcher's rules are held with a synthetic source: without
    # it every folder fails and the stray and contents cases below would pass whatever the rules.
    synthetic = [(r"\.tmp[A-Za-z0-9]{6}", r"audit\.jsonl\.hwm", 3, "a synthetic source")]
    assert unexpected({".tmpAb12Cd": hwm}, synthetic) == [], "the synthetic source allows its own folder"
    home = [".mcp-gateway/protocol-revision-telemetry/window.json", "tasks/stdio/store.lease"]
    control = [".gateway.yaml.lock", ".mcp-gateway/transparency/transparency.jsonl",
               "gateway-control-plane/audit.jsonl"]
    full = [".mcp-gateway/tasks/task-981b20ff-769a-4959-92ed-26da6107c4bf.json",
            *(f".mcp-gateway/transparency/transparency.jsonl{x}" for x in ("", ".hwm", ".lock")),
            *(f"gateway-control-plane/audit.jsonl{x}" for x in ("", ".hwm", ".lock")),
            "serve.log"]
    # A spawned gateway's home is no longer a known leftover: the HTTP harness
    # drains its gateway before its folders go (#4576), and no int-a run since
    # left one. Each of its three shapes now fails, even alone.
    for files in (home, control, full):
        assert unexpected({".tmpAb12Cd": files}) == [".tmpAb12Cd"], files
    # Neither a leaked TempLog folder nor, since the late audit writes were fixed,
    # a plain temp dir holding only the audit high-water mark is tolerated.
    assert unexpected({"audit-log-Ab12Cd": hwm, ".tmpAb12Cd": hwm}) == [".tmpAb12Cd", "audit-log-Ab12Cd"]
    # The folder-name rule itself, held with the synthetic source: the same files pass in a
    # .tmp-named folder and fail in a TempLog-named one.
    assert unexpected({"audit-log-Ab12Cd": hwm, ".tmpAb12Cd": hwm}, synthetic) == ["audit-log-Ab12Cd"]
    # The families whose tests now use their own temp folders are no longer
    # tolerated.
    gone = ["oauth_test_no_token", "chain-test-0b1c", "http_transport_tls_guard", "stdio-tail-1"]
    assert unexpected({n: ["tokens"] for n in gone}) == sorted(gone), gone
    # A test's task store or events store keeps its folder until its last
    # write, so a task record or an events-store file in a plain temp folder
    # is a leak: none is tolerated, not even alone or beside an audit file.
    stores = [["stdio/task-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json"],
              ["tasks/task-0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0.json"],
              ["subs/sub_u1_pt.json"], ["outbox/evt_0b1c.json"],
              ["dead/evt_0b1c.json"], ["verified/0b1c.json"],
              ["audit.jsonl.hwm", "subs/sub_u1_pt.json"]]
    for files in stores:
        assert unexpected({".tmpAb12Cd": files}) == [".tmpAb12Cd"], files
    # No source is known any more, so not even one audit high-water-mark folder
    # passes (the per-source count itself is held by "the count bounds a source").
    assert unexpected({".tmpAb12C0": hwm}) == [".tmpAb12C0"]
    # A plain temp folder is tolerated only for what its source writes: a stray
    # file, a source's file beside a stray one and an empty folder all fail under
    # the synthetic source, though each folder has a name it matches.
    for files in (["other.db"], [*hwm, "other.db"], [*home, "keys/secret.pem"],
                  [*control, "gateway-control-plane/other.jsonl"],
                  [*full, "serve.log.1"], [*full, ".mcp-gateway/tasks/task-x.json"], []):
        assert unexpected({".tmpAb12Cd": files}, synthetic) == [".tmpAb12Cd"], files
    # The same check end to end: a run that leaves a generically named temp
    # folder holding a stray file turns red on it.
    fake_dir = (*fake[:2], fake[2].replace(
        "open(os.path.join(os.environ['TMPDIR'], '.tmpAbC123.hwm'), 'w').close()",
        "d = os.path.join(os.environ['TMPDIR'], '.tmpXyZ789')\n"
        "    os.mkdir(d)\n"
        "    for f in ('a.db', 'b.db', 'c.db', 'other.db'):\n"
        "        open(os.path.join(d, f), 'w').close()"))
    assert fake_dir != fake, "the planted folder must replace the planted file"
    os.environ["PLANT_LEAK"] = "1"
    try:
        planted = run_steps("linux", "lib-a", fake_dir)
    finally:
        del os.environ["PLANT_LEAK"]
    # Every file is named, the fourth too: no "+1 more" hides the writer.
    assert planted == ["left in TMPDIR: .tmpXyZ789 (a.db 0B, b.db 0B, c.db 0B, other.db 0B)"], \
        planted
    # Through the same step, a planted gateway home turns red, and so does the
    # audit high-water mark that used to be the one known source.
    fake_home = (*fake[:2], fake[2].replace(
        "open(os.path.join(os.environ['TMPDIR'], '.tmpAbC123.hwm'), 'w').close()",
        "d = os.path.join(os.environ['TMPDIR'], '.tmpHoMe12', 'tasks', 'stdio')\n"
        "    os.makedirs(d)\n"
        "    open(os.path.join(d, 'store.lease'), 'w').close()"))
    assert fake_home != fake, "the planted home must replace the planted file"
    os.environ["PLANT_LEAK"] = "1"
    try:
        home_run = run_steps("linux", "lib-a", fake_home)
    finally:
        del os.environ["PLANT_LEAK"]
    assert home_run == ["left in TMPDIR: .tmpHoMe12 (tasks/stdio/store.lease 0B)"], home_run
    fake_known = (*fake[:2], fake[2].replace(
        "open(os.path.join(os.environ['TMPDIR'], '.tmpAbC123.hwm'), 'w').close()",
        "d = os.path.join(os.environ['TMPDIR'], '.tmpKnoWn1')\n"
        "    os.makedirs(d)\n"
        "    open(os.path.join(d, 'audit.jsonl.hwm'), 'w').close()"))
    assert fake_known != fake, "the planted former known source must replace the planted file"
    os.environ["PLANT_LEAK"] = "1"
    try:
        known_run = run_steps("linux", "lib-a", fake_known)
    finally:
        del os.environ["PLANT_LEAK"]
    assert known_run == ["left in TMPDIR: .tmpKnoWn1 (audit.jsonl.hwm 0B)"], known_run
    # The same on real folders: files_in feeds the match, and a link to a
    # folder beside an allowed file is a stray of its own.
    with tempfile.TemporaryDirectory() as root:
        def plant(name: str, files: list[str]) -> str:
            for f in files:
                path = os.path.join(root, name, *f.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w").close()
            return name
        found = {name: files_in(os.path.join(root, name)) for name in (
            plant(".tmpKnown1", hwm), plant(".tmpStray1", [*hwm, "other.db"]),
            plant(".tmpLink01", hwm))}
        os.symlink(root, os.path.join(root, ".tmpLink01", "elsewhere"))
        found[".tmpLink01"] = files_in(os.path.join(root, ".tmpLink01"))
        assert found[".tmpKnown1"] == hwm, found
        assert found[".tmpLink01"] == ["audit.jsonl.hwm", "elsewhere"], found
        assert unexpected(found) == [".tmpKnown1", ".tmpLink01", ".tmpStray1"], found
        # Under the synthetic source the link and the stray still fail on their contents alone.
        assert unexpected(found, synthetic) == [".tmpLink01", ".tmpStray1"], found
    per_binary_rows()
    prebuilt_rows()
    unkept_rows()
    built_parts_rows()
    built_parts_root_rows()
    # H1: every shard, on every OS, gives cargo and a prebuilt lib
    # binary a private gateway home beside its TMPDIR, and removes it after the
    # shard, also when cargo fails (R6.1, R6.4, R6.5). The recorder stands in
    # for cargo and writes down what it was given.
    record_dir = tempfile.mkdtemp(prefix="shard-record-")
    record = os.path.join(record_dir, "env.json")
    keys = ("MCP_GATEWAY_TEST_HOME_DIR", "XDG_CONFIG_HOME", "MCP_GATEWAY_CONFIG_DIR", "TMPDIR", "TESTS_REQUIRE_ALL")
    recorder_src = (
        "import json, os, sys\n"
        f"keys = {keys!r}\n"
        "if '--list' in sys.argv:\n"
        "    sys.exit(0)\n"
        "seen = {k: os.environ.get(k) for k in keys}\n"
        "seen['mode'] = os.stat(seen['MCP_GATEWAY_TEST_HOME_DIR']).st_mode & 0o777\n"
        "json.dump(seen, open(os.environ['RECORD_ENV'], 'w'))\n"
        "print('     Running unittests src/lib.rs (x)')\n"
        "print('running 99999 tests')\n"
        "print('test result: ok. 99999 passed; 0 failed; 0 ignored')\n"
        "sys.exit(int(os.environ.get('RECORD_RC', '0')))\n"
    )
    recorder = (sys.executable, "-c", recorder_src)

    def home_given(os_kind: str, expect_required: str = "1") -> str:
        seen = json.load(open(record, encoding="utf-8"))
        home = seen["MCP_GATEWAY_TEST_HOME_DIR"]
        assert home and os.path.basename(home).startswith("shard-home-"), (os_kind, seen)
        assert seen["XDG_CONFIG_HOME"] == os.path.join(home, ".config"), (os_kind, seen)
        assert seen["MCP_GATEWAY_CONFIG_DIR"] == os.path.join(home, ".mcp-gateway"), (os_kind, seen)
        assert seen["TESTS_REQUIRE_ALL"] == expect_required, ("a skip for a missing tool or right fails in a shard", os_kind, seen)
        if os.name != "nt":
            assert seen["mode"] == 0o700, ("the home is owner-only", os_kind, oct(seen["mode"]))
        if os_kind in TMP_GUARDED:
            # A prebuilt binary gets its BY_BINARY folder; the shard's own TMPDIR is above it.
            shard_tmp = seen["TMPDIR"]
            while shard_tmp and not os.path.basename(shard_tmp).startswith("shard-tmp-"):
                shard_tmp = os.path.dirname(shard_tmp) if os.path.dirname(shard_tmp) != shard_tmp else ""
            assert shard_tmp and os.path.dirname(home) == os.path.dirname(shard_tmp), (os_kind, seen)
            assert not os.path.commonpath([home, shard_tmp]) == shard_tmp, "beside, not inside, TMPDIR"
        return home

    os.environ["RECORD_ENV"] = record
    try:
        for os_kind in sorted(SHARDS):
            shard = sorted(SHARDS[os_kind])[0]
            assert run_steps(os_kind, shard, recorder) == [], (os_kind, shard)
            assert not os.path.exists(home_given(os_kind)), (os_kind, "the shard removes its home")
        os.environ["RECORD_RC"] = "1"
        try:
            failed = run_steps("linux", "lib-a", recorder)
        finally:
            del os.environ["RECORD_RC"]
        assert any("cargo exited 1" in f for f in failed), failed
        assert not os.path.exists(home_given("linux")), "a failed shard removes its home too"
        # C2: an ambient TESTS_REQUIRE_ALL=0 survives, so a developer can opt out locally; the shard only fills in an unset one.
        os.environ["TESTS_REQUIRE_ALL"] = "0"
        try:
            assert run_steps("linux", "lib-a", recorder) == [], "the opt-out run"
        finally:
            del os.environ["TESTS_REQUIRE_ALL"]
        assert json.load(open(record, encoding="utf-8"))["TESTS_REQUIRE_ALL"] == "0", "an ambient 0 survives"
        if os.name == "posix":
            binary = os.path.join(record_dir, "fake-lib")
            with open(binary, "w", encoding="utf-8") as f:
                f.write(f"#!{sys.executable}\n{recorder_src}")
            with open(binary + ".root", "w", encoding="utf-8") as f:  # as export-lib leaves it
                f.write(ROOT + "\n")
            single = next(name for name, steps in SHARDS["linux"].items() if len(steps) == 1)
            assert run_prebuilt("linux", single, binary) == 0, "the prebuilt control run"
            assert not os.path.exists(home_given("linux")), "a prebuilt shard removes its home"
    finally:
        del os.environ["RECORD_ENV"]
        shutil.rmtree(record_dir, ignore_errors=True)
    # R5.2: a forgotten harness. A test binary given no home builds its
    # fallback in TMPDIR, and the leftover check names it. Given the shard's
    # home it builds none, and the shard stays green.
    forgetful = (sys.executable, "-c", (
        "import os, tempfile\n"
        "print('     Running unittests src/lib.rs (x)')\n"
        "print('running 99999 tests')\n"
        "print('test result: ok. 99999 passed; 0 failed; 0 ignored')\n"
        "if os.environ.get('PLANT_FORGOTTEN') or not os.environ.get('MCP_GATEWAY_TEST_HOME_DIR'):\n"
        "    tempfile.mkdtemp(prefix='mcp-gateway-test-home-')\n"
    ))
    os.environ["PLANT_FORGOTTEN"] = "1"
    try:
        forgot = run_steps("linux", "lib-a", forgetful)
    finally:
        del os.environ["PLANT_FORGOTTEN"]
    assert len(forgot) == 1 and forgot[0].startswith("left in TMPDIR: mcp-gateway-test-home-"), forgot
    assert run_steps("linux", "lib-a", forgetful) == [], "given the shard's home, no fallback is built"
    parts_rows()
    with_home_rows()
    export_home_rows()
    home_copies_rows()
    windows_shared_rows()
    print("shard_tests self-test: ok")
    return 0


def unkept_rows() -> None:
    """K6: every unkept-dir report fails the shard naming its test, whatever its kind, wherever it
    starts on the line (raw stderr lands mid-line after a `test x ... ` prefix); a clean log passes."""
    audit = ("test gateway::server::test_seams::health_start_tests::h12_both_files_are_saved_before_serving_and"
             "_the_stop_is_clean ... audit log at /tmp/.tmpmFJ46f/audit.jsonl is in a temp dir no test kept;"
             " created by gateway::server::test_seams::health_start_tests::h12_both_files_are_saved_before_ser"
             "ving_and_the_stop_is_clean")
    assert unkept([audit]) == [
        "unkept temp dir: audit log at /tmp/.tmpmFJ46f/audit.jsonl; created by gateway::server::test_seams::"
        "health_start_tests::h12_both_files_are_saved_before_serving_and_the_stop_is_clean"], unkept([audit])
    # A kind no writer uses today fails the same way: the check reads the report, not a list of kinds.
    novel = "frobnicator spool at /tmp/.tmpQx12Ab/spool.bin is in a temp dir no test kept; created by a::b::row"
    assert unkept(["", novel, "test a::b::row ... ok"]) == [
        "unkept temp dir: frobnicator spool at /tmp/.tmpQx12Ab/spool.bin; created by a::b::row"], unkept([novel])
    # The same report printed twice by one test is one failure; two tests are two.
    other = novel.replace("a::b::row", "a::b::other")
    assert len(unkept([novel, novel, other])) == 2, unkept([novel, novel, other])
    clean = ["running 2 tests", "test a::b::row ... ok", "test a::b::other ... ok",
             "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"]
    assert unkept(clean) == [], unkept(clean)
    # One raw line per kind the writers emit, from the full-lib sizing run (only the Spark mirror prefix of each
    # path is replaced by /tmp), and the worker-thread creator a multi-thread runtime gives.
    sized = [
        ("package cache", "/tmp/.tmpOpr9CV/pkg-cache",
         "backend::package_cache::retry_tests::a_backend_that_dies_for_an_unrelated_reason_is_not_retried"),
        ("config lock", "/tmp/.tmpTQ6JVm/capabilities",
         "capability::file_writer::tests::create_race_has_one_winner"),
        ("shutdown save", "/tmp/.tmpBsItVX/ranker.json",
         "gateway::server::persistence::shutdown_deadline_tests::the_state_saves_end_at_the_deadline_they_are_given"),
        ("periodic save", "/tmp/.tmpnwcyRg", "gateway::server::persistence::tests::cost_saver_stops_on_shutdown"),
        ("skill bundle", "/tmp/.tmp6oTLRb/skills",
         "skills::watcher::burst_tests::a_pass_that_leaves_changes_behind_warns_once"),
        ("config lock", "/tmp/.tmpzYfy13/gateway.yaml", "tokio-rt-worker"),
    ]
    for kind, path, creator in sized:
        line = f"{kind} at {path} is in a temp dir no test kept; created by {creator}"
        assert unkept([line]) == [f"unkept temp dir: {kind} at {path}; created by {creator}"], line
    # A path with a space is read whole: the report's fixed suffix ends it, so a spaced temp dir and a Windows
    # user name with a space both fail the shard with the whole path.
    for path in ("/tmp/with space/.tmpAb12Cd/audit.jsonl", r"C:\Users\Jane Doe\AppData\Local\Temp\.tmpAb12Cd\skills"):
        line = f"test a::b::row ... audit log at {path} is in a temp dir no test kept; created by a::b::row"
        assert unkept([line]) == [f"unkept temp dir: audit log at {path}; created by a::b::row"], unkept([line])
    # Raw stderr ahead of the report on one line: lowercase words, and a panic message with its own " at ",
    # are read into neither the kind nor the path.
    tail = "audit log at /tmp/.tmpZz9Yy8/a.jsonl is in a temp dir no test kept; created by a::b::row"
    want = ["unkept temp dir: audit log at /tmp/.tmpZz9Yy8/a.jsonl; created by a::b::row"]
    for noise in ("warning some text ", "thread 'x' panicked at src/a.rs:1:2: oops "):
        assert unkept([noise + tail]) == want, unkept([noise + tail])


def with_home_rows() -> None:
    """S1: `with-home -- CMD` runs CMD in a private gateway home, hands back its exit code, and
    removes the home afterwards, also when CMD fails."""
    probe = (
        "import json, os, sys\n"
        "keys = ('MCP_GATEWAY_TEST_HOME_DIR', 'XDG_CONFIG_HOME', 'MCP_GATEWAY_CONFIG_DIR')\n"
        "seen = {k: os.environ.get(k) for k in keys}\n"
        "home = seen['MCP_GATEWAY_TEST_HOME_DIR'] or ''\n"
        "seen['mode'] = os.stat(home).st_mode & 0o777 if os.path.isdir(home) else None\n"
        "json.dump(seen, open(sys.argv[1], 'w'))\n"
        "sys.exit(int(sys.argv[2]))\n"
    )
    with tempfile.TemporaryDirectory() as scratch:
        record = os.path.join(scratch, "seen.json")
        for rc in (0, 3):
            got = main(["shard_tests.py", "with-home", "--", sys.executable, "-c", probe, record, str(rc)])
            assert got == rc, f"with-home returned {got} for a command that exited {rc}"
            seen = json.load(open(record, encoding="utf-8"))
            home = seen["MCP_GATEWAY_TEST_HOME_DIR"]
            assert home and seen["mode"] is not None, f"the command saw no existing home: {seen}"
            assert seen["XDG_CONFIG_HOME"] == os.path.join(home, ".config"), seen
            assert seen["MCP_GATEWAY_CONFIG_DIR"] == os.path.join(home, ".mcp-gateway"), seen
            if os.name != "nt":
                assert seen["mode"] == 0o700, f"the home is not owner-only: {oct(seen['mode'])}"
            assert not os.path.exists(home), f"exit {rc}: the home {home} was left behind"


def export_home_rows() -> None:
    """S2: `export-home FILE` makes a gateway home in RUNNER_TEMP for the rest of a CI job and appends its three
    variables to FILE ($GITHUB_ENV) after what is already there; the home stays for the job's later steps."""
    keys = ["MCP_GATEWAY_TEST_HOME_DIR", "XDG_CONFIG_HOME", "MCP_GATEWAY_CONFIG_DIR"]
    with tempfile.TemporaryDirectory() as runner_temp:
        env_file = os.path.join(runner_temp, "github_env")
        with open(env_file, "w", encoding="utf-8") as f:
            f.write("EARLIER=kept\n")
        saved = os.environ.get("RUNNER_TEMP")
        os.environ["RUNNER_TEMP"] = runner_temp
        try:
            rc = main(["shard_tests.py", "export-home", env_file])
        finally:
            if saved is None:
                del os.environ["RUNNER_TEMP"]
            else:
                os.environ["RUNNER_TEMP"] = saved
        assert rc == 0, f"export-home returned {rc}"
        lines = open(env_file, encoding="utf-8").read().splitlines()
        assert lines[0] == "EARLIER=kept", f"export-home rewrote what was there: {lines}"
        got = dict(line.split("=", 1) for line in lines[1:])
        assert sorted(got) == sorted(keys), f"exported {sorted(got)}, expected {sorted(keys)}"
        home = got["MCP_GATEWAY_TEST_HOME_DIR"]
        assert os.path.dirname(home) == runner_temp, f"the home {home} is not in RUNNER_TEMP"
        assert os.path.isdir(home), "the exported home does not exist after the step"
        assert got["XDG_CONFIG_HOME"] == os.path.join(home, ".config"), got
        assert got["MCP_GATEWAY_CONFIG_DIR"] == os.path.join(home, ".mcp-gateway"), got
        if os.name != "nt":
            assert os.stat(home).st_mode & 0o777 == 0o700, "the exported home is not owner-only"


def home_copies_rows() -> None:
    """S3: the mutant runner keeps its own copy of make_home, because it is fetched alone from the release line and
    must not import from the tree it tests. The two copies must make the same home: the same three variables, each
    at the same place under the home, and the same mode. A deliberately drifted copy must read as different."""
    import importlib.util
    import inspect

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants", "run_mutants.py")
    spec = importlib.util.spec_from_file_location("run_mutants_for_s3", path)
    runner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runner
    spec.loader.exec_module(runner)

    def shape(values: dict[str, str]) -> dict:
        home = values["MCP_GATEWAY_TEST_HOME_DIR"]
        return {"keys": sorted(values), "mode": os.stat(home).st_mode & 0o777 if os.name != "nt" else None,
                **{key: os.path.relpath(value, home) for key, value in values.items() if value != home}}

    with tempfile.TemporaryDirectory() as parent:
        ours = shape(make_home(parent))
    with runner.gateway_home({}) as child:
        theirs = shape(child)
        drifted = shape({**child, "XDG_CONFIG_HOME": os.path.join(child["MCP_GATEWAY_TEST_HOME_DIR"], "config")})
    assert drifted != theirs, "control: the shape comparison cannot see a moved config dir"
    assert ours == theirs, f"the mutant runner's home drifted from make_home: {theirs} vs {ours}"
    # The mode above is only this OS's branch: compare the mkdir lines too, so a drift in the Windows branch
    # shows on a POSIX runner as well.
    def mkdir_line(function) -> str:
        return next(line.strip() for line in inspect.getsource(function).splitlines()
                    if line.strip().startswith("os.mkdir("))

    assert mkdir_line(make_home) == mkdir_line(runner.gateway_home), (
        f"the two copies make the home differently: {mkdir_line(runner.gateway_home)!r}")


def built_parts_rows() -> None:
    """R1-R5: a part-building leg builds its parts in order through lib-parts.sh, deletes each binary before the next
    build, accounts for every listed name, keeps going after a failed part, and holds its floor."""
    saved = {leg: SHARDS["macos"][leg] for leg in PARTS["macos"]}
    with tempfile.TemporaryDirectory() as root:
        log = os.path.join(root, "log")
        fake = os.path.join(root, "lib-parts.sh")
        # The fake build: logs `build K`, refuses to build while a part binary is still on disk, and writes a binary
        # that lists `mK::a mK::b mK::<SDK>` and runs per BEHAVE_K (ok, short, extra, red, panic: b in libtest's
        # should-panic form, child: b's result after a child's unfinished `test <child> ... ` on one line, diag: b only in
        # a diagnostic's text, `diagnostic: test mK::b ... ok`, never run). FAIL_LIST_K=1
        # fails the export after the binary is written, before its list.
        with open(fake, "w") as f:
            f.write('#!/bin/sh\nk=$2; d=$3; echo "build $k" >> "$LOG"\n'
                    'for b in "$d"/p*/lib-tests-p*; do [ -e "$b" ] && { echo "left $b" >> "$LOG"; exit 7; }; done\n'
                    '[ "$(eval echo \\${FAIL_BUILD_$k:-})" = 1 ] && exit 5\n'
                    'mkdir -p "$d/p$k"; printf "m$k::a: test\\nm$k::b: test\\nm$k::' + SDK + ': test\\n" > "$d/p$k/list.txt"\n'
                    'cat > "$d/p$k/lib-tests-p$k" <<EOF\n#!/bin/sh\nb=\\${BEHAVE_$k:-ok}\n'
                    'echo "test m$k::a ... ok"\ncase "\\$b" in short) ;; panic) echo "test m$k::b - should panic ... ok" ;;'
                    ' child) echo "test m$k::child_process ... test m$k::b ... ok" ;;'
                    ' diag) echo "diagnostic: test m$k::b ... ok" ;;'
                    ' unkept) echo "test m$k::b ... ok"; echo "skill bundle at /tmp/.tmpQq1Ww2/skills is in a temp dir'
                    ' no test kept; created by m$k::b" >&2 ;;'
                    ' *) echo "test m$k::b ... ok" ;; esac\n'
                    '[ "\\$b" = extra ] && echo "test m$k::z ... ok"\n[ "\\$b" = red ] && exit 101\nexit 0\nEOF\n'
                    '[ "$(eval echo \\${FAIL_LIST_$k:-})" = 1 ] && { rm "$d/p$k/list.txt"; exit 6; }\nexit 0\n')
        os.chmod(fake, 0o755)

        def leg_run(leg: str, floor: int, **env: str) -> tuple[int, list[str]]:
            open(log, "w").close()
            SHARDS["macos"][leg] = [("parts", ["--lib"], [], floor)]
            out_dir = tempfile.mkdtemp(dir=root)
            keep = {k: os.environ.get(k) for k in ("LOG", "MACOS_LIB_SOLO", *env)}
            os.environ.update({"LOG": log, **env})
            try:
                with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
                    rc = run_built_parts("macos", leg, out_dir, ("sh", fake))
            finally:
                for k, v in keep.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            return rc, open(log).read().split("\n")[:-1]

        try:
            # R1: the leg's parts from PARTS, in order, each binary gone before the next build; the clean run passes.
            rc, steps = leg_run("lib-b", 8)
            assert (rc, steps) == (0, ["build 1", "build 2", "build 3", "build 4"]), (rc, steps)
            rc, steps = leg_run("int-lib", 2)
            assert (rc, steps) == (0, ["build 5"]), (rc, steps)
            # R2: a part that ran a listed test less, or a test it does not list, fails the leg.
            assert leg_run("lib-b", 8, BEHAVE_2="short")[0] == 1, "a part that ran one test fewer passed"
            assert leg_run("lib-b", 8, BEHAVE_3="extra")[0] == 1, "a part that ran an unlisted test passed"
            # R3: the SDK name each part lists is skipped (libtest's substring rule) and not expected to run.
            # R4: a failed build or a red binary fails the leg, and every later part still runs; the floor holds.
            rc, steps = leg_run("lib-b", 6, FAIL_BUILD_2="1")
            assert rc == 1 and steps == ["build 1", "build 2", "build 3", "build 4"], (rc, steps)
            rc, steps = leg_run("lib-b", 8, BEHAVE_2="red")
            assert rc == 1 and steps == ["build 1", "build 2", "build 3", "build 4"], (rc, steps)
            # An export that failed after writing its binary: the binary is gone before part 3 builds (the fake build
            # logs `left` and refuses while one is on disk), and the leg fails.
            rc, steps = leg_run("lib-b", 6, FAIL_LIST_2="1")
            assert rc == 1 and steps == ["build 1", "build 2", "build 3", "build 4"], (rc, steps)
            # A #[should_panic] test's result line counts as run.
            assert leg_run("lib-b", 8, BEHAVE_2="panic")[0] == 0, "a should-panic result was not counted"
            # A result after a child process's unfinished line, on the same line, counts as run.
            assert leg_run("lib-b", 8, BEHAVE_2="child")[0] == 0, "a result after a child's partial line was not counted"
            # A result-shaped phrase inside other output is not a result: b never ran, so the leg fails.
            assert leg_run("lib-b", 8, BEHAVE_2="diag")[0] == 1, "a diagnostic's text counted as a run test"
            assert leg_run("lib-b", 9)[0] == 1, "a leg under its floor passed"
            # K6 on the built-parts path: a part whose tests all ran and passed still fails the leg when one
            # printed an unkept report.
            assert leg_run("lib-b", 8, BEHAVE_2="unkept")[0] == 1, "a part whose test printed an unkept report passed"
            # R5: the solo lane's lib-b builds every part.
            rc, steps = leg_run("lib-b", 10, MACOS_LIB_SOLO="true")
            assert (rc, steps) == (0, [f"build {k}" for k in range(1, part_count() + 1)]), (rc, steps)
        finally:
            SHARDS["macos"].update(saved)


def built_parts_root_rows() -> None:
    """R6-R9: the part that lists a root row runs it once more under PRIVILEGE, before its binary goes; a red, a
    non-zero exit or a missing row fails the leg; parts without root rows never use PRIVILEGE."""
    global PRIVILEGE
    saved_leg, saved_priv = SHARDS["macos"]["lib-b"], PRIVILEGE
    row = ROOT_ROWS + "r"
    with tempfile.TemporaryDirectory() as root:
        log, build, priv = (os.path.join(root, x) for x in ("log", "build.sh", "priv.sh"))
        # Stand-in build: part K lists mK::a, and the part named by ROOT_PART also lists the root row. Its binary
        # reports the row as ignored on a plain run; with --ignored it acts per ROOT_BEHAVE (ok, some, red, exit, none).
        with open(build, "w") as f:
            f.write(f'#!/bin/sh\necho "build $2" >> "$LOG"\nmkdir -p "$3/p$2"\nout="$3/p$2/lib-tests-p$2"\n'
                    f'echo "m$2::a: test" > "$3/p$2/list.txt"\n'
                    f'[ "$2" = "${{ROOT_PART:-}}" ] && printf "{row}1: test\\n{row}2: test\\n" >> "$3/p$2/list.txt"\n'
                    f'printf \'#!/bin/sh\\ncase " $* " in *" --ignored "*) ;; *) echo "test m%s::a ... ok"\\n'
                    f'  grep -q root "$0.list" && echo "test {row}1 ... ignored" && echo "test {row}2 ... ignored"\\n'
                    f'  echo run >> "$LOG"\\n  exit 0 ;; esac\\n\' "$2" > "$out"\n'
                    f'cp "$3/p$2/list.txt" "$out.list"\n'
                    f'cat >> "$out" <<"EOF"\ncase "${{ROOT_BEHAVE:-ok}}" in\n'
                    f'  ok) echo "test {row}1 ... ok"; echo "test {row}2 ... ok" ;;\n'
                    f'  some) echo "test {row}1 ... ok" ;;\n'
                    f'  dup) echo "test {row}1 ... ok"; echo "test {row}1 ... ok"; echo "test {row}2 ... ok" ;;\n'
                    f'  ignored) echo "test {row}1 ... ignored"; echo "test {row}2 ... ignored" ;;\n'
                    f'  red) echo "test {row}1 ... FAILED"; echo "test {row}2 ... ok"; exit 101 ;;\n'
                    f'  exit) echo "test {row}1 ... ok"; echo "test {row}2 ... ok"; exit 3 ;;\n'
                    f'esac\nexit 0\nEOF\n')
        # Stand-in privilege: logs the binary it starts, whether that binary is still on disk, the directory and
        # manifest dir it runs in (the part's own run gets both as the repo root; tests read fixtures by them), and
        # its arguments.
        with open(priv, "w") as f:
            f.write('#!/bin/sh\nb=$1; shift\n[ -e "$b" ] && on=present || on=gone\n'
                    # A private gateway home leaking into the root run would stop the rows' mcpg-c child.
                    '[ -n "${MCP_GATEWAY_TEST_HOME_DIR:-}" ] && on="$on private-home"\n'
                    'echo "priv $(basename "$b") $on cwd=$(pwd -P) manifest=${CARGO_MANIFEST_DIR:-unset} $*" >> "$LOG"\n'
                    'exec "$b" "$@"\n')
        # The production prefix the root run uses, pinned before the stand-in replaces it.
        assert PRIVILEGE == ("sudo", "-E"), PRIVILEGE
        # The rows below build their expected call from ROOT_ROWS, so pin its literal value here.
        assert ROOT_ROWS == "config_persistence_access_tests::root::", ROOT_ROWS
        PRIVILEGE = ("sh", priv)
        SHARDS["macos"]["lib-b"] = [("parts", ["--lib"], [], 4)]

        def leg(**env: str) -> tuple[int, list[str]]:
            open(log, "w").close()
            keep = {k: os.environ.get(k) for k in ("LOG", "MACOS_LIB_SOLO", "ROOT_PART", "ROOT_BEHAVE", "MCP_GATEWAY_TEST_HOME_DIR")}
            for k in ("MACOS_LIB_SOLO", "ROOT_PART", "ROOT_BEHAVE", "MCP_GATEWAY_TEST_HOME_DIR"):
                os.environ.pop(k, None)
            os.environ.update({"LOG": log, **env})
            # Run from elsewhere, so a root run that does not set its own directory shows in R6's cwd= field.
            here = os.getcwd()
            os.chdir(root)
            try:
                with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
                    rc = run_built_parts("macos", "lib-b", tempfile.mkdtemp(dir=root), ("sh", build))
            finally:
                os.chdir(here)
                for k, v in keep.items():
                    os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            return rc, open(log).read().split("\n")[:-1]

        # Each part's plain run logs `run` after its build; the root run must come after part 3's.
        plain = [x for k in range(1, 5) for x in (f"build {k}", "run")]
        call = (f"priv lib-tests-p3 present cwd={os.path.realpath(ROOT)} manifest={ROOT} "
                f"{ROOT_ROWS} --ignored --test-threads=1")
        try:
            # R9: no part lists a root row, so nothing runs under PRIVILEGE.
            assert leg() == (0, plain), leg()
            # R10 (fixture): the stand-ins behave as these rows assume, run directly with no runner in between.
            fixture = os.path.join(root, "fixture")
            env = {**os.environ, "LOG": log, "ROOT_PART": "3"}
            subprocess.run(["sh", build, "export", "3", fixture], env=env, check=True)
            binary = os.path.join(fixture, "p3", "lib-tests-p3")
            os.chmod(binary, 0o755)
            expect = {"ok": ([f"{row}1 ... ok", f"{row}2 ... ok"], 0), "some": ([f"{row}1 ... ok"], 0),
                      "dup": ([f"{row}1 ... ok", f"{row}1 ... ok", f"{row}2 ... ok"], 0),
                      "red": ([f"{row}1 ... FAILED", f"{row}2 ... ok"], 101),
                      "exit": ([f"{row}1 ... ok", f"{row}2 ... ok"], 3), "none": ([], 0),
                      "ignored": ([f"{row}1 ... ignored", f"{row}2 ... ignored"], 0)}
            for behave, (lines, code) in expect.items():
                p = subprocess.run(["sh", priv, binary, ROOT_ROWS, "--ignored", "--test-threads=1"],
                                   env={**env, "ROOT_BEHAVE": behave}, capture_output=True, text=True)
                got = [x[len("test "):] for x in p.stdout.splitlines()]
                assert (got, p.returncode) == (lines, code), (behave, got, p.returncode)
            p = subprocess.run(["sh", binary], env=env, capture_output=True, text=True)
            assert (p.stdout.splitlines(), p.returncode) == (
                ["test m3::a ... ok", f"test {row}1 ... ignored", f"test {row}2 ... ignored"], 0), (p.stdout, p.returncode)
            # R6: part 3's root rows run under PRIVILEGE once, with the filter, after part 3's own run and while its
            # binary is on disk.
            rc, steps = leg(ROOT_PART="3")
            assert (rc, steps) == (0, [*plain[:6], call, *plain[6:]]), (rc, steps)
            # The same for part 1, so a root run tied to one part number cannot pass.
            rc, steps = leg(ROOT_PART="1")
            assert (rc, steps) == (0, [*plain[:2], call.replace("-p3 ", "-p1 "), *plain[2:]]), (rc, steps)
            # R7: a FAILED root row, or a root run that exits non-zero, fails the leg; the one privileged call happens in
            # the same place as in R6, and part 4 still builds and runs.
            for behave in ("red", "exit"):
                rc, steps = leg(ROOT_PART="3", ROOT_BEHAVE=behave)
                assert (rc, steps) == (1, [*plain[:6], call, *plain[6:]]), (behave, rc, steps)
            # R8: a root run that reports none, only some, or none as passed (every root row ignored, exit 0) of the
            # listed root rows fails the leg, and so does one that reports a listed row twice (each runs once).
            for behave in ("none", "some", "ignored", "dup"):
                rc, steps = leg(ROOT_PART="3", ROOT_BEHAVE=behave)
                assert (rc, steps) == (1, [*plain[:6], call, *plain[6:]]), (behave, rc, steps)
        finally:
            SHARDS["macos"]["lib-b"], PRIVILEGE = saved_leg, saved_priv


def prebuilt_rows() -> None:
    """The lib test binary is found in cargo's JSON and exported, and a shared-build leg run from it counts its
    selection against its floor, fails on a red binary and keeps the TMPDIR guard."""
    art = {"reason": "compiler-artifact", "target": {"kind": ["lib"], "name": "mcp_gateway"},
           "profile": {"test": True}, "executable": "/t/deps/mcp_gateway-1"}
    other = [json.dumps({**art, "target": {"kind": ["bin"]}}), json.dumps({**art, "profile": {"test": False}}),
             json.dumps({**art, "executable": None}), "not json", "   Compiling x"]
    assert lib_test_binary([*other, json.dumps(art)]) == "/t/deps/mcp_gateway-1"
    assert lib_test_binary(other) is None
    with tempfile.TemporaryDirectory() as root:
        fake = os.path.join(root, "fake-tests")

        # `--list`: the whole set is gateway::a, gateway::b and other::c; each half lists its own
        # unless LIST says otherwise (overlap: the skip half lists gateway::a too; gap: it drops c).
        def binary(body: str, lists: str = "ok") -> None:
            skip_half = {"ok": "other::c", "overlap": "gateway::a other::c", "gap": ""}[lists]
            with open(fake, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = --list ]; then shift 3\n'
                        '  case "$1 $2" in "gateway:: "*) n="gateway::a gateway::b";; "--skip gateway::") n="' + skip_half + '";;'
                        ' *) n="gateway::a gateway::b other::c";; esac\n'
                        '  for t in $n; do echo "$t: test"; done; exit 0; fi\n'
                        f"{body}\n")
            os.chmod(fake, 0o644)  # run_prebuilt restores the exec bit an artifact drops
            with open(fake + ".root", "w") as f:  # export-lib's record of where it built
                f.write(ROOT + "\n")
        # Linux: a shared-build leg runs under the TMPDIR guard a cargo shard has. The binary sees its own
        # BY_BINARY folder as TMPDIR, and a test that leaves a file there fails the leg.
        lfloor = max(SHARDS["linux"][leg][0][3] for leg in SHARED_BUILD["linux"])
        lok = f'echo "running {lfloor} tests"; echo "test result: ok. {lfloor} passed; 0 failed; 0 ignored"'
        binary(lok + f'; case "$TMPDIR" in */{BY_BINARY}/{LIB_TARGET}) ;; *) exit 8;; esac')
        assert run_prebuilt("linux", "lib-a", fake) == 0, "a clean Linux shared-build leg failed"
        assert main(["shard_tests.py", "run-prebuilt", "linux", "lib-b", fake]) == 0, "lib-b was refused"
        binary(lok + '; echo x > "$TMPDIR/stray-file"')
        # The same verdict line `run` prints for a cargo shard whose lib binary (mcp_gateway-<hash>) left it.
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with contextlib.redirect_stdout(out):
            rc = run_prebuilt("linux", "lib-a", fake)
        out.flush()
        said = out.buffer.getvalue().decode()
        assert rc == 1 and f"::error::linux lib-a left in TMPDIR: {LIB_TARGET}/stray-file" in said, \
            f"a Linux leg that left a temp file did not fail as `run` does: rc {rc}"
        # K6 on the prebuilt path: a report the binary's test printed on stderr fails the leg by its test, as
        # it does a cargo shard, even when nothing is left in TMPDIR.
        binary(lok + '; echo "shutdown save at /tmp/.tmpPb4Qr5/s.json is in a temp dir no test kept;'
               ' created by gateway::a" >&2')
        out = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with contextlib.redirect_stdout(out):
            rc = run_prebuilt("linux", "lib-a", fake)
        out.flush()
        said = out.buffer.getvalue().decode()
        want = "::error::linux lib-a unkept temp dir: shutdown save at /tmp/.tmpPb4Qr5/s.json; created by gateway::a"
        assert rc == 1 and want in said, f"a prebuilt leg whose test printed an unkept report passed: rc {rc}"
        # Only the shared-build legs run from the binary on Linux: an integration shard compiles its own.
        assert main(["shard_tests.py", "run-prebuilt", "linux", "int-a", fake]) == 2, "int-a ran prebuilt"
        # export-lib copies the executable cargo names, and fails when cargo names none.
        built = os.path.join(root, "built")
        with open(built, "w") as f:
            f.write("bin")
        cargo_ok = os.path.join(root, "cargo-ok")
        with open(cargo_ok, "w") as f:
            f.write(f"#!/bin/sh\necho '{json.dumps({**art, 'executable': built})}'\n")
        os.chmod(cargo_ok, 0o755)
        dest = os.path.join(root, "out")
        assert export_lib(dest, (cargo_ok,)) == 0
        assert open(os.path.join(dest, LIB_BINARY)).read() == "bin"
        cargo_none = os.path.join(root, "cargo-none")
        with open(cargo_none, "w") as f:
            f.write("#!/bin/sh\necho '   Compiling x'\n")
        os.chmod(cargo_none, 0o755)
        assert export_lib(os.path.join(root, "out2"), (cargo_none,)) == 1


def windows_shared_rows() -> None:
    """Windows lib legs run from one exported exe: the four-leg table, the run-prebuilt route, the .exe name and
    its recorded build root, a pairwise overlap check, and no test run once the partition check has failed."""
    # The four legs and the filters each one runs (cascade form: each skips the filters before it).
    want = {
        "lib-a": ["gateway::router::", "gateway::server::"],
        "lib-d": ["gateway::", "--skip", "gateway::router::", "--skip", "gateway::server::"],
        "lib-c": ["security::", "--skip", "gateway::router::", "--skip", "gateway::server::", "--skip", "gateway::"],
        "lib-b": ["--skip", "gateway::router::", "--skip", "gateway::server::", "--skip", "gateway::",
                  "--skip", "security::"],
    }
    libs = {leg: steps[0][2] for leg, steps in SHARDS["windows"].items() if steps[0][1] == ["--lib"]}
    assert libs == want, f"Windows lib legs are not the four-leg cut: {sorted(libs)}"
    assert set(SHARED_BUILD.get("windows", ())) == set(want), "every Windows lib leg runs from the shared exe"
    # Overlap is pairwise: a name two of three legs list is caught even though no name is in all three.
    saved_listed = globals()["listed"]
    picks = {(): {"t1", "t2", "t3"}}
    try:
        def fake_listed(_binary, args, _os_kind):
            return picks.get(tuple(args), set())
        globals()["listed"] = fake_listed
        saved_win = SHARDS["windows"]
        SHARDS["windows"] = {"x": [("suite", ["--lib"], ["x"], 1)], "y": [("suite", ["--lib"], ["y"], 1)],
                             "z": [("suite", ["--lib"], ["z"], 1)]}
        picks.update({("x",): {"t1"}, ("y",): {"t1", "t2"}, ("z",): {"t3"}})
        found = union_problems("fake", "windows")
        assert found and "both" in found[0] and "t1" in found[0], f"a test in two of three legs passed: {found}"
    finally:
        globals()["listed"] = saved_listed
        SHARDS["windows"] = saved_win
    with tempfile.TemporaryDirectory() as root:
        art = {"reason": "compiler-artifact", "target": {"kind": ["lib"], "name": "mcp_gateway"},
               "profile": {"test": True}, "executable": os.path.join(root, "built.exe")}
        with open(art["executable"], "w") as f:
            f.write("exe")
        cargo = os.path.join(root, "cargo")
        with open(cargo, "w") as f:
            f.write(f"#!/bin/sh\necho '{json.dumps(art)}'\n")
        os.chmod(cargo, 0o755)
        dest = os.path.join(root, "out")
        assert export_lib(dest, (cargo,), os_name="nt") == 0
        exe = os.path.join(dest, LIB_BINARY + ".exe")
        assert open(exe).read() == "exe", "export-lib on Windows did not write lib-tests.exe"
        assert open(exe + ".root").read().strip() == ROOT, "export-lib did not record the root it built in"
        # A leg runs only from an exe built in its own checkout: a missing or different root is refused
        # before the exe runs (it would exit 9 if run).
        fake = os.path.join(root, "leg-exe")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nexit 9\n")
        os.chmod(fake, 0o755)
        assert run_prebuilt("windows", "lib-a", fake) == 1, "an exe with no recorded root ran"
        with open(fake + ".root", "w") as f:
            f.write("/somewhere/else\n")
        assert run_prebuilt("windows", "lib-a", fake) == 1, "an exe built under another root ran"
        # A failed partition check stops the leg before any test runs (the exe marks a run).
        ran = os.path.join(root, "ran")
        with open(fake, "w") as f:
            f.write(f'#!/bin/sh\nif [ "$1" = --list ]; then echo "only::one: test"; exit 0; fi\ntouch {ran}\n')
        with open(fake + ".root", "w") as f:
            f.write(ROOT + "\n")
        assert run_prebuilt("windows", "lib-a", fake) == 1 and not os.path.exists(ran), \
            "a leg ran its tests after the partition check failed"
    assert main(["shard_tests.py", "run-prebuilt", "windows", "int-a", "x"]) == 2, "a Windows int leg ran prebuilt"


def parts_rows() -> None:
    """S1 and S2: the shard and single-test consumers on five part binaries (fake ones that record each run)."""
    n = 5
    with tempfile.TemporaryDirectory() as d:
        log = os.path.join(d, "runs")

        def part(k: int, names: list[str], listed: list[str] | None = None, residue: bool = False,
                 rc: int = 0) -> None:
            folder = os.path.join(d, f"linux-lib-tests-p{k}", f"p{k}")
            os.makedirs(folder, exist_ok=True)
            exe = os.path.join(folder, f"lib-tests-p{k}")
            body = " ".join(names)
            with open(exe, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = --list ]; then shift; f="$1"\n'
                        f'  for t in {body}; do case "$t" in *"$f"*) echo "$t: test";; esac; done; exit 0; fi\n'
                        f'echo "p{k} $*" >> {log}\n'
                        'h="${MCP_GATEWAY_TEST_HOME_DIR:-none}"; [ -d "$h" ] && there=exists || there=missing\n'
                        f'echo "$h|${{XDG_CONFIG_HOME:-none}}|${{MCP_GATEWAY_CONFIG_DIR:-none}}|$there" > {log}.home\n'
                        + ('touch "$TMPDIR/leftover"\n' if residue else "")
                        + f'echo "running {len(names)} tests"; echo "test result: ok. {len(names)} passed; 0 failed; 0 ignored"\n'
                        + f'exit {rc}\n')
            os.chmod(exe, 0o755)
            with open(os.path.join(folder, "list.txt"), "w") as f:
                f.write("".join(f"{t}: test\n" for t in (names if listed is None else listed)))

        def fresh(names_by_part=None):
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            for k in range(1, n + 1):
                part(k, (names_by_part or {}).get(k, [f"m{k}::upgrade_x{k}", f"m{k}::t{k}"]))

        fresh()
        assert part_binaries(d)[1] == [], part_binaries(d)[1]
        shutil.rmtree(os.path.join(d, "linux-lib-tests-p3"))
        assert part_binaries(d)[1], "a missing part passed"
        fresh()
        part(2, ["m2::t2"], listed=["m2::t2", "m2::other"])
        assert part_binaries(d)[1], "a binary differing from its list.txt passed"
        fresh({1: ["m1::t1", "shared::x"], 2: ["shared::x"]})
        assert part_binaries(d)[1], "two parts sharing a test passed"
        # run-one, exact: exactly one test over all parts, run once on its binary.
        fresh()
        assert run_one("--exact", "m3::t3", d, []) == 0
        runs = open(log).read().splitlines()
        assert runs == ["p3 m3::t3 --exact"], runs
        # H1: the run gets a private gateway home of its own, present while it runs, with the config and data
        # dirs beneath it, and removed after it.
        def run_home() -> str:
            home, xdg, cfg, there = open(log + ".home").read().strip().split("|")
            assert os.path.basename(home).startswith("shard-home-"), ("run-one gives the binary a home", home)
            assert (xdg, cfg) == (os.path.join(home, ".config"), os.path.join(home, ".mcp-gateway")), (xdg, cfg)
            assert there == "exists", ("the home exists while the binary runs", home)
            assert not os.path.exists(home), ("run-one removes its home", home)
            return home
        run_home()
        # A failing binary: its exit code is run-one's, and the home is still removed.
        fresh()
        part(3, ["m3::upgrade_x3", "m3::t3"], rc=3)
        assert run_one("--exact", "m3::t3", d, []) == 3, "run-one passes the binary's exit code on"
        run_home()
        fresh()
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            assert which_one("m4::t4", d, []) == 0
        assert buf.getvalue().strip().endswith("lib-tests-p4"), buf.getvalue()
        assert which_one("m9::none", d, []) == 1, "which found a test that is not there"
        fresh()
        assert run_one("--exact", "m9::none", d, []) == 1, "zero selected passed"
        fresh({1: ["a::dup", "b::dup"]})
        assert run_one("--exact", "dup", d, []) == 1, "an exact name matching nothing exactly passed"
        # run-one, module: at least one, all on one part, by exact names. The prefix is anchored: libtest's filter
        # also lists part 2's name, which holds the prefix only in the middle.
        fresh({4: ["upgrade_notice_tests::a", "upgrade_notice_tests::b", "m4::t4"], 2: ["m2::upgrade_notice_tests::c"]})
        assert run_one("--module", "upgrade_notice_tests::", d, []) == 0
        assert open(log).read().split() == ["p4", "upgrade_notice_tests::a", "upgrade_notice_tests::b", "--exact"]
        fresh({1: ["upgrade_notice_tests::a"], 2: ["upgrade_notice_tests::b"]})
        assert run_one("--module", "upgrade_notice_tests::", d, []) == 1, "a module split over parts passed"
        fresh()
        assert run_one("--module", "nothing_tests::", d, []) == 1, "an empty module selection passed"
        # S1, run-prebuilt-parts: each binary runs its half under today's guards; the floor is on the sum.
        def shard_part(k: int, count: int, residue: bool = False) -> None:
            folder = os.path.join(d, f"linux-lib-tests-p{k}", f"p{k}")
            os.makedirs(folder, exist_ok=True)
            exe = os.path.join(folder, f"lib-tests-p{k}")
            names = f"gateway::g{k} other::o{k}"
            with open(exe, "w") as f:
                f.write("#!/bin/sh\n"
                        'if [ "$1" = --list ]; then shift; [ "$1" = --format ] && shift 2\n'
                        '  case "$1 $2" in\n'
                        f'    "gateway:: "*) for t in {names}; do case $t in gateway::*) echo "$t: test";; esac; done;;\n'
                        f'    "--skip gateway::") for t in {names}; do case $t in gateway::*) ;; *) echo "$t: test";; esac; done;;\n'
                        f'    *) for t in {names}; do echo "$t: test"; done;;\n'
                        '  esac; exit 0; fi\n'
                        + ('touch "$TMPDIR/leftover"\n' if residue else "")
                        + f'echo "running {count} tests"; echo "test result: ok. {count} passed; 0 failed; 0 ignored"\n')
            os.chmod(exe, 0o755)
            with open(os.path.join(folder, "list.txt"), "w") as f:
                f.write(f"gateway::g{k}: test\nother::o{k}: test\n")

        def shards(count: int, residue_part: int | None = None) -> None:
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            for k in range(1, n + 1):
                shard_part(k, count, residue=k == residue_part)

        big = max(SHARDS["linux"][leg][0][3] for leg in SHARED_BUILD["linux"])
        shards(big // n + 1)
        assert run_prebuilt_parts("linux", "lib-a", d) == 0
        shards(1)
        assert run_prebuilt_parts("linux", "lib-a", d) == 1, "a sum under the floor passed"
        shards(big // n + 1, residue_part=3)
        assert run_prebuilt_parts("linux", "lib-b", d) == 1, "a leftover from the middle part passed"


def per_binary_rows() -> None:
    """Each test binary gets its own TMPDIR under BY_BINARY, so a leftover names the binary that left it."""
    # The runner itself: a binary named by cargo with its hash suffix runs with TMPDIR set to
    # BY_BINARY/<target>, which the runner creates.
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as bins:
        runner = write_runner(tmp)
        stub = os.path.join(bins, "a0_per_caller_cache-0123456789abcdef")
        with open(stub, "w") as f:
            f.write('#!/bin/sh\nprintf %s "$TMPDIR"\n')
        os.chmod(stub, 0o755)
        out = subprocess.run([runner, stub], env={**os.environ, "TMPDIR": tmp},
                             capture_output=True, text=True, check=True).stdout
        want = os.path.join(tmp, BY_BINARY, "a0_per_caller_cache")
        assert out == want, f"the binary's TMPDIR is {out!r}, not {want!r}"
        assert os.path.isdir(want), "the runner creates the binary's folder"
        # Its exit status is the binary's.
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nexit 7\n")
        assert subprocess.run([runner, stub], env={**os.environ, "TMPDIR": tmp}).returncode == 7, \
            "the runner keeps the binary's exit status"
    # cargo is told to use it.
    cfg = runner_config("/x/r.sh")
    assert cfg == ["--config", "target.'cfg(all())'.runner=['/x/r.sh']"], cfg
    # End to end through run_steps: a fake cargo that starts stub test binaries through the runner its
    # --config names, as real cargo does. PLANT selects what each binary leaves in its own TMPDIR.
    with tempfile.TemporaryDirectory() as bins:
        stubs = []
        for name in ("gh452_session_owner-fedcba9876543210", "a0_per_caller_cache-0123456789abcdef"):
            stub = os.path.join(bins, name)
            with open(stub, "w") as f:
                f.write('#!/bin/sh\ncase " $PLANT " in *" leak "*) mkdir -p "$TMPDIR/.tmpXyZ789/tasks"; '
                        ': > "$TMPDIR/.tmpXyZ789/tasks/task-x.json" ;; esac\n'
                        'case " $PLANT " in *" hwm "*) mkdir -p "$TMPDIR/.tmpHwmA12"; '
                        ': > "$TMPDIR/.tmpHwmA12/audit.jsonl.hwm" ;; esac\n')
            os.chmod(stub, 0o755)
            stubs.append(stub)
        fake_cargo = (sys.executable, "-c", (
            "import os, re, subprocess, sys\n"
            "args = sys.argv[1:]\n"
            "cfg = [args[i + 1] for i, a in enumerate(args) if a == '--config']\n"
            "run = [re.search(r\"runner=\\['(.*)'\\]\", c).group(1) for c in cfg if 'runner=' in c]\n"
            f"for stub in {stubs!r}:\n"
            "    subprocess.run([*run, stub], check=True)\n"
            "print('     Running unittests src/lib.rs (x)')\n"
            "print('running 99999 tests')\n"
            "print('test result: ok. 99999 passed; 0 failed; 0 ignored')\n"))
        def run(plant: str) -> list[str]:
            os.environ["PLANT"] = plant
            try:
                return run_steps("linux", "lib-a", fake_cargo)
            finally:
                del os.environ["PLANT"]
        # A task record each binary leaves is named under its own binary, the same entry name in both.
        got = run("leak")
        assert got == ["left in TMPDIR: a0_per_caller_cache/.tmpXyZ789 (tasks/task-x.json 0B)",
                       "left in TMPDIR: gh452_session_owner/.tmpXyZ789 (tasks/task-x.json 0B)"], got
        # An audit high-water mark inside a binary's folder fails too, named under each binary
        # that left it.
        got = run("hwm")
        assert got == ["left in TMPDIR: a0_per_caller_cache/.tmpHwmA12 (audit.jsonl.hwm 0B)",
                       "left in TMPDIR: gh452_session_owner/.tmpHwmA12 (audit.jsonl.hwm 0B)"], got
        assert run("") == [], "clean binaries leave only their empty folders"
    # An allowance is shared across binaries: with a known source of three, four leftovers in four
    # binaries fail on the fourth (held with an explicit list now that KNOWN_LEFTOVERS is empty).
    four = {f"bin{i}/.tmpAb12C{i}": ["audit.jsonl.hwm"] for i in range(4)}
    three = [(r"\.tmp[A-Za-z0-9]{6}", r"audit\.jsonl\.hwm", 3, "a source allowed three")]
    assert unexpected(four, three) == ["bin3/.tmpAb12C3"], unexpected(four, three)
    # An unexpected empty folder at the top of TMPDIR still fails, as before.
    assert unexpected({"stray": []}) == ["stray"]

def lib_test_binary(lines: list[str]) -> str | None:
    """The `--lib` test executable in `cargo test --no-run --message-format=json` output."""
    for line in lines:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        target = msg.get("target", {}) if isinstance(msg, dict) else {}
        if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
                and msg.get("profile", {}).get("test") and "lib" in target.get("kind", [])):
            return msg["executable"]
    return None


def export_lib(dest: str, program: tuple[str, ...] = ("cargo",), os_name: str = os.name) -> int:
    """Build the `--lib` test binary (the same build `cargo test --all-features --lib` reuses) and
    copy it to `dest` as LIB_BINARY, for the SHARED_BUILD legs on other runners."""
    rc, lines = cargo([*BASE, "--lib", "--no-run", "--message-format=json-render-diagnostics"], program)
    path = lib_test_binary(lines) if rc == 0 else None
    if path is None:
        print(f"::error::export-lib: no lib test executable (cargo exited {rc})")
        return 1
    os.makedirs(dest, exist_ok=True)
    # Windows runs only a file named .exe; beside the copy, `.root` names the checkout it was built in,
    # since the exe's compile-time paths point there.
    out = os.path.join(dest, LIB_BINARY + (".exe" if os_name == "nt" else ""))
    shutil.copy2(path, out)
    with open(out + ".root", "w") as f:
        f.write(ROOT + "\n")
    os.chmod(out, 0o755)
    print(f"::notice::export-lib: {path} -> {out} ({os.path.getsize(out)} bytes)")
    return 0


def listed(binary: str, test_args: list[str], os_kind: str) -> set[str]:
    """The test names `binary` selects with `test_args` and the OS skips (`--list`, nothing runs)."""
    out = subprocess.run([binary, "--list", "--format", "terse", *test_args, *SKIPS[os_kind]],
                         capture_output=True, text=True, env={**os.environ, "CARGO_MANIFEST_DIR": ROOT},
                         cwd=ROOT)
    if out.returncode != 0:
        raise RuntimeError(f"--list exited {out.returncode}: {out.stderr.strip()[-300:]}")
    return {line[: -len(": test")] for line in out.stdout.splitlines() if line.endswith(": test")}


def union_problems(binary: str, os_kind: str) -> list[str]:
    """Problems with this OS's lib halves on `binary`: a test both select, or one neither does.
    The halves' filters come from the table, so this checks exactly what the jobs run."""
    halves = {name: steps[0][2] for name, steps in SHARDS[os_kind].items()
              if any("--lib" in args for _, args, _, _ in steps)}
    try:
        whole = listed(binary, [], os_kind)
        sets = {name: listed(binary, args, os_kind) for name, args in halves.items()}
    except RuntimeError as error:
        return [f"lib union: {error}"]
    names = sorted(sets)
    # Pairwise: with three legs or more, a test two of them pick is in no all-legs intersection.
    seen: set[str] = set()
    both: set[str] = set()
    for chosen in sets.values():
        both |= seen & chosen
        seen |= chosen
    missing = whole - seen
    print(f"::notice::{os_kind} lib union: whole {len(whole)}, "
          + ", ".join(f"{n} {len(sets[n])}" for n in names) + f", overlap {len(both)}, missing {len(missing)}")
    out = [f"lib union: {len(both)} test(s) that two legs both select, e.g. {sorted(both)[:3]}"] * bool(both)
    out += [f"lib union: {len(missing)} test(s) no leg selects, e.g. {sorted(missing)[:3]}"] * bool(missing)
    return out


def _run_binary(os_kind: str, shard: str, binary: str) -> tuple[int, list[str]]:
    """Run SHARD's selection on one exported lib test binary, as `cargo test` would run it: from the package root
    with CARGO_MANIFEST_DIR set, and on a TMP_GUARDED OS with the TMPDIR guard `run` applies (the binary's own
    BY_BINARY folder as TMPDIR, a leftover fails the shard). (Tests selected, problems), the halves' partition of
    this binary's list included; the floor is the caller's."""
    ((step, _args, test_args, _floor),) = SHARDS[os_kind][shard]
    os.chmod(binary, 0o755)  # an artifact round trip drops the exec bit
    # The coverage guard: the halves' selections on this binary partition its whole list.
    union = union_problems(binary, os_kind)
    if union:
        # The legs do not partition this binary, so no count it gives could be trusted: run nothing.
        return 0, union
    env = {**os.environ, "CARGO_MANIFEST_DIR": ROOT}
    tmp = tempfile.mkdtemp(prefix="shard-tmp-") if os_kind in TMP_GUARDED else None
    if tmp:
        # What the cargo runner gives this binary: its own folder, so a leftover is reported under it.
        env["TMPDIR"] = os.path.join(tmp, BY_BINARY, LIB_TARGET)
        os.makedirs(env["TMPDIR"])
    lines = []
    with private_home(env, tmp) as home_env:
        p = subprocess.Popen([binary, *test_args, *OUTPUT.get(os_kind, []), *SKIPS[os_kind]],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=home_env, cwd=ROOT)
        assert p.stdout is not None
        for raw in p.stdout:
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            lines.append(ANSI.sub("", raw.decode("utf-8", "replace").rstrip("\r\n")))
        rc = p.wait()
    # The binary prints no cargo `Running` header: arm the count as cargo's would.
    n = selected(["     Running unittests src/lib.rs (prebuilt)", *lines])
    failed = [f"{step}: test binary {os.path.basename(binary)} exited {rc}"] * (rc != 0)
    failed += union
    failed += unkept(lines)
    if tmp:
        failed += tmp_problems(os_kind, shard, tmp)
    return n, failed


def run_prebuilt(os_kind: str, shard: str, binary: str) -> int:
    """Run a SHARED_BUILD shard from one exported lib test binary. Same floor and report."""
    ((step, _args, _test_args, floor),) = SHARDS[os_kind][shard]
    # Its compile-time paths point at the checkout export-lib recorded; refuse an exe from any other.
    try:
        built_in = open(binary + ".root").read().strip()
    except OSError:
        built_in = None
    if built_in != ROOT:
        print(f"::error::{os_kind} {shard} {step}: {os.path.basename(binary)} was built in "
              f"{built_in or 'a checkout it did not record'}, not {ROOT}")
        return 1
    n, failed = _run_binary(os_kind, shard, binary)
    print(f"::notice::{os_kind} {shard} {step} (prebuilt): selected {n} (floor {floor})")
    failed += [f"{step}: selected {n} tests, below the floor of {floor}"] * (n < floor)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


def part_binaries(directory: str) -> tuple[dict[int, str], list[str]]:
    """The lib test part binaries under DIRECTORY (`*/pK/lib-tests-pK`, one artifact folder each) and the problems
    that stop a run before any test: parts other than exactly 1..N, a binary whose `--list` differs from the
    `list.txt` the union job checked, or two parts listing the same test."""
    n = part_count()
    found: dict[int, str] = {}
    out: list[str] = []
    for path in sorted(glob.glob(os.path.join(directory, "*", "p*", "lib-tests-p*"))):
        m = re.fullmatch(r"lib-tests-p(\d+)", os.path.basename(path))
        if m is None or os.path.basename(os.path.dirname(path)) != f"p{m.group(1)}":
            continue
        k = int(m.group(1))
        if k in found:
            out.append(f"part {k} appears twice")
        found[k] = path
    if sorted(found) != list(range(1, n + 1)):
        out.append(f"part binaries {sorted(found)}, not exactly 1..{n}")
    owner: dict[str, int] = {}
    for k, path in sorted(found.items()):
        os.chmod(path, 0o755)
        listed_now = subprocess.run([path, "--list"], capture_output=True, text=True, cwd=ROOT).stdout
        names = {x[: -len(": test")] for x in listed_now.splitlines() if x.endswith(": test")}
        recorded = os.path.join(os.path.dirname(path), "list.txt")
        if not os.path.isfile(recorded) or names != {x[: -len(": test")] for x in open(recorded).read().splitlines()
                                                     if x.endswith(": test")}:
            out.append(f"part {k}'s binary does not list what its list.txt recorded")
        for name in names:
            if name in owner:
                out.append(f"{name} is listed by parts {owner[name]} and {k}")
            owner.setdefault(name, k)
    return found, out


def run_prebuilt_parts(os_kind: str, shard: str, directory: str) -> int:
    """Run a SHARED_BUILD shard across the lib test part binaries: the parts are checked first, then each binary
    runs the shard's half under today's guards, and the floor applies to the sum."""
    ((step, _args, _test_args, floor),) = SHARDS[os_kind][shard]
    binaries, failed = part_binaries(directory)
    total = 0
    if not failed:
        for k, path in sorted(binaries.items()):
            n, problems = _run_binary(os_kind, shard, path)
            total += n
            failed += [f"part {k}: {x}" for x in problems]
    print(f"::notice::{os_kind} {shard} {step} (parts): selected {total} (floor {floor})")
    failed += [f"{step}: selected {total} tests over the parts, below the floor of {floor}"] * (total < floor)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


# libtest's per-test result line; a #[should_panic] test reads `test <name> - should panic ... ok`. Anchored at the line
# start, with any number of unfinished `test <name> ... ` before the result: a test that re-runs the binary as a child
# shares stdout, and the child's unfinished line can precede the parent's result (E1, run 44460056220). Text that is
# not a libtest prefix (`diagnostic: test x ... ok`) never counts.
RESULT_LINE = re.compile(r"^(?:test \S+(?: - should panic)? \.\.\. )*test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)\b")

# The writer's rows that need root: #[ignore]d, so the part run above reports them as ignored. The part step runs
# them once more as root, from the same binary, before it is deleted. PRIVILEGE is the prefix for that run; the
# self-test swaps in a logging stand-in.
ROOT_ROWS = "config_persistence_access_tests::root::"
PRIVILEGE: tuple[str, ...] = ("sudo", "-E")


def _echo_results(p: subprocess.Popen) -> dict[str, list[str]]:
    """Pass P's output through to the job log as it comes and gather every libtest result, by test name, in order."""
    assert p.stdout is not None
    seen: dict[str, list[str]] = {}
    for chunk in p.stdout:
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        if hit := RESULT_LINE.match(ANSI.sub("", chunk.decode("utf-8", "replace").rstrip("\r\n"))):
            seen.setdefault(hit.group(1), []).append(hit.group(2))
    return seen


def _run_root_rows(binary: str, roots: list[str], env: dict[str, str]) -> list[str]:
    """ROOTS, the root rows a part lists, run again under PRIVILEGE from the repo root with the plain job env (the
    0700 gateway dirs of private_home would block the mcpg-c child those rows start). Returns the problems: a non-zero
    exit, and every root row whose results are anything but a single `ok`."""
    p = subprocess.Popen([*PRIVILEGE, binary, ROOT_ROWS, "--ignored", "--test-threads=1"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
    results = _echo_results(p)
    rc = p.wait()
    out = [f"root rows exited {rc}"] * (rc != 0)
    out += [f"root row {name}: {', '.join(results.get(name, [])) or 'not reported'}"
            for name in roots if results.get(name) != ["ok"]]
    return out


def run_built_parts(os_kind: str, leg: str, directory: str, script: tuple[str, ...] = ()) -> int:
    """Build and run LEG's lib test parts one at a time (PARTS, leg_parts): `lib-parts.sh export K DIRECTORY` builds
    part K and writes pK/lib-tests-pK and pK/list.txt; the binary runs every test with the OS skips; the names it
    reports must be its list less the names a skip matches (libtest's substring rule); then the binary is deleted
    before the next part builds. Every part runs even after one fails; the floor applies to the sum."""
    ((step, _args, _test_args, floor),) = SHARDS[os_kind][leg]
    script = script or ("bash", os.path.join(ROOT, "scripts", "ci", "lib-parts.sh"))
    patterns = [a for a in SKIPS[os_kind] if a != "--skip"]
    solo = os.environ.get("MACOS_LIB_SOLO") == "true"
    env = {**os.environ, "CARGO_MANIFEST_DIR": ROOT}
    failed: list[str] = []
    total = 0
    for k in leg_parts(os_kind, leg, solo):
        print(f"::group::{os_kind} {leg}: part {k}", flush=True)
        binary = os.path.join(directory, f"p{k}", f"lib-tests-p{k}")
        recorded = os.path.join(directory, f"p{k}", "list.txt")
        try:
            rc = subprocess.run([*script, "export", str(k), directory], cwd=ROOT).returncode
            if rc != 0 or not os.path.isfile(binary) or not os.path.isfile(recorded):
                failed.append(f"part {k}: its build failed (lib-parts.sh exited {rc})")
                continue
            listed_names = {x[: -len(": test")] for x in open(recorded).read().splitlines() if x.endswith(": test")}
            want = {n for n in listed_names if not any(p in n for p in patterns)}
            os.chmod(binary, 0o755)
            reported: dict[str, str] = {}
            part_lines: list[str] = []
            with private_home(env, None) as home_env:
                p = subprocess.Popen([binary, *SKIPS[os_kind]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=home_env, cwd=ROOT)
                assert p.stdout is not None
                for raw in p.stdout:
                    sys.stdout.buffer.write(raw)
                    sys.stdout.buffer.flush()
                    part_lines.append(ANSI.sub("", raw.decode("utf-8", "replace").rstrip("\r\n")))
                    m = RESULT_LINE.match(part_lines[-1])
                    if m:
                        reported[m.group(1)] = m.group(2)
                prc = p.wait()
            # The writer's root rows, which the run above reports as ignored: once more as root, from this binary
            # before it goes. Only a part whose own list holds them; no other part calls the prefix.
            roots = sorted(n for n in listed_names if n.startswith(ROOT_ROWS))
            if roots:
                failed += [f"part {k}: {x}" for x in _run_root_rows(binary, roots, env)]
        finally:
            # The binary goes before the next part builds, also when an export or a run failed part way.
            if os.path.lexists(binary):
                os.remove(binary)
            print("::endgroup::", flush=True)
        total += len(reported)
        print(f"::notice::{os_kind} {leg} part {k}: ran {len(reported)}, its list less the skips {len(want)}")
        if prc != 0:
            failed.append(f"part {k}: test binary exited {prc}")
        failed += [f"part {k}: {u}" for u in unkept(part_lines)]
        if set(reported) != want:
            failed.append(f"part {k}: ran {len(reported)} tests, its list less the skips is {len(want)} "
                          f"(missing e.g. {sorted(want - set(reported))[:3]}, extra e.g. {sorted(set(reported) - want)[:3]})")
    print(f"::notice::{os_kind} {leg} {step} (built parts): ran {total} (floor {floor})")
    failed += [f"{step}: ran {total} tests over the parts, below the floor of {floor}"] * (total < floor)
    for f in failed:
        print(f"::error::{os_kind} {leg} {f}")
    return 1 if failed else 0


def which_one(name: str, directory: str, extra: list[str]) -> int:
    """Print the one part binary that holds exactly-named test NAME (a step that must run the binary itself, as the
    keychain steps inside their D-Bus session do). Fails unless exactly one test over the parts matches."""
    binaries, failed = part_binaries(directory)
    hits = []
    for k, path in sorted(binaries.items()):
        out = subprocess.run([path, "--list", name, "--exact", *extra], capture_output=True, text=True, cwd=ROOT).stdout
        hits += [path for x in out.splitlines() if x.endswith(": test")]
    if len(hits) != 1:
        failed.append(f"{name}: {len(hits)} tests selected over the parts, not exactly one")
    for f in failed:
        print(f"::error::which {f}", file=sys.stderr)
    if failed:
        return 1
    print(hits[0])
    return 0


def run_one(mode: str, pattern: str, directory: str, extra: list[str]) -> int:
    """List PATTERN on every part binary first, then run it once. `--exact`: exactly one test in total (libtest
    `--exact`). `--module`: names under the anchored path prefix PATTERN, at least one, all on one binary, run there
    by exact name. EXTRA passes through (for example `--ignored`)."""
    binaries, failed = part_binaries(directory)
    hits: dict[int, list[str]] = {}
    for k, path in sorted(binaries.items()):
        args = [pattern, "--exact"] if mode == "--exact" else [pattern]
        out = subprocess.run([path, "--list", *args, *extra], capture_output=True, text=True, cwd=ROOT).stdout
        names = [x[: -len(": test")] for x in out.splitlines() if x.endswith(": test")]
        if mode == "--module":
            names = [x for x in names if x.startswith(pattern)]
        if names:
            hits[k] = names
    count = sum(len(v) for v in hits.values())
    if mode == "--exact" and count != 1:
        failed.append(f"{pattern}: {count} tests selected over the parts, not exactly one")
    if mode == "--module" and (not count or len(hits) != 1):
        failed.append(f"{pattern}: {count} tests on {len(hits)} parts; a module filter needs one part")
    for f in failed:
        print(f"::error::run-one {f}")
    if failed:
        return 1
    ((k, names),) = hits.items()
    env = {**os.environ, "CARGO_MANIFEST_DIR": ROOT}
    # A private gateway home, as every other lib test run gets (H1).
    with private_home(env, None) as home_env:
        return subprocess.run([binaries[k], *names, "--exact", *extra], env=home_env, cwd=ROOT).returncode


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 4 and argv[1] == "run" and argv[3] in SHARDS.get(argv[2], {}):
        return run(argv[2], argv[3])
    if len(argv) == 3 and argv[1] == "export-lib":
        return export_lib(argv[2])
    if len(argv) == 5 and argv[1] == "run-prebuilt-parts" and argv[3] in SHARED_BUILD.get(argv[2], ()):
        return run_prebuilt_parts(argv[2], argv[3], argv[4])
    if (len(argv) == 6 and argv[1] == "run-prebuilt-parts" and argv[4] == "--build"
            and argv[3] in PARTS.get(argv[2], {})):
        return run_built_parts(argv[2], argv[3], argv[5])
    if len(argv) >= 4 and argv[1] == "which":
        return which_one(argv[2], argv[3], argv[5:] if len(argv) > 4 and argv[4] == "--" else [])
    if len(argv) >= 5 and argv[1] == "run-one" and argv[2] in ("--exact", "--module"):
        extra = argv[6:] if len(argv) > 5 and argv[5] == "--" else []
        return run_one(argv[2], argv[3], argv[4], extra)
    if len(argv) == 5 and argv[1] == "run-prebuilt" and argv[3] in SHARED_BUILD.get(argv[2], ()):
        return run_prebuilt(argv[2], argv[3], argv[4])
    if len(argv) >= 4 and argv[1] == "with-home" and argv[2] == "--":
        return with_home(argv[3:])
    if len(argv) == 3 and argv[1] == "export-home":
        return export_home(argv[2])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
