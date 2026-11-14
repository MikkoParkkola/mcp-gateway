#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of an OS test job (MIK-8482).

The Tests, Windows check and macOS check suites run as shards. Each shard is
a plain `cargo test` over a subset of test targets. The shards of one OS are
exact complements of the command that job ran before sharding:

- the library is split by a libtest filter and the matching `--skip` (Windows
  splits the skipped part again by module filters, so it has three lib
  shards), or run whole in one shard (macOS). Filters match substrings of
  the test path, so a module filter also takes its nested paths;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`) where the OS runs a single integration shard.

`scripts/ci/test_os_shards.py` holds the table below to that rule. Each shard
also fails when it selects fewer tests than its floor, so a filter that
quietly stops matching cannot read as green. A floor that drops because tests
were deleted is lowered in the same diff, where review sees it.

  shard_tests.py run <os> <shard>    run it (exit 1 on failure or under floor)
  shard_tests.py export-lib <dir>    build the lib test binary and copy it to <dir>
  shard_tests.py wait-lib <artifact> <producer job name>
                                     wait for it in this run (found=true|false)
  shard_tests.py run-prebuilt <os> <shard> <binary>
                                     run a PREBUILT or SHARED_BUILD shard from that binary
  shard_tests.py --self-test         check the counter against fixed logs
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

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
# Windows splits lib-b again: its tests ran about 23 min after a 22-min build (run 42493724287),
# the longest job on a lane pull request. These top-level modules move to lib-c (4,727 of 9,251
# tests then); lib-b skips them, so each library test still runs in exactly one shard.
LIB_C_MODULES = ["security::", "capability::", "events::", "backend::", "transport::", "oauth::"]
_WIN_LIB_B = ("suite", ["--lib"], ["--skip", LIB_SPLIT, *(x for m in LIB_C_MODULES for x in ("--skip", m))])
_WIN_LIB_C = ("suite", ["--lib"], [*LIB_C_MODULES, "--skip", LIB_SPLIT])
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
        "lib-a": [(*_LIB_A, 5335)],
        # The former lib-b floor (6747), divided in the measured proportion.
        "lib-b": [(*_WIN_LIB_B, 3299)],
        "lib-c": [(*_WIN_LIB_C, 3448)],
        "int-a": [("suite", ["--bins", "--test", GLOB_A], [], 295)],
        "int-b": [("suite", ["--test", GLOB_B], [], 1238)],
    },
    # macOS builds the `--lib` test binary once (about two macOS runners; a
    # second build cost 19-86 min, which #4562 removed). The `lib-b` job builds
    # it, uploads it and runs the heavier half (Linux 45b: 1237 s of 2170 s);
    # the `int` job, after its own suite, runs the other half from that binary
    # (PREBUILT). Coverage is checked exactly on the binary (union_problems:
    # no overlap, nothing missing); the floors are a coarse check, about 2%
    # under the halves the pilot selected (run 42527204476: 9539 + 8161).
    "macos": {
        "lib-b": [(*_LIB_B, 9350)],
        "lib-a": [(*_LIB_A, 8000)],
        "int": [("suite", ["--bins", "--test", GLOB_ALL], [], 1600), ("doc", ["--doc"], [], 55)],
    },
}
# Shards that are no matrix leg of their own: each runs from the lib test
# binary another shard of its OS built and exported (`export-lib`).
PREBUILT = {"macos": {"lib-a": "lib-b"}}
# Shards that are matrix legs of their own but compile nothing: they run from the lib test binary one job
# of the run builds and shares (ci.yml's linux-lib-build, `export-lib`), under the same guards as `run`.
SHARED_BUILD = {"linux": ("lib-a", "lib-b")}
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
# LEFTOVER_CEILING.
TMP_GUARDED = {"linux"}
_TMP = r"\.tmp[A-Za-z0-9]{6}"
KNOWN_LEFTOVERS: list[tuple[str, str, int, str]] = [
    (_TMP, r"audit\.jsonl\.hwm", 3,
     "an audit write that outlives its test's temp dir "
     "(transparency_log::bounded_tests, identity_propagation::audit_fail_closed, "
     "signing_allocation_tests::withheld_parity_stdio, hardened_signing_e2e, "
     "gateway::router::task_lifecycle_tests)"),
]
# Written out, not derived from the list above: an entry added there and not
# here, or a count raised past its ceiling, fails the self-test, so the list
# can only lose entries. A leaked TempLog folder is named `audit-log-*` and
# matches none of these.
LEFTOVER_CEILING: dict[tuple[str, str], int] = {
    (r"\.tmp[A-Za-z0-9]{6}", r"audit\.jsonl\.hwm"): 3,
}

HEADER = re.compile(r"^\s*(Running|Doc-tests) ")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RUNNING = re.compile(r"^running (\d+) tests?$")
RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")


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


def run(os_kind: str, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    failed = run_steps(os_kind, shard, program)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


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
    failed = []
    tmp = tempfile.mkdtemp(prefix="shard-tmp-") if os_kind in TMP_GUARDED else None
    env = {**os.environ, "TMPDIR": tmp} if tmp else None
    runner = runner_config(write_runner(tmp)) if tmp else []
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
    assert unexpected({"a": ["x"], "b": ["x"]}, [("[ab]", "x", 1, "one allowed")]) == ["b"], \
        "the count bounds a source"
    assert all(n <= LEFTOVER_CEILING.get((p, h), 0) for p, h, n, _ in KNOWN_LEFTOVERS), \
        "KNOWN_LEFTOVERS may only shrink"
    hwm = ["audit.jsonl.hwm"]
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
    # A leaked TempLog folder is never one of the tolerated plain temp dirs.
    assert unexpected({"audit-log-Ab12Cd": hwm, ".tmpAb12Cd": hwm}) == ["audit-log-Ab12Cd"]
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
    # Each known source is tolerated up to its own count.
    for files, most in ((hwm, 3),):
        names = [f".tmpAb12C{i}" for i in range(most + 1)]
        assert unexpected({n: files for n in names}) == [names[-1]], (files, most)
    # A plain temp folder is tolerated only for what a known source writes: a
    # stray file, a known file beside a stray one, an empty folder and a plain
    # file all fail, though each has a tolerated name.
    for files in (["other.db"], [*hwm, "other.db"], [*home, "keys/secret.pem"],
                  [*control, "gateway-control-plane/other.jsonl"],
                  [*full, "serve.log.1"], [*full, ".mcp-gateway/tasks/task-x.json"], []):
        assert unexpected({".tmpAb12Cd": files}) == [".tmpAb12Cd"], files
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
    # Through the same step, a planted gateway home now turns red, and the one
    # known source's leftover, the audit high-water mark, stays green.
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
    assert fake_known != fake, "the planted known source must replace the planted file"
    os.environ["PLANT_LEAK"] = "1"
    try:
        assert run_steps("linux", "lib-a", fake_known) == [], "a known source turned red"
    finally:
        del os.environ["PLANT_LEAK"]
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
        assert unexpected(found) == [".tmpLink01", ".tmpStray1"], found
    per_binary_rows()
    prebuilt_rows()
    print("shard_tests self-test: ok")
    return 0


def prebuilt_rows() -> None:
    """The lib test binary is found in cargo's JSON, exported, and a PREBUILT shard run
    from it counts its selection against its floor and fails on a red binary."""
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
        floor = SHARDS["macos"]["lib-a"][0][3]
        binary(f'echo "running {floor} tests"; echo "test result: ok. {floor} passed; 0 failed; 0 ignored"; '
               '[ "$1" = "gateway::" ] && [ "$CARGO_MANIFEST_DIR" = "$PWD" ] || exit 9')
        assert run_prebuilt("macos", "lib-a", fake) == 0
        binary(f'echo "running {floor - 1} tests"')
        assert run_prebuilt("macos", "lib-a", fake) == 1, "a selection under the floor passed"
        binary(f'echo "running {floor} tests"; exit 101')
        assert run_prebuilt("macos", "lib-a", fake) == 1, "a red binary passed"
        # The coverage guard: halves that overlap, or leave a test out, fail a green run.
        ok_run = f'echo "running {floor} tests"; echo "test result: ok. {floor} passed; 0 failed; 0 ignored"'
        binary(ok_run, "overlap")
        assert run_prebuilt("macos", "lib-a", fake) == 1 and union_problems(fake, "macos"), "overlap passed"
        binary(ok_run, "gap")
        assert run_prebuilt("macos", "lib-a", fake) == 1 and union_problems(fake, "macos"), "a gap passed"
        binary(ok_run)
        assert run_prebuilt("macos", "lib-a", fake) == 0 and union_problems(fake, "macos") == []
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
    # wait_for_lib: when int waits, and when it gives up and builds its half itself.
    def waits(states, grace=600):
        t = [0.0]
        seq = iter(states)
        return wait_for_lib(lambda: next(seq), lambda s: t.__setitem__(0, t[0] + s), lambda: t[0], grace, 20)
    assert waits([(False, "in_progress")] * 400 + [(True, "in_progress")]), "a slow producer was abandoned"
    assert waits([(True, None)]), "a binary from an earlier attempt was not reused"
    assert not waits([(False, "in_progress"), (False, "completed")]), "a producer that ended without it was awaited"
    assert not waits([(False, None)] * 40), "an absent producer (int rerun alone) was awaited past grace"
    assert not waits([(False, "queued")] * 40), "a producer queued past grace was awaited"
    assert waits([(False, "queued")] * 5 + [(True, "in_progress")]), "a briefly queued producer was abandoned"
    # The rehearsal input skips the wait and asks for the fallback, touching no API.
    with tempfile.TemporaryDirectory() as root:
        out = os.path.join(root, "out")
        saved = {k: os.environ.get(k) for k in ("MACOS_LIB_REHEARSE_FALLBACK", "GITHUB_OUTPUT")}
        os.environ.update(MACOS_LIB_REHEARSE_FALLBACK="true", GITHUB_OUTPUT=out)
        try:
            assert wait_lib("macos-lib-tests", "macOS shard lib-b") == 0
            assert open(out).read() == "found=false\n"
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


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
        # A known leftover inside a binary's folder stays tolerated, and its count is shared across
        # binaries (two here, within the allowance of three).
        assert run("hwm") == [], run("hwm")
        assert run("") == [], "clean binaries leave only their empty folders"
    # The allowance is shared across binaries: four known leftovers in four binaries fail on the fourth.
    four = {f"bin{i}/.tmpAb12C{i}": ["audit.jsonl.hwm"] for i in range(4)}
    assert unexpected(four) == ["bin3/.tmpAb12C3"], unexpected(four)
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


def export_lib(dest: str, program: tuple[str, ...] = ("cargo",)) -> int:
    """Build the `--lib` test binary (the same build `cargo test --all-features --lib` reuses) and
    copy it to `dest` as LIB_BINARY, for a PREBUILT shard on another runner."""
    rc, lines = cargo([*BASE, "--lib", "--no-run", "--message-format=json-render-diagnostics"], program)
    path = lib_test_binary(lines) if rc == 0 else None
    if path is None:
        print(f"::error::export-lib: no lib test executable (cargo exited {rc})")
        return 1
    os.makedirs(dest, exist_ok=True)
    out = os.path.join(dest, LIB_BINARY)
    shutil.copy2(path, out)
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
    both = set.intersection(*sets.values()) if len(sets) > 1 else set()
    missing = whole - set().union(*sets.values())
    print(f"::notice::{os_kind} lib union: whole {len(whole)}, "
          + ", ".join(f"{n} {len(sets[n])}" for n in names) + f", overlap {len(both)}, missing {len(missing)}")
    out = [f"lib union: {len(both)} test(s) in both halves, e.g. {sorted(both)[:3]}"] * bool(both)
    out += [f"lib union: {len(missing)} test(s) in neither half, e.g. {sorted(missing)[:3]}"] * bool(missing)
    return out


def run_prebuilt(os_kind: str, shard: str, binary: str) -> int:
    """Run a PREBUILT or SHARED_BUILD shard from an exported lib test binary, as `cargo test` would run it:
    from the package root with CARGO_MANIFEST_DIR set, and on a TMP_GUARDED OS with the TMPDIR guard `run`
    applies (the binary's own BY_BINARY folder as TMPDIR, a leftover fails the shard). Same floor and report."""
    ((step, _args, test_args, floor),) = SHARDS[os_kind][shard]
    os.chmod(binary, 0o755)  # an artifact round trip drops the exec bit
    # The coverage guard: the halves' selections on this binary partition its whole list.
    union = union_problems(binary, os_kind)
    env = {**os.environ, "CARGO_MANIFEST_DIR": ROOT}
    tmp = tempfile.mkdtemp(prefix="shard-tmp-") if os_kind in TMP_GUARDED else None
    if tmp:
        # What the cargo runner gives this binary: its own folder, so a leftover is reported under it.
        env["TMPDIR"] = os.path.join(tmp, BY_BINARY, LIB_TARGET)
        os.makedirs(env["TMPDIR"])
    p = subprocess.Popen([binary, *test_args, *OUTPUT.get(os_kind, []), *SKIPS[os_kind]],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=ROOT)
    lines = []
    assert p.stdout is not None
    for raw in p.stdout:
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        lines.append(ANSI.sub("", raw.decode("utf-8", "replace").rstrip("\r\n")))
    rc = p.wait()
    # The binary prints no cargo `Running` header: arm the count as cargo's would.
    n = selected(["     Running unittests src/lib.rs (prebuilt)", *lines])
    print(f"::notice::{os_kind} {shard} {step} (prebuilt): selected {n} (floor {floor}), rc {rc}")
    failed = [f"{step}: test binary exited {rc}"] * (rc != 0)
    failed += [f"{step}: selected {n} tests, below the floor of {floor}"] * (n < floor)
    failed += union
    if tmp:
        failed += tmp_problems(os_kind, shard, tmp)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


def wait_for_lib(fetch, sleep, clock, grace: float = 600, interval: float = 20) -> bool:
    """Whether the exported lib binary arrives. `fetch()` gives (artifact present, producer job
    status in this attempt or None). Gives up, so the caller builds the half itself, when the
    producer finished without it, or is absent from this attempt (a rerun of int alone) or still
    queued `grace` seconds in (both macOS runners held by waiting jobs). An in-progress producer
    is waited for: building again would cost more than waiting."""
    start = clock()
    while True:
        present, status = fetch()
        if present:
            return True
        if status == "completed":
            return False
        if status in (None, "queued", "waiting", "pending") and clock() - start >= grace:
            return False
        sleep(interval)


def wait_lib(artifact: str, producer: str) -> int:
    """Wait for `artifact` from job `producer` of this run; write found=true|false to GITHUB_OUTPUT."""
    if os.environ.get("MACOS_LIB_REHEARSE_FALLBACK") == "true":
        # A dispatch input: rehearse the path a missing binary takes, without breaking lib-b.
        print(f"::notice::wait-lib: rehearsing the fallback; {artifact} not used")
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("found=false\n")
        return 0
    repo, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")

    def gh(path: str, jq: str) -> str:
        return subprocess.run(["gh", "api", path, "--jq", jq], capture_output=True, text=True,
                              check=True).stdout.strip()

    def fetch():
        count = gh(f"repos/{repo}/actions/runs/{run_id}/artifacts?name={artifact}", ".total_count")
        status = gh(f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100",
                    f'[.jobs[] | select(.name == "{producer}") | .status][0] // ""')
        return int(count or 0) > 0, status or None

    import time
    start = time.monotonic()
    found = wait_for_lib(fetch, time.sleep, time.monotonic)
    waited = int(time.monotonic() - start)
    print(f"::notice::wait-lib: {artifact} {'found' if found else 'not coming; building this half here'}"
          f" after {waited} s")
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        f.write(f"found={'true' if found else 'false'}\n")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 4 and argv[1] == "run" and argv[3] in SHARDS.get(argv[2], {}):
        return run(argv[2], argv[3])  # a PREBUILT shard too: int's fallback build
    if len(argv) == 3 and argv[1] == "export-lib":
        return export_lib(argv[2])
    if len(argv) == 4 and argv[1] == "wait-lib":
        return wait_lib(argv[2], argv[3])
    if (len(argv) == 5 and argv[1] == "run-prebuilt"
            and (argv[3] in PREBUILT.get(argv[2], {}) or argv[3] in SHARED_BUILD.get(argv[2], ()))):
        return run_prebuilt(argv[2], argv[3], argv[4])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
