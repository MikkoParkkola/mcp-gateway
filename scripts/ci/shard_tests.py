#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of an OS test job (MIK-8482).

The Tests, Windows check and macOS check suites run as shards. Each shard is
a plain `cargo test` over a subset of test targets. The shards of one OS are
exact complements of the command that job ran before sharding:

- the library is split by a libtest filter and the matching `--skip`;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`) where the OS runs a single integration shard.

`scripts/ci/test_os_shards.py` holds the table below to that rule. Each shard
also fails when it selects fewer tests than its floor, so a filter that
quietly stops matching cannot read as green. A floor that drops because tests
were deleted is lowered in the same diff, where review sees it.

  shard_tests.py run <os> <shard>    run it (exit 1 on failure or under floor)
  shard_tests.py --self-test         check the counter against fixed logs
"""
from __future__ import annotations

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
GLOB_A, GLOB_B, GLOB_ALL = "[a-l]*", "[!a-l]*", "*"
BASE = ["test", "--all-features", "--no-fail-fast"]

# (step, cargo args after `cargo test --all-features --no-fail-fast`,
#  libtest args before the OS skips, floor of selected tests)
_LIB_A = ("suite", ["--lib"], [LIB_SPLIT])
_LIB_B = ("suite", ["--lib"], ["--skip", LIB_SPLIT])
SHARDS: dict[str, dict[str, list[tuple[str, list[str], list[str], int]]]] = {
    # Floors: the selections measured by the MIK-8482 probe (run 39135535466).
    "linux": {
        "lib-a": [(*_LIB_A, 5353)],
        "lib-b": [(*_LIB_B, 6941)],
        "int-a": [("suite", ["--bins", "--test", GLOB_A], [], 835)],
        "int-b": [("suite", ["--test", GLOB_B], [], 1371), ("doc", ["--doc"], [], 55)],
    },
    "windows": {
        "lib-a": [(*_LIB_A, 5335)],
        "lib-b": [(*_LIB_B, 6747)],
        "int-a": [("suite", ["--bins", "--test", GLOB_A], [], 763)],
        "int-b": [("suite", ["--test", GLOB_B], [], 1238)],
    },
    "macos": {
        "lib-a": [(*_LIB_A, 5352)],
        "lib-b": [(*_LIB_B, 6942)],
        "int": [("suite", ["--bins", "--test", GLOB_ALL], [], 2205), ("doc", ["--doc"], [], 55)],
    },
}
# Built, not run: the default `cargo test` target set compiles examples, and
# Windows' former `cargo test --no-run` did too.
EXAMPLES = {"linux": "int-b", "macos": "int", "windows": "int-b"}
# Windows printed every test's output (`--show-output`) before sharding.
OUTPUT = {"windows": ["--show-output"]}

# A test leaves nothing in the temp directory. The Linux shards run
# cargo with TMPDIR set to a fresh private directory and fail on any entry left
# there that KNOWN_LEFTOVERS does not allow. The list holds only what a pending
# fix removes, each as (pattern on the entry name, most allowed, why). It may
# only shrink: the self-test holds each pattern and count to LEFTOVER_CEILING.
TMP_GUARDED = {"linux"}
KNOWN_LEFTOVERS: list[tuple[str, int, str]] = [
    (r"\.tmp[A-Za-z0-9]{6}", 4,
     "a late write that outlives its test's temp dir: an audit write "
     "(transparency_log::bounded_tests up to 3, identity_propagation::audit_fail_closed, "
     "signing_allocation_tests::withheld_parity_stdio; hardened_signing_e2e and "
     "mik_7272_task_1_acs) or a stdio task record"),
]
# Written out, not derived from the list above: a pattern added there and not
# here, or a count raised past its ceiling, fails the self-test, so the list
# can only lose entries. A leaked TempLog folder is named `audit-log-*` and
# matches none of these.
LEFTOVER_CEILING: dict[str, int] = {
    r"\.tmp[A-Za-z0-9]{6}": 4,
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


def unexpected(names: list[str], known: list[tuple[str, int, str]] = KNOWN_LEFTOVERS) -> list[str]:
    """The entries `known` does not allow, each pattern up to its count."""
    used: dict[str, int] = {}
    bad = []
    for name in sorted(names):
        for pattern, most, _why in known:
            if re.fullmatch(pattern, name) and used.get(pattern, 0) < most:
                used[pattern] = used.get(pattern, 0) + 1
                break
        else:
            bad.append(name)
    return bad


def contents(path: str, most: int = 3) -> str:
    """The first few files under a leftover entry, with sizes, so a guard failure
    names the writer instead of a random folder name."""
    try:
        if not os.path.isdir(path):
            return f"{os.lstat(path).st_size}B"
        files = [os.path.join(root, f) for root, _dirs, fs in os.walk(path) for f in fs]
        found = sorted(f"{os.path.relpath(f, path)} {os.lstat(f).st_size}B" for f in files)
    except OSError as error:
        return f"unreadable: {error}"
    shown = ", ".join(found[:most]) or "empty"
    return shown + (f", +{len(found) - most} more" if len(found) > most else "")


def run(os_kind: str, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    failed = run_steps(os_kind, shard, program)
    for f in failed:
        print(f"::error::{os_kind} {shard} {f}")
    return 1 if failed else 0


def run_steps(os_kind: str, shard: str, program: tuple[str, ...] = ("cargo",)) -> list[str]:
    failed = []
    tmp = tempfile.mkdtemp(prefix="shard-tmp-") if os_kind in TMP_GUARDED else None
    env = {**os.environ, "TMPDIR": tmp} if tmp else None
    for step, cargo_args, test_args, floor in SHARDS[os_kind][shard]:
        rc, lines = cargo(
            [*BASE, *cargo_args, "--", *test_args, *OUTPUT.get(os_kind, []), *SKIPS[os_kind]],
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
        names = os.listdir(tmp)
        bad = unexpected(names)
        # Tolerated entries are printed too: which ones count against the
        # allowance is only sort order, so the cause can sit in either list.
        for name in sorted(set(names) - set(bad)):
            print(f"::notice::{os_kind} {shard} tolerated in TMPDIR: {name} "
                  f"({contents(os.path.join(tmp, name))})")
        failed += [f"left in TMPDIR: {name} ({contents(os.path.join(tmp, name))})" for name in bad]
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
    assert run_steps("linux", "lib-a", fake) == [], "the control run must stay green"
    assert unexpected(["a", "b"], [("[ab]", 1, "one allowed")]) == ["b"], "the count bounds a pattern"
    assert all(n <= LEFTOVER_CEILING.get(p, 0) for p, n, _ in KNOWN_LEFTOVERS), \
        "KNOWN_LEFTOVERS may only shrink"
    # A leaked TempLog folder is never one of the tolerated plain temp dirs.
    assert unexpected(["audit-log-Ab12Cd", ".tmpAb12Cd"]) == ["audit-log-Ab12Cd"]
    # The families whose tests now use their own temp folders are no longer
    # tolerated, and the plain temp dirs only up to their count.
    gone = ["oauth_test_no_token", "chain-test-0b1c", "http_transport_tls_guard", "stdio-tail-1"]
    assert unexpected(gone) == sorted(gone), unexpected(gone)
    plain = [f".tmpAb12C{i}" for i in range(5)]
    assert unexpected(plain) == [".tmpAb12C4"], unexpected(plain)
    print("shard_tests self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 4 and argv[1] == "run" and argv[3] in SHARDS.get(argv[2], {}):
        return run(argv[2], argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
