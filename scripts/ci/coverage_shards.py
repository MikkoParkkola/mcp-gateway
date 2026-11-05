#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of the coverage grade's test run, for a sharding trial.

The grade's Linux job runs every test target under `cargo llvm-cov` in one
step (`--all-features --tests`, the SDK journey skipped and run alone before
it). A trial splits that step across runners and merges the profiles. Each
shard is the same command over a subset, and the shards of one plan are exact
complements of it:

- the library is split by a libtest filter and the matching `--skip`;
- the bins go whole into one shard;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`).

`check` reads `cargo metadata` and fails when a target that `--tests` builds
falls in no shard or in two, so a new kind of target cannot drop out of the
merged grade unnoticed. Unlike `shard_tests.py`, nothing else is skipped (the
grade runs the full-burst test), and there are no doctests, examples or
TMPDIR guard, as in the single job.

  coverage_shards.py plan <n>              print the plan's shards as JSON
  coverage_shards.py check <n> <metadata>  check the partition (file or -)
  coverage_shards.py run <n> <shard>       run one shard, or `sdk` (exit 1 on failure)
  coverage_shards.py --self-test
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shard_tests import HEADER, RESULT, SDK, cargo  # noqa: E402

LIB_SPLIT = "gateway::"
# Every plan also runs the SDK journey's binary as its own part, as the single
# job runs it alone before the rest.
SDK_PART, SDK_TARGET = "sdk", "task_upstream_recovery_sdk"
GLOB_A, GLOB_B, GLOB_ALL = "[a-l]*", "[!a-l]*", "*"
BASE = ["llvm-cov", "--no-report", "--all-features"]
_LIB_A = (["--lib"], [LIB_SPLIT])
_LIB_B = (["--lib"], ["--skip", LIB_SPLIT])

# shard -> (cargo args after BASE, libtest args before `--skip SDK`)
PLANS: dict[int, dict[str, tuple[list[str], list[str]]]] = {
    # Today's single job, run the same way (listing and reconciling) so the
    # equivalence comparison reads the same files from both pipelines.
    1: {
        "all": (["--tests"], []),
    },
    3: {
        "lib-a": _LIB_A,
        "lib-b": _LIB_B,
        "int": (["--bins", "--test", GLOB_ALL], []),
    },
    4: {
        "lib-a": _LIB_A,
        "lib-b": _LIB_B,
        "int-a": (["--bins", "--test", GLOB_A], []),
        "int-b": (["--test", GLOB_B], []),
    },
}


def owners(plan: dict[str, tuple[list[str], list[str]]], kind: str, name: str) -> list[str]:
    """The shards that run target `name` of `kind`. The library is split by a
    filter and its complement, so its two shards together are one owner."""
    found = []
    for shard, (args, _test) in plan.items():
        if "--tests" in args:
            found.append(shard)
        elif kind == "lib" and "--lib" in args:
            found.append(shard)
        elif kind == "bin" and "--bins" in args:
            found.append(shard)
        elif kind == "test":
            globs = [args[i + 1] for i, a in enumerate(args) if a == "--test"]
            if any(fnmatch.fnmatchcase(name, g) for g in globs):
                found.append(shard)
    return found


def check(n: int, metadata: dict) -> list[str]:
    """Every target `cargo test --tests` builds, with the shards that own it:
    the problems, empty when the library is split in exactly two shards by a
    filter and its `--skip`, and every other target is in exactly one."""
    plan = PLANS[n]
    problems = []
    # The grade runs without `--workspace`, so cargo builds the workspace's
    # default members; an older cargo that omits them means the root package.
    default = metadata.get("workspace_default_members")
    root_manifest = os.path.join(metadata["workspace_root"], "Cargo.toml")
    packages = [p for p in metadata["packages"]
                if (p["id"] in default if default is not None else p["manifest_path"] == root_manifest)]
    if not packages:
        return ["no package: neither a default member nor the root manifest's"]
    for package in packages:
        for target in package["targets"]:
            kinds = [k for k in target["kind"] if k != "proc-macro"]
            kind = "lib" if any(k in ("lib", "rlib", "cdylib", "staticlib") for k in kinds) else kinds[0]
            # `--tests` builds every target whose `test` flag is set.
            if not target.get("test", kind in ("lib", "bin", "test")):
                continue
            found = owners(plan, kind, target["name"])
            if kind == "lib":
                # Whole in one shard, or split by the filter and its `--skip`.
                filters = sorted(" ".join(plan[s][1]) for s in found)
                if filters not in ([""], sorted([LIB_SPLIT, f"--skip {LIB_SPLIT}"])):
                    problems.append(f"lib {target['name']}: split as {filters}")
            elif len(found) != 1:
                problems.append(f"{kind} {target['name']}: in {found or 'no shard'}")
    return problems


def run(n: int, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    if shard == SDK_PART:
        # The SDK journey's binary alone, single-threaded, the same in every plan.
        select = [*BASE, "--test", SDK_TARGET, "--", "--test-threads", "1"]
    else:
        args, test_args = PLANS[n][shard]
        select = [*BASE, *args, "--", *test_args, "--skip", SDK]
    # The tests come from libtest's own listing, before anything runs, so no
    # output can interleave with a name; the run's per-binary result lines then
    # have to account for every listed test.
    rc, every = cargo([*select, "--list"], program)
    rc2, ignored = cargo([*select, "--list", "--ignored"], program)
    if rc or rc2:
        print(f"::error::coverage {n}/{shard}: listing the tests failed ({rc}, {rc2})")
        return rc or rc2
    rc, lines = cargo(select, program)
    listed, skipped = listing(every), listing(ignored)
    problems = reconcile(listed, skipped, results(lines))
    for p in problems:
        print(f"::error::coverage {n}/{shard}: {p}")
    with open("tests.tsv", "w", encoding="utf-8") as f:
        for binary in sorted(listed):
            for name in listed[binary]:
                outcome = "ignored" if name in skipped.get(binary, ()) else "ok"
                f.write(f"{binary}\t{name}\t{outcome}\n")
    print(f"::notice::coverage {n}/{shard}: {sum(map(len, listed.values()))} tests "
          f"in {len(listed)} binaries, rc {rc}")
    return rc or (1 if problems else 0)


def binary_of(header: str) -> str:
    """The binary a `Running`/`Doc-tests` header names, without its build hash:
    `unittests src/lib.rs` or `tests/x.rs`, the same in every run of one commit."""
    text = HEADER.sub("", header).strip()
    return text.split(" (", 1)[0]


def listing(lines: list[str]) -> dict[str, list[str]]:
    """`--list` output: each binary's test names (libtest prints `<name>: test`)."""
    found: dict[str, list[str]] = {}
    current = None
    for line in lines:
        if HEADER.match(line):
            current = binary_of(line)
            found.setdefault(current, [])
        elif current is not None and line.endswith(": test"):
            found[current].append(line[: -len(": test")])
    return found


def results(lines: list[str]) -> dict[str, tuple[int, int, int]]:
    """Each binary's (passed, failed, ignored) from its LAST result line: a test
    that re-runs its own binary as a child prints the child's line inside it."""
    found: dict[str, tuple[int, int, int]] = {}
    current = None
    for line in lines:
        if HEADER.match(line):
            current = binary_of(line)
        elif current is not None and (m := RESULT.search(line)):
            found[current] = tuple(map(int, m.groups()))  # type: ignore[assignment]
    return found


def reconcile(listed: dict[str, list[str]], ignored: dict[str, list[str]],
              ran: dict[str, tuple[int, int, int]]) -> list[str]:
    """The run accounts for every listed test: per binary, nothing failed, the
    ignored count is the ignored listing's, and the rest passed."""
    problems = []
    for binary, names in sorted(listed.items()):
        if binary not in ran:
            problems.append(f"{binary}: listed {len(names)} tests, no result line")
            continue
        passed, failed, skipped = ran[binary]
        want = len(ignored.get(binary, []))
        if failed or skipped != want or passed != len(names) - want:
            problems.append(f"{binary}: ran {passed} passed, {failed} failed, {skipped} ignored; "
                            f"listed {len(names)}, {want} of them ignored")
    for binary in sorted(set(ran) - set(listed)):
        problems.append(f"{binary}: a result line for a binary the listing did not name")
    return problems


# The sections a profile is mapped through: two builds of one binary whose bytes differ
# only elsewhere (a constant a dependency generates at build time, and so the build id)
# map the same counters to the same functions.
COVERAGE_SECTIONS = ("__llvm_covfun", "__llvm_covmap", "__llvm_prf_names", "__llvm_prf_data")


# A function compiled only under coverage and never called (src/coverage_canary.rs). A
# report that dropped functions no test reached (a merge from profiles alone, or with a
# part's binaries lost) drops it too.
CANARY_FILE = "src/coverage_canary.rs"
CANARY_FN = "coverage_canary"


def canary(lcov: str) -> list[str]:
    """The problems with the canary in an lcov report: empty when the canary's file is
    there with its function recorded (FN) at a count of 0 (FNDA) and every line at 0."""
    inside, found, named, problems = False, False, False, []
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            path = line[3:].strip().replace("\\", "/")
            inside = path == CANARY_FILE or path.endswith("/" + CANARY_FILE)
            found = found or inside
        elif not inside:
            continue
        elif line.startswith("FN:") and CANARY_FN in line:
            named = True
        elif line.startswith("FNDA:"):
            count, name = line[5:].split(",", 1)
            if CANARY_FN in name and int(count) != 0:
                problems.append(f"canary called {count} times")
        elif line.startswith("DA:") and int(line[3:].split(",")[1]) != 0:
            problems.append(f"canary line {line[3:].split(',')[0]} covered")
    if not found:
        return [f"{CANARY_FILE} is not in the report"]
    if not named:
        problems.append(f"{CANARY_FN} has no FN record")
    return problems


def digest(data: bytes) -> str:
    """The sha256 of an ELF64 file's coverage sections, by name and in order; of the
    whole file, marked `file:`, when it is not ELF64 or has none of them."""
    import hashlib
    import struct

    whole = "file:" + hashlib.sha256(data).hexdigest()
    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2:
        return whole
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    heads = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    names = heads[shstrndx][4]
    found = {}
    for name, kind, _flags, _addr, off, size in heads:
        label = data[names + name:data.index(b"\0", names + name)].decode("latin-1")
        if label in COVERAGE_SECTIONS:
            found[label] = b"" if kind == 8 else data[off:off + size]  # NOBITS: no bytes
    if not found:
        return whole
    h = hashlib.sha256()
    for label in COVERAGE_SECTIONS:
        body = found.get(label)
        h.update(f"{label}:{-1 if body is None else len(body)}\n".encode())
        h.update(body or b"")
    return "cov:" + h.hexdigest()


def elf(sections: list[tuple[str, bytes]]) -> bytes:
    """A minimal ELF64 file holding `sections`, for the self-test."""
    import struct

    names = b"\0" + b"".join(n.encode() + b"\0" for n, _ in sections) + b".shstrtab\0"
    body, entries, off = b"", [], 64
    for i, (n, data) in enumerate(sections):
        entries.append((names.index(n.encode() + b"\0"), 1, off + len(body), len(data)))
        body += data
    entries.append((names.index(b".shstrtab\0"), 3, off + len(body), len(names)))
    body += names
    shoff = off + len(body)
    head = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(entries) + 1, len(entries))
    table = b"\0" * 64 + b"".join(
        struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, o, size, 0, 0, 1, 0)
        for name, kind, o, size in entries)
    return head + body + table


def self_test() -> int:
    def target(kind: str, name: str, test: bool = True) -> dict:
        return {"kind": [kind], "name": name, "test": test}

    good = {"workspace_root": "/w", "workspace_default_members": ["gw"], "packages": [
        {"id": "gw", "manifest_path": "/w/Cargo.toml", "targets": [
            target("lib", "mcp_gateway"), target("bin", "mcp-gateway"),
            target("bin", "provenance-eval"), target("test", "audit_trail"),
            target("test", "zz_last"), target("test", "Lower_upper_A"),
            target("bench", "gateway_benchmarks", test=False)]},
        # A workspace member outside the default members is not in the run.
        {"id": "other", "manifest_path": "/w/crates/other/Cargo.toml",
         "targets": [target("lib", "other")]},
    ]}
    # A default member's targets are walked: a testable example in the second
    # package is reported once it is a default member, and only then.
    both = json.loads(json.dumps(good))
    both["packages"][1]["targets"].append(target("example", "other_demo"))
    assert check(4, both) == [], check(4, both)
    both["workspace_default_members"] = ["gw", "other"]
    assert check(4, both) == ["example other_demo: in no shard"], check(4, both)
    # Without the field (an older cargo), the root manifest's package is the run.
    old = json.loads(json.dumps(good))
    del old["workspace_default_members"]
    assert check(4, old) == [], check(4, old)
    for n in PLANS:
        assert check(n, good) == [], (n, check(n, good))
    # A target kind no shard runs (a testable example) is reported, not dropped;
    # the single job's `--tests` does run it, as cargo would.
    extra = json.loads(json.dumps(good))
    extra["packages"][0]["targets"].append(target("example", "demo"))
    for n in PLANS:
        want = [] if n == 1 else ["example demo: in no shard"]
        assert check(n, extra) == want, (n, check(n, extra))
    # A glob class that stops being a complement shows up as an unowned target.
    broken = {k: (list(a), list(t)) for k, (a, t) in PLANS[4].items()}
    broken["int-b"] = (["--test", "[m-z]*"], [])
    PLANS[99] = broken
    try:
        assert check(99, good) == ["test Lower_upper_A: in no shard"], check(99, good)
    finally:
        del PLANS[99]
    # Glob classes match case-sensitively, as cargo does: an upper-case first
    # letter falls in [!a-l]* and only there.
    assert owners(PLANS[4], "test", "Lower_upper_A") == ["int-b"]
    # Two builds differing only outside the coverage sections digest alike; a different
    # coverage mapping, a missing section or a non-ELF file does not.
    cov = [("__llvm_covfun", b"FUN"), ("__llvm_covmap", b"MAP"), (".rodata", b"seed-1")]
    one = elf(cov)
    other = elf([*cov[:2], (".rodata", b"seed-2")])
    assert one != other and digest(one) == digest(other) and digest(one).startswith("cov:")
    assert digest(elf([("__llvm_covfun", b"FUX"), *cov[1:]])) != digest(one)
    assert digest(elf([cov[0], cov[2]])) != digest(one), "a missing section counts"
    assert digest(b"#!/bin/sh\n").startswith("file:")
    assert digest(elf([(".rodata", b"x")])).startswith("file:"), "no coverage sections"
    # The canary: present at zero passes; absent, unnamed or reached fails.
    sf = f"SF:/home/runner/work/g/g/{CANARY_FILE}\n"
    other = "SF:/home/runner/work/g/g/src/lib.rs\nFN:3,_RNv4lib\nFNDA:0,_RNv4lib\nDA:3,0\nend_of_record\n"
    good = other + sf + f"FN:5,_RNvCs1_11mcp_gateway15{CANARY_FN}\nFNDA:0,_RNvCs1_11mcp_gateway15{CANARY_FN}\nDA:5,0\nDA:6,0\nend_of_record\n"
    assert canary(good) == [], canary(good)
    assert canary(other) == [f"{CANARY_FILE} is not in the report"]
    assert canary(good.replace("FNDA:0,_RNvCs1", "FNDA:2,_RNvCs1").replace("DA:6,0", "DA:6,2")) == \
        ["canary called 2 times", "canary line 6 covered"]
    assert canary(other + sf + "DA:5,0\nend_of_record\n") == [f"{CANARY_FN} has no FN record"]
    # The test accounting: names from the listing, outcomes reconciled per binary.
    lib = "     Running unittests src/lib.rs (target/llvm-cov-target/debug/deps/mcp_gateway-ab12)"
    lease = "     Running tests/lease.rs (target/llvm-cov-target/debug/deps/lease-cd34)"
    every = listing([lib, "a::b: test", "a::c: test", "", "2 tests, 0 benchmarks",
                     lease, "child_reruns: test", "", "1 test, 0 benchmarks"])
    assert every == {"unittests src/lib.rs": ["a::b", "a::c"], "tests/lease.rs": ["child_reruns"]}, every
    skipped = listing([lib, "a::c: test", lease])
    # The lease binary re-runs itself as a child: the child's result line comes
    # first, the binary's own last.
    ran = results([lib, "running 2 tests", "test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured",
                   lease, "running 1 test", "running 1 test",
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured",
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured"])
    assert reconcile(every, skipped, ran) == [], reconcile(every, skipped, ran)
    ran_child_only = results([lib, "test result: ok. 1 passed; 0 failed; 1 ignored",
                              lease, "test result: ok. 0 passed; 0 failed; 1 ignored",
                              "test result: ok. 1 passed; 0 failed; 0 ignored"])
    assert reconcile(every, skipped, ran_child_only) == [], "the last line is the binary's"
    assert reconcile(every, skipped, {"unittests src/lib.rs": (1, 0, 1)}) == \
        ["tests/lease.rs: listed 1 tests, no result line"]
    assert reconcile(every, {}, ran) == \
        ["unittests src/lib.rs: ran 1 passed, 0 failed, 1 ignored; listed 2, 0 of them ignored"]
    assert reconcile(every, skipped, {**ran, "tests/other.rs": (1, 0, 0)}) == \
        ["tests/other.rs: a result line for a binary the listing did not name"]
    assert reconcile(every, skipped, {**ran, "unittests src/lib.rs": (0, 1, 1)})[0].startswith(
        "unittests src/lib.rs: ran 0 passed, 1 failed")
    print("coverage_shards self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 3 and argv[1] == "canary":
        problems = canary(open(argv[2], encoding="utf-8", errors="replace").read())
        for p in problems:
            print(f"::error::coverage canary: {p}")
        return 1 if problems else 0
    if len(argv) >= 2 and argv[1] == "digest":
        # `digest <file>...`, in sha256sum's layout: "<digest>  <path>".
        for path in argv[2:]:
            with open(path, "rb") as f:
                print(f"{digest(f.read())}  {path}")
        return 0
    if len(argv) == 3 and argv[1] == "plan" and argv[2].isdigit() and int(argv[2]) in PLANS:
        print(json.dumps(sorted(PLANS[int(argv[2])])))
        return 0
    if len(argv) == 4 and argv[1] == "check" and argv[2].isdigit() and int(argv[2]) in PLANS:
        raw = sys.stdin.read() if argv[3] == "-" else open(argv[3], encoding="utf-8").read()
        problems = check(int(argv[2]), json.loads(raw))
        for p in problems:
            print(f"::error::coverage partition: {p}")
        return 1 if problems else 0
    if (len(argv) == 4 and argv[1] == "run" and argv[2].isdigit() and int(argv[2]) in PLANS
            and (argv[3] == SDK_PART or argv[3] in PLANS[int(argv[2])])):
        return run(int(argv[2]), argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
