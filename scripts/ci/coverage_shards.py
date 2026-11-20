#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run one shard of the coverage grade's test run, for a sharding trial.

The grade's Linux job runs every test target under `cargo llvm-cov` in one
step (`--all-features --tests`, the SDK journey skipped and run alone before
it). A trial splits that step across runners and merges the profiles. Each
shard is the same command over a subset, and the shards of one plan are exact
complements of it:

- plan 4 compiles the library as parts `lib-1` through `lib-N`, with no
  libtest filter; N comes from the shared build script reader;
- plan 3 splits the library by a libtest filter and the matching `--skip`,
  while plan 1 runs every target together;
- the bins go whole into one shard;
- the integration targets are split by `--test` glob classes `[a-l]*` and
  `[!a-l]*`, or taken whole (`*`).

`check` reads `cargo metadata` and fails when a target that `--tests` builds
falls in no shard or has unexpected owners. Plan 4 requires exactly the N
library parts; every other target has one owner. `lists` adapts downloaded
library test inventories for the union check, which verifies their contents
against the source. Unlike `shard_tests.py`, nothing else is skipped (the
grade runs the full-burst test), and there are no doctests, examples or
TMPDIR guard, as in the single job.

  coverage_shards.py plan <n>              print the plan's shards as JSON
  coverage_shards.py check <n> <metadata>  check the partition (file or -)
  coverage_shards.py run <n> <shard>       run one shard, or `sdk` (exit 1 on failure)
  coverage_shards.py lists OUT SHARDS     write OUT/lib-K/pK/list.txt from
                                           SHARDS/cov-shard-lib-K/tests.tsv
  coverage_shards.py objects <report-log> <manifest>...
                                           every manifest executable with coverage
                                           sections is read by each llvm-cov command
  coverage_shards.py on-disk <root> <manifest>...
                                           every manifest executable is unpacked intact
  coverage_shards.py --self-test
"""
from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib_union  # noqa: E402
from shard_tests import GLOB_A, GLOB_ALL, GLOB_B, HEADER, LIB_SPLIT, RESULT, SDK, cargo, private_home  # noqa: E402

# Every plan also runs the SDK journey's binary as its own part, as the single
# job runs it alone before the rest.
SDK_PART, SDK_TARGET = "sdk", "task_upstream_recovery_sdk"
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
        "int-a": (["--bins", "--test", GLOB_A], []),
        "int-b": (["--test", GLOB_B], []),
    },
}


def plan(n: int) -> dict[str, tuple[list[str], list[str]]]:
    """Build a fresh plan on demand without changing the registry.

    Bundle readers can import this module without a build script. Resolve the
    reader's path against this checkout so callers can change working directory.
    """
    # Callers may edit either argument list without changing later plans.
    selected = {shard: (list(args), list(test)) for shard, (args, test) in PLANS[n].items()}
    if n == 4:
        count = lib_union.part_count(Path(__file__).resolve().parents[2] / lib_union.BUILD_SCRIPT)
        selected = {
            **{f"lib-{k}": (["--lib"], []) for k in range(1, count + 1)},
            **selected,
        }
    return selected


def owners(plan: dict[str, tuple[list[str], list[str]]], kind: str, name: str) -> list[str]:
    """The shards that run target `name` of `kind`, including every library part."""
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
    the problems, empty when the library has exactly its plan's owners and
    filters, and every other target is in exactly one shard."""
    selected = plan(n)
    parts = ([f"lib-{k}" for k in range(1, lib_union.part_count(
        Path(__file__).resolve().parents[2] / lib_union.BUILD_SCRIPT) + 1)]
        if any(re.fullmatch(r"lib-[1-9][0-9]*", shard) for shard in selected) else None)
    filter_pair = _LIB_A in selected.values() and _LIB_B in selected.values()
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
            found = owners(selected, kind, target["name"])
            if kind == "lib":
                # Numbered compile parts must each run without a libtest filter.
                # The plan's contents choose the rule, not its registry number.
                filters = sorted(" ".join(selected[s][1]) for s in found)
                if parts is not None:
                    if sorted(found) != sorted(parts) or any(selected[s][1] for s in found):
                        problems.append(f"lib {target['name']}: in {found}, filters {filters}; expected {parts}")
                elif filters != (sorted([LIB_SPLIT, f"--skip {LIB_SPLIT}"]) if filter_pair else [""]):
                    problems.append(f"lib {target['name']}: split as {filters}")
            elif len(found) != 1:
                problems.append(f"{kind} {target['name']}: in {found or 'no shard'}")
    return problems


def run(n: int, shard: str, program: tuple[str, ...] = ("cargo",)) -> int:
    if shard == SDK_PART:
        # The SDK journey's binary alone, single-threaded, the same in every plan.
        select = [*BASE, "--test", SDK_TARGET, "--", "--test-threads", "1"]
    else:
        args, test_args = plan(n)[shard]
        select = [*BASE, *args, "--", *test_args, "--skip", SDK]
    # The tests come from libtest's own listing, before anything runs, so no
    # output can interleave with a name; the run's per-binary result lines then
    # have to account for every listed test.
    rc, every = cargo([*select, "--list"], program)
    rc2, ignored = cargo([*select, "--list", "--ignored"], program)
    if rc or rc2:
        print(f"::error::coverage {n}/{shard}: listing the tests failed ({rc}, {rc2})")
        return rc or rc2
    # A home of the part's own, as the test shards get: tests that resolve the gateway home
    # in-process refuse to run without one.
    with private_home(None, None) as env:
        rc, lines = cargo(select, program, env)
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


def lists(out: Path, shards: Path) -> list[str]:
    """Adapt downloaded numbered lib inventories, preserving ignored test names.

    Missing parts remain absent for lib_union to diagnose; a present artifact
    must supply a nonempty library inventory before it can become a list.
    """
    # Reject reused output before writing anything: a missing shard must never
    # inherit a stale inventory from an earlier download.
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        return [f"{out}: output must be absent or an empty directory"]
    problems = []
    for shard in sorted(shards.glob("cov-shard-lib-*")):
        match = re.fullmatch(r"cov-shard-lib-([1-9][0-9]*)", shard.name)
        if match is None or not shard.is_dir():
            continue
        source = shard / "tests.tsv"
        try:
            rows = source.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            problems.append(f"{source}: {error}")
            continue
        names = [fields[1] for row in rows if len(fields := row.split("\t")) == 3
                 and fields[0] == "unittests src/lib.rs" and fields[1]]
        if not names:
            problems.append(f"{source}: lists no library test")
            continue
        k = match.group(1)
        destination = out / f"lib-{k}" / f"p{k}" / "list.txt"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("".join(f"{name}: test\n" for name in names), encoding="utf-8")
    return problems


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
    inside, found, named, counted, lines, problems = False, False, False, False, 0, []
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
            if CANARY_FN in name:
                counted = True
                if int(count) != 0:
                    problems.append(f"canary called {count} times")
        elif line.startswith("DA:"):
            lines += 1
            if int(line[3:].split(",")[1]) != 0:
                problems.append(f"canary line {line[3:].split(',')[0]} covered")
    if not found:
        return [f"{CANARY_FILE} is not in the report"]
    if not named:
        problems.append(f"{CANARY_FN} has no FN record")
    # A zero needs a record to be zero in: a count, and at least one line.
    if not counted:
        problems.append(f"{CANARY_FN} has no FNDA count")
    if not lines:
        problems.append(f"{CANARY_FILE} has no DA line")
    return problems


def digest(data: bytes) -> str:
    """The sha256 of an ELF64 file's coverage sections, by name and in order; of the
    whole file, marked `file:`, when it is not ELF64 or has none of them."""
    import hashlib
    import struct

    def whole() -> str:
        return "file:" + hashlib.sha256(data).hexdigest()

    if data[:4] != b"\x7fELF" or len(data) < 64 or data[4] != 2:
        return whole()
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
        return whole()
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


REPORT_ROOT = "target/llvm-cov-target"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata", "llvm_cov_report_v.txt")


def manifest_paths(text: str) -> dict[str, str]:
    """Each executable's digest in a bundle manifest, by its path under REPORT_ROOT."""
    found = {}
    for line in text.splitlines():
        if line.startswith(("cov:", "file:")) and "  " in line:
            sha, path = line.split("  ", 1)
            found[os.path.normpath(path)] = sha
    return found


def report_objects(log: str) -> list[set[str]]:
    """The `-object` paths of each llvm-cov command in `cargo llvm-cov report -v`
    output, one set per command, relative to REPORT_ROOT."""
    import shlex

    commands = []
    for line in log.splitlines():
        line = line.strip()
        if not line.startswith("Running `"):
            continue
        cmd = shlex.split(line[len("Running `"):].rstrip("`"))
        if cmd and os.path.basename(cmd[0]) == "llvm-cov":
            commands.append({os.path.relpath(cmd[i + 1], REPORT_ROOT)
                             for i, arg in enumerate(cmd[:-1]) if arg == "-object"})
    return commands


def objects(log: str, manifests: list[str]) -> list[str]:
    """Every executable a manifest records with coverage sections must be among the
    `-object` arguments of each llvm-cov command the report ran: a report that read
    fewer would drop their functions from the grade. Checked per command, never as a
    union. Executables without coverage sections (dependency proc-macro libraries)
    are not read by report and not required."""
    commands = report_objects(log)
    if not commands:
        return ["no llvm-cov command in the report output (run report with -v)"]
    want = {path for text in manifests for path, sha in manifest_paths(text).items()
            if sha.startswith("cov:")}
    return [f"llvm-cov command {i}: {path} is not among its -object arguments"
            for i, got in enumerate(commands, 1) for path in sorted(want - got)]


def on_disk(root: str, manifests: list[str]) -> list[str]:
    """Every executable in every manifest is under `root` after unpacking, with the
    manifest's digest."""
    problems = []
    for text in manifests:
        for path, sha in manifest_paths(text).items():
            full = os.path.join(root, path)
            if not os.path.isfile(full):
                problems.append(f"{path}: missing after unpacking")
                continue
            with open(full, "rb") as f:
                if digest(f.read()) != sha:
                    problems.append(f"{path}: digest differs from its manifest")
    return problems


def self_test() -> int:
    from unittest.mock import patch

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
    broken = plan(4)
    broken["int-b"] = (["--test", "[m-z]*"], [])
    with patch(__name__ + ".plan", return_value=broken):
        assert check(4, good) == ["test Lower_upper_A: in no shard"], check(4, good)
    # Glob classes match case-sensitively, as cargo does: an upper-case first
    # letter falls in [!a-l]* and only there.
    assert owners(plan(4), "test", "Lower_upper_A") == ["int-b"]
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
    assert canary(other + sf + "DA:5,0\nend_of_record\n") == \
        [f"{CANARY_FN} has no FN record", f"{CANARY_FN} has no FNDA count"]
    # A file and a function record with no count or line is no evidence of zero.
    bare = other + sf + f"FN:5,_RNvCs1_11mcp_gateway15{CANARY_FN}\nend_of_record\n"
    assert canary(bare) == [f"{CANARY_FN} has no FNDA count", f"{CANARY_FILE} has no DA line"], \
        canary(bare)
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

    # The report reads every executable with coverage sections, in each command.
    with open(FIXTURE, encoding="utf-8") as f:
        real = f.read()
    (got,) = report_objects(real)
    assert len(got) == 261, len(got)
    sample = sorted(got)[0]
    manifest = "".join(f"cov:{i:064x}  ./{p}\n" for i, p in enumerate(sorted(got)))
    manifest += f"file:{0:064x}  ./debug/deps/libsome_derive-0.so\n"
    assert objects(real, [manifest]) == [], objects(real, [manifest])
    dropped = real.replace(f" -object {REPORT_ROOT}/{sample}", "", 1)
    assert dropped != real, "the fixture names the sample"
    assert objects(dropped, [manifest]) == \
        [f"llvm-cov command 1: {sample} is not among its -object arguments"]
    # Per command, never a union: the lcov command omitting it fails though the
    # JSON command read it.
    assert objects(real + "\n" + dropped, [manifest]) == \
        [f"llvm-cov command 2: {sample} is not among its -object arguments"]
    assert objects("     Running `llvm-profdata merge -o x`\n", [manifest]) == \
        ["no llvm-cov command in the report output (run report with -v)"]
    # On disk: present with the manifest's digest.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "debug", "deps"))
        files = {"debug/deps/a-1": elf(cov), "debug/deps/b-2": elf([("__llvm_covfun", b"B")])}
        for name, data in files.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        listed = "".join(f"{digest(data)}  ./{name}\n" for name, data in files.items())
        assert on_disk(d, [listed]) == [], on_disk(d, [listed])
        os.remove(os.path.join(d, "debug/deps/b-2"))
        assert on_disk(d, [listed]) == ["debug/deps/b-2: missing after unpacking"]
        with open(os.path.join(d, "debug/deps/a-1"), "wb") as f:
            f.write(elf([("__llvm_covfun", b"other"), *cov[1:]]))
        assert on_disk(d, [listed])[0] == "debug/deps/a-1: digest differs from its manifest"
    print("coverage_shards existing self-test rows: ok")
    return coverage_parts_self_test()


def coverage_parts_self_test() -> int:
    """Run every assertion row even when earlier RED rows fail."""
    import contextlib
    import copy
    import io
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    import lib_union

    def p1() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build = root / "scripts/dev/test-parts-build.rs"
            build.parent.mkdir(parents=True)
            build.write_text("const N: u32 = 5;\n", encoding="utf-8")
            with contextlib.chdir(root), patch.object(lib_union, "BUILD_SCRIPT", build):
                got = set(plan(4))
            want = {"lib-1", "lib-2", "lib-3", "lib-4", "lib-5", "int-a", "int-b"}
            assert got == want, f"plan(4) names {sorted(got)}, expected {sorted(want)}"

    def p2() -> None:
        # The implementation must retain plan(n) and call this module's one reader.
        with patch.object(lib_union, "part_count", return_value=2) as reader:
            got = set(plan(4))
        want = {"lib-1", "lib-2", "int-a", "int-b"}
        assert got == want, f"patched N=2: plan(4) names {sorted(got)}, expected {sorted(want)}"
        assert reader.called, "plan(4) did not call lib_union.part_count"

    def p3() -> None:
        selected = plan(4)
        assert "lib-2" in selected, "plan(4) has no lib-2 for run's argv check"
        header = "     Running unittests src/lib.rs (target/debug/deps/mcp_gateway-fixture)"
        responses = [(0, [header, "sample: test"]), (0, [header]),
                     (0, [header, "test result: ok. 1 passed; 0 failed; 0 ignored"])]
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
            with patch(__name__ + ".cargo", side_effect=responses) as fake:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = run(4, "lib-2")
        expected = ["llvm-cov", "--no-report", "--all-features", "--lib", "--", "--skip", SDK]
        got = [call.args[0] for call in fake.call_args_list]
        assert got == [expected + ["--list"], expected + ["--list", "--ignored"], expected], got
        assert rc == 0, f"run returned {rc}"

    metadata = {"workspace_root": "/w", "packages": [
        {"id": "gw", "manifest_path": "/w/Cargo.toml", "targets": [
            {"kind": ["lib"], "name": "mcp_gateway", "test": True}]}]}
    complete = {f"lib-{k}": (["--lib"], []) for k in range(1, 6)}
    complete.update({"int-a": (["--bins", "--test", "[a-l]*"], []),
                     "int-b": (["--test", "[!a-l]*"], [])})

    def p4(change: str) -> None:
        candidate = copy.deepcopy(complete)
        if change == "missing lib-3":
            del candidate["lib-3"]
        elif change == "extra lib-6":
            candidate["lib-6"] = (["--lib"], [])
        elif change == "duplicate lib-2":
            # Ordinary dict literals discard repeated keys. Preserve a repeated
            # item so owners() really returns lib-2 twice, not a different name.
            class RepeatedPart(dict):
                def items(self):
                    return [*super().items(), ("lib-2", self["lib-2"])]

            candidate = RepeatedPart(candidate)
        elif change == "filtered lib-2":
            candidate["lib-2"] = (["--lib"], ["gateway::"])
        with patch.object(lib_union, "part_count", return_value=5):
            with patch(__name__ + ".plan", return_value=complete):
                control = check(4, metadata)
            with patch(__name__ + ".plan", return_value=candidate):
                broken = check(4, metadata)
        # Each negative row requires a passing control: rejecting everything is not validation.
        assert control == [], f"valid five-part ownership rejected: {control}"
        if change != "complete":
            assert broken, f"{change} was accepted"

    def p5(case: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shards, out = root / "shards", root / "lists"
            lib = shards / "cov-shard-lib-2"
            lib.mkdir(parents=True)
            if case == "mixed binaries":
                (lib / "tests.tsv").write_text(
                    "unittests src/lib.rs\ta::one\tok\n"
                    "tests/x.rs\tintegration::excluded\tok\n"
                    "unittests src/lib.rs\tb::two\tignored\n", encoding="utf-8")
                other = shards / "cov-shard-lib-5"
                other.mkdir()
                (other / "tests.tsv").write_text("unittests src/lib.rs\tc::three\tok\n", encoding="utf-8")
                for name in ("int-a", "int-b", "sdk"):
                    other = shards / f"cov-shard-{name}"
                    other.mkdir()
                    (other / "tests.tsv").write_text("unittests src/lib.rs\tnot_a_lib_part\tok\n", encoding="utf-8")
            elif case == "empty tsv":
                (lib / "tests.tsv").write_text("", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["coverage_shards.py", "lists", str(out), str(shards)])
            if case != "mixed binaries":
                assert rc != 0, f"lists accepted {case}: exit {rc}"
                return
            assert rc == 0, f"lists returned {rc}"
            got = {p.relative_to(out).as_posix(): p.read_text(encoding="utf-8")
                   for p in out.rglob("*") if p.is_file()}
            want = {"lib-2/p2/list.txt": "a::one: test\nb::two: test\n",
                    "lib-5/p5/list.txt": "c::three: test\n"}
            assert got == want, f"lists wrote {got!r}, expected {want!r} (no integration or SDK lists)"

    def p6() -> None:
        # Resolving different build counts must never turn the registry into a cache.
        before = copy.deepcopy(PLANS)
        for count in (2, 5):
            with patch.object(lib_union, "part_count", return_value=count):
                selected, again = plan(4), plan(4)
            assert PLANS == before, "plan(4) mutated PLANS"
            want = {f"lib-{k}" for k in range(1, count + 1)} | {"int-a", "int-b"}
            assert set(selected) == set(again) == want, "plan(4) lost numbered lib parts"
            assert selected is not again and selected is not PLANS[4], "plan(4) reused a plan dict"

    def p7() -> None:
        # Exercise both argument lists, including the generated library parts.
        before = copy.deepcopy(PLANS)
        try:
            for n in PLANS:
                selected, second = plan(n), plan(n)
                expected = copy.deepcopy(second)
                for args, test in selected.values():
                    args.append("changed cargo argument")
                    test.append("changed libtest argument")
                assert PLANS == before, f"mutating plan({n}) argument lists changed PLANS"
                assert second == expected, f"mutating plan({n}) argument lists changed another call"
                assert plan(n) == expected, f"mutating plan({n}) argument lists changed a later call"
        finally:
            # A failing isolation row must not contaminate subsequent rows.
            if PLANS != before:
                PLANS.clear()
                PLANS.update(before)

    def p9() -> None:
        # A plan number alone says nothing about how its library is partitioned.
        whole = {"lib": (["--lib"], [])}
        with patch(__name__ + ".plan", return_value=whole):
            problems = check(2, metadata)
        assert problems == [], f"whole-lib fixture plan 2 rejected: {problems}"

    def p8() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shards, out = root / "shards", root / "lists"
            lib = shards / "cov-shard-lib-2"
            lib.mkdir(parents=True)
            (lib / "tests.tsv").write_text("unittests src/lib.rs\tfresh\tok\n", encoding="utf-8")
            stale = out / "lib-1/p1/list.txt"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale: test\n", encoding="utf-8")
            before = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            with contextlib.redirect_stdout(io.StringIO()):
                rc = main(["coverage_shards.py", "lists", str(out), str(shards)])
            assert rc != 0, "lists accepted a nonempty output directory"
            after = {p.relative_to(out): p.read_bytes() for p in out.rglob("*") if p.is_file()}
            assert after == before, "lists wrote files before rejecting a nonempty output directory"

    def p10() -> None:
        # Integration tests that resolve the gateway home refuse to run without a private one,
        # so the part's test run must get a fresh home, removed again once the part ends.
        header = "     Running unittests src/lib.rs (target/debug/deps/mcp_gateway-fixture)"
        for shard in ("int-a", SDK_PART):
            calls: list[tuple[list[str], dict[str, str] | None, bool]] = []

            def fake(args, program=("cargo",), env=None):
                home = (env or {}).get("MCP_GATEWAY_TEST_HOME_DIR", "")
                calls.append((args, env, bool(home) and os.path.isdir(home)))
                if "--list" not in args:
                    return 0, [header, "test result: ok. 1 passed; 0 failed; 0 ignored"]
                return 0, [header] if "--ignored" in args else [header, "sample: test"]

            with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp):
                with patch(__name__ + ".cargo", side_effect=fake):
                    with contextlib.redirect_stdout(io.StringIO()):
                        rc = run(4, shard)
            assert rc == 0, f"{shard}: run returned {rc}"
            test_run = [c for c in calls if "--list" not in c[0]]
            assert len(test_run) == 1, f"{shard}: {len(test_run)} test runs"
            _args, env, existed = test_run[0]
            assert env is not None and existed, f"{shard}: the test run had no existing private home"
            home = env["MCP_GATEWAY_TEST_HOME_DIR"]
            assert env.get("XDG_CONFIG_HOME") == os.path.join(home, ".config"), f"{shard}: config dir outside the home"
            assert env.get("MCP_GATEWAY_CONFIG_DIR") == os.path.join(home, ".mcp-gateway"), \
                f"{shard}: data dir outside the home"
            assert not os.path.exists(home), f"{shard}: the private home {home} was left behind"

    rows = [("P1 fixture N=5", p1), ("P2 shared reader N=2", p2), ("P3 literal cargo argv", p3)]
    rows += [(f"P4 {case}", lambda case=case: p4(case)) for case in
             ("complete", "missing lib-3", "extra lib-6", "duplicate lib-2", "filtered lib-2")]
    rows += [(f"P5 {case}", lambda case=case: p5(case)) for case in
             ("mixed binaries", "empty tsv", "missing tsv")]
    rows += [("P6 plan registry unchanged", p6), ("P7 plan argument lists isolated", p7),
             ("P8 nonempty lists output refused", p8), ("P9 whole-lib plan 2", p9),
             ("P10 test run in a private home", p10)]
    wrong = 0
    for label, test in rows:
        try:
            test()
        except AssertionError as error:
            wrong += 1
            print(f"FAIL {label}: {error}")
        else:
            print(f"ok   {label}")
    print(f"coverage parts self-test: {len(rows) - wrong} ok, {wrong} assertion failures")
    return 1 if wrong else 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) == 4 and argv[1] == "lists":
        problems = lists(Path(argv[2]), Path(argv[3]))
        for problem in problems:
            print(f"::error::coverage lists: {problem}")
        return 1 if problems else 0
    if len(argv) == 3 and argv[1] == "canary":
        problems = canary(open(argv[2], encoding="utf-8", errors="replace").read())
        for p in problems:
            print(f"::error::coverage canary: {p}")
        return 1 if problems else 0
    if len(argv) >= 4 and argv[1] in ("objects", "on-disk"):
        manifests = [open(m, encoding="utf-8").read() for m in argv[3:]]
        if argv[1] == "objects":
            problems = objects(open(argv[2], encoding="utf-8").read(), manifests)
        else:
            problems = on_disk(argv[2], manifests)
        for problem in problems:
            print(f"::error::coverage {argv[1]}: {problem}")
        return 1 if problems else 0
    if len(argv) >= 2 and argv[1] == "digest":
        # `digest <file>...`, in sha256sum's layout: "<digest>  <path>".
        for path in argv[2:]:
            with open(path, "rb") as f:
                print(f"{digest(f.read())}  {path}")
        return 0
    if len(argv) == 3 and argv[1] == "plan" and argv[2].isdigit() and int(argv[2]) in PLANS:
        print(json.dumps(sorted(plan(int(argv[2])))))
        return 0
    if len(argv) == 4 and argv[1] == "check" and argv[2].isdigit() and int(argv[2]) in PLANS:
        raw = sys.stdin.read() if argv[3] == "-" else open(argv[3], encoding="utf-8").read()
        problems = check(int(argv[2]), json.loads(raw))
        for p in problems:
            print(f"::error::coverage partition: {p}")
        return 1 if problems else 0
    if (len(argv) == 4 and argv[1] == "run" and argv[2].isdigit() and int(argv[2]) in PLANS
            and (argv[3] == SDK_PART or argv[3] in plan(int(argv[2])))):
        return run(int(argv[2]), argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
