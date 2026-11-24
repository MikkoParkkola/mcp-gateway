#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The per-test file map: for each test unit, the repository files it executed, opened, listed or probed.

Built on Linux on release-line pushes (.github/workflows/affected-map.yml) and published as a cache; nothing reads
it yet. A unit is one integration target, or a group of lib tests: grouped by module path at depth 2, and any
group over SPLIT_SHARE of the run's lib test time split one level deeper, down to single tests (the times are
this run's own). Each unit runs as its own process with coverage on (a killed child still writes its counters)
under a file-access trace. A unit is unmapped, and selects with every change, when its traced run failed or left
no trace, when its coverage is missing or a coverage tool failed, when its listing failed, or when its pass count
differs from its listing.

    affected_map.py guard MAP NOW_ISO           prints build=true|false: false while MAP is younger than MAP_AGE
    affected_map.py part PART OUT               one part (lib-K, int-a or int-b): its depth-2 units, OUT/part.json
    affected_map.py merge SHA PART_DIRS... OUT  the run's lib total, the deeper splits, OUT/affected-map.json
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]

# A group heavier than this share of the run's lib test time is split one level deeper (r6 R2).
SPLIT_SHARE = 0.10
# The map is rebuilt at most once in this long: the workflow ends early while the newest map is younger (D5). Not a
# full day: a run that starts a little late must still build the next day.
MAP_AGE = timedelta(hours=20)
# Coverage that a killed child still writes: counter relocation plus continuous mode (%c in the profile name), so a
# gateway child SIGKILLed by kill_on_drop credits the code it ran (r6 R1).
COVERAGE_RUSTFLAGS = "-C instrument-coverage -C llvm-args=-runtime-counter-relocation"
PROFILE_NAME = "%c%m-%p.profraw"
# Every way a unit can depend on a path: opens (failed ones too), folder reads, the stat, access and readlink
# families, and the calls that move the directory a relative path is read against. -s 4096: strace cuts strings at
# 32 bytes by default, which would cut the paths. -y prints the path behind every descriptor.
TRACE_CALLS = (
    "openat", "openat2", "open", "creat", "getdents64", "chdir", "fchdir",
    "stat", "lstat", "newfstatat", "fstatat64", "statx", "access", "faccessat", "faccessat2",
    "readlink", "readlinkat",
    # A new process starts in its parent's working directory; a thread (CLONE_FS) shares it.
    "clone", "clone3", "fork", "vfork",
)
UNIT_KEYS = ("files", "dirs", "probes", "tests", "seconds", "binary", "unmapped")
MAP_KEYS = ("map_sha", "built_at", "units")
LIB_BINARY = "unittests src/lib.rs"


def strace_command(trace_path: str) -> list[str]:
    """The trace a unit runs under, children included."""
    return ["strace", "-f", "-y", "-s", "4096", "--seccomp-bpf", "-e", "trace=" + ",".join(TRACE_CALLS),
            "-o", trace_path, "--"]


def unit_env(unit_dir: str) -> dict[str, str]:
    """A unit's own profile folder, with the continuous-mode name."""
    return {"LLVM_PROFILE_FILE": os.path.join(unit_dir, PROFILE_NAME)}


# ---- the age guard (D5) -------------------------------------------------------------------------------------------

def should_build(newest_built_at: str | None, now: datetime) -> bool:
    """True when no map is published, or the newest one is at least MAP_AGE old (its own build time decides)."""
    if not newest_built_at:
        return True
    try:
        built = datetime.fromisoformat(newest_built_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    if built.tzinfo is None:
        built = built.replace(tzinfo=timezone.utc)
    return now - built >= MAP_AGE


# ---- units by weight (r6 R2) --------------------------------------------------------------------------------------

def group(names: list[str], depth: int) -> dict[str, list[str]]:
    """Names grouped by their first `depth` path segments; a name with no more segments is its own group."""
    out: dict[str, list[str]] = {}
    for name in names:
        out.setdefault("::".join(name.split("::")[:depth]), []).append(name)
    return out


def split_heavy(prefix: str, members: list[str], depth: int, total: float,
                measure: Callable[[str, list[str]], float], share: float | None = None) -> dict[str, list[str]]:
    """The units one group becomes: itself when it weighs at most `share` (SPLIT_SHARE unless given) of `total` or
    is a single test, else each of its next-level groups, split again the same way. `measure` runs a candidate
    and returns its seconds."""
    share = SPLIT_SHARE if share is None else share
    units: dict[str, list[str]] = {}
    pending = [(prefix, members, depth)]
    while pending:
        key, names, d = pending.pop()
        seconds = measure(key, names)
        # One test cannot be split, whatever its group is called: re-running it would only spend time.
        single = len(names) == 1
        if seconds > share * total and not single:
            pending.extend((k, v, d + 1) for k, v in group(names, d + 1).items())
        else:
            units[key] = sorted(names)
    return units


# ---- the trace ----------------------------------------------------------------------------------------------------

@dataclass
class Access:
    """What one unit's trace shows, by repository-relative path. `ambiguous`: the trace cannot say for certain
    which directory some relative path was read against, so the unit must be unmapped."""
    files: set[str] = field(default_factory=set)
    dirs: set[str] = field(default_factory=set)
    probes: set[str] = field(default_factory=set)
    ambiguous: bool = False


_LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(.*)$")
_CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+)(?:<([^>]*)>)?(?:\s+(\w+).*)?$")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_FD = re.compile(r"^(?:AT_FDCWD|-?\d+)(?:<([^>]*)>)?")
_OPENS = ("openat", "openat2", "open", "creat")
# Calls whose first argument is a directory descriptor the path is relative to.
_DIRFD = ("openat", "openat2", "newfstatat", "fstatat64", "statx", "faccessat", "faccessat2", "readlinkat")


def _unescape(text: str) -> str:
    """strace's C-style escapes back to the path's own bytes, read as UTF-8."""
    raw = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
    return raw.encode("latin-1", "replace").decode("utf-8", "replace")


def _completed_calls(lines: list[str]) -> tuple[list[tuple[str, str, int]], list[str]]:
    """(pid, call text, the line its call started on) for every completed call, joining strace -f's
    `<unfinished ...>` and `<... resumed>` halves; and the text of every call still unfinished when the trace ends."""
    halves: dict[str, tuple[str, int]] = {}
    out = []
    for index, raw in enumerate(lines):
        m = _LINE.match(raw.rstrip("\n"))
        if not m:
            continue
        pid, rest = m.groups()
        if rest.endswith("<unfinished ...>"):
            halves[pid] = (rest[: -len("<unfinished ...>")].rstrip(), index)
            continue
        start = index
        resumed = re.match(r"^<\.\.\. \w+ resumed>\s?(.*)$", rest)
        if resumed:
            head, start = halves.pop(pid, ("", index))
            rest = head + resumed.group(1)
        out.append((pid, rest, start))
    return out, [head for head, _ in halves.values()]


def repo_key(path: str, repo: str) -> str | None:
    """`path` as a key inside `repo` (POSIX separators), or None for a path outside it."""
    path = os.path.normpath(path)
    repo = os.path.normpath(repo)
    if path == repo:
        return ""
    if path.startswith(repo + os.sep):
        return os.path.relpath(path, repo).replace(os.sep, "/")
    return None


_CREATE = ("clone", "clone3", "fork", "vfork")


def creation_tree(calls: list[tuple[str, str, int]]) -> tuple[dict[str, tuple[str, bool]], bool]:
    """child pid -> (its creator, whether it shares the creator's working directory: a clone with CLONE_FS), read
    whole before the trace is walked (strace can print a child's first calls before its creator's clone returns);
    and whether a pid was reused: created twice, or acting before its creating call began (an earlier lifetime)."""
    tree: dict[str, tuple[str, bool]] = {}
    first: dict[str, int] = {}
    for pid, _call, start in calls:
        first.setdefault(pid, start)
    reused = False
    for pid, call, start in calls:
        m = _CALL.match(call)
        if m and m.group(1) in _CREATE and int(m.group(3)) > 0:
            child = m.group(3)
            if child in tree or first.get(child, start + 1) < start:
                reused = True
            tree[child] = (pid, m.group(1).startswith("clone") and "CLONE_FS" in m.group(2))
    return tree, reused


def unknown_creation(call: str) -> bool:
    """A creating call whose result is not a number (strace prints `= ?` when the creator was killed inside it):
    a child may exist whose creator the trace cannot name."""
    name = call.split("(", 1)[0]
    return name in _CREATE and _CALL.match(call) is None


def parse_trace(text: str, repo: str, start_cwd: str) -> Access:
    """Opens become files (a failed open a probe), folder reads dirs, the stat/access/readlink families probes.
    A relative path resolves against the call's directory descriptor (strace -y shows its path) or the process's
    working directory, which chdir and fchdir move, a new process inherits and a CLONE_FS thread shares. strace's
    escapes are decoded in every path, descriptor paths included. Paths outside `repo` are dropped, but an open
    whose descriptor resolves inside it (reached through a link from outside) credits that real path. Where the
    trace cannot say which directory a process had, it is `ambiguous` and the unit unmapped rather than guessed:
    a creation that never returned (its creator died), a reused pid, or a directory change by a process sharing its
    directory with another (it could land while a sibling is inside a creation that copies the directory)."""
    access = Access()
    calls, dangling = _completed_calls(text.splitlines())
    creator, reused = creation_tree(calls)
    access.ambiguous = (reused or any(head.split("(", 1)[0] in _CREATE for head in dangling)
                        or any(unknown_creation(call) for _pid, call, _start in calls))
    fs_of: dict[str, str] = {}  # pid -> the process whose working directory it uses (itself, or a CLONE_FS sharer)
    cwd_of: dict[str, str] = {}
    started: set[str] = set()

    def cwd(pid: str) -> str:
        return cwd_of.get(fs_of.get(pid, pid), start_cwd)

    def start(pid: str) -> None:
        """A process takes its creator's working directory the first time it acts or its creation returns,
        whichever comes first; the creator is still inside the creating call then, so its directory is the one
        it had at creation."""
        if pid in started:
            return
        started.add(pid)
        if pid in creator:
            parent, shares = creator[pid]
            start(parent)
            if shares:
                fs_of[pid] = fs_of.get(parent, parent)
            else:
                cwd_of[pid] = cwd(parent)

    def shares_directory(pid: str) -> bool:
        group = fs_of.get(pid, pid)
        return any(fs_of.get(other, other) == group for other in started if other != pid)

    for pid, call, _start in calls:
        m = _CALL.match(call)
        if not m:
            continue
        start(pid)
        name, args, ret, ret_path, _err = m.groups()
        ok = not ret.startswith("-")
        ret_path = _unescape(ret_path) if ret_path else None
        if name in _CREATE:
            if ok and ret != "0":
                start(ret)
            continue
        if name in ("chdir", "fchdir") and ok and shares_directory(pid):
            access.ambiguous = True
        fd = _FD.match(args)
        fd_path = _unescape(fd.group(1)) if fd and fd.group(1) else None
        if name == "fchdir":
            if ok and fd_path:
                cwd_of[fs_of.get(pid, pid)] = fd_path
            continue
        if name == "getdents64":
            key = repo_key(fd_path, repo) if fd_path else None
            if key is not None:
                access.dirs.add(key)
            continue
        s = _STR.search(args)
        if not s:
            continue
        target = _unescape(s.group(1))
        if not os.path.isabs(target):
            base = fd_path if name in _DIRFD and fd_path else cwd(pid)
            target = os.path.join(base, target)
        if name == "chdir":
            if ok:
                cwd_of[fs_of.get(pid, pid)] = os.path.normpath(target)
            continue
        key = repo_key(target, repo)
        # A successful open's descriptor names the file really opened: credit it under that name too (a link,
        # from inside or outside the repository), so an edit under either name selects the unit.
        real = repo_key(ret_path, repo) if name in _OPENS and ok and ret_path else None
        kind = access.dirs if "O_DIRECTORY" in args else access.files
        if real:
            kind.add(real)
        if key is None:
            continue
        if name not in _OPENS or not ok:
            access.probes.add(key)
        else:
            kind.add(key)
    access.files.discard("")
    return access


# ---- coverage and compile inputs ----------------------------------------------------------------------------------

def lcov_files(text: str, repo: str) -> set[str]:
    """The repository files with at least one executed function in an lcov export."""
    files: set[str] = set()
    current = None
    for line in text.splitlines():
        if line.startswith("SF:"):
            current = repo_key(line[3:], repo)
        elif line.startswith("FNDA:") and current:
            count = line[5:].split(",", 1)[0]
            if count.isdigit() and int(count) > 0:
                files.add(current)
    return files


def depinfo_inputs(text: str, repo: str) -> set[str]:
    """The non-.rs compile inputs a cargo dep-info file names (include_str!, include_bytes!): a change to one
    reaches every test of that binary. The binary's .rs inputs stay per unit, through coverage."""
    out: set[str] = set()
    for line in text.splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        for dep in re.split(r"(?<!\\)\s+", line.split(":", 1)[1].strip()):
            dep = dep.replace("\\ ", " ")
            if not dep:
                continue
            key = repo_key(dep if os.path.isabs(dep) else os.path.join(repo, dep), repo)
            if key and not key.endswith(".rs"):
                out.add(key)
    return out


# ---- units --------------------------------------------------------------------------------------------------------

@dataclass
class Run:
    """One unit's run: its time, libtest's counts (listed -1 when the listing failed), its trace (None when the file
    is missing; trace_rc the traced run's exit status), and its coverage (coverage_ok False when no profile was
    written or a coverage tool failed)."""
    seconds: float
    passed: int
    ignored: int
    listed: int
    trace_rc: int
    trace_text: str | None
    covered: set[str]
    # No default: a caller that forgot it would mark a unit covered, and selection would skip its tests.
    coverage_ok: bool


_RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")


def results(output: str) -> tuple[int, int]:
    """(passed, ignored) from libtest's last result line: a test that runs its own binary as a child can print a
    child's summary before the run's own (as coverage_shards.results reads it)."""
    found = _RESULT.findall(output)
    if not found:
        return 0, 0
    passed, _failed, ignored = found[-1]
    return int(passed), int(ignored)


def unmapped_reasons(run: Run, access: Access) -> list[str]:
    """Why a unit is unmapped, each reason a fixed label (none: the unit is mapped). Counted per reason in the
    merge's log, so the share of always-run units can be read by cause."""
    reasons = []
    if run.trace_text is None:
        reasons.append("no trace")
    elif run.trace_rc != 0:
        reasons.append("traced run failed")
    if not run.coverage_ok:
        reasons.append("coverage")
    if run.listed < 0:
        reasons.append("listing failed")
    elif run.passed + run.ignored != run.listed:
        reasons.append("pass count")
    if access.ambiguous:
        reasons.append("ambiguous process tree")
    return reasons


def unit_record_and_reasons(run: Run, tests: list[str], binary: str, extra_files: set[str],
                            repo: str) -> tuple[dict, list[str]]:
    """The unit's record and why it is unmapped (see unit_record)."""
    access = parse_trace(run.trace_text, repo, repo) if run.trace_text is not None else Access()
    reasons = unmapped_reasons(run, access)
    return {
        "files": sorted(run.covered | access.files | extra_files),
        "dirs": sorted(access.dirs),
        "probes": sorted(access.probes),
        "tests": sorted(tests),
        "seconds": round(run.seconds, 3),
        "binary": binary,
        "unmapped": bool(reasons),
    }, reasons


def unit_record(run: Run, tests: list[str], binary: str, extra_files: set[str], repo: str) -> dict:
    """A unit as the map stores it, exactly UNIT_KEYS. Unmapped when the traced run failed or left no trace, when
    its coverage is missing or a coverage tool failed, when its process tree is ambiguous, or when passed plus
    ignored differs from the tests it listed (a failed listing never matches); a trace that names no repository
    file is normal."""
    return unit_record_and_reasons(run, tests, binary, extra_files, repo)[0]


def map_document(sha: str, built_at: str, units: dict[str, dict]) -> dict:
    """The published map, exactly MAP_KEYS."""
    return {"map_sha": sha, "built_at": built_at, "units": units}


# ---- running a unit (the runner half; needs cargo, strace and the llvm tools) ------------------------------------

def llvm_tool(name: str) -> str:
    """A tool from the active toolchain's llvm-tools component."""
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True, check=True).stdout
    for path in sorted(Path(sysroot.strip(), "lib", "rustlib").glob(f"*/bin/{name}")):
        return str(path)
    raise SystemExit(f"affected_map: {name} not found; the toolchain needs the llvm-tools component")


def run_unit(binary: str, args: list[str], listed: int, unit_dir: str, objects: list[str]) -> Run:
    """One unit under the trace with coverage on; its profile and trace stay in `unit_dir`."""
    os.makedirs(unit_dir, exist_ok=True)
    trace = os.path.join(unit_dir, "trace.txt")
    env = {**os.environ, **unit_env(unit_dir), "CARGO_MANIFEST_DIR": str(ROOT)}
    start = time.monotonic()
    proc = subprocess.run([*strace_command(trace), binary, *args], capture_output=True, text=True, cwd=ROOT,
                          env=env)
    seconds = time.monotonic() - start
    passed, ignored = results(proc.stdout)
    text = Path(trace).read_text(encoding="utf-8", errors="replace") if os.path.exists(trace) else None
    covered: set[str] = set()
    coverage_ok = False
    raws = sorted(Path(unit_dir).glob("*.profraw"))
    if raws:
        profdata = os.path.join(unit_dir, "unit.profdata")
        if subprocess.run([llvm_tool("llvm-profdata"), "merge", "-sparse", *map(str, raws), "-o", profdata]
                          ).returncode == 0:
            cmd = [llvm_tool("llvm-cov"), "export", "-format=lcov", "-instr-profile", profdata, objects[0]]
            for extra in objects[1:]:
                cmd += ["-object", extra]
            export = subprocess.run(cmd, capture_output=True, text=True)
            if export.returncode == 0:
                covered = lcov_files(export.stdout, str(ROOT))
                coverage_ok = True
        for raw in raws:
            raw.unlink()
    # strace exits with the traced program's status: any failure, a test's or the trace's own, leaves it unmapped.
    trace_rc = proc.returncode if text else 1
    return Run(seconds, passed, ignored, listed, trace_rc, text, covered, coverage_ok)


def list_tests(binary: str, args: list[str]) -> list[str] | None:
    """The test names `binary` lists for `args` (libtest --list), ignored ones included; None when listing fails."""
    out = subprocess.run([binary, "--list", *args], capture_output=True, text=True, cwd=ROOT,
                         env={**os.environ, "CARGO_MANIFEST_DIR": str(ROOT)})
    if out.returncode != 0:
        return None
    return [line[: -len(": test")] for line in out.stdout.splitlines() if line.endswith(": test")]


# ---- one part, then the merge ----------------------------------------------------------------------------------

def _shard_tests():
    """scripts/ci/shard_tests.py, for its cargo flags and integration globs (one source with the test legs)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import shard_tests  # noqa: E402
    return shard_tests


def _coverage_env() -> dict[str, str]:
    return {**os.environ, "RUSTFLAGS": (os.environ.get("RUSTFLAGS", "") + " " + COVERAGE_RUSTFLAGS).strip()}


def _artifacts(lines: list[str]) -> list[dict]:
    """cargo's compiler-artifact messages that carry an executable."""
    out = []
    for line in lines:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            out.append(msg)
    return out


def _depinfo(executable: str) -> set[str]:
    path = executable + ".d"
    return depinfo_inputs(Path(path).read_text(encoding="utf-8"), str(ROOT)) if os.path.exists(path) else set()


def artifact_depinfo_path(artifact: dict) -> str | None:
    """Where cargo wrote an artifact's dep-info: beside an executable as `<exe>.d`; for a library, `<crate>-<hash>.d`
    beside its `lib<crate>-<hash>.rlib`."""
    if artifact.get("executable"):
        return artifact["executable"] + ".d"
    for filename in artifact.get("filenames", []):
        base = os.path.basename(filename)
        if base.startswith("lib") and base.endswith(".rlib"):
            return os.path.join(os.path.dirname(filename), base[3:-len(".rlib")] + ".d")
    return None


def _all_artifacts(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") == "compiler-artifact":
            out.append(msg)
    return out


def _workspace_inputs(artifacts: list[dict]) -> set[str]:
    """The non-.rs compile inputs of this package's library and binaries: an integration test reaches them through
    the library it links and the gateway child it spawns, so they belong to every integration unit."""
    out: set[str] = set()
    for art in artifacts:
        if art.get("profile", {}).get("test") or str(ROOT) not in art.get("package_id", ""):
            continue
        path = artifact_depinfo_path(art)
        if path and os.path.exists(path):
            out |= depinfo_inputs(Path(path).read_text(encoding="utf-8"), str(ROOT))
    return out


def _lib_part(k: str, out: Path) -> dict:
    """lib-K: the part's binary, built instrumented by lib-parts.sh (the one place the part is chosen), its
    depth-2 groups each run as a unit."""
    proc = subprocess.run(["bash", str(ROOT / "scripts/ci/lib-parts.sh"), "export", k, str(out / "bin")],
                          capture_output=True, text=True, env=_coverage_env(), cwd=ROOT)
    sys.stdout.write(proc.stdout[-4000:])
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"affected_map: lib part {k} did not build")
    binary = out / "bin" / f"p{k}" / f"lib-tests-p{k}"
    built = re.search(r"export-lib: (\S+) -> ", proc.stdout + proc.stderr)
    names = [line[: -len(": test")] for line in (out / "bin" / f"p{k}" / "list.txt").read_text().splitlines()
             if line.endswith(": test")]
    units, reasons = {}, {}
    for key, members in sorted(group(names, 2).items()):
        run = run_unit(str(binary), ["--exact", *members], len(members), str(out / "units" / key), [str(binary)])
        units["lib:" + key], reasons["lib:" + key] = unit_record_and_reasons(run, members, LIB_BINARY, set(),
                                                                             str(ROOT))
    return {"part": f"lib-{k}", "binary": str(binary.relative_to(out)), "units": units, "unmapped_reasons": reasons,
            "extra_files": sorted(_depinfo(built.group(1)) if built else set())}


def _int_part(name: str, out: Path) -> dict:
    """int-a / int-b: every test target in the part's glob (and the bins' own tests on int-a) is one unit."""
    st = _shard_tests()
    select = ["--bins", "--test", st.GLOB_A] if name == "int-a" else ["--test", st.GLOB_B]
    proc = subprocess.run(["cargo", *st.BASE, *select, "--no-run", "--message-format=json"], capture_output=True,
                          text=True, env=_coverage_env(), cwd=ROOT)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit(f"affected_map: {name} did not build")
    artifacts = _artifacts(proc.stdout.splitlines())
    shared = _workspace_inputs(_all_artifacts(proc.stdout.splitlines()))
    gateway = [a["executable"] for a in artifacts if "bin" in a["target"]["kind"] and not a["profile"]["test"]]
    units, reasons = {}, {}
    for art in artifacts:
        if not art["profile"]["test"]:
            continue
        kind = "test" if "test" in art["target"]["kind"] else "bin"
        label = f"{kind}:{art['target']['name']}"
        exe = art["executable"]
        listed = list_tests(exe, [])
        # A listing that failed never matches the pass count, so the unit is unmapped.
        run = run_unit(exe, [], -1 if listed is None else len(listed), str(out / "units" / label), [exe, *gateway])
        src = repo_key(art["target"]["src_path"], str(ROOT)) or art["target"]["name"]
        units[label], reasons[label] = unit_record_and_reasons(run, listed or [], src, _depinfo(exe) | shared,
                                                               str(ROOT))
    return {"part": name, "binary": None, "units": units, "unmapped_reasons": reasons, "extra_files": []}


def parts() -> list[str]:
    """The workflow's matrix: every lib part (N from the build script) and the two integration halves."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import lib_union  # noqa: E402
    return [f"lib-{k}" for k in range(1, lib_union.part_count(lib_union.BUILD_SCRIPT) + 1)] + ["int-a", "int-b"]


def part(name: str, out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if name.startswith("lib-") and name[4:].isdigit():
        doc = _lib_part(name[4:], out)
    elif name in ("int-a", "int-b"):
        doc = _int_part(name, out)
    else:
        print(f"affected_map: unknown part {name!r}", file=sys.stderr)
        return 2
    (out / "part.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"affected_map: {name}: {len(doc['units'])} units, "
          f"{sum(1 for u in doc['units'].values() if u['unmapped'])} unmapped")
    return 0


def merge(sha: str, part_dirs: list[str], out_dir: str, now: datetime | None = None) -> int:
    """The run's lib total over every part; each lib group heavier than SPLIT_SHARE of it re-run deeper on its
    part's binary (the same run's times), then the map. A lib group's extra (non-.rs) inputs reach all its units."""
    parts = [(Path(d), json.loads((Path(d) / "part.json").read_text(encoding="utf-8"))) for d in part_dirs]
    total = sum(u["seconds"] for _, doc in parts for u in doc["units"].values() if u["binary"] == LIB_BINARY)
    units: dict[str, dict] = {}
    why: dict[str, list[str]] = {}
    for where, doc in parts:
        extra = set(doc["extra_files"])
        for label, unit in doc["units"].items():
            single = len(unit["tests"]) == 1
            if unit["binary"] != LIB_BINARY or unit["seconds"] <= SPLIT_SHARE * total or single:
                units[label] = {**unit, "files": sorted(set(unit["files"]) | extra)}
                why[label] = doc.get("unmapped_reasons", {}).get(label, ["unknown"] if unit["unmapped"] else [])
                continue
            binary = str(where / doc["binary"])
            key = label[len("lib:"):]
            runs: dict[str, tuple[Run, list[str]]] = {}

            def measure(k: str, names: list[str], key: str = key, seconds: float = unit["seconds"],
                        binary: str = binary, runs: dict = runs) -> float:
                if k == key:
                    return seconds
                run = run_unit(binary, ["--exact", *names], len(names), str(Path(out_dir) / "deep" / k), [binary])
                runs[k] = (run, names)
                return run.seconds

            for leaf in split_heavy(key, unit["tests"], len(key.split("::")), total, measure):
                run, names = runs[leaf]
                units["lib:" + leaf], why["lib:" + leaf] = unit_record_and_reasons(run, names, LIB_BINARY, extra,
                                                                                   str(ROOT))
    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    doc = map_document(sha, stamp, units)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "affected-map.json").write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
    counts = reason_counts(why)
    (Path(out_dir) / "unmapped-reasons.json").write_text(json.dumps(counts, sort_keys=True) + "\n", encoding="utf-8")
    unmapped = sum(1 for u in units.values() if u["unmapped"])
    print(f"affected_map: {len(units)} units, {unmapped} unmapped ({100 * unmapped / max(len(units), 1):.1f}%), "
          f"lib {total:.0f} s; unmapped by reason: "
          + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"))
    return 0


def reason_counts(why: dict[str, list[str]]) -> dict[str, int]:
    """How many units each unmapped reason covers (a unit with two reasons counts under both)."""
    counts: dict[str, int] = {}
    for reasons in why.values():
        for reason in reasons:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


# ---- commands -----------------------------------------------------------------------------------------------------

def guard(map_path: str, now_iso: str) -> int:
    """Prints build=true|false for the workflow's first job."""
    built = None
    try:
        built = json.loads(Path(map_path).read_text(encoding="utf-8")).get("built_at")
    except (OSError, ValueError, AttributeError):
        built = None
    now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    print(f"build={'true' if should_build(built, now) else 'false'}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "guard":
        return guard(argv[2], argv[3])
    if len(argv) == 2 and argv[1] == "parts":
        print(json.dumps(parts()))
        return 0
    if len(argv) == 4 and argv[1] == "part":
        return part(argv[2], argv[3])
    if len(argv) >= 5 and argv[1] == "merge":
        return merge(argv[2], argv[3:-1], argv[-1])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
