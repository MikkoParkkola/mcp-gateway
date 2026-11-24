#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shadow selection for the Linux test legs: what each leg would run for this pull request, written to a record.

Called by a leg just before its shard step. The leg runs everything regardless; the record is evidence for
deciding later whether narrowing is safe. Inputs: the map affected_map.py publishes (restored from the cache), the
merge commit CI checked out, and the GitHub event. Output: a JSON record with the leg, a mode (full, reduced or
none), a reason, the map commit and a sorted name list.

Anything uncertain answers full. Git work happens in a throwaway bare repository, never in the checkout.

    affected_select.py LEG RECORD [--map MAP] [--lib-bin DIR]
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shard_tests  # noqa: E402  (filters and part binaries come from here so the split has one source)

LINE = "docs/ranking-1-release-line"
ROOT = Path(__file__).resolve().parents[2]
MAP_PATH = "map/affected-map.json"
LEGS = ("int-a", "int-b", "lib-a", "lib-b")
LIB_LEGS = ("lib-a", "lib-b")
MAP_KEYS = {"map_sha", "built_at", "units"}
UNIT_KEYS = {"files", "dirs", "probes", "tests", "seconds", "binary", "unmapped"}
RECORD_KEYS = ("leg", "mode", "reason", "map_sha", "names", "run_attempt")
# Seconds per git command. Slower than this and the answer is full, so the shard step keeps its job time.
GIT_TIMEOUT = 30
LINK_MODE = "120000"

# Paths whose change means everything: a set, written sorted. Trailing "/" = the whole subtree. Cargo.toml's
# `build` key adds one more at run time (build_script).
FORCE_FULL = frozenset({
    ".cargo/",
    ".github/actions/",
    ".github/workflows/",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
    "scripts/ci/",
    "scripts/dev/test-parts.tsv",
    "scripts/dev/test_parts.py",
    "tests/common/",
})

# Names a leg records on every judged run. Their inputs live outside what the map traced: the UPGRADING steps
# read a guide built in $RUNNER_TEMP, and int-a's #[ignore] rows hit a gateway started only by that leg.
# For a lib leg, an entry is a module prefix ("::" at the end) matched against the leg's listing.
ALWAYS = {
    "lib-b": ("commands::upgrade::upgrade_notice_tests::",),
    "int-b": ("test:upgrading_summary_rows",),
    "int-a": ("test:integration_tests",),
}

# The closed set of reasons. A report can count them; an unknown string is a bug (see Full).
REASONS = (
    "lane PR",
    "event: push", "event: tag", "event: dispatch", "event: train PR", "event: fork PR", "event: PR into another base",
    "event: other",
    "map missing", "map unreadable", "map not the map schema", "map not an ancestor of the base",
    "not the PR merge", "diff unread", "listing unread", "map path taken",
    "force-full path", "unmapped .rs", "link or type change", "error",
    "select skipped", "select failure", "select cancelled", "select success",
)


class Full(Exception):
    """Raised anywhere the answer must be the whole suite; carries one of REASONS."""

    def __init__(self, reason: str) -> None:
        assert reason in REASONS, reason
        super().__init__(reason)
        self.reason = reason


def event_class(event_name: str, event: dict, repository: str, ref: str = "") -> str:
    """Classify the run from the event payload. Only "lane PR" goes on to read a map."""
    if event_name == "pull_request":
        pr = event.get("pull_request") or {}
        if (pr.get("base") or {}).get("ref") != LINE:
            return "event: PR into another base"
        if ((pr.get("head") or {}).get("repo") or {}).get("full_name") != repository:
            return "event: fork PR"
        if str((pr.get("head") or {}).get("ref", "")).startswith("train/"):
            return "event: train PR"
        return "lane PR"
    if event_name == "push":
        return "event: tag" if ref.startswith("refs/tags/") else "event: push"
    if event_name == "workflow_dispatch":
        return "event: dispatch"
    return "event: other"


def read_map(path: str) -> dict:
    """Load the restored map and check its shape key for key; anything off raises Full."""
    if not os.path.isfile(path):
        raise Full("map missing")
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise Full("map unreadable") from None
    units = doc.get("units") if isinstance(doc, dict) else None
    if (not isinstance(doc, dict) or set(doc) != MAP_KEYS or not isinstance(doc["map_sha"], str)
            or not isinstance(units, dict)
            or any(not isinstance(u, dict) or set(u) != UNIT_KEYS for u in units.values())):
        raise Full("map not the map schema")
    return doc


def git(repo: str, *args: str) -> str:
    """Run git in `repo` and return stdout. A non-zero exit, a missing git or a slow call raises Full."""
    try:
        out = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=GIT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        raise Full("diff unread") from None
    if out.returncode != 0:
        raise Full("diff unread")
    return out.stdout


@dataclass
class Change:
    status: str  # one letter from `git diff --raw --no-renames`: A, D, M or T
    path: str
    old_mode: str
    new_mode: str


@dataclass
class History:
    base: str
    changes: list[Change]
    dirs_at_map: set[str]
    dirs_at_merge: set[str]


def parse_raw(text: str) -> list[Change]:
    """Split NUL-terminated `--raw -z` output: a ":modes shas status" field, then the path, per entry. NUL framing
    keeps spaces and odd bytes in a path intact."""
    parts = text.split("\0")
    out: list[Change] = []
    i = 0
    while i + 1 < len(parts) and parts[i].startswith(":"):
        old_mode, new_mode, _old, _new, status = parts[i][1:].split()
        out.append(Change(status[:1], parts[i + 1], old_mode, new_mode))
        i += 2
    return out


def folders(repo: str, commit: str) -> set[str]:
    """Every folder in `commit`'s tree, with "" for the root."""
    return {"", *(p for p in git(repo, "ls-tree", "-r", "-d", "--name-only", "-z", commit).split("\0") if p)}


def is_ancestor(repo: str, older: str, newer: str) -> bool:
    """`git merge-base --is-ancestor`: exit 0 yes, 1 no (or not provable in the fetched window); else Full."""
    try:
        out = subprocess.run(["git", "-C", repo, "merge-base", "--is-ancestor", older, newer], capture_output=True,
                             timeout=GIT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        raise Full("diff unread") from None
    if out.returncode not in (0, 1):
        raise Full("diff unread")
    return out.returncode == 0


def history(origin: str, merge: str, head_sha: str, map_sha: str, scratch: str) -> History:
    """Fetch only what the rule reads, into a fresh bare repository under `scratch`.

    The merge commit with its parents and trees (blobs are never needed): its first parent is the base, and its
    second must be the event's head, which proves this is the PR merge. The map commit with its trees. Commits
    only (no trees) of the base from a day before the map commit onward, for the ancestry test; if the walk
    cannot reach the map commit inside that window the test fails, which answers full, never a wrong subset."""
    repo = os.path.join(scratch, "select.git")
    git(scratch, "init", "-q", "--bare", repo)
    git(repo, "fetch", "-q", "--depth=2", "--filter=blob:none", origin, merge)
    parents = git(repo, "rev-list", "--parents", "-n", "1", merge).split()
    if len(parents) != 3 or parents[2] != head_sha:
        raise Full("not the PR merge")
    base = parents[1]
    git(repo, "fetch", "-q", "--depth=1", "--filter=blob:none", origin, map_sha)
    since = int(git(repo, "log", "-1", "--format=%ct", map_sha).strip()) - 86400
    git(repo, "fetch", "-q", "--filter=tree:0", f"--shallow-since={since}", origin, base)
    if not is_ancestor(repo, map_sha, base):
        raise Full("map not an ancestor of the base")
    changes = parse_raw(git(repo, "diff", "--raw", "--no-renames", "-z", map_sha, merge))
    return History(base, changes, folders(repo, map_sha), folders(repo, merge))


def build_script(cargo_toml: str) -> str | None:
    """The `[package] build` value of Cargo.toml, so renaming the build script moves the force-full entry."""
    try:
        build = tomllib.loads(Path(cargo_toml).read_text(encoding="utf-8")).get("package", {}).get("build")
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return build if isinstance(build, str) else None


def force_full(path: str, build: str | None) -> bool:
    entries = FORCE_FULL | ({build} if build else set())
    return any(path.startswith(e) if e.endswith("/") else path == e for e in entries)


def ancestors(path: str) -> list[str]:
    """Enclosing folders of `path`, innermost first, ending with "" (the root)."""
    out = []
    while path:
        path = os.path.dirname(path)
        out.append(path)
    return out


def select_units(units: dict, h: History, build: str | None) -> set[str]:
    """Labels of the units the diff can reach; raises Full when it cannot say.

    A path counts against a unit when the unit opened it or probed it. When a path appears or disappears, the
    listing of every enclosing folder changed, so units that read or probed those folders count too. The walk
    up stops at the first folder present on both sides: above it nothing appeared or vanished. Unmapped units
    always count."""
    by_path: dict[str, set[str]] = {}
    by_folder: dict[str, set[str]] = {}
    for label, u in units.items():
        for p in (*u["files"], *u["probes"]):
            by_path.setdefault(p, set()).add(label)
        for p in (*u["dirs"], *u["probes"]):
            by_folder.setdefault(p, set()).add(label)
    executed = {p for u in units.values() for p in u["files"]}
    chosen = {label for label, u in units.items() if u["unmapped"]}
    for c in h.changes:
        if c.status == "T" or LINK_MODE in (c.old_mode, c.new_mode):
            raise Full("link or type change")
        if force_full(c.path, build):
            raise Full("force-full path")
        if c.path.endswith(".rs") and c.path not in executed:
            raise Full("unmapped .rs")
        chosen |= by_path.get(c.path, set())
        if c.status in ("A", "D"):
            for folder in ancestors(c.path):
                chosen |= by_folder.get(folder, set())
                if folder in h.dirs_at_map and folder in h.dirs_at_merge:
                    break
    return chosen


def _shard(leg: str) -> list[tuple[str, list[str], list[str], int]]:
    return shard_tests.SHARDS["linux"][leg]


def lib_listing(leg: str, lib_bin: str) -> set[str]:
    """Ask the fetched part binaries which tests this leg runs, through shard_tests' own checks and filters, so
    the names match what the shard step will run."""
    binaries, problems = shard_tests.part_binaries(lib_bin)
    if problems or not binaries:
        raise Full("listing unread")
    names: set[str] = set()
    for binary in binaries.values():
        for _step, _cargo, test_args, _floor in _shard(leg):
            try:
                names |= shard_tests.listed(binary, test_args, "linux")
            except (OSError, RuntimeError):
                raise Full("listing unread") from None
    if not names:
        raise Full("listing unread")
    return names


def int_scope(leg: str) -> tuple[list[str], bool, bool]:
    """Read the integration leg's cargo arguments: its `--test` globs, and whether `--bins` and `--doc` appear."""
    globs, bins, doc = [], False, False
    for _step, cargo, _test_args, _floor in _shard(leg):
        bins |= "--bins" in cargo
        doc |= "--doc" in cargo
        globs += [cargo[i + 1] for i, a in enumerate(cargo) if a == "--test" and i + 1 < len(cargo)]
    return globs, bins, doc


def leg_record(leg: str, units: dict, chosen: set[str], listing: set[str] | None) -> tuple[str, list[str]]:
    """Turn the chosen units into this leg's mode and names.

    Lib leg: names are the chosen lib units' tests that the leg lists, plus listed names no lib unit knows
    (new tests, compared against lib units only since test names are free text), plus its ALWAYS prefixes;
    "none" only if that is empty. Integration leg: never "none"; chosen targets matching its globs, plus "bins"
    and every bin unit when it runs --bins, "doc" when it runs --doc, plus its ALWAYS names."""
    if leg in LIB_LEGS:
        assert listing is not None
        known = {t for label, u in units.items() if label.startswith("lib:") for t in u["tests"]}
        names = {t for label in chosen if label.startswith("lib:") for t in units[label]["tests"]} & listing
        names |= listing - known
        names |= {t for prefix in ALWAYS.get(leg, ()) for t in listing if t.startswith(prefix)}
        return ("reduced" if names else "none"), sorted(names)
    globs, bins, doc = int_scope(leg)
    names = {label for label in chosen if label.startswith("test:")
             and any(fnmatch.fnmatchcase(label[len("test:"):], g) for g in globs)}
    if bins:
        names |= {label for label in units if label.startswith("bin:")} | {"bins"}
    if doc:
        names.add("doc")
    names |= set(ALWAYS.get(leg, ()))
    return "reduced", sorted(names)


def record(leg: str, mode: str, reason: str, map_sha: str | None, names: list[str], attempt: int) -> dict:
    assert reason in REASONS and mode in ("full", "reduced", "none")
    return dict(zip(RECORD_KEYS, (leg, mode, reason, map_sha, names, attempt)))


def write_record(path: str, rec: dict) -> None:
    """Write to a temporary file beside the target, then rename over it, so a reader never sees half a record."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".record-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(rec, f, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


@dataclass
class Inputs:
    leg: str
    event_name: str
    event: dict
    repository: str
    ref: str
    merge: str
    origin: str
    map_path: str
    lib_bin: str | None
    attempt: int
    checkout: str = str(ROOT)
    tracked_map: bool = False
    scratch: str | None = None


def decide(inp: Inputs) -> dict:
    """Build the leg's record. Every exception becomes a full record; the caller never sees one."""
    map_sha = None
    try:
        cls = event_class(inp.event_name, inp.event, inp.repository, inp.ref)
        if cls != "lane PR":
            raise Full(cls)
        if inp.tracked_map:
            raise Full("map path taken")
        doc = read_map(inp.map_path)
        map_sha = doc["map_sha"]
        head_sha = ((inp.event.get("pull_request") or {}).get("head") or {}).get("sha", "")
        with tempfile.TemporaryDirectory(dir=inp.scratch) as scratch:
            h = history(inp.origin, inp.merge, head_sha, map_sha, scratch)
        chosen = select_units(doc["units"], h, build_script(os.path.join(inp.checkout, "Cargo.toml")))
        listing = lib_listing(inp.leg, inp.lib_bin) if inp.leg in LIB_LEGS else None
        mode, names = leg_record(inp.leg, doc["units"], chosen, listing)
        return record(inp.leg, mode, "lane PR", map_sha, names, inp.attempt)
    except Full as full:
        return record(inp.leg, "full", full.reason, map_sha, [], inp.attempt)
    except Exception:  # noqa: BLE001  (a bug here must not cost the leg anything; it shows as reason "error")
        return record(inp.leg, "full", "error", map_sha, [], inp.attempt)


def map_is_tracked(checkout: str) -> bool:
    """Whether the checkout's own commit holds anything under map/ (then the restore never ran, see ci.yml)."""
    out = subprocess.run(["git", "-C", checkout, "ls-files", "--", "map"], capture_output=True, text=True)
    return out.returncode == 0 and bool(out.stdout.strip())


def drop_restored_map(map_path: str, tracked: bool) -> None:
    """Delete the map the cache restore wrote, so the suite runs on the PR's tree alone; a tracked one stays."""
    if not tracked and os.path.isfile(map_path):
        os.remove(map_path)


def main(argv: list[str]) -> int:
    started = time.monotonic()
    args = argv[1:]
    if len(args) < 2 or args[0] not in LEGS:
        print(__doc__, file=sys.stderr)
        return 2
    leg, out = args[0], args[1]
    opts = dict(zip(args[2::2], args[3::2]))
    env = os.environ
    event: dict = {}
    if env.get("GITHUB_EVENT_PATH") and os.path.isfile(env["GITHUB_EVENT_PATH"]):
        try:
            event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            event = {}
    checkout = env.get("GITHUB_WORKSPACE") or str(ROOT)
    map_path = opts.get("--map", os.path.join(checkout, MAP_PATH))
    tracked = map_is_tracked(checkout)
    inp = Inputs(
        leg=leg, event_name=env.get("GITHUB_EVENT_NAME", ""), event=event,
        repository=env.get("GITHUB_REPOSITORY", ""), ref=env.get("GITHUB_REF", ""), merge=env.get("GITHUB_SHA", ""),
        origin=f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env.get('GITHUB_REPOSITORY', '')}.git",
        map_path=map_path, lib_bin=opts.get("--lib-bin"), attempt=int(env.get("GITHUB_RUN_ATTEMPT", "1") or 1),
        checkout=checkout, tracked_map=tracked, scratch=env.get("RUNNER_TEMP"),
    )
    rec = decide(inp)
    write_record(out, rec)
    drop_restored_map(map_path, tracked)
    line = (f"affected tests (shadow) {leg}: {rec['mode']} ({rec['reason']}), {len(rec['names'])} names, "
            f"map {rec['map_sha'] or 'none'}, {time.monotonic() - started:.0f} s")
    print(line)
    for name, text in (("GITHUB_OUTPUT", f"mode={rec['mode']}\n"), ("GITHUB_STEP_SUMMARY", line + "\n")):
        if env.get(name):
            with open(env[name], "a", encoding="utf-8") as f:
                f.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
