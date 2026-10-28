#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every function a change adds on the seven COV.3 paths is classified (MIK-7324, MIK-8169).

docs/release/v4.0.0-critical-path-coverage.md: "A function added to one of
these paths that meets the definition is added to the inventory in the same
change." This check makes that mechanical. Each non-test function the change
adds under the seven paths needs a row in the same change, in one of:

  docs/release/inventory.d/<pr>.critical.tsv     it enforces (critical/standard)
  docs/release/inventory.d/<pr>.unenforcing.tsv  reviewed: enforces nothing

A fragment per PR, so row-adding PRs never edit the same file (MIK-8279). The
base ledgers, docs/release/v4.0.0-critical-functions.tsv and
docs/release/v4.0.0-unenforcing-functions.tsv, hold the older rows and are
read together with the fragments by inventory_ledger.py. A key stated twice,
in one ledger or across both, fails.

Usage:
  check_inventory_rows.py <base> [<head>]   fail when a function <head> (default
                                            HEAD) adds since its merge-base with
                                            <base> has no row in <head>
  check_inventory_rows.py --all [<head>]    fail when any function on the paths
                                            in <head> has no row (MIK-8195): a
                                            gap older than the diff check
"""

from __future__ import annotations

import functools
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_ledger as ledger  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
ROOT_OF_SCRIPTS = Path(__file__).resolve().parents[1]
INVENTORY = "docs/release/v4.0.0-critical-functions.tsv"
UNENFORCING = "docs/release/v4.0.0-unenforcing-functions.tsv"
ALL = "--all"
# Diffing against git's empty tree reads every line of <head> as added.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# The seven paths, as scripts/release coverage grading names them.
PREFIXES = (
    "src/gateway/server/",
    "src/oauth/",
    "src/transport/http/",
    "src/gateway/router/",
    "src/transport/stdio.rs",
    # Its start sequence, split out of stdio.rs: the same functions,
    # inventoried where they now live.
    "src/transport/stdio_start.rs",
    # Its child environment, split out of stdio.rs earlier and restored here.
    "src/transport/stdio_env.rs",
    "src/transport/command_split.rs",
    "src/gateway/input_bridge.rs",
    # Its child modules (channel, debug, outcome), spelled apart for the same
    # reason as task_confirmation below.
    "src/gateway/input_bridge/",
    "src/gateway/task_service/",
    # The module file and its directory, spelled apart: a git pathspec names
    # one path, so the stem alone matched only the directory.
    "src/gateway/meta_mcp/task_confirmation.rs",
    "src/gateway/meta_mcp/task_confirmation/",
    "src/personal_accounts/",
    "src/config/account_bindings.rs",
    "src/identity_propagation/",
    # The outbound read judge and its delivery (MIK-8195 W8 took stdio.rs,
    # MIK-8321 the rest). Inventory and probe surface only:
    # critical_path_coverage.py PATHS does not grade it as a path.
    "src/gateway/outbound/",
)

FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_]\w*)')
TEST_FILE = re.compile(r"(^|/)tests?(/|\.rs$)|_tests?\.rs$|_tests/")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def blanked(lines: list[str]) -> list[str]:
    """`lines` with every comment and string or char literal blanked by the
    orphan gate's `blank()` (block comments nested and multi-line included),
    one entry per line, so a `#[cfg(test)]` or brace inside one is never read
    as code (MIK-8405.SPLIT.5). The one lexer for both release checks."""
    return orphan_gate().blank("\n".join(lines))[0].split("\n")


def test_only(text: str) -> bool:
    """Whether an attribute line carries a `#[cfg(<expr>)]` that compiles
    only under test, by the orphan gate's one cfg judgement (`cfg_is_test`).
    Several attributes may share the line (`#[cfg(test)] #[cfg(unix)]`), so
    each expression is read to its balancing `)`."""
    text = text.strip()
    if not text.startswith("#["):
        return False
    gate = orphan_gate()
    return any(
        gate.cfg_is_test(gate.cfg_expression(text, m.end()))
        for m in re.finditer(r"#\s*\[\s*cfg\s*\(", text)
    )


def bodyless(lines: list[str], line: int) -> bool:
    """The signature at 1-based `line` ends in `;` before any `{`: a trait
    declaration, which has no lines of its own to cover. `lines` are
    [`blanked`]."""
    square = 0  # a `;` inside `[u8; 16]` does not end the signature
    for raw in lines[line - 1 :]:
        for ch in raw:
            square += (ch == "[") - (ch == "]")
            if ch == "{" or (ch == ";" and square == 0):
                return ch == ";"
    return False


def test_lines(lines: list[str]) -> set[int]:
    """1-based line numbers inside a `#[cfg(test)]` item (a module, fn or
    impl). `lines` are [`blanked`]."""
    inside: set[int] = set()
    pending = False
    depth = 0
    start_depth: int | None = None
    for n, raw in enumerate(lines, 1):
        text = raw.strip()
        if start_depth is not None:
            inside.add(n)
        elif test_only(text):
            pending = True
        elif pending and text and not text.startswith("#["):
            inside.add(n)
            if text.endswith(";"):
                pending = False  # `#[cfg(test)] mod x;` or a use: one line
            else:
                start_depth = depth
                pending = False
        depth += text.count("{") - text.count("}")
        if start_depth is not None and depth <= start_depth and "}" in text:
            start_depth = None
    return inside


@functools.lru_cache(maxsize=None)
def show(rev: str, path: str) -> str | None:
    """`path` as `rev` has it; None when it does not exist there. Cached:
    callers pass a resolved commit, never a moving name like HEAD."""
    done = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=ROOT, capture_output=True, text=True
    )
    return done.stdout if done.returncode == 0 else None


LEDGER_OF = {INVENTORY: ledger.CRITICAL, UNENFORCING: ledger.UNENFORCING}


@functools.cache
def ledger_rows(root: Path, rev: str, path: str) -> tuple[dict, ...]:
    """The rows of the ledger at `path` as `rev` has it: the base TSV plus its
    fragments (inventory_ledger.py). Raises LedgerError on any bad row."""
    return tuple(ledger.load_rev(root, rev, LEDGER_OF[path], path))


def rows(rev: str, path: str) -> set[tuple[str, str, int]]:
    """(file, fn, occurrence) of every row of one ledger, base and fragments.
    `rev` is resolved first, so the cache never serves a moved name."""
    return {ledger.key(row) for row in ledger_rows(ROOT, git("rev-parse", rev).strip(), path)}


def occurrence(lines: list[str], name: str, line: int) -> int:
    """Which `fn <name>` in the file the definition at 1-based `line` is,
    counted as the grader counts (critical_function_coverage.fn_line): every
    line matching, test code included. A same-named function added beside an
    inventoried one is a new occurrence, so it needs its own row."""
    pattern = re.compile(r"\bfn\s+" + re.escape(name) + r"\b")
    return sum(1 for text in lines[:line] if pattern.search(text))


@functools.lru_cache(maxsize=1)
def _load_orphan_gate():
    spec = importlib.util.spec_from_file_location(
        "orphan_gate", ROOT_OF_SCRIPTS / "dev" / "check-orphan-test-modules.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def orphan_gate():
    """scripts/dev/check-orphan-test-modules.py: the one module resolver
    (MIK-8405.SPLIT.5). It walks declarations from the crate roots by Rust's
    rules, so this check and the orphan gate cannot disagree about where a
    file is mounted or whether it compiles outside tests. Pointed at this
    module's ROOT on every use."""
    module = _load_orphan_gate()
    module.ROOT = ROOT
    return module


@functools.lru_cache(maxsize=None)
def mount_status(root: Path, commit: str) -> tuple[frozenset[str], frozenset[str]]:
    """(reachable, test-only) source paths as `commit` has them,
    repo-relative. Read from the commit, never the working tree, so the
    mounts are judged on the same revision as the diff, the file contents and
    the rows: a dirty or different checkout cannot change the verdict. Every
    committed `.rs` blob is written out straight from the object store, so a
    `#[path]` into any directory resolves, and no export-ignore attribute
    (which `git archive` would honour) can hide a source."""
    run = lambda args, data=None: subprocess.run(
        ["git", *args], cwd=root, input=data, check=True, capture_output=True
    ).stdout
    blobs = []
    for entry in run(["ls-tree", "-r", "-z", "--full-tree", commit]).split(b"\0"):
        meta, _, path = entry.partition(b"\t")
        if path.endswith(b".rs") and meta.split(b" ")[1:2] == [b"blob"]:
            mode, _, sha = meta.split(b" ")
            blobs.append((sha, path.decode(), mode == b"120000"))
    contents = run(["cat-file", "--batch"], b"".join(sha + b"\n" for sha, _, _ in blobs))
    gate = orphan_gate()
    with tempfile.TemporaryDirectory() as tree:
        at = 0
        for _, path, link in blobs:
            header_end = contents.index(b"\n", at)
            size = int(contents[at:header_end].split(b" ")[2])
            body = contents[header_end + 1 : header_end + 1 + size]
            at = header_end + 1 + size + 1
            target = Path(tree, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            if link:  # a symlink's blob is its target; rustc follows it
                target.symlink_to(body.decode())
            else:
                target.write_bytes(body)
        gate.ROOT = Path(tree)
        try:
            base = Path(tree).resolve()
            rel = lambda paths: frozenset(
                p.relative_to(base).as_posix() for p in paths if p.is_relative_to(base)
            )
            live = gate.reachable()
            return rel(live), rel(gate.test_only_files(live))
        finally:
            gate.ROOT = ROOT


def outside_inventory(path: str, commit: str) -> bool:
    """Whether `path`'s functions are out of the inventory's scope at
    `commit`: it compiles only under test, or it is reached by no crate root
    (not compiled at all; the orphan gate reports that). A file named like a
    test but compiled outside tests is IN scope (MIK-8405.SPLIT.5)."""
    reachable, test_only = mount_status(ROOT, commit)
    return path in test_only or path not in reachable


def test_file_problems(base: str, head: str) -> list[str]:
    """Test-named `.rs` files `head` adds or changes on the COV.3 paths
    (every one with `--all`) that compile outside tests: their code would
    ship under a test's name (MIK-8405.SPLIT.5). An unreached file is the
    orphan gate's to report."""
    head = git("rev-parse", head).strip()
    merge_base = EMPTY_TREE if base == ALL else git("merge-base", base, head).strip()
    changed = git(
        "diff", "--name-only", "-z", "--no-renames", "--diff-filter=AM", merge_base, head, "--", *PREFIXES
    ).split("\0")
    reachable, test_only = mount_status(ROOT, head)
    return [
        f"{path}: named like a test file but compiled outside tests"
        for path in changed
        if path.endswith(".rs") and TEST_FILE.search(path) and path in reachable and path not in test_only
    ]


def added_functions(base: str, head: str) -> list[tuple[str, str, int, int]]:
    head = git("rev-parse", head).strip()
    merge_base = EMPTY_TREE if base == ALL else git("merge-base", base, head).strip()
    diff = git("diff", "-U0", "--no-renames", merge_base, head, "--", *PREFIXES)
    found: list[tuple[str, str, int, int]] = []
    path = None
    lines: list[str] = []
    code: list[str] = []
    tests: set[int] = set()
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            if path and (not path.endswith(".rs") or outside_inventory(path, head)):
                path = None
            if path:
                lines = (show(head, path) or "").splitlines()
                code = blanked(lines)
                tests = test_lines(code)
        elif line.startswith("@@"):
            new_line = int(re.match(r"@@ -\S+ \+(\d+)", line).group(1))
        elif line.startswith("+") and path:
            match = FN.match(line[1:])
            if match and new_line not in tests and not bodyless(code, new_line):
                name = match.group(1)
                found.append((path, name, new_line, occurrence(lines, name, new_line)))
            new_line += 1
    return found


def missing_rows(base: str, head: str) -> list[tuple[str, str, int, int]]:
    """Functions `head` adds since its merge-base with `base` that have no row
    in `head`: (file, fn, line, occurrence)."""
    head = git("rev-parse", head).strip()
    known = rows(head, INVENTORY) | rows(head, UNENFORCING)
    return [f for f in added_functions(base, head) if (f[0], f[1], f[3]) not in known]


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    head = argv[2] if len(argv) == 3 else "HEAD"
    try:
        resolved = git("rev-parse", head).strip()
        broken = ledger.overlap(list(ledger_rows(ROOT, resolved, INVENTORY)), list(ledger_rows(ROOT, resolved, UNENFORCING)))
        missing = missing_rows(argv[1], head)
        misnamed = test_file_problems(argv[1], resolved)
    except ledger.LedgerError as error:
        broken = error.problems
        missing = []
        misnamed = []
    for problem in broken:
        print(f"inventory: {problem}")
    if broken:
        print(f"{len(broken)} inventory problem(s); see inventory_ledger.py for the row rules.")
        return 1
    for problem in misnamed:
        print(f"test file: {problem}")
    if misnamed:
        print(
            f"{len(misnamed)} test-named file(s) are not mounted only for tests. Mount each "
            "under #[cfg(test)], or rename a file that is production code (MIK-8405.SPLIT.5)."
        )
    for path, name, line, nth in missing:
        print(f"no inventory row: {path}:{line} fn {name} (occurrence {nth})")
    if missing:
        print(
            f"{len(missing)} function(s) on the COV.3 paths have no row. Add each to "
            "docs/release/inventory.d/<pr>.critical.tsv (it enforces) or "
            "docs/release/inventory.d/<pr>.unenforcing.tsv (it does not, with a reason)."
        )
    if misnamed or missing:
        return 1
    scope = "on the COV.3 paths" if argv[1] == ALL else "added on the COV.3 paths"
    print(f"every function {scope} has a row")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
