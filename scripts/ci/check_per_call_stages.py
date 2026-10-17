#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8014: no per-call stage lands unmeasured.

Every `fn` in the checked files must be listed in one of the two
authoritative table parts -- docs/internal/perf/per_call_stages.tsv
(meta/router rows) and its required companion
docs/internal/perf/per_call_stages_stdio.tsv (`src/gateway/server/` rows)
-- with the per-call timing row that covers it, or with `-` and a reason.
The normal inventory reads both parts together, in that order; either
part missing fails the check rather than silently dropping its rows.
A reason may say a function is on the per-call path but untimed (the
harness never exercises its condition); it
may not present that as the function costing nothing. Every row the table
names must be a stage in the harness's `STAGES` table, which the gate then
requires to print. A new layer on the path therefore adds a table entry or
fails here.

The checked set is derived, not a fixed file list (F1: the stdio path moved
out of server/mod.rs into stdio_*.rs child modules and escaped a fixed
list, and a later family-prefix filter still let invoke/budget.rs and any
arbitrarily named new child module escape). The tools/call path has five
anchor modules (design r4 K-M6: the HTTP handler, the meta wrapper chain,
the stdio request path). The checked set is each anchor plus every
non-test `.rs` file under the anchor's child-module directory (`mod.rs`:
its own directory; `x.rs`: the `x/` directory beside it), whatever the
file is named. Files under a `tests/` directory and `*_tests.rs` files are
excluded. A stage split into a new child module of an anchor -- by any
name, such as server/new_stage.rs or invoke/budget_extension.rs -- is
checked the moment the file lands; only a stage under a wholly new
top-level module, outside every anchor's child directory, still needs a
new anchor here.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TABLE = ROOT / "docs/internal/perf/per_call_stages.tsv"
TABLE_STDIO = ROOT / "docs/internal/perf/per_call_stages_stdio.tsv"
HARNESS = ROOT / "src/gateway/server/tests/per_call_timing.rs"
TEST_MOD = re.compile(
    r"^#\[cfg\((?:all\()?test\b[^\n]*\n(?:#\[[^\n]*\n)*\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+",
    re.M,
)
# The tools/call path anchor modules; see the docstring for the rule.
ANCHORS = [
    "src/gateway/router/handlers.rs",
    "src/gateway/meta_mcp/grant_audit.rs",
    "src/gateway/meta_mcp/call_dispatch.rs",
    "src/gateway/meta_mcp/invoke.rs",
    "src/gateway/server/mod.rs",
]


def is_test_file(path):
    """A `*_tests.rs` file, or any file under a `tests/` directory."""
    return path.stem.endswith("_tests") or "tests" in path.parts


def child_dir(anchor):
    """Where an anchor module's child modules live (Rust's rule)."""
    if anchor.name == "mod.rs":
        return anchor.parent
    return anchor.parent / anchor.stem


def path_files(root=ROOT):
    """The checked files, as sorted root-relative paths: the anchors plus
    every non-test `.rs` file under each anchor's child-module directory,
    derived as the docstring states."""
    found = set()
    for rel in ANCHORS:
        anchor = root / rel
        found.add(rel)
        base = child_dir(anchor)
        if not base.is_dir():
            continue
        for path in base.rglob("*.rs"):
            rel_path = path.relative_to(root)
            if is_test_file(rel_path):
                continue
            found.add(rel_path.as_posix())
    return sorted(found)


def without_test_modules(source):
    """The source with each inline cfg(test) module's body removed: its
    helpers are not stages. A file-mounted `mod x;` carries no body here, and
    nothing after a test module is dropped."""
    out, at = [], 0
    for m in TEST_MOD.finditer(source):
        rest = source[m.end():]
        brace = len(rest) - len(rest.lstrip())
        if not rest[brace:].startswith("{"):
            continue  # `mod x;`: the body lives in another file
        depth, end = 0, m.end() + brace
        for i in range(end, len(source)):
            depth += {"{": 1, "}": -1}.get(source[i], 0)
            if depth == 0:
                end = i + 1
                break
        out.append(source[at:m.start()])
        at = end
    return "".join(out) + source[at:]


def stages(harness=HARNESS):
    """The harness's STAGES names: the first string in each table entry
    (every entry's only string literal, F6)."""
    text = pathlib.Path(harness).read_text()
    block = re.search(r"const STAGES\b[^=]*=\s*&\[(.*?)\];", text, re.S)
    if not block:
        sys.exit(f"{harness}: no STAGES table")
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def _table_paths(path):
    """The table part(s) to read, in deterministic order. No path, or the
    main TABLE itself, means the normal inventory: both authoritative
    parts. Any other single path is a caller's own fixture and stays a
    single file; a list or tuple names its parts explicitly."""
    if path is None:
        return (TABLE, TABLE_STDIO)
    if isinstance(path, (list, tuple)):
        return tuple(path)
    if pathlib.Path(path) == TABLE:
        return (TABLE, TABLE_STDIO)
    return (path,)


def table(path=None):
    """Every (file, fn) -> (row, reason) entry across the table part(s).
    A missing part fails closed, and a (file, fn) listed twice -- in one
    part or across parts -- is an error, never a silent overwrite."""
    rows = {}
    origins = {}
    for part in _table_paths(path):
        part = pathlib.Path(part)
        try:
            lines = part.read_text().splitlines()
        except OSError as err:
            sys.exit(f"{part}: required per-call stage table part is missing or unreadable ({err})")
        for n, line in enumerate(lines, 1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                sys.exit(f"{part}:{n}: want file, fn, row, reason (tab-separated)")
            file, fn, row, reason = parts
            if (file, fn) in rows:
                sys.exit(
                    f"{part}:{n}: duplicate entry for {file} {fn} "
                    f"(already listed at {origins[(file, fn)]})"
                )
            rows[(file, fn)] = (row, reason)
            origins[(file, fn)] = f"{part}:{n}"
    return rows


def check(root=ROOT, table_path=TABLE, harness_path=HARNESS):
    """Every way the inventory disagrees with the tree, as error strings."""
    known = stages(harness_path)
    rows = table(table_path)
    errors = []
    for (file, fn), (row, reason) in rows.items():
        if row != "-" and row not in known:
            errors.append(f"{file} {fn}: row '{row}' is not in STAGES {sorted(known)}")
        if row == "-" and not reason.strip():
            errors.append(f"{file} {fn}: off the per-call path needs a reason")
    present = {}
    for file in path_files(root):
        source = (root / file).read_text()
        source = without_test_modules(source)
        present[file] = set(re.findall(r"\bfn ([a-z_][a-z0-9_]*)", source))
        for fn in sorted(present[file]):
            if (file, fn) not in rows:
                errors.append(f"{file} {fn}: no entry in {TABLE.relative_to(ROOT)}")
    # A row whose function moved or went away would vouch for nothing.
    for file, fn in rows:
        if file not in present:
            errors.append(f"{file} {fn}: the file is not in the checked set")
        elif fn not in present[file]:
            errors.append(f"{file} {fn}: in the table but not in the file (stale row)")
    return errors


def main():
    errors = check()
    if errors:
        print("\n".join(errors))
        print(f"{len(errors)} per-call stage(s) unaccounted for (MIK-8014)")
        return 1
    print(f"every function on the {len(path_files())} tools/call path files has a stage entry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
