#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MIK-8014: no per-call stage lands unmeasured.

Every `fn` in the tools/call path files must be listed in
docs/internal/perf/per_call_stages.tsv with the per-call timing row that covers
it, or with `-` and a reason (not on the per-call path). Every row the table
names must be a stage in the harness's `STAGES` table, which the gate then
requires to print. A new layer on the path therefore adds a table entry or
fails here.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TABLE = ROOT / "docs/internal/perf/per_call_stages.tsv"
HARNESS = ROOT / "src/gateway/server/tests/per_call_timing.rs"
TEST_MOD = re.compile(
    r"^#\[cfg\((?:all\()?test\b[^\n]*\n(?:#\[[^\n]*\n)*\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+",
    re.M,
)
# The tools/call path (design r4 K-M6): the HTTP handler, the meta wrapper
# chain, and the stdio request path.
PATH_FILES = [
    "src/gateway/router/handlers.rs",
    "src/gateway/router/handlers/dispatch_intake.rs",
    "src/gateway/router/handlers/dispatch_tools_call.rs",
    "src/gateway/meta_mcp/grant_audit.rs",
    "src/gateway/meta_mcp/call_dispatch.rs",
    "src/gateway/meta_mcp/invoke/dispatch.rs",
    "src/gateway/meta_mcp/invoke.rs",
    # The stdio request path (secE, MIK-8176 stage 2 wrap; lead ruling).
    "src/gateway/server/mod.rs",
    "src/gateway/server/stdio_notify.rs",
]


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


def stages():
    text = HARNESS.read_text()
    block = re.search(r"const STAGES: &\[&str\] = &\[(.*?)\];", text, re.S)
    if not block:
        sys.exit(f"{HARNESS}: no STAGES table")
    return set(re.findall(r'"([^"]+)"', block.group(1)))


def table():
    rows = {}
    for n, line in enumerate(TABLE.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 4:
            sys.exit(f"{TABLE}:{n}: want file, fn, row, reason (tab-separated)")
        file, fn, row, reason = parts
        rows[(file, fn)] = (row, reason)
    return rows


def main():
    known = stages()
    rows = table()
    errors = []
    for (file, fn), (row, reason) in rows.items():
        if row != "-" and row not in known:
            errors.append(f"{file} {fn}: row '{row}' is not in STAGES {sorted(known)}")
        if row == "-" and not reason.strip():
            errors.append(f"{file} {fn}: off the per-call path needs a reason")
    present = {}
    for file in PATH_FILES:
        source = (ROOT / file).read_text()
        source = without_test_modules(source)
        present[file] = set(re.findall(r"\bfn ([a-z_][a-z0-9_]*)", source))
        for fn in sorted(present[file]):
            if (file, fn) not in rows:
                errors.append(f"{file} {fn}: no entry in {TABLE.relative_to(ROOT)}")
    # A row whose function moved or went away would vouch for nothing.
    for file, fn in rows:
        if file not in present:
            errors.append(f"{file} {fn}: the file is not one of PATH_FILES")
        elif fn not in present[file]:
            errors.append(f"{file} {fn}: in the table but not in the file (stale row)")
    if errors:
        print("\n".join(errors))
        print(f"{len(errors)} per-call stage(s) unaccounted for (MIK-8014)")
        return 1
    print(f"every function on the {len(PATH_FILES)} tools/call path files has a stage entry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
