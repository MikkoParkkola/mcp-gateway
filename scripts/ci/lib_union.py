#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The per-run union check over the lib test part binaries (the gate the part jobs need).

Each part leg uploads `linux-lib-tests-pK/pK/list.txt`, its binary's unfiltered `--list` (a macOS leg uploads all its
parts' `pK/list.txt` as one artifact). `test_parts.py expect` writes `pK.txt`, the names that part must list. This fails
unless the parts present are exactly 1..N (N from the build script), each part has one list, each list equals its
expected set name for name, no part is empty, and no name sits in two parts.

Usage: lib_union.py LISTS_DIR EXPECTED_DIR [BUILD_SCRIPT]"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BUILD_SCRIPT = Path("scripts/dev/test-parts-build.rs")


def part_count(build: Path) -> int:
    m = re.search(r"const\s+N\s*:\s*u32\s*=\s*(\d+)\s*;", build.read_text(encoding="utf-8"))
    if m is None:
        raise SystemExit(f"{build}: no `const N: u32`")
    return int(m.group(1))


def listed(path: Path) -> set[str]:
    return {line[: -len(": test")] for line in path.read_text(encoding="utf-8").splitlines() if line.endswith(": test")}


def problems(lists_dir: Path, expected_dir: Path, build: Path = BUILD_SCRIPT) -> list[str]:
    n = part_count(build)
    # `pK/list.txt` at any depth: download-artifact puts each artifact in a folder of its name, except when the
    # pattern matches only one (the os-sensitive lane's lone macOS leg), which it unpacks into LISTS_DIR itself.
    paths: dict[int, list[Path]] = {}
    for p in sorted(lists_dir.glob("**/p*/list.txt")):
        if m := re.fullmatch(r"p(\d+)", p.parent.name):
            paths.setdefault(int(m.group(1)), []).append(p)
    found = {k: ps[0] for k, ps in paths.items()}
    out = [f"part {k} has {len(ps)} lists: {[str(p.relative_to(lists_dir)) for p in ps]}"
           for k, ps in sorted(paths.items()) if len(ps) > 1]
    out += [f"part {k} was not built (no list)" for k in range(1, n + 1) if k not in found]
    out += [f"part {k} is outside 1..={n}" for k in sorted(found) if not 1 <= k <= n]
    owner: dict[str, int] = {}
    for k in sorted(found):
        if not 1 <= k <= n:
            continue
        got = listed(found[k])
        exp_path = expected_dir / f"p{k}.txt"
        want = set(exp_path.read_text(encoding="utf-8").split()) if exp_path.is_file() else set()
        if not got:
            out.append(f"part {k} lists no test")
        for name in sorted(want - got):
            out.append(f"part {k} does not list {name}, which the source puts in it")
        for name in sorted(got - want):
            out.append(f"part {k} lists {name}, which the source does not put in it")
        for name in got:
            if name in owner:
                out.append(f"{name} is in two parts: {owner[name]} and {k}")
            owner.setdefault(name, k)
    return out


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    found = problems(Path(argv[1]), Path(argv[2]), Path(argv[3]) if len(argv) == 4 else BUILD_SCRIPT)
    for p in found[:200]:
        print(f"::error::lib union: {p}")
    print(f"lib union: {len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
