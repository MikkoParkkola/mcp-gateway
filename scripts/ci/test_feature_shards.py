#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The feature-combination shards cover exactly the documented matrix.

feature-combos.yml runs the supported feature combinations in a few shards,
each shard a list of combinations. This fails when a combination is missing
from every shard, appears twice, or is not in
docs/release/v4.0.0-supported-matrix.md (and the other way round), so a
combination cannot silently drop out.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def shard_combos(workflow: dict) -> dict[str, list[str]]:
    include = workflow["jobs"]["feature-combos"]["strategy"]["matrix"].get("include") or []
    incomplete = [e for e in include if not (isinstance(e, dict) and e.get("shard") and e.get("combos"))]
    if incomplete:
        # Actions still launches such a row, and its loop checks nothing.
        raise SystemExit(f"feature-shards: matrix rows without a shard name or combos: {incomplete}")
    names = [e["shard"] for e in include]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        # A dict keyed by name would silently drop the repeated shard.
        raise SystemExit(f"feature-shards: duplicate shard names: {dup}")
    return {e["shard"]: [c.strip() for c in e["combos"].splitlines() if c.strip()] for e in include}


def documented(text: str) -> list[str]:
    return re.findall(r"^\|\s*`([^`]+)`\s*\|\s*`feature-combos`\s*\|", text, flags=re.M)


def check(shards: dict[str, list[str]], docs: list[str]) -> list[str]:
    errors = []
    flat = [c for combos in shards.values() for c in combos]
    for shard, combos in shards.items():
        if not combos:
            errors.append(f"shard {shard!r} runs nothing")
    dup = sorted({c for c in flat if flat.count(c) > 1})
    if dup:
        errors.append(f"combinations in more than one shard: {dup}")
    missing = sorted(set(docs) - set(flat))
    extra = sorted(set(flat) - set(docs))
    if missing:
        errors.append(f"documented combinations no shard runs: {missing}")
    if extra:
        errors.append(f"shard combinations the matrix doc does not list: {extra}")
    if not docs:
        errors.append("no feature-combos rows found in the matrix doc")
    return errors


def table_problems(shards: dict[str, list[str]], table: str) -> list[str]:
    """The lib test split's CI table (scripts/dev/test-parts-ci.tsv, read by `test_parts.py expect` to decide which
    tests compile nowhere) records exactly the feature sets the workflows pass: on x86_64-unknown-linux-gnu,
    `--all-features` and every combination here without a target; on each `--target`, that target's combinations.
    Rows with a custom cfg (coverage, kani, ...) are other jobs' builds and stay out of the comparison."""
    linux = "x86_64-unknown-linux-gnu"
    want: dict[str, set[str]] = {linux: {"--all-features"}}
    for combos in shards.values():
        for combo in combos:
            m = re.search(r"\s--target\s+(\S+)", combo)
            want.setdefault(m.group(1) if m else linux, set()).add(re.sub(r"\s*--target\s+\S+", "", combo).strip())
    got: dict[str, set[str]] = {t: set() for t in want}
    for line in table.splitlines():
        cols = line.split("\t")
        if line.startswith("#") or cols[0] != "config" or len(cols) < 3 or cols[1] not in got:
            continue
        if len(cols) > 3 and cols[3].strip():
            continue
        got[cols[1]].add(cols[2])
    return [f"test-parts-ci.tsv, {t}: rows missing {sorted(want[t] - got[t])}, rows no workflow passes "
            f"{sorted(got[t] - want[t])}" for t in sorted(want) if got[t] != want[t]]


def self_test() -> list[str]:
    docs = ["--a", "--b", "--c"]
    cases = {
        "complete": ({"x": ["--a", "--b"], "y": ["--c"]}, 0),
        "dropped": ({"x": ["--a"], "y": ["--c"]}, 1),
        "duplicated": ({"x": ["--a", "--b"], "y": ["--b", "--c"]}, 1),
        "undocumented": ({"x": ["--a", "--b"], "y": ["--c", "--d"]}, 1),
        "empty shard": ({"x": ["--a", "--b", "--c"], "y": []}, 1),
    }
    out = []
    for name, (shards, want) in cases.items():
        if bool(check(shards, docs)) != bool(want):
            out.append(f"self-test case {name!r} misclassified")
    shards = {"x": ["--features default", "--no-default-features"], "w": ["--all-features --target t-gnu"]}
    rows = ("config\tx86_64-unknown-linux-gnu\t--all-features\t\n"
            "config\tx86_64-unknown-linux-gnu\t--features default\t\n"
            "config\tx86_64-unknown-linux-gnu\t--no-default-features\t\n"
            "config\tt-gnu\t--all-features\t\n")
    table_cases = {
        "table matches": (rows, 0),
        "a custom-cfg row is another job's": (rows + "config\tx86_64-unknown-linux-gnu\t--features z\tcoverage\n", 0),
        "a combination missing from the table": (rows.replace("--no-default-features\t\n", "--features x\t\n"), 1),
        "a row no workflow passes": (rows + "config\tx86_64-unknown-linux-gnu\t--features y\t\n", 1),
        "the target's row missing": (rows.replace("config\tt-gnu\t--all-features\t\n", ""), 1),
    }
    for name, (table, want) in table_cases.items():
        if bool(table_problems(shards, table)) != bool(want):
            out.append(f"self-test case {name!r} misclassified")
    return out


def main() -> int:
    errors = self_test()
    workflow = yaml.safe_load((ROOT / ".github/workflows/feature-combos.yml").read_text(encoding="utf-8"))
    docs = documented((ROOT / "docs/release/v4.0.0-supported-matrix.md").read_text(encoding="utf-8"))
    shards = shard_combos(workflow)
    errors += check(shards, docs)
    errors += table_problems(shards, (ROOT / "scripts/dev/test-parts-ci.tsv").read_text(encoding="utf-8"))
    for e in errors:
        print(f"feature-shards: {e}", file=sys.stderr)
    if not errors:
        n = sum(len(c) for c in shards.values())
        print(f"feature-shards: {n} documented combinations in {len(shards)} shards, each exactly once")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
