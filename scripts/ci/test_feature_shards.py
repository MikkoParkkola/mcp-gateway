#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The feature-combination shards cover exactly the documented matrix.

ci.yml runs the supported feature combinations in a few shards, each shard a
list of combinations. This fails when a combination is missing from every
shard, appears twice, or is not in docs/release/v4.0.0-supported-matrix.md
(and the other way round), so a combination cannot silently drop out.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def shard_combos(workflow: dict) -> dict[str, list[str]]:
    include = workflow["jobs"]["feature-combos"]["strategy"]["matrix"].get("include") or []
    include = [e for e in include if "shard" in e and "combos" in e]
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
    return out


def main() -> int:
    errors = self_test()
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    docs = documented((ROOT / "docs/release/v4.0.0-supported-matrix.md").read_text(encoding="utf-8"))
    shards = shard_combos(workflow)
    errors += check(shards, docs)
    for e in errors:
        print(f"feature-shards: {e}", file=sys.stderr)
    if not errors:
        n = sum(len(c) for c in shards.values())
        print(f"feature-shards: {n} documented combinations in {len(shards)} shards, each exactly once")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
