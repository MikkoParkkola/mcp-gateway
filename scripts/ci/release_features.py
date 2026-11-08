#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Print the comma-separated feature list a release build may enable.

Every feature in Cargo.toml's [features] table except `default` and the
test-only ones. Release clippy takes this list instead of `--all-features`,
so a test-only feature (whose code refuses to compile without
debug_assertions) never reaches a release build, while a new feature joins
release clippy without anyone editing a list.

Fails when the list comes out empty, or when it still holds a test-only
feature, so a broken parse cannot turn release clippy into a no-op.
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Features that exist only for tests: never in a release build.
TEST_ONLY = frozenset({"sandbox-fixtures"})


def enabled(features: dict, name: str) -> set[str]:
    """Every feature of this crate that `name` switches on, itself included,
    following the [features] table (`dep:x` and `x/y` name dependencies, not
    this crate's features, and are skipped)."""
    seen, todo = set(), [name]
    while todo:
        f = todo.pop()
        if f in seen or f not in features:
            continue
        seen.add(f)
        todo.extend(e for e in features[f] if ":" not in e and "/" not in e)
    return seen


def release_features(manifest: dict) -> list[str]:
    features = manifest.get("features") or {}
    # An optional dependency named nowhere as `dep:x` gets an implicit feature
    # that is not in [features], so this list would silently leave it out of
    # the release build that --all-features used to cover.
    refs = {e for enables in features.values() for e in enables}
    tables = [manifest.get("dependencies") or {}]
    tables += [t.get("dependencies") or {} for t in (manifest.get("target") or {}).values()]
    implicit = sorted(
        name
        for table in tables
        for name, spec in table.items()
        if isinstance(spec, dict) and spec.get("optional") and f"dep:{name}" not in refs
    )
    if implicit:
        raise SystemExit(f"release-features: optional dependencies without a dep: feature: {implicit}")
    # A renamed test-only feature must not slip into release unnoticed.
    gone = TEST_ONLY.difference(features)
    if features and gone:
        raise SystemExit(f"release-features: test-only features missing from Cargo.toml: {sorted(gone)}")
    picked = sorted(f for f in features if f != "default" and f not in TEST_ONLY)
    if not picked:
        raise SystemExit("release-features: no features found in Cargo.toml")
    # A release feature (or `default`) that switches a test-only one on would
    # carry it into release builds through the list.
    for f in [*picked, "default"]:
        reached = TEST_ONLY.intersection(enabled(features, f))
        if reached:
            raise SystemExit(f"release-features: {f} enables test-only {sorted(reached)}")
    return picked


def main() -> int:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    print(",".join(release_features(manifest)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
