#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Self-test for release_features.py: the release feature list drops
`default` and every test-only feature, keeps every other feature, and
refuses an empty table."""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_features import ROOT, TEST_ONLY, release_features  # noqa: E402


def refuses(manifest: dict) -> bool:
    try:
        release_features(manifest)
    except SystemExit:
        return True
    return False


def main() -> int:
    toy = {"features": {"default": ["a"], "a": [], "b": [], "sandbox-fixtures": []}}
    assert release_features(toy) == ["a", "b"], release_features(toy)
    assert refuses({"features": {}}), "an empty table was accepted"
    assert refuses({"features": {"default": [], "sandbox-fixtures": []}}), "a test-only-only table was accepted"
    assert refuses({}), "a manifest without [features] was accepted"
    assert refuses({"features": {"a": []}}), "a manifest without the test-only feature was accepted"
    # Transitive: a release feature, or default, that switches a test-only one on.
    assert refuses({"features": {"a": ["b"], "b": ["sandbox-fixtures"], "sandbox-fixtures": []}}), "a two-step enable was accepted"
    assert refuses({"features": {"default": ["sandbox-fixtures"], "a": [], "sandbox-fixtures": []}}), "default enabling it was accepted"
    # A dependency feature of the same name is not this crate's feature.
    dep = {"features": {"a": ["dep:sandbox-fixtures", "x/sandbox-fixtures"], "sandbox-fixtures": []}}
    assert release_features(dep) == ["a"], release_features(dep)

    # The real manifest: every non-default, non-test-only feature is listed.
    real = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    listed = release_features(real)
    expected = sorted(set(real["features"]) - {"default"} - TEST_ONLY)
    assert listed == expected, (listed, expected)
    assert not TEST_ONLY.intersection(listed), listed
    print(f"release-features: OK ({len(listed)} features)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
