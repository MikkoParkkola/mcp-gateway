# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Whether a Python test that cannot run on this host (a missing tool) must fail instead of skipping.

TESTS_REQUIRE_ALL: unset -> CI decides (the value `true` in any case, or `1`, means required); `0` -> not required,
whatever CI says; `1` -> required; any other value is an error naming it, so a typo cannot silently turn it off.
The Rust helper reads the same variable (crate::test_wait::required_mode). Rows: scripts/ci/test_required_mode.py.
"""
from __future__ import annotations

import os
import unittest
from typing import Mapping


def required(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    value = env.get("TESTS_REQUIRE_ALL")
    if value is None:
        return env.get("CI", "").lower() in ("true", "1")
    if value == "0":
        return False
    if value == "1":
        return True
    raise ValueError(f"TESTS_REQUIRE_ALL must be 0 or 1 when set, got {value!r}")


def skip_or_fail(case: unittest.TestCase, requirement: str, env: Mapping[str, str] | None = None) -> None:
    """Skip the test, or fail it naming the requirement where required mode is on."""
    if required(env):
        case.fail(f"required here but unavailable on this host: {requirement}")
    case.skipTest(f"{requirement} is not available here")
