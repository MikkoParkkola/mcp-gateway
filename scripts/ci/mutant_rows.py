#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The in-process mutant check the affected-map suites share: each mutant patches attributes of the module under
test, and the row class it names must then fail an assertion. A mutant that only crashes the row proves nothing
about what the row checks, so errors do not count."""
from __future__ import annotations

import io
import unittest
from types import ModuleType


def check_mutants(test: unittest.TestCase, module: ModuleType, mutants: list[tuple[str, str, dict]],
                  rows: dict[str, type]) -> None:
    """For each (name, row class name, {attribute: replacement}) in `mutants`: patch `module`, run the named class
    out of `rows`, restore, and require at least one failing assertion."""
    for name, target, patch in mutants:
        with test.subTest(mutant=name):
            saved = {k: getattr(module, k) for k in patch}
            for k, v in patch.items():
                setattr(module, k, v)
            try:
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(rows[target])
                outcome = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
            finally:
                for k, v in saved.items():
                    setattr(module, k, v)
            test.assertTrue(outcome.failures, f"{name}: {target} had no failing assertion "
                            f"({len(outcome.errors)} errors)")
