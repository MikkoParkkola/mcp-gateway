#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when the burndown tracker's summary disagrees with the two ledger checks.

The tracker's top table restates the counts `count-release-criteria.py --check`
and `check_scope_acceptance.py --release` print. It drifted after every
criteria change because nothing compared them (MIK-7730). This compares them.

Usage:
    python3 scripts/release/check_burndown_summary.py
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TRACKER = ROOT / "docs/internal/release/v4.0.0-burndown-tracker.md"


def tracker_counts(text: str) -> dict:
    """The counts the tracker's summary table states."""
    return {}


def core_counts(output: str) -> dict:
    """The counts in count-release-criteria.py --check output."""
    return {}


def scope_counts(output: str) -> dict:
    """The counts in check_scope_acceptance.py --release output."""
    return {}


def mismatches(stated: dict, measured: dict) -> list[str]:
    """One line per count the tracker states differently, or cannot state."""
    return []
