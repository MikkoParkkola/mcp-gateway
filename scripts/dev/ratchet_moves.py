#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The moved-text rule the shrink-only baselines share (MIK-8283, MIK-8291).

A baseline keyed by file path reads a split or a rename as a new allowance.
These two functions let a gate tell a move from growth: a new row may hold
only items (lines, asserts) that left a row which shrank, matched by exact
text, and each moved item is spent once. What a row's size and the total mean
stays with each gate; this module only matches.

Text changed on the way does not match, so a move keeps moved text identical.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping


def gone(
    base_items: Mapping[str, list[str]],
    head_items: Mapping[str, list[str]],
    shrunk: Iterable[str],
) -> Counter[str]:
    """The items that left the rows in `shrunk`: each one's base items less
    its head items, as one multiset."""
    moved: Counter[str] = Counter()
    for path in shrunk:
        moved += Counter(base_items.get(path, [])) - Counter(head_items.get(path, []))
    return moved


def carry(new_rows: Mapping[str, list[str]], moved: Counter[str]) -> dict[str, int]:
    """How many of each new row's items match `moved`, in path order. A
    matched item is spent, so two new rows cannot claim the same move."""
    left = Counter(moved)
    carried = {}
    for path in sorted(new_rows):
        took = Counter(new_rows[path]) & left
        left -= took
        carried[path] = sum(took.values())
    return carried
