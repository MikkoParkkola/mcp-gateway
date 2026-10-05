#!/usr/bin/env python3
"""The graded run's cell order: a counterbalanced 18-rep design.

A fresh shuffle per rep (the diagnostic default) does not balance slots in
18 reps. Under seed 20261007 the candidate C sat at mean slot 2.61 against
3.11 (A) and 3.06 (B), so C ran earlier in a rep than the cells it is compared
with, and any within-rep drift biased the comparison.

The graded design instead:
  * 15 rows from three Latin squares on A..E (steps 1, 2 and 3, so each cell
    has different neighbours in each square): every cell sits in every slot
    exactly 3 times;
  * 3 rows chosen so the gated cells A, B and C each take slots summing to 9,
    which makes their mean slot exactly 3.0 over all 18 reps. D and E, which
    are report-only, absorb the remainder (2.89 and 3.11).
The 18 rows then run in an order shuffled by the seed. Shuffling whole rows
keeps every slot count, so the balance does not depend on the seed.

Run: python3 benchmarks/workload/schedule.py SEED REP   -> the cells of REP
"""

from __future__ import annotations

import random
import sys

CELLS = "ABCDE"
GRADED_REPS = 18
GRADED_SEED = 20261007
GATED = "ABC"
EXTRA_ROWS = ("ABCDE", "CDBEA", "DEABC")


def _rows() -> list[str]:
    squares = [
        "".join(CELLS[(step * slot + shift) % 5] for slot in range(5))
        for step in (1, 2, 3)
        for shift in range(5)
    ]
    return squares + list(EXTRA_ROWS)


def graded_orders(seed: int) -> list[list[str]]:
    """The 18 rep orders of a graded run, rep 1 first."""
    rows = _rows()
    random.Random(f"{seed}:graded").shuffle(rows)
    return [list(row) for row in rows]


def balance_problems(orders: list[list[str]]) -> list[str]:
    """Why `orders` is not the planned graded schedule's balance; empty if it is."""
    problems = []
    if len(orders) != GRADED_REPS:
        problems.append(f"{len(orders)} reps, not {GRADED_REPS}")
    for n, order in enumerate(orders, 1):
        if sorted(order) != list(CELLS):
            problems.append(f"rep {n} order {order} is not a permutation of {CELLS}")
    if problems:
        return problems
    for cell in CELLS:
        slots = [order.index(cell) + 1 for order in orders]
        counts = [slots.count(s) for s in range(1, 6)]
        if any(c not in (3, 4) for c in counts):
            problems.append(f"cell {cell} slot counts {counts} are not all 3 or 4")
        if cell in GATED and sum(slots) != 3 * GRADED_REPS:
            problems.append(f"gated cell {cell} mean slot {sum(slots) / GRADED_REPS:.2f} is not 3.00")
    return problems


if __name__ == "__main__":
    seed, rep = int(sys.argv[1]), int(sys.argv[2])
    print(" ".join(graded_orders(seed)[rep - 1]))
