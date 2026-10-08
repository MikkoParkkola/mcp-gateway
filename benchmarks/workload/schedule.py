#!/usr/bin/env python3
"""The graded run's cell order: a counterbalanced 18-rep design.

A fresh shuffle per rep (the diagnostic default) does not balance slots in
18 reps. Under seed 20261007 the candidate C sat at mean slot 2.61 against
3.11 (A) and 3.06 (B), so C ran earlier in a rep than the cells it is compared
with, and any within-rep drift biased the comparison.

The graded design instead:
  * 15 rows from three Latin squares on A..E (steps 1, 2 and 3): every cell
    sits in every slot exactly 3 times. With five cells only two cyclic
    neighbour structures exist, and steps 2 and 3 are the same pairs in
    reverse, so directed carryover is only partly balanced: each cell has one
    other cell that never immediately follows it. The balance this design
    guarantees is by slot, not by predecessor;
  * 3 rows chosen so the gated cells A, B and C each take slots summing to 9,
    which makes their mean slot exactly 3.0 over all 18 reps. D and E, which
    are report-only, absorb the remainder (2.89 and 3.11).
The 18 rows then run in an order shuffled by the seed. Shuffling whole rows
keeps every slot count, so the balance does not depend on the seed.

Run: python3 benchmarks/workload/schedule.py SEED REP   -> the cells of REP
"""

from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path

CELLS = "ABCDE"
GRADED_REPS = 18
GRADED_SEED = 20261007
GATED = "ABC"
EXTRA_ROWS = ("ABCDE", "CDBEA", "DEABC")

# Contract §9: a graded run runs on bench-host. The host is named by an
# app-specific hash of its machine-id, never the raw id, which systemd treats
# as confidential (machine-id(5)).
HOST_ID_PREFIX = "mcp-gateway-workload-v1:"
BENCH_HOST_ID = "02e36bb9d76598a7b1218b5ba2e13d95868b5b6ebea93ff216be8a6c413a3dd8"


def host_id(machine_id: Path = Path("/etc/machine-id")) -> str | None:
    """This host's workload id, or None when it has no readable machine-id."""
    try:
        raw = machine_id.read_text().strip()
    except OSError:
        return None
    if not raw:
        return None
    return hashlib.sha256((HOST_ID_PREFIX + raw).encode()).hexdigest()


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
    if sys.argv[1:] == ["host-id"]:
        print(host_id() or "")
        sys.exit(0)
    if sys.argv[1:2] == ["is-bench-host"]:
        # This host, or the id given: exit 0 only for bench-host.
        given = sys.argv[2] if len(sys.argv) > 2 else host_id()
        sys.exit(0 if given == BENCH_HOST_ID else 1)
    seed, rep = int(sys.argv[1]), int(sys.argv[2])
    print(" ".join(graded_orders(seed)[rep - 1]))
