#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The COV.3 function inventory, read as a base TSV plus per-PR fragments (MIK-8279).

This is the only reader of the inventory. `check_inventory_rows.py` and
`critical_function_coverage.py` both load through it, so every reader sees
the same rows.

Two ledgers:

  docs/release/v4.0.0-critical-functions.tsv     enforces (tier critical/standard)
  docs/release/v4.0.0-unenforcing-functions.tsv  reviewed: enforces nothing

A PR that adds rows writes them to its own fragment files, so no two PRs edit
the same file:

  docs/release/inventory.d/<pr>.critical.tsv      the critical columns
  docs/release/inventory.d/<pr>.unenforcing.tsv   the unenforcing columns
  (<pr>-<n>.<ledger>.tsv for a second file)

A fragment has no header row. Blank lines and lines starting with `#` are
skipped. An edit or removal of an existing row is made where the row lives;
a move between ledgers is a removal there plus an add in a fragment.

Every row is checked, base and fragment alike. A key (path, fn, occurrence)
stated twice in a ledger, a malformed row, or a misnamed fragment is an
error naming its location; nothing is skipped.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

CRITICAL = "critical"
UNENFORCING = "unenforcing"
COLUMNS = {
    CRITICAL: ("path", "fn", "occurrence", "tier", "category", "qualified", "reason"),
    UNENFORCING: ("path", "fn", "occurrence", "reason"),
}
TIERS = ("critical", "standard")
FRAGMENT_DIR = "inventory.d"
# ASCII digits only: `\d` would also accept other scripts' digits.
NAME = re.compile(r"^[0-9]+(?:-[0-9]+)?\.(critical|unenforcing)\.tsv$")


class LedgerError(Exception):
    """Every problem found while reading, one message per location."""

    def __init__(self, problems: list[str]):
        super().__init__("\n".join(problems))
        self.problems = problems


def parse(ledger: str, where: str, text: str, *, header: bool) -> tuple[list[dict], list[str]]:
    """The rows of one file, each with its `where` (file:line), and the problems.

    A base file starts with its header row; a fragment has none."""
    columns = COLUMNS[ledger]
    rows, problems = [], []
    expect_header = header
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        at = f"{where}:{number}"
        if expect_header:
            expect_header = False
            if tuple(cells) != columns:
                problems.append(f"{at}: the header must be {chr(9).join(columns)!r}")
            continue
        if len(cells) != len(columns):
            problems.append(f"{at}: {len(cells)} columns, a {ledger} row has {len(columns)}")
            continue
        row = dict(zip(columns, cells))
        if not row["path"] or not row["fn"]:
            problems.append(f"{at}: path and fn must not be empty")
        if not row["occurrence"].isdigit() or int(row["occurrence"]) < 1:
            problems.append(f"{at}: occurrence {row['occurrence']!r} is not a whole number from 1")
        if ledger == CRITICAL and row["tier"] not in TIERS:
            problems.append(f"{at}: tier {row['tier']!r} is not one of {', '.join(TIERS)}")
        if not row["reason"].strip():
            problems.append(f"{at}: the reason must not be empty")
        row["where"] = at
        rows.append(row)
    if expect_header:
        problems.append(f"{where}: no header row")
    return rows, problems


def key(row: dict) -> tuple[str, str, int]:
    return (row["path"], row["fn"], int(row["occurrence"]))


def merge(ledger: str, base: tuple[str, str], fragments: list[tuple[str, str]]) -> list[dict]:
    """The ledger's rows: its base file plus every fragment, as (name, text) pairs.

    `fragments` is every `*.tsv` in the fragment directory, so a misnamed
    file is caught here; those named for the other ledger are skipped."""
    rows, problems = parse(ledger, base[0], base[1], header=True)
    for name, text in sorted(fragments):
        match = NAME.match(Path(name).name)
        if not match:
            problems.append(f"{name}: a fragment is named <pr>[-<n>].critical.tsv or <pr>[-<n>].unenforcing.tsv")
            continue
        if match.group(1) != ledger:
            continue
        found, wrong = parse(ledger, name, text, header=False)
        rows += found
        problems += wrong
    seen: dict[tuple[str, str, int], str] = {}
    for row in rows:
        try:
            k = key(row)
        except ValueError:
            continue  # already reported as a bad occurrence
        if k in seen:
            problems.append(f"{row['where']}: {k[0]} {k[1]} occurrence {k[2]} is already rowed at {seen[k]}")
        else:
            seen[k] = row["where"]
    if problems:
        raise LedgerError(problems)
    return rows


def listed_fragments(names: list[str]) -> list[str]:
    """The one listing rule both loaders apply to a directory's entries:
    every `*.tsv`, misnamed or not, so `merge` judges each name."""
    return sorted(n for n in names if n.endswith(".tsv"))


def load_files(ledger: str, base: Path) -> list[dict]:
    """The ledger as the filesystem has it: `base` plus the `*.tsv` files in
    `inventory.d/` beside it. A missing directory holds no fragments."""
    folder = base.parent / FRAGMENT_DIR
    names = listed_fragments([str(p) for p in folder.iterdir() if p.is_file()]) if folder.is_dir() else []
    fragments = [(name, Path(name).read_text()) for name in names]
    return merge(ledger, (str(base), base.read_text()), fragments)


def load_rev(root: Path, rev: str, ledger: str, base: str) -> list[dict]:
    """The ledger as commit `rev` of the repository at `root` has it: `base`
    (a repository path) plus the `*.tsv` files in `inventory.d/` beside it.

    A path absent at `rev` is empty: a missing base has no rows and a missing
    directory no fragments. Any other git failure, including a failed read of
    a listed fragment, raises LedgerError rather than reading as empty."""
    folder = str(Path(base).parent / FRAGMENT_DIR)

    def git(*args: str) -> str:
        done = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
        if done.returncode != 0:
            raise LedgerError([f"git {' '.join(args)} failed at {rev}: {done.stderr.strip()}"])
        return done.stdout

    def listed(pathspec: str) -> list[str]:
        # From the commit root with a pathspec, so an absent path lists nothing
        # (exit 0) while a bad revision still fails; -z keeps names unquoted.
        return [n for n in git("ls-tree", "-z", "--name-only", rev, "--", pathspec).split("\0") if n]

    names = listed_fragments(listed(folder + "/"))
    fragments = [(name, git("show", f"{rev}:{name}")) for name in names]
    if base not in listed(base):
        return merge(ledger, (base, "\t".join(COLUMNS[ledger]) + "\n"), fragments)
    return merge(ledger, (base, git("show", f"{rev}:{base}")), fragments)


def overlap(critical: list[dict], unenforcing: list[dict]) -> list[str]:
    """A key in both ledgers: the critical row wins, so the unenforcing row is
    what to delete (MIK-8279 lead ruling)."""
    where = {key(r): r["where"] for r in critical}
    return [
        f"{r['where']}: {r['path']} {r['fn']} occurrence {r['occurrence']} is also rowed critical at "
        f"{where[key(r)]}; a function with any enforcing role is critical, so delete this row"
        for r in unenforcing
        if key(r) in where
    ]
