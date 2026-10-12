#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""UPGRADING covers every non-KEEP surface row (MIK-8044.SURF.6).

docs/UPGRADING-4.0.md ends with an appendix generated from
docs/design/surface-4.0.md: every INTERNAL, AUTO and REMOVE row, hidden rows
grouped by what 4.0 does to them, derived and removed rows one per line.
Every REMOVE and AUTO row also cites the prose a user reads about it in its
Migration cell: `UPGRADING <n>` or `upgrading.d/<file>.md`. An AUTO row that
nothing documents and whose behaviour did not change says
`no UPGRADING item: <reason>`.

Usage:
  surface_upgrading.py check   fail on a stale appendix, a missing citation or
                               a missing QUICKSTART minimal block
  surface_upgrading.py write   regenerate the appendix in place
"""

from __future__ import annotations

import difflib
import re
import sys
from collections import Counter
from pathlib import Path

import check_surface_inventory as inv

ROOT = inv.ROOT
GUIDE = ROOT / "docs/UPGRADING-4.0.md"
FRAGMENTS = ROOT / "upgrading.d"
QUICKSTART = ROOT / "docs/QUICKSTART.md"
TESTS = ROOT / "tests"
START = "<!-- surface-appendix:start -->"
END = "<!-- surface-appendix:end -->"
QS_START = "<!-- quickstart-minimal-config -->"
QS_END = "<!-- /quickstart-minimal-config -->"
# SURF.7's end-to-end test that the minimal block loads and serves a call.
SURF7_TEST = "e2e_quickstart_minimal_config.rs"
MINIMAL_MAX_LINES = 15

WORD = {"INTERNAL": "hidden", "AUTO": "derived", "REMOVE": "removed"}
TITLE = {
    "config": "Config keys",
    "cli": "Commands and flags",
    "env": "Environment variables",
    "routes": "HTTP routes",
    "lib": "Library items",
}
CLASS_ORDER = ("REMOVE", "AUTO", "INTERNAL")
CITE_ITEM = re.compile(r"\bUPGRADING (\d+)\b")
CITE_FRAGMENT = re.compile(r"\bupgrading\.d/([\w.-]+\.md)\b")
NO_ITEM = "no UPGRADING item:"


def rows_of(text: str) -> list:
    return [r for r in inv.parse_doc(text) if r.surface in TITLE]


def esc(text: str) -> str:
    return text.replace("|", "\\|")


def _lines(rows: list) -> list[tuple]:
    """(surface, class order, first id, ids, class, migration, reason) per line."""
    out, groups = [], {}
    for r in rows:
        if r.cls not in WORD:
            continue
        if r.cls == "INTERNAL":
            groups.setdefault((r.surface, r.migration), []).append(r)
        else:
            out.append((r.surface, CLASS_ORDER.index(r.cls), r.id, [r.id], r.cls, r.migration, r.reason))
    for (surface, migration), members in groups.items():
        ids = sorted(m.id for m in members)
        out.append((surface, CLASS_ORDER.index("INTERNAL"), ids[0], ids, "INTERNAL", migration, ""))
    order = list(TITLE)
    return sorted(out, key=lambda t: (order.index(t[0]), t[1], t[2]))


def render(rows: list) -> str:
    """The appendix body, between the markers."""
    out = [
        "",
        "## Appendix: hidden, derived and removed surface (generated)",
        "",
        "Generated from docs/design/surface-4.0.md by `scripts/release/surface_upgrading.py write`;",
        "edit the inventory, not this table. Hidden items still work: a config key or variable is",
        "still read and `mcp-gateway doctor` lists it when set, a command still runs, a route stays",
        "mounted. Derived items work out their value when unset. Removed items are refused.",
        "",
    ]
    current = None
    for surface, _, _, ids, cls, migration, reason in _lines(rows):
        if surface != current:
            out += [f"### {TITLE[surface]}", "", "| Item | Class | What 4.0 does | Why |", "|---|---|---|---|"]
            current = surface
        items = ", ".join(f"`{esc(i)}`" for i in ids)
        out.append(f"| {items} | {WORD[cls]} | {esc(migration)} | {esc(reason)} |")
    return "\n".join(out) + "\n\n"


def item_ids(block: str) -> list[str]:
    """Every id in the Item column of the appendix tables."""
    ids = []
    for line in block.splitlines():
        if line.startswith("| `"):
            first = inv.cells(line)[0]
            ids += [i.replace("\\|", "|") for i in re.findall(r"`([^`]+)`", first)]
    return ids


def write(guide: str, block: str) -> str:
    """The guide with the appendix replaced, or appended when it has none."""
    starts, ends = guide.count(START), guide.count(END)
    if starts == 0 and ends == 0:
        return guide.rstrip("\n") + "\n\n" + START + block + END + "\n"
    if starts == 1 and ends == 1 and guide.index(START) < guide.index(END):
        head, rest = guide.split(START, 1)
        _, tail = rest.split(END, 1)
        return head + START + block + END + tail
    raise ValueError("the guide's appendix markers are not one start followed by one end; fix them by hand")


def appendix_errors(guide: str, block: str) -> list[str]:
    starts, ends = guide.count(START), guide.count(END)
    if starts == 0 and ends == 0:
        return ["UPGRADING-4.0.md has no surface appendix; run `python3 scripts/release/surface_upgrading.py write`"]
    if starts != 1 or ends != 1 or guide.index(START) > guide.index(END):
        return ["UPGRADING-4.0.md: the surface appendix markers must be one start followed by one end"]
    errors = []
    current = guide.split(START, 1)[1].split(END, 1)[0]
    if current != block:
        diff = "\n".join(difflib.unified_diff(
            current.splitlines(), block.splitlines(), "UPGRADING-4.0.md", "generated", lineterm="", n=0))
        errors.append("the surface appendix is stale; run `python3 scripts/release/surface_upgrading.py write`\n" + diff)
    if guide.split(END, 1)[1].strip():
        errors.append("the surface appendix must be the last thing in UPGRADING-4.0.md")
    return errors


def coverage_errors(rows: list, guide: str) -> list[str]:
    """The guide's appendix names every non-KEEP id exactly once and nothing else."""
    if guide.count(START) != 1 or guide.count(END) != 1:
        return []  # appendix_errors reports the markers
    listed = Counter(item_ids(guide.split(START, 1)[1].split(END, 1)[0]))
    want = Counter(r.id for r in rows if r.cls in WORD)
    errors = [f"`{i}` is missing from the surface appendix" for i in sorted(want - listed)]
    errors += [f"`{i}` is in the surface appendix but is no non-KEEP row" for i in sorted(set(listed) - set(want))]
    errors += [f"`{i}` appears {n} times in the surface appendix" for i, n in sorted(listed.items()) if i in want and n > want[i]]
    return errors


def citation_errors(rows: list, guide: str, fragments) -> list[str]:
    """Every REMOVE and AUTO row cites prose that exists."""
    items = {int(n) for n in re.findall(r"^## (\d+)\. ", guide, re.M)}
    names = set(fragments)
    errors = []
    for r in rows:
        if r.cls not in ("REMOVE", "AUTO"):
            continue
        cited_items = [int(n) for n in CITE_ITEM.findall(r.migration)]
        cited_files = CITE_FRAGMENT.findall(r.migration)
        escaped = r.cls == "AUTO" and NO_ITEM in r.migration
        if escaped and not r.migration.split(NO_ITEM, 1)[1].strip(" ;.-"):
            errors.append(f"`{r.id}`: `{NO_ITEM}` needs a reason after it")
        if escaped and (cited_items or cited_files):
            errors.append(f"`{r.id}` both cites prose and says `{NO_ITEM}`; keep one")
        if not cited_items and not cited_files and not escaped:
            errors.append(
                f"`{r.id}` ({r.cls}) cites no UPGRADING item: add `UPGRADING <n>` or "
                f"`upgrading.d/<file>.md` to its Migration cell"
                + ("" if r.cls == "REMOVE" else f", or `{NO_ITEM} <reason>` if nothing changed")
            )
        errors += [f"`{r.id}` cites UPGRADING {n}, which does not exist" for n in cited_items if n not in items]
        errors += [f"`{r.id}` cites upgrading.d/{f}, which does not exist" for f in cited_files if f not in names]
    return errors


def rewrite_citations(inventory: str, numbers: dict[str, int]) -> str:
    """Fragment citations become item numbers when release prep folds them."""
    for name, n in numbers.items():
        inventory = inventory.replace(f"upgrading.d/{name}", f"UPGRADING {n}")
    return inventory


def minimal_setup_errors(quickstart: str, test_names) -> list[str]:
    """QUICKSTART holds one marked minimal config of at most 15 lines that
    names a backend, and SURF.7's test that it loads and serves exists."""
    if quickstart.count(QS_START) != 1 or quickstart.count(QS_END) != 1 or quickstart.index(QS_START) > quickstart.index(QS_END):
        return [f"QUICKSTART.md needs exactly one `{QS_START}` ... `{QS_END}` block"]
    body = quickstart.split(QS_START, 1)[1].split(QS_END, 1)[0]
    m = re.search(r"```ya?ml\n(.*?)```", body, re.S)
    if not m:
        return ["the QUICKSTART minimal block holds no yaml fence"]
    yaml = m.group(1).rstrip("\n").split("\n")
    errors = []
    if len(yaml) > MINIMAL_MAX_LINES:
        errors.append(f"the QUICKSTART minimal config is {len(yaml)} lines; the limit is {MINIMAL_MAX_LINES}")
    names_backend = any(
        line.startswith("backends:") and i + 1 < len(yaml) and yaml[i + 1].startswith("  ") and yaml[i + 1].strip().endswith(":")
        for i, line in enumerate(yaml)
    )
    if not names_backend:
        errors.append("the QUICKSTART minimal config names no backend")
    if SURF7_TEST not in set(test_names):
        errors.append(f"tests/{SURF7_TEST} (SURF.7: the minimal config loads and serves a call) is missing")
    return errors


def repo_errors() -> list[str]:
    rows = rows_of(inv.DOC.read_text(encoding="utf-8"))
    guide = GUIDE.read_text(encoding="utf-8")
    fragments = {p.name for p in FRAGMENTS.glob("*.md")}
    errors = appendix_errors(guide, render(rows))
    errors += coverage_errors(rows, guide)
    errors += citation_errors(rows, guide, fragments)
    errors += minimal_setup_errors(QUICKSTART.read_text(encoding="utf-8"), {p.name for p in TESTS.glob("*.rs")})
    return errors


def main(argv: list[str]) -> int:
    if argv[:1] == ["write"]:
        rows = rows_of(inv.DOC.read_text(encoding="utf-8"))
        GUIDE.write_text(write(GUIDE.read_text(encoding="utf-8"), render(rows)), encoding="utf-8", newline="\n")
        print("surface appendix written")
        return 0
    if argv[:1] != ["check"]:
        print(__doc__, file=sys.stderr)
        return 2
    errors = repo_errors()
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print(f"surface upgrading: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print("surface upgrading: every non-KEEP row is in the guide")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
