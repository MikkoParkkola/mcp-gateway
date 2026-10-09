#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""UPGRADING fragments: one file per pull request instead of a numbered list.

Two open pull requests that each added an item to docs/UPGRADING-4.0.md took
the same next number, and the second to merge renumbered and paid a CI round.
A PR now adds `upgrading.d/<pr>.md` with no number, and release preparation
numbers the fragments in file-name order, so the result does not depend on
which PR merged first.

    upgrading_fragments.py check [--base <ref> --head <ref>]
        Validate every fragment's shape, refuse numbered items above
        upgrading.d/.frozen-max, and (with --base) refuse a PR that deletes a
        fragment without folding it into the guide.

    upgrading_fragments.py assemble [--dry-run]
        Number the fragments from .frozen-max + 1, add each row after the last
        summary row and each section before the walkthrough, raise
        .frozen-max and delete the fragments. --dry-run prints the guide and
        changes nothing.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = "docs/UPGRADING-4.0.md"
FRAGMENT_DIR = "upgrading.d"
FROZEN_MAX = ".frozen-max"
NOT_FRAGMENTS = {".gitkeep", FROZEN_MAX}
NAME = re.compile(r"^(\d+)(?:-(\d+))?\.md$")
WALKTHROUGH = "## Upgrading from 3.5.x: a walkthrough"
KEYS = ("change", "action", "notice")


REQUIRED = ("change", "action")
MARKER = "**Startup:** "
NOTICE_MARKER = MARKER + "prints a notice"
ROW = re.compile(r"^\|\s*(\d+)\s*\|")
SECTION = re.compile(r"^## (\d+)\. (.*)$")


class Fragment:
    """One parsed fragment. `lines` is the section after its title: the marker
    first, then the body, with surrounding blank lines removed."""

    def __init__(self, name: str, change: str, action: str, title: str, lines: list[str], notice: str | None):
        self.name, self.change, self.action = name, change, action
        self.title, self.lines, self.notice = title, lines, notice

    @property
    def body(self) -> str:
        return "\n".join(self.lines)

    def section(self, number: int) -> str:
        """The assembled `## N. Title` section, the notice phrase under the marker."""
        lines = list(self.lines)
        if self.notice is not None:
            lines.insert(1, f"<!-- notice: {self.notice} -->")
        return "\n".join([f"## {number}. {self.title}", "", *lines]) + "\n\n"

    def row(self, number: int) -> str:
        return f"| {number} | {self.change} | {self.action} |"


def sort_key(name: str) -> tuple:
    """Order by PR number, then suffix, then the whole name, so the result never
    depends on the order the files were listed or merged in."""
    m = NAME.match(name)
    return (int(m[1]), int(m[2] or 0), name) if m else (sys.maxsize, 0, name)


def name_errors(names: list[str]) -> list[str]:
    return [
        f"{FRAGMENT_DIR}/{n}: fragment names are <pr>.md or <pr>-<n>.md"
        for n in names
        if n not in NOT_FRAGMENTS and not NAME.match(n)
    ]


def parse(name: str, text: str) -> tuple[Fragment | None, list[str]]:
    """Parse a fragment; every error names the file."""
    where = f"{FRAGMENT_DIR}/{name}"
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[0] != "---" or "---" not in lines[1:]:
        return None, [f"{where}: starts with a `---` front-matter block holding change and action"]
    end = lines.index("---", 1)
    errors, fields = [], {}
    for line in lines[1:end]:
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not sep or key not in KEYS:
            errors.append(f"{where}: unknown key in front matter: {line!r}")
        elif key in fields:
            errors.append(f"{where}: `{key}` given twice")
        elif not value:
            errors.append(f"{where}: empty `{key}`")
        else:
            fields[key] = value
    for key in REQUIRED:
        if key not in fields and not any(e.endswith(f"empty `{key}`") for e in errors):
            errors.append(f"{where}: missing `{key}`")
        if "|" in fields.get(key, ""):
            errors.append(f"{where}: `{key}` may not contain `|`: it is a summary-table cell")
    rest = lines[end + 1 :]
    titles = [i for i, line in enumerate(rest) if line.startswith("## ")]
    if len(titles) != 1:
        errors.append(f"{where}: needs exactly one `## ` title, found {len(titles)}")
        return None, errors
    title = rest[titles[0]][3:].strip()
    if re.match(r"^\d+\.", title):
        errors.append(f"{where}: the title carries a number; release preparation assigns it")
    if any(line.strip() for line in rest[: titles[0]]):
        errors.append(f"{where}: text before the `## ` title")
    body = rest[titles[0] + 1 :]
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    if not body or not body[0].startswith(MARKER):
        errors.append(f"{where}: `{MARKER.strip()}` must be the first line after the title")
    elif body[0].startswith(NOTICE_MARKER) != ("notice" in fields):
        errors.append(
            f"{where}: a `prints a notice` marker needs a `notice:` phrase in the front matter, and only it"
        )
    if errors:
        return None, errors
    return Fragment(name, fields["change"], fields["action"], title, body, fields.get("notice")), []


def _summary_rows(lines: list[str]) -> list[int]:
    """Line indices of the numbered rows in the `## What changed` table."""
    found, inside = [], False
    for i, line in enumerate(lines):
        if line.startswith("## "):
            inside = line.strip() == "## What changed"
        elif inside and ROW.match(line):
            found.append(i)
    return found


def _numbers(doc: str) -> set[int]:
    lines = doc.replace("\r\n", "\n").split("\n")
    rows = {int(ROW.match(lines[i])[1]) for i in _summary_rows(lines)}
    return rows | {int(m[1]) for m in map(SECTION.match, lines) if m}


def _titles(doc: str) -> dict[str, int]:
    return {m[2].strip(): int(m[1]) for m in map(SECTION.match, doc.replace("\r\n", "\n").split("\n")) if m}


def _parse_all(fragments: dict[str, str]) -> list[Fragment]:
    parsed, errors = [], []
    for name in sorted(fragments, key=sort_key):
        fragment, problems = parse(name, fragments[name])
        errors += problems
        if fragment:
            parsed.append(fragment)
    if errors:
        raise ValueError("\n".join(errors))
    return parsed


def assemble(doc: str, frozen_max: int, fragments: dict[str, str]) -> tuple[str, int]:
    """Number the fragments from frozen_max + 1 in file-name order, add each
    row after the last summary row and each section before the walkthrough.
    Returns the guide and the new ceiling; with no fragments, the guide as is."""
    if not fragments:
        return doc, frozen_max
    parsed = _parse_all(fragments)
    lines = doc.replace("\r\n", "\n").split("\n")
    numbers = range(frozen_max + 1, frozen_max + 1 + len(parsed))
    sections = "".join(f.section(n) for f, n in zip(parsed, numbers)).rstrip("\n").split("\n") + [""]
    lines[lines.index(WALKTHROUGH) : lines.index(WALKTHROUGH)] = sections
    last_row = _summary_rows(lines)[-1]
    lines[last_row + 1 : last_row + 1] = [f.row(n) for f, n in zip(parsed, numbers)]
    return "\n".join(lines), numbers[-1]


def check_doc(doc: str, frozen_max: int, fragments: list[Fragment]) -> list[str]:
    """The committed guide grows numbers only through `assemble`, and every
    title (numbered or pending) names one entry."""
    errors = []
    numbers = _numbers(doc)
    for n in sorted(x for x in numbers if x > frozen_max):
        errors.append(
            f"{DOC}: item {n} is above {FRAGMENT_DIR}/{FROZEN_MAX} ({frozen_max}). New entries are not numbered: "
            f"move its row and section into {FRAGMENT_DIR}/<pr>.md (see CONTRIBUTING.md)"
        )
    highest = max(numbers, default=0)
    if highest != frozen_max:
        errors.append(f"{FRAGMENT_DIR}/{FROZEN_MAX} is {frozen_max}, but the highest item in {DOC} is {highest}")
    numbered, seen = _titles(doc), {}
    for f in fragments:
        if f.title in numbered:
            errors.append(f"{FRAGMENT_DIR}/{f.name}: title `{f.title}` is already item {numbered[f.title]}")
        elif f.title in seen:
            errors.append(f"{FRAGMENT_DIR}/{f.name}: title `{f.title}` is also used by {FRAGMENT_DIR}/{seen[f.title]}")
        seen.setdefault(f.title, f.name)
    return errors


def check_deletions(changes: list[tuple[str, str]], head_doc: str, base_fragments: dict[str, str]) -> list[str]:
    """A fragment leaves only by being folded into the guide: its row under the
    number it was given, and its whole section exactly as `assemble` writes it
    (marker, notice phrase and body), so a fold cannot drop the explanation."""
    lines = head_doc.replace("\r\n", "\n").split("\n")
    titles = _titles(head_doc)
    errors = []
    for status, path in changes:
        name = path.removeprefix(f"{FRAGMENT_DIR}/")
        if status != "D" or name == path or not NAME.match(name):
            continue
        fragment, _ = parse(name, base_fragments.get(name, ""))
        if fragment is None:
            continue  # it never was a valid fragment, so there is nothing to fold
        n = titles.get(fragment.title)
        missing = []
        if n is None:
            missing.append(f"a `## N. {fragment.title}` section")
        else:
            if fragment.row(n) not in lines:
                missing.append(f"the summary row `{fragment.row(n)}`")
            start = lines.index(f"## {n}. {fragment.title}")
            end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
            if "\n".join(lines[start:end]).strip() != fragment.section(n).strip():
                missing.append("its section as written in the fragment (marker, notice phrase and body)")
        if missing:
            errors.append(f"{FRAGMENT_DIR}/{name} is deleted but not folded into {DOC}: missing {', '.join(missing)}")
    return errors


def check_ceiling(base_max: int | None, head_max: int, folded: int) -> list[str]:
    """`.frozen-max` rises only by folding fragments: by exactly as many as the
    PR folds. Raising it beside a hand-numbered item would reopen the race
    fragments close. None: the base has no ceiling yet (the cutover itself)."""
    if base_max is None or head_max <= base_max:
        return []
    if head_max - base_max == folded:
        return []
    return [
        f"{FRAGMENT_DIR}/{FROZEN_MAX} rises from {base_max} to {head_max}, but this PR folds {folded} fragment(s). "
        f"Only `upgrading_fragments.py assemble` raises it; add the entry as {FRAGMENT_DIR}/<pr>.md instead"
    ]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def _tree() -> tuple[pathlib.Path, list[str], list[str]]:
    """The fragment directory, its file names, and the errors in naming and the ceiling file."""
    frag_dir = ROOT / FRAGMENT_DIR
    names = sorted(p.name for p in frag_dir.iterdir()) if frag_dir.is_dir() else []
    errors = name_errors(names)
    if not (frag_dir / FROZEN_MAX).is_file():
        errors.append(f"{FRAGMENT_DIR}/{FROZEN_MAX} is missing")
    return frag_dir, [n for n in names if NAME.match(n)], errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--base")
    c.add_argument("--head", default="HEAD")
    a = sub.add_parser("assemble")
    a.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    frag_dir, names, errors = _tree()
    texts = {n: (frag_dir / n).read_text(encoding="utf-8") for n in names}
    parsed = []
    for n in names:
        fragment, problems = parse(n, texts[n])
        errors += problems
        parsed += [fragment] if fragment else []
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    frozen_max = int((frag_dir / FROZEN_MAX).read_text(encoding="utf-8").strip())
    doc = (ROOT / DOC).read_text(encoding="utf-8")

    if args.cmd == "check":
        errors = check_doc(doc, frozen_max, parsed)
        if args.base:
            rows = [r.split("\t", 1) for r in _git("diff", "--name-status", "--no-renames", f"{args.base}...{args.head}").splitlines() if r]
            gone = [p.removeprefix(f"{FRAGMENT_DIR}/") for s, p in rows if s == "D" and p.startswith(f"{FRAGMENT_DIR}/")]
            base = {n: _git("show", f"{args.base}:{FRAGMENT_DIR}/{n}") for n in gone if NAME.match(n)}
            deletion_errors = check_deletions([tuple(r) for r in rows], _git("show", f"{args.head}:{DOC}"), base)
            errors += deletion_errors
            try:
                base_max = int(_git("show", f"{args.base}:{FRAGMENT_DIR}/{FROZEN_MAX}").strip())
            except subprocess.CalledProcessError:
                base_max = None
            head_max = int(_git("show", f"{args.head}:{FRAGMENT_DIR}/{FROZEN_MAX}").strip())
            folded = len(base) if not deletion_errors else 0
            errors += check_ceiling(base_max, head_max, folded)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1 if errors else 0

    result, top = assemble(doc, frozen_max, texts)
    if args.dry_run:
        sys.stdout.write(result)
        return 0
    if texts:
        (ROOT / DOC).write_text(result, encoding="utf-8")
        (frag_dir / FROZEN_MAX).write_text(f"{top}\n", encoding="utf-8")
        for n in texts:
            (frag_dir / n).unlink()
    print(f"numbered {len(texts)} fragment(s) into {DOC}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
