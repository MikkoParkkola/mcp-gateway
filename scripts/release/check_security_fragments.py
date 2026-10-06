#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every bullet of a Security changelog fragment says who is affected and what an
operator must do (RELEASING.md step 1, item 5), so the release fold is mechanical.

usage: check_security_fragments.py [DIR]   (default: changelog.d)

Each bullet ("- " at column 0, with its two-space continuation lines) of every
`*.security.md` file must carry `Affects: <text>.` and `Operator action: <text>.`
Each value runs to the next label and must be a non-empty sentence; an `Affects`
value naming UNVERIFIED fails, as does a DIR that is not a directory. A bullet
labelled `Security:` in any other fragment fails too: the filename picks the
release-notes subsection, so it would be filed under the wrong one (MIK-7865).
Exit 0 when every bullet passes, 1 otherwise, naming each failing file and bullet."""
import pathlib
import re
import sys

LABEL = re.compile(r"\b(Affects|Operator action):")
# Letters and digits only bound the marker, so `_UNVERIFIED_` emphasis still matches.
# `Security:`, `**Security:**` or `**Security**:` opening a bullet.
SECURITY_LABEL = re.compile(r"^- \**Security\**:")
UNVERIFIED = re.compile(r"(?<![A-Za-z0-9])UNVERIFIED(?![A-Za-z0-9])", re.IGNORECASE)


def clauses(item):
    """(label, value) for every label; a value runs to the next label or the end."""
    marks = list(LABEL.finditer(item))
    ends = [m.start() for m in marks[1:]] + [len(item)]
    return [(m.group(1), item[m.end():end].strip()) for m, end in zip(marks, ends)]


def value_problem(value):
    """None when the value says something (a letter or digit) and ends in a period."""
    if not re.search(r"[A-Za-z0-9]", value):
        return "an empty '{}' value"
    if not value.endswith("."):
        return "a '{}' value with no closing period"
    return None


def bullets(text):
    out, cur = [], None
    for line in text.splitlines():
        if line.startswith("- "):
            cur = [line]
            out.append(cur)
        elif cur is not None and line.startswith("  ") and line.strip():
            cur.append(line)
        else:
            cur = None
    return [" ".join(part.strip() for part in b) for b in out]


def problems(directory):
    root = pathlib.Path(directory)
    if not root.is_dir():
        return [f"{root}: not a directory"]
    found = []
    for path in sorted(root.glob("*.security.md")):
        items = bullets(path.read_text(encoding="utf-8"))
        if not items:
            found.append(f"{path}: no bullet")
        for i, item in enumerate(items, 1):
            found += [f"{path} bullet {i}: {p}" for p in bullet_problems(item)]
    for path in sorted(root.glob("*.md")):
        if path.name.endswith(".security.md"):
            continue
        for i, item in enumerate(bullets(path.read_text(encoding="utf-8")), 1):
            if SECURITY_LABEL.match(item):
                found.append(f"{path} bullet {i}: a Security bullet; name the fragment .security.md")
    return found


def bullet_problems(item):
    found = []
    pairs = clauses(item)
    for label in ("Affects", "Operator action"):
        values = [v for l, v in pairs if l == label]
        if not values:
            found.append(f"no '{label}: ...' clause")
        else:
            found += sorted({p.format(label) for p in map(value_problem, values) if p})
    if any(UNVERIFIED.search(v) for l, v in pairs if l == "Affects"):
        found.append("'Affects' is UNVERIFIED")
    return found


def main(argv):
    directory = argv[1] if len(argv) > 1 else "changelog.d"
    found = problems(directory)
    for line in found:
        print(line)
    if found:
        print(f"{len(found)} Security fragment problem(s)")
        return 1
    print("every Security fragment bullet names who is affected and the operator action")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
