#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every bullet of a Security changelog fragment says who is affected and what an
operator must do (RELEASING.md step 1, item 5), so the release fold is mechanical.

usage: check_security_fragments.py [DIR]   (default: changelog.d)

Each bullet ("- " at column 0, with its two-space continuation lines) of every
`*.security.md` file must carry `Affects: <text>.` and `Operator action: <text>.`
An `Affects: UNVERIFIED` value fails. Exit 0 when every bullet passes, 1 otherwise,
naming each failing file and bullet."""
import pathlib
import re
import sys

AFFECTS = re.compile(r"\bAffects: (?P<v>[^.\n][^\n]*?)\.(\s|$)")
ACTION = re.compile(r"\bOperator action: [^.\n][^\n]*?\.(\s|$)")


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
    found = []
    for path in sorted(pathlib.Path(directory).glob("*.security.md")):
        items = bullets(path.read_text(encoding="utf-8"))
        if not items:
            found.append(f"{path}: no bullet")
        for i, item in enumerate(items, 1):
            affects = AFFECTS.search(item)
            if not affects:
                found.append(f"{path} bullet {i}: no 'Affects: ...' clause")
            elif affects.group("v").strip().upper().startswith("UNVERIFIED"):
                found.append(f"{path} bullet {i}: 'Affects' is UNVERIFIED")
            if not ACTION.search(item):
                found.append(f"{path} bullet {i}: no 'Operator action: ...' clause")
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
