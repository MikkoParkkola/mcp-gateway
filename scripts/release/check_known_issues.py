# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Known issues gate for the release notes.

--check (every PR): the "## Known issues" section must not name a later
release. Nothing in 4.0 is deferred to 4.0.1, so a "fixed in 4.0.1" line is
a promise the release plan no longer makes.

--release (at a tag): the section must also be empty or absent. A known issue
left at tag time is shipped, so it blocks the tag instead.

Exit 0 when the gate holds, 1 otherwise (an unreadable notes file included).
"""

import argparse
import pathlib
import re
import sys

DEFAULT_NOTES = "docs/release/v4.0.0-release-notes-DRAFT.md"
LATER_RELEASE = "4.0.1"
HEADING = re.compile(r"^## known issues\s*$", re.IGNORECASE)


def known_issues(text):
    """The section's lines after its heading, up to the next "## " heading."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if HEADING.match(line)), None)
    if start is None:
        return []
    body = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return body


def problems(section, release):
    found = [
        f"Known issues names {LATER_RELEASE}: {line.strip()}"
        for line in section
        if LATER_RELEASE in line
    ]
    content = [line for line in section if line.strip()]
    if release and content:
        found.append(
            f"Known issues is not empty at a tag ({len(content)} lines): "
            "fix them or remove the section before tagging"
        )
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notes", default=DEFAULT_NOTES)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--release", action="store_true")
    args = parser.parse_args(argv)
    try:
        text = pathlib.Path(args.notes).read_text(encoding="utf-8")
    except OSError as err:
        print(f"cannot read {args.notes}: {err}", file=sys.stderr)
        return 1
    found = problems(known_issues(text), args.release)
    for problem in found:
        print(problem, file=sys.stderr)
    if not found:
        print(f"Known issues gate OK ({args.notes})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
