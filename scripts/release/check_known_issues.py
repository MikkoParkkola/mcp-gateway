# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Known issues gate for the release notes.

--check (every PR): the "## Known issues" section must not name a later
release. Nothing in 4.0 is deferred to 4.0.1, so a "fixed in 4.0.1" line is
a promise the release plan no longer makes.

--release (at a tag): the section must also be empty or absent. A known issue
left at a final tag is shipped, so it blocks the tag instead. A prerelease tag
(v4.0.0-beta.N, v4.0.0-rc.N) may ship open items as known gaps
(docs/release/v4.0.0-prerelease-channel.md), so only the later-release rule
applies to it. The tag is --tag, else $GITHUB_REF_NAME; anything that is not a
v-prefixed semver prerelease tag, a branch name included, is held to the
final-tag rule.

Exit 0 when the gate holds, 1 otherwise (an unreadable notes file included).
"""

import argparse
import importlib.util
import os
import pathlib
import re
import sys

_spec = importlib.util.spec_from_file_location(
    "check_tag_manifest", pathlib.Path(__file__).with_name("check_tag_manifest.py")
)
tag_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tag_manifest)

DEFAULT_NOTES = "docs/release/v4.0.0-release-notes-DRAFT.md"
LATER_RELEASE = "4.0.1"
# ATX headings: up to three spaces of indent, optional closing hashes.
HEADING = re.compile(r"^ {0,3}##[ \t]+known issues(?:[ \t]+#*)?[ \t]*$", re.IGNORECASE)
SECTION_END = re.compile(r"^ {0,3}#{1,2}(?:[ \t]|$)")


def known_issues(text):
    """Every Known issues section's lines, each up to the next level 1-2 heading."""
    body, inside = [], False
    for line in text.splitlines():
        if HEADING.match(line):
            inside = True
        elif SECTION_END.match(line):
            inside = False
        elif inside:
            body.append(line)
    return body


def is_prerelease_tag(tag):
    """True only for a v-prefixed semver tag with a prerelease identifier."""
    version = tag[1:] if tag.startswith("v") else ""
    return bool(tag_manifest.SEMVER.match(version)) and tag_manifest.is_prerelease(version)


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
    parser.add_argument(
        "--tag",
        default="",
        help="tag being released; falls back to $GITHUB_REF_NAME when empty",
    )
    args = parser.parse_args(argv)
    tag = args.tag.strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    try:
        text = pathlib.Path(args.notes).read_text(encoding="utf-8")
    except OSError as err:
        print(f"cannot read {args.notes}: {err}", file=sys.stderr)
        return 1
    found = problems(known_issues(text), args.release and not is_prerelease_tag(tag))
    for problem in found:
        print(problem, file=sys.stderr)
    if not found:
        print(f"Known issues gate OK ({args.notes})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
