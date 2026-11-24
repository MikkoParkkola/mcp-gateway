# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when CHANGELOG.md has a version section with no release tag, or one twice.

A `## [<version>]` heading must have a `v<version>` git tag. Three kinds of
heading are spared that rule, never the duplicate rule:
- `[Unreleased]` (not a version);
- a section dated `Unreleased`;
- the section for Cargo.toml's `[package] version`, the release being prepared,
  whose tag is cut only after its pull request lands.
Any other `## [` heading (a typo such as `## [v1.2.0]`) fails, since neither rule
would see it.

Run from the repository root with the tags fetched (CI checks out with
fetch-depth 0). A checkout without tags fails loudly on every section rather
than passing. Exit 0 and no output when clean; exit 1 and one line per problem.
"""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

# Markdown reads up to three leading spaces and any run of spaces or tabs after
# `##` as the same level-2 heading, so all of them count as one here.
HEADING = r" {0,3}##[ \t]+"
VERSION_HEADING = re.compile(HEADING + r"\[(\d[^\]]*)\](?:[ \t]+-[ \t]+(.+))?")
ANY_BRACKET_HEADING = re.compile(HEADING + r"\[")
UNRELEASED_HEADING = re.compile(HEADING + r"\[Unreleased\]")


def problems(changelog, tags, prepared):
    """One message per untagged or repeated version section, in file order."""
    seen_at = {}
    found = []
    for number, line in enumerate(changelog.splitlines(), 1):
        line = line.rstrip()
        heading = VERSION_HEADING.fullmatch(line)
        if heading is None:
            # Any other `## [` heading would escape both rules unseen.
            if ANY_BRACKET_HEADING.match(line) and not UNRELEASED_HEADING.fullmatch(line):
                found.append(
                    f"CHANGELOG.md:{number}: heading is neither [Unreleased] nor a version section: {line}"
                )
            continue
        version, dated = heading.groups()
        if version in seen_at:
            found.append(
                f"CHANGELOG.md:{number}: [{version}] appears again (first at line {seen_at[version]})"
            )
            continue
        seen_at[version] = number
        exempt = dated == "Unreleased" or version == prepared
        if not exempt and f"v{version}" not in tags:
            found.append(f"CHANGELOG.md:{number}: [{version}] has no tag v{version}")
    return found


def main():
    listed = subprocess.run(
        ["git", "tag", "--list", "v*"], capture_output=True, text=True, check=True
    )
    prepared = tomllib.loads(Path("Cargo.toml").read_text())["package"]["version"]
    found = problems(Path("CHANGELOG.md").read_text(), set(listed.stdout.split()), prepared)
    for message in found:
        print(message)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
