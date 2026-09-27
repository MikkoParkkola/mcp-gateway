#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Changelog fragments: one file per pull request instead of a shared section.

Every open pull request used to edit `## [Unreleased]` in CHANGELOG.md, so each
merge made the others conflict. A PR now adds `changelog.d/<number>.<type>.md`
holding its bullet(s), and the release folds them in.

    changelog_fragments.py check --base <ref> [--head <ref>]
        Fail a PR that changes src/ without adding a fragment. The label
        `no-changelog` (in the PR_LABELS environment variable, comma separated)
        waives it. A misnamed fragment always fails.

    changelog_fragments.py assemble [--dry-run]
        Append every fragment to its `### <Type>` subsection under
        `## [Unreleased]`, creating the subsection when missing, then delete
        the fragments. --dry-run prints the result and changes nothing.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FRAGMENT_DIR = "changelog.d"
# Keep a Changelog order; a missing subsection is created in this order.
TYPES = ("added", "changed", "removed", "fixed", "security")
FRAGMENT = re.compile(r"^(\d+)\.(" + "|".join(TYPES) + r")\.md$")
# Files in changelog.d/ that are not fragments.
NOT_FRAGMENTS = {".gitkeep"}
SKIP_LABEL = "no-changelog"
# Shipped source: the gateway crate and the workspace crates.
SOURCE = re.compile(r"^(src|crates/[^/]+/src)/")


def fragment_name_errors(names: list[str]) -> list[str]:
    return [
        f"{FRAGMENT_DIR}/{n}: fragment names are <number>.<type>.md, type one of {', '.join(TYPES)}"
        for n in names
        if n not in NOT_FRAGMENTS and not FRAGMENT.match(n)
    ]


def check(changes: list[tuple[str, str]], labels: set[str]) -> list[str]:
    """Errors for a PR's `git diff --name-status` rows (status, path)."""
    added = [
        path.split("/", 1)[1]
        for status, path in changes
        if path.startswith(f"{FRAGMENT_DIR}/") and status.startswith("A")
    ]
    errors = fragment_name_errors(added)
    if SKIP_LABEL in labels:
        return errors
    touches_src = any(SOURCE.match(path) for _, path in changes)
    if touches_src and not any(FRAGMENT.match(n) for n in added):
        errors.append(
            f"this PR changes source but adds no {FRAGMENT_DIR}/<number>.<type>.md; "
            f"add one (see CONTRIBUTING.md) or apply the '{SKIP_LABEL}' label"
        )
    # Only the release fold, which deletes the fragments it folds in, edits
    # CHANGELOG.md; a hand edit brings back the conflicts fragments remove.
    folds = any(
        status.startswith("D") and path.startswith(f"{FRAGMENT_DIR}/")
        for status, path in changes
    )
    if any(path == "CHANGELOG.md" for _, path in changes) and not folds:
        errors.append(
            f"this PR edits CHANGELOG.md; put the entry in {FRAGMENT_DIR}/<number>.<type>.md "
            f"instead, or apply the '{SKIP_LABEL}' label"
        )
    return errors


def assemble(changelog: str, fragments: dict[str, str]) -> str:
    """Fold `fragments` ({file name: text}) into the Unreleased section."""
    if not fragments:
        return changelog
    lines = changelog.split("\n")
    try:
        start = lines.index("## [Unreleased]")
    except ValueError:
        raise SystemExit("CHANGELOG.md has no '## [Unreleased]' heading") from None
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    section = lines[start:end]
    ordered = sorted(fragments, key=lambda n: (int(FRAGMENT.match(n)[1]), n))
    for kind in TYPES:
        body = [
            fragments[n].strip("\n") for n in ordered if FRAGMENT.match(n)[2] == kind
        ]
        if not body:
            continue
        heading = f"### {kind.capitalize()}"
        if heading not in section:
            # Before the first subsection of a later type, else at the end.
            later = [f"### {k.capitalize()}" for k in TYPES[TYPES.index(kind) + 1 :]]
            at = next((i for i, line in enumerate(section) if line in later), None)
            if at is None:
                while section and section[-1] == "":
                    section.pop()
                section += ["", heading, ""]
                at = len(section)
            else:
                section[at:at] = [heading, ""]
                at += 2
        else:
            top = section.index(heading)
            at = next(
                (i for i in range(top + 1, len(section)) if section[i].startswith("### ")),
                len(section),
            )
            while section[at - 1] == "":
                at -= 1
        # Each fragment is kept as written: its own bullet(s), no blank line.
        block = [line for text in body for line in text.split("\n")]
        if section[at - 1] == heading:
            block.insert(0, "")
        if at < len(section) and section[at] != "":
            block.append("")
        section[at:at] = block
    while section and section[-1] == "":
        section.pop()
    section.append("")
    return "\n".join(lines[:start] + section + lines[end:])


def _changes(base: str, head: str) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["git", "diff", "--name-status", "--no-renames", f"{base}...{head}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [tuple(row.split("\t", 1)) for row in out.splitlines() if row]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--base", required=True)
    c.add_argument("--head", default="HEAD")
    a = sub.add_parser("assemble")
    a.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.cmd == "check":
        labels = {x.strip() for x in os.environ.get("PR_LABELS", "").split(",")}
        errors = check(_changes(args.base, args.head), labels)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1 if errors else 0

    frag_dir = ROOT / FRAGMENT_DIR
    names = sorted(p.name for p in frag_dir.iterdir()) if frag_dir.is_dir() else []
    errors = fragment_name_errors(names)
    errors += [
        f"{FRAGMENT_DIR}/{n}: empty fragment"
        for n in names
        if FRAGMENT.match(n) and not (frag_dir / n).read_text(encoding="utf-8").strip()
    ]
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    fragments = {
        n: (frag_dir / n).read_text(encoding="utf-8") for n in names if FRAGMENT.match(n)
    }
    changelog_path = ROOT / "CHANGELOG.md"
    result = assemble(changelog_path.read_text(encoding="utf-8"), fragments)
    if args.dry_run:
        sys.stdout.write(result)
        return 0
    changelog_path.write_text(result, encoding="utf-8")
    for n in fragments:
        (frag_dir / n).unlink()
    print(f"folded {len(fragments)} fragment(s) into CHANGELOG.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
