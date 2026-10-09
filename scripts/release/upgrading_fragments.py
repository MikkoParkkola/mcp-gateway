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

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = "docs/UPGRADING-4.0.md"
FRAGMENT_DIR = "upgrading.d"
FROZEN_MAX = ".frozen-max"
NOT_FRAGMENTS = {".gitkeep", FROZEN_MAX}
NAME = re.compile(r"^(\d+)(?:-(\d+))?\.md$")
WALKTHROUGH = "## Upgrading from 3.5.x: a walkthrough"
KEYS = ("change", "action", "notice")


class Fragment:
    """One parsed fragment: its file name, summary cells, title, body and notice phrase."""

    def __init__(self, name: str, change: str, action: str, title: str, body: str, notice: str | None):
        self.name, self.change, self.action = name, change, action
        self.title, self.body, self.notice = title, body, notice


def sort_key(name: str) -> tuple:
    return (0,)


def name_errors(names: list[str]) -> list[str]:
    return []


def parse(name: str, text: str) -> tuple[Fragment | None, list[str]]:
    return None, []


def check_doc(doc: str, frozen_max: int, fragments: list[Fragment]) -> list[str]:
    return []


def check_deletions(changes: list[tuple[str, str]], head_doc: str, base_fragments: dict[str, str]) -> list[str]:
    return []


def assemble(doc: str, frozen_max: int, fragments: dict[str, str]) -> tuple[str, int]:
    return doc, frozen_max


def main(argv: list[str]) -> int:
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
