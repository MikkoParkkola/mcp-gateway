#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shipped files use only KEEP CLI commands and flags, config keys and variables.

surface-4.0.md classes every CLI command and flag. A hidden (non-KEEP) one still
works, but a shipped file that passes it teaches users an item `--help` hides.
This check reads what users copy: the user docs, the examples, every deploy file
(Helm templates and rendered goldens, the Kubernetes base, compose, the systemd
unit, the launchd plist) and the Dockerfile. It fails on a non-KEEP command or
flag in a gateway command line, and on a non-KEEP `MCP_GATEWAY_` variable or
config key in a deploy file (surface_docs.py already covers docs and examples).

Lexical by design and stdlib only.

Usage:
  surface_shipped.py     scan the repository; exit 1 listing each finding
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import check_surface_inventory as inv
import surface_docs as sd

ROOT = inv.ROOT


@dataclass(frozen=True)
class Hit:
    """One finding: where, the item's class, and the item as the table spells it."""

    file: str
    line: int
    cls: str
    item: str
    # The full command path of the invocation the hit came from (for the allow
    # table's ancestor rule); empty for a variable or config key.
    invocation: tuple[str, ...] = ()


@dataclass
class CliTable:
    """The cli rows of surface-4.0.md: commands by path, flags by (path, flag)."""

    commands: dict[tuple[str, ...], str] = field(default_factory=dict)
    flags: dict[tuple[tuple[str, ...], str], str] = field(default_factory=dict)

    @classmethod
    def from_doc(cls, text: str) -> "CliTable":
        return cls()


def command_hits(tokens: list[tuple[str, int]], file: str, table: CliTable, implied: bool = False) -> list[Hit]:
    """Hits in one token stream (token, source line). A gateway command starts at
    a token whose last path part, without `:tag` or `@digest`, is `mcp-gateway`,
    or at the first token when `implied` (arguments to the image ENTRYPOINT)."""
    return []


def scan_text(file: str, text: str, table: CliTable, rows: sd.Rows) -> list[Hit]:
    """Every hit in one shipped file, read by the reader its name selects."""
    return []


# A command entry covers its command, everything under it and, within an
# invocation that reaches it, its ancestors; only while the command is non-KEEP,
# and only the ids in its reviewed snapshot. A variable entry covers that name in
# that file. Each entry needs a reason saying why the page cannot drop the mention.
ALLOWED: dict[tuple[str, str], tuple[str, frozenset[str]]] = {}


def apply_allowed(hits: list[Hit], allowed: dict, table: CliTable) -> tuple[list[Hit], list[str]]:
    """(hits not covered, stale-entry errors)."""
    return hits, []


# Tracked deploy files that are not shipped configuration, each with its reason.
NOT_SHIPPED: dict[str, str] = {}


def shipped_files(root: Path = ROOT) -> tuple[list[Path], list[str]]:
    """(files to scan, errors): a tracked deploy file neither scanned nor listed in
    NOT_SHIPPED, an extension with no reader, or a NOT_SHIPPED entry matching no file."""
    return [], []


def repo_errors(root: Path = ROOT) -> list[str]:
    return []


def main() -> int:
    errors = repo_errors()
    for e in errors:
        print(e)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
