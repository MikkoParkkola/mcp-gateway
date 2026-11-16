#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The lib test split's codemod and checker (stub: the rows in test_test_parts.py are written first)."""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple


class Finding(NamedTuple):
    code: str
    path: str
    line: int
    message: str


class Refusal(Exception):
    def __init__(self, findings: list[Finding]):
        super().__init__("; ".join(f"{f.path}:{f.line}: {f.code}: {f.message}" for f in findings))
        self.findings = findings


def token_inventory(path: str, text: str) -> dict[tuple[str, ...], int]:
    return {}


def check(root: Path) -> list[Finding]:
    return []


def apply(root: Path) -> None:
    return None
