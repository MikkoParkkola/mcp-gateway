#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shared fixtures for the timing-assert guard tests (MIK-8291)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-timing-asserts.py"
SPEC = importlib.util.spec_from_file_location("guard", SCRIPT)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

PATH = "src/x_tests.rs"


def wrap(body: str, prelude: str = "") -> str:
    return f"{prelude}\nfn case() {{\n    let start = Instant::now();\n{body}\n}}\n"


def scan(body: str, prelude: str = "", consts=None):
    return guard.scan_text(PATH, wrap(body, prelude), consts or {})


class ScratchGit:
    """A scratch tree bound as the guard's root, restored on close."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.saved = guard.ROOT, guard.ALLOWLIST
        guard.ROOT = self.root
        guard.ALLOWLIST = self.root / "scripts/dev/timing-asserts-allowlist.tsv"

    def git(self, *args):
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@t", "PATH": os.environ["PATH"], "HOME": self.dir.name}
        return subprocess.run(["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", *args], cwd=self.root, check=True, capture_output=True, text=True, env=env).stdout.strip()

    def close(self):
        guard.ROOT, guard.ALLOWLIST = self.saved
        self.dir.cleanup()
