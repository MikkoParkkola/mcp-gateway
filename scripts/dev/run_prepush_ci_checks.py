# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run CI's cargo-free PR-workflow checks before a push (MIK-8410).

pre-push.sh calls this once. Every listed line runs in a scratch clone, one
clone per worker reset after every command, at most PREPUSH_CI_WORKERS at a
time, slowest first. A failing line is rerun on the merge-base and the result
is printed on its own line; every failure still fails the push.

SKELETON: the interface only. `run` and `run_rust` dispatch nothing yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Lead ruling 2026-10-22: three at a time on a lane Mac. Macs are
# interactive-only, so this is a cap, not a tuning knob.
PREPUSH_CI_WORKERS = 3
LINE_TIMEOUT_S = 300
DEADLINE_S = 300


@dataclass
class LineResult:
    command: str
    rc: int
    seconds: float
    log: Path | None = None
    status: str = ""


@dataclass
class Report:
    rc: int
    failures: list[LineResult] = field(default_factory=list)
    text: str = ""


def run(
    lines,
    *,
    repo,
    head,
    merge_base,
    base_tip,
    workers=PREPUSH_CI_WORKERS,
    executor=None,
    drift=None,
    line_timeout_s=LINE_TIMEOUT_S,
    deadline_s=DEADLINE_S,
) -> Report:
    """Run every line; SKELETON: returns success without running anything.

    `lines` use the list-file format: `command<TAB>seconds<TAB>direction` with an
    optional `<TAB>marker=<text>` (open lines) and `<TAB>requires=<sha>`.
    `executor` and `drift` are private test seams (function arguments, never
    environment variables)."""
    return Report(rc=0)


def run_rust(targets, *, cargo, repo, merge_base, base_tip) -> Report:
    """Run the doc/CLI-reading Rust targets; SKELETON: returns success."""
    return Report(rc=0)


def yaml_status() -> str:
    """One line naming the PyYAML version, or the install hint. SKELETON."""
    return ""


def resolve_base_tip(repo, *, remote="origin", branch="docs/ranking-1-release-line", timeout_s=60) -> str:
    """Fetch `branch` (bounded) and return its tip SHA. SKELETON."""
    return ""


def main(argv=None) -> int:
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
