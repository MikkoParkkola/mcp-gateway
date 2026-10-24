#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for the BUILD.1 client-run block in the gate-day procedure (MIK-8602.VERIFY.8).

The block is taken from the procedure exactly as the gate-day sheet takes it. The
structure tests pin that the client and the gateway run outside the frozen worktree.
The behaviour tests run the block's own tree-check lines against a temporary git repo
standing in for that worktree. Standard library only.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROCEDURE = ROOT / "docs" / "release" / "v4.0.0-gate-day-procedure.md"
START = 'W="$W" FREEZE_SHA='
CHECK_MARK = "# VERIFY.8: the frozen worktree is unchanged"


def block_lines() -> list[str]:
    """The block, from its `W="$W" FREEZE_SHA=` line to `VERIFY`, as the sheet extracts it."""
    lines = PROCEDURE.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith(START)]
    if len(starts) != 1:
        raise AssertionError(f"the block's first line appears {len(starts)} times")
    end = lines.index("VERIFY", starts[0])
    return lines[starts[0] : end + 1]


def first(lines: list[str], pattern: str) -> int:
    for i, line in enumerate(lines):
        if re.search(pattern, line):
            return i
    raise AssertionError(f"no line matches {pattern!r}")


class Build1BlockStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lines = block_lines()

    def test_the_run_directory_is_outside_the_frozen_worktree(self) -> None:
        self.assertIn('R="$W/verify-run"', self.lines)

    def test_gateway_and_client_start_from_the_run_directory(self) -> None:
        cd = first(self.lines, r'^cd "\$R"$')
        # The login pre-check rightly runs before the build, so it is not in this list.
        for pattern in (r'"\$BIN" --config', r"^claude --version", r"^claude -p "):
            self.assertLess(cd, first(self.lines, pattern), pattern)

    def test_no_relative_run_path_after_the_move(self) -> None:
        cd = first(self.lines, r'^cd "\$R"$')
        for line in self.lines[cd:]:
            self.assertNotRegex(line, r"(?<![\w$/])verify-run/", line)

    def test_paths_the_gateway_and_check_read_are_absolute(self) -> None:
        text = "\n".join(self.lines)
        self.assertIn('BIN="$W/verify/target/release/mcp-gateway"', text)
        self.assertIn("directories: [$W/verify/capabilities]", text)
        self.assertIn('jq -s -e -f "$W/verify/scripts/release/build1_pass_check.jq"', text)
        self.assertIn('HOME="$R/home"', text)

    def test_the_tree_check_closes_the_block(self) -> None:
        mark = self.lines.index(CHECK_MARK)
        tail = self.lines[mark + 1 : -1]
        self.assertTrue(tail, "the check has lines")
        self.assertIn("--untracked-files=all", tail[0])
        self.assertTrue(any("rev-parse HEAD" in line for line in tail), "the HEAD check is there")


def check_lines() -> str:
    """The block's own tree-check lines, from its VERIFY.8 marker to the end of the block."""
    lines = block_lines()
    return "\n".join(lines[lines.index(CHECK_MARK) : -1])


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class Build1TreeCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.w = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.w)
        self.repo = self.w / "verify"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "CLAUDE.md").write_text("committed\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        # Untracked files must be found by the check's own flag, not by this repo's default.
        git(self.repo, "config", "status.showUntrackedFiles", "no")
        self.sha = git(self.repo, "rev-parse", "HEAD")

    def run_check(self) -> subprocess.CompletedProcess:
        script = "set -euo pipefail\n" + check_lines() + "\n"
        env = {**os.environ, "W": str(self.w), "FREEZE_SHA": self.sha}
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(self.run_check().returncode, 0)

    def test_rewritten_tracked_file_fails_and_is_named(self) -> None:
        (self.repo / "CLAUDE.md").write_text("rewritten by a hook\n", encoding="utf-8")
        done = self.run_check()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("CLAUDE.md", done.stderr)

    def test_new_untracked_file_fails_and_is_named(self) -> None:
        (self.repo / "CLAUDE.original.md").write_text("committed\n", encoding="utf-8")
        done = self.run_check()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("CLAUDE.original.md", done.stderr)

    def test_file_in_a_new_directory_is_named_by_its_path(self) -> None:
        (self.repo / "newdir").mkdir()
        (self.repo / "newdir" / "f").write_text("x\n", encoding="utf-8")
        done = self.run_check()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("newdir/f", done.stderr)

    def test_ignored_build_output_passes(self) -> None:
        (self.repo / "target").mkdir()
        (self.repo / "target" / "x").write_text("x\n", encoding="utf-8")
        self.assertEqual(self.run_check().returncode, 0)

    def test_a_moved_head_fails(self) -> None:
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "moved")
        self.assertNotEqual(self.run_check().returncode, 0)


def gates_check() -> str:
    """The release-gates subshell, from its `(dirty=` line to the fence: the same defect, fixed once."""
    lines = PROCEDURE.read_text(encoding="utf-8").splitlines()
    add = lines.index('git worktree add -q --detach "$W/gates" "$FREEZE_SHA"')
    end = lines.index("```", add)
    return "\n".join(lines[add + 1 : end])


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class ReleaseGatesTreeCheckTests(Build1TreeCheckTests):
    """The release gates' worktree check stops on a dirty tree instead of only printing it."""

    def setUp(self) -> None:
        super().setUp()
        self.repo.rename(self.w / "gates")
        self.repo = self.w / "gates"

    def run_check(self) -> subprocess.CompletedProcess:
        env = {**os.environ, "W": str(self.w), "FREEZE_SHA": self.sha}
        return subprocess.run(["bash", "-c", gates_check()], capture_output=True, text=True, env=env)

    def test_clean_tree_passes(self) -> None:
        # Clean: the check lets the gates run (they then fail here, as the scripts are absent).
        self.assertNotIn("STOP", self.run_check().stderr)

    def test_ignored_build_output_passes(self) -> None:
        (self.repo / "target").mkdir()
        (self.repo / "target" / "x").write_text("x\n", encoding="utf-8")
        self.assertNotIn("STOP", self.run_check().stderr)

    def test_a_moved_head_fails(self) -> None:
        self.skipTest("the gates step checks the tree only; its scripts check the commit")

    def test_the_old_print_only_form_is_gone(self) -> None:
        self.assertNotIn("git status --short &&", gates_check())


if __name__ == "__main__":
    unittest.main()
