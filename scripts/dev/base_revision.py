# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Which commit a shrink-only gate compares a change against.

A gate keeps a committed list that may only shrink and, with `--base REV`, refuses a list larger
than the one committed at the comparison commit. Two modes:

- BASE: REV itself. Push jobs: REV is the commit before the push, and a force push (REV no
  ancestor of HEAD) is still judged against the list it replaced.
- MERGE_BASE: where HEAD's history left REV (`git merge-base HEAD REV`). Pull requests and lanes:
  REV is the line tip, which may have shrunk the list after the branch was cut. A branch is then
  judged on its own change only; an entry it leaves alone merges onto the tip's shrunk list, and
  one it adds or raises shows as an addition. The train checks the merged tree.
"""
from __future__ import annotations

import enum
import subprocess
from pathlib import Path


class Compare(enum.Enum):
    BASE = "base"
    MERGE_BASE = "merge-base"


def comparison_commit(root: Path, rev: str, compare: Compare) -> str:
    """The commit `compare` names for `rev`, as a full sha. RuntimeError when `rev` is no commit
    in this clone, or has no merge-base with HEAD: a gate refuses then, never passes."""
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True)

    commit = git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
    if commit.returncode != 0 or not commit.stdout.strip():
        raise RuntimeError(f"base revision {rev!r} is not in this clone")
    if compare is Compare.BASE:
        return commit.stdout.strip()
    fork = git("merge-base", "HEAD", commit.stdout.strip())
    if fork.returncode != 0 or not fork.stdout.strip():
        raise RuntimeError(
            f"no merge-base between HEAD and {rev!r}: fetch full history (fetch-depth: 0, or "
            "git fetch --unshallow) so the branch point is in the clone"
        )
    return fork.stdout.strip()


def add_argument(parser) -> None:
    """The `--compare` option every shrink-only gate takes beside `--base`."""
    parser.add_argument(
        "--compare", choices=[c.value for c in Compare], default=Compare.BASE.value,
        help="base: the list at --base itself (push jobs); merge-base: at the branch point "
             "(pull requests and lanes)",
    )
