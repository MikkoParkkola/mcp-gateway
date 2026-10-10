#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No `... | grep -q` in a shell script or workflow step (MIK-8333).

Under `set -o pipefail` (and a workflow step's `shell: bash`), `grep -q` exits
on its first match, the writer takes SIGPIPE (141) and the pipeline fails: a
false red, or under `!` a false pass. Capture the text and match it with a
here-string (`grep -q pat <<<"$x"`) or read a file instead.

Scans every tracked `*.sh` and `*.bash` file and `.github/workflows/*.y*ml`,
pipefail or not: a script that gains `set -o pipefail` later inherits the bug
silently.
Covers `grep`/`egrep`/`fgrep`/`rg` with `-q`, `--quiet` or `--silent`.
Lexical: a pipe split across a line continuation ending in `|` is missed.

Usage: check-pipefail-grep-q.py [--self-test] [<root>]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PIPED_QUIET = re.compile(
    r"(?<![|])\|(?![|&])\s*(?:grep|egrep|fgrep|rg)\b[^|;&]*?\s"
    r"(?:-[A-Za-z]*q[A-Za-z]*|--quiet|--silent)\b"
)


def check_text(path: str, text: str) -> list[str]:
    return [
        f"{path}:{n}: piped quiet grep; under pipefail a match can fail the pipeline "
        f"(use `grep -q pat <<<\"$x\"`): {line.strip()}"
        for n, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith("#") and PIPED_QUIET.search(line)
    ]


def problems(root: Path) -> list[str]:
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "*.sh", "*.bash", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout.decode()
    paths = [root / name for name in tracked.split("\0") if name]
    return [
        e
        for p in paths
        for e in check_text(str(p.relative_to(root)), p.read_text(encoding="utf-8"))
    ]


def self_test() -> list[str]:
    bad = {
        "negated guard": '! echo "$rbac" | grep -qE "^kind: ClusterRole" || exit 1\n',
        "command producer": '"$HELM" template t "$CHART" | grep -q "^kind: Deployment"\n',
        "continuation line": '  | grep -q "mcp-gateway@sha256:" \\\n',
        "printf producer": 'if ! printf "%s" "$PROBE" | grep -q /livez; then\n',
        "kind clusters": 'if ! "$KIND" get clusters | grep -qx "$CLUSTER"; then\n',
        "rg": 'git log -1 | rg -q "^Local-Tested: "\n',
        "long option": 'cat f | grep --quiet x\n',
        "split flags": 'if printf "%s\\n" "$file" | grep -E -q -i -e "$marker"; then\n',
        "compact flags": 'echo "$x" | grep -Eqi pat\n',
        "workflow step": "        run: helm template t c | grep -q '^kind: Deployment'\n",
    }
    good = {
        "here-string": 'grep -q "$field" <<<"$render"\n',
        "file operand": "grep -q '^kind: Deployment' rendered.yaml\n",
        "or-list": 'cmd || grep -q x f\n',
        "comment": "# never `render | grep -q`: under pipefail ...\n",
        "count, not quiet": 'echo "$x" | grep -c y\n',
        "quiet grep then pipe": 'grep -q x f | cat\n',
    }
    errors = [f"self-test: not flagged ({k})" for k, t in bad.items() if not check_text("t", t)]
    errors += [f"self-test: flagged ({k})" for k, t in good.items() if check_text("t", t)]
    return errors


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--self-test"]
    errors = self_test()
    if errors or "--self-test" in argv:
        print("\n".join(errors) or "self-test ok", file=sys.stderr if errors else sys.stdout)
        return 1 if errors else 0
    found = problems(Path(args[0]) if args else Path(__file__).resolve().parents[2])
    print("\n".join(found) or "no piped quiet grep", file=sys.stderr if found else sys.stdout)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
