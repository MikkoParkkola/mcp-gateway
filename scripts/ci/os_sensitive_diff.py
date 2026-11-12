#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Does this pull request's diff need the `os-int` label?

A lane pull request whose diff adds or removes a line, in a Rust or TOML file, that names the secret store, the
keychain or a file lock is OS-sensitive: macOS behaves differently there, and only a merge train ran macOS, so a break
cost a whole train (train 46u: the keychain change to `init` passed its own CI and broke the macOS int shard). The
label makes the pull request run the macOS int shard; the lane adds it at READY, not on every push.

Docs, a file's name alone and platform cfg lines do not count (docs/ and markdown are not Rust or TOML; a measured
7-day window had 16 of 167 lane pull requests hit, against 23 for a cfg trigger of which 21 were noise).

  os_sensitive_diff.py --base REF --head REF --pr N --labels '["a","b"]' [--repo DIR]
exits 1 with the matched lines and the exact `gh pr edit` command when the label is missing, else 0.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

LABEL = "os-int"
# Words that put a Rust or TOML line in the OS-sensitive set.
PATTERN = re.compile(r"secret_store|SecretStore|keychain|Keychain|security_framework|fs_lock|flock|fcntl|O_EXLOCK|keyring")
SUFFIXES = (".rs", ".toml")
SHOWN = 10
HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan(diff_text: str) -> list[tuple[str, int, str]]:
    """(path, line number in the new file, the changed line) for each added or removed line that matches.
    A removed line is numbered where it stood in the old file."""
    out = []
    path = None
    old = new = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
            continue
        if line.startswith("--- ") or line.startswith("diff --git"):
            continue
        m = HUNK.match(line)
        if m:
            old, new = int(m.group(1)), int(m.group(2))
            continue
        if path is None or not path.endswith(SUFFIXES):
            continue
        if line.startswith("+"):
            if PATTERN.search(line[1:]):
                out.append((path, new, line[1:].strip()))
            new += 1
        elif line.startswith("-"):
            if PATTERN.search(line[1:]):
                out.append((path, old, line[1:].strip()))
            old += 1
    return out


def verdict(hits: list[tuple[str, int, str]], labels: list[str], pr: int) -> str | None:
    """None when the pull request is fine, else the failure message."""
    if not hits or LABEL in labels:
        return None
    lines = [f"  {p}:{n}: {t[:100]}" for p, n, t in hits[:SHOWN]]
    if len(hits) > SHOWN:
        lines.append(f"  ... and {len(hits) - SHOWN} more")
    return (
        "This diff touches OS-sensitive code (the secret store, the keychain or a file lock), and only a merge train\n"
        "runs macOS, so a macOS break would cost a train. Matched lines:\n" + "\n".join(lines) + "\n"
        f"Run the macOS int shard on this pull request at READY (not on every push):\n"
        f"  gh pr edit {pr} --add-label {LABEL}\n"
        "then push or reopen once, since a label counts from the next run (CONTRIBUTING.md)."
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--labels", default="[]")
    ap.add_argument("--repo", default=".")
    args = ap.parse_args()
    diff_text = subprocess.run(["git", "-C", args.repo, "diff", "--unified=0", "--no-color", args.base, args.head],
                               check=True, capture_output=True, text=True).stdout
    hits = scan(diff_text)
    message = verdict(hits, json.loads(args.labels), args.pr)
    if message:
        print(message)
        return 1
    print(f"{len(hits)} OS-sensitive line(s); the {LABEL} label is {'on' if hits else 'not needed'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
