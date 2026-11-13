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
exits 1 with the matched lines and the exact `gh pr edit` command when the label is missing, else 0. The CI job also
checks that the label exists in the repository at all (a rename or delete would otherwise make `gh pr edit` fail for
every OS-sensitive pull request) and says how to recreate it.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

LABEL = "os-int"
# Words that put a Rust or TOML line in the OS-sensitive set, in any case (KEYCHAIN_SERVICE, FileLock): the secret
# store and keychain (Cargo.toml spells the crates with hyphens), file locks (flock and fcntl, the fs2 and fd-lock
# crates, std's File lock and unlock methods by their qualified or shared/exclusive names; a bare `x.lock()` is not
# matched, since it is as often a Mutex).
PATTERN = re.compile(
    r"secret[_-]?store|keychain|security[_-]?framework|fs[_-]?lock|fd[_-]?lock|file[_-]?lock|\bfs2\b|FileExt\b"
    r"|flock|fcntl|O_EXLOCK|keyring|File::(?:try_)?(?:un)?lock\b|\.unlock\s*\(|(?:try_)?lock_(?:shared|exclusive)\b",
    re.IGNORECASE,
)
SUFFIXES = (".rs", ".toml")
SHOWN = 10
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def unquote(path: str) -> str:
    """A path as git prints it: quoted with C escapes when it holds odd bytes, or with a trailing tab when it holds a space."""
    path = path.rstrip("\t")
    if len(path) >= 2 and path[0] == path[-1] == '"':
        body = path[1:-1]
        try:
            return body.encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode("utf-8", "replace")
        except (UnicodeError, ValueError):
            return body
    return path


def header_path(line: str, prefix: str) -> str | None:
    """The file named by a `--- a/x` or `+++ b/x` header, or None for /dev/null."""
    raw = unquote(line[4:])
    if raw == "/dev/null":
        return None
    return raw[2:] if raw[:2] in ("a/", "b/") else raw


def scan(diff_text: str) -> list[tuple[str, int, str]]:
    """(path, line number, the changed line) for each added or removed line in a .rs or .toml file that matches.
    An added line is numbered in the new file, a removed one where it stood in the old file. File headers are read
    only outside a hunk: a hunk's own line counts say where its body ends, so a body line that starts with `++ ` or
    `-- ` is content, not a header. A deleted file is read by its old path."""
    out = []
    old_path = new_path = None
    old = new = 0
    left_old = left_new = 0
    for line in diff_text.splitlines():
        if left_old > 0 or left_new > 0:
            if line.startswith("\\"):  # "\ No newline at end of file"
                continue
            if line.startswith("+") and left_new > 0:
                path = new_path or old_path
                if path and path.endswith(SUFFIXES) and PATTERN.search(line[1:]):
                    out.append((path, new, line[1:].strip()))
                new += 1
                left_new -= 1
                continue
            if line.startswith("-") and left_old > 0:
                path = old_path or new_path  # a removed line belongs to the old file, which a rename changes
                if path and path.endswith(SUFFIXES) and PATTERN.search(line[1:]):
                    out.append((path, old, line[1:].strip()))
                old += 1
                left_old -= 1
                continue
            left_old = left_new = 0  # a malformed hunk: fall through and read the line as a header
        if line.startswith("diff --git"):
            old_path = new_path = None
        elif line.startswith("--- "):
            old_path = header_path(line, "--- ")
        elif line.startswith("+++ "):
            new_path = header_path(line, "+++ ")
        else:
            m = HUNK.match(line)
            if m:
                old, new = int(m.group(1)), int(m.group(3))
                left_old = int(m.group(2)) if m.group(2) is not None else 1
                left_new = int(m.group(4)) if m.group(4) is not None else 1
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
        "then push or reopen once, since a label counts from the next run (CONTRIBUTING.md).\n"
        f"If that command says the label does not exist (it was renamed or deleted), create it first:\n"
        f"  gh label create {LABEL} --description 'run the macOS int shard on this pull request'"
    )


def merge_problem(repo: str, base: str, head: str, expect_second: str) -> str | None:
    """None when `head` is the pull request's test-merge commit and `base` is its first parent: two parents, the second
    being the PR's head. Diffing against anything else would silently cover only part of the pull request, or changes
    that are not its own, so the check fails loudly instead."""
    def rev(ref: str) -> str:
        return subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}"],
                              capture_output=True, text=True).stdout.strip()
    expect = expect_second.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", expect):
        return f"the expected pull request head {expect_second!r} is not a full commit sha"
    parents = subprocess.run(["git", "-C", repo, "rev-list", "--parents", "-n", "1", head],
                             check=True, capture_output=True, text=True).stdout.split()[1:]
    if len(parents) != 2:
        return f"{head} has {len(parents)} parent(s), not the two of a pull request's merge commit; cannot tell which diff is the pull request's"
    if parents[1] != expect:
        return f"the merge commit's second parent is {parents[1][:12]}, not the pull request head {expect[:12]}; the checkout is not this run's merge"
    if rev(base) != parents[0]:
        return f"--base {base} is {rev(base)[:12] or 'not a commit'}, not the merge commit's first parent {parents[0][:12]}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--labels", default="[]")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--expect-second-parent", required=True,
                    help="the pull request's full head sha; --head must be its merge commit and --base its first parent")
    args = ap.parse_args()
    problem = merge_problem(args.repo, args.base, args.head, args.expect_second_parent)
    if problem:
        print(f"os-int check cannot run: {problem}")
        return 2
    # Bytes, decoded leniently: an unrelated non-UTF-8 file must not turn the check into a traceback. --text reads a
    # .rs or .toml that git guesses is binary; the pathspecs keep the dump to the files that can count.
    raw = subprocess.run(["git", "-C", args.repo, "diff", "--unified=0", "--no-color", "--text", "--no-ext-diff",
                          "--no-textconv", args.base, args.head, "--", "*.rs", "*.toml"],
                         check=True, capture_output=True).stdout
    hits = scan(raw.decode("utf-8", "replace"))
    message = verdict(hits, json.loads(args.labels), args.pr)
    if message:
        print(message)
        return 1
    print(f"{len(hits)} OS-sensitive line(s); the {LABEL} label is {'on' if hits else 'not needed'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
