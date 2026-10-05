#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A change that adds an event source leaves the events core alone (MIK-7720 U10).

Each new source is one `EventSource` implementation and nothing else
(docs/design/2026-10-01-mik-7630-event-sources-4.0.0.md section 1). A change
counts as adding a source when any line it adds under `src/` holds an
`impl EventSource for`, in a new file or an existing one. Such a change may
add files under `src/events/` and add or remove bare module declarations in
`src/events/mod.rs` (the registry line). Any other edit under `src/events/` is
a core change and fails. A change that
adds no source is not judged: core fixes land through their own review.

Usage: check-event-source-scope.py [BASE]   (default: origin/docs/ranking-1-release-line)
"""

from __future__ import annotations

import re
import subprocess
import sys

EVENTS = "src/events/"
REGISTRY = "src/events/mod.rs"
# Generic and path-qualified forms too: `impl<T> crate::events::EventSource for`.
SOURCE_IMPL = re.compile(r"\bimpl\b[^{;]*\bEventSource\s+for\b")
# The registry line: a bare module declaration, nothing else.
DECLARATION = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?mod\s+\w+\s*;\s*$")


def violations(changes, adds_source, registry_lines):
    """Core edits a source-adding change makes; `None` when it adds no source.

    `changes` is `(status, path)` pairs from `git diff --name-status`,
    `adds_source` whether an added line under `src/` holds an `impl
    EventSource for`, and `registry_lines` the `+`/`-` lines of the
    registry's diff without their marker.
    """
    if not adds_source:
        return None
    found = []
    for status, path in changes:
        if not path.startswith(EVENTS) or status == "A":
            continue
        if path == REGISTRY and status == "M":
            stray = [l for l in registry_lines if l.strip() and not DECLARATION.match(l)]
            found.extend(f"{path}: not a module declaration: {l.strip()}" for l in stray)
            continue
        found.append(f"{path}: {status} (core file)")
    return found


def changed_lines(span, path, marker):
    return [
        l[1:]
        for l in git("diff", "--unified=0", "--no-renames", span, "--", path).splitlines()
        if l[:1] in marker and not l.startswith(("+++", "---"))
    ]


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/docs/ranking-1-release-line"
    span = f"{base}...HEAD"
    changes = []
    for line in git("diff", "--name-status", "--no-renames", span, "--", EVENTS).splitlines():
        status, path = line.split("\t", 1)
        changes.append((status[0], path))
    adds_source = any(SOURCE_IMPL.search(l) for l in changed_lines(span, "src/", "+"))
    registry_lines = changed_lines(span, REGISTRY, "+-")
    found = violations(changes, adds_source, registry_lines)
    if found is None:
        print("event-source scope: this change adds no event source; not judged")
        return 0
    if found:
        for line in found:
            print(f"FAIL {line}")
        print("A change that adds an event source must not edit the events core (MIK-7720 U10).")
        return 1
    print("event-source scope: the new source touches no core file")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
