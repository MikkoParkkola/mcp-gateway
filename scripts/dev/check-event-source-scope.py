#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A change that adds an event source leaves the events core alone (MIK-7720 U10).

Each new source is one `EventSource` implementation and nothing else
(docs/design/2026-10-01-mik-7630-event-sources-4.0.0.md section 1). A change
counts as adding a source when any line it adds under `src/` holds an
`impl EventSource for`, in a new file or an existing one. Such a change may
add files under `src/events/` and add or remove bare module declarations in
`src/events/mod.rs` for the modules it adds (the registry line). Any other
edit under `src/events/` is a core change and fails. Test code and comments
that mention a source do not count as adding one. A change that
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
DECLARATION = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)\s*;\s*$")


def is_test_path(path):
    """Test code may mock a source without adding one."""
    name = path.rsplit("/", 1)[-1]
    return path.startswith("tests/") or "/tests/" in path or name == "tests.rs" or name.endswith("_tests.rs")


def adds_source(added_lines):
    """Whether any `(path, line)` added outside tests and comments holds a source impl."""
    return any(
        SOURCE_IMPL.search(line)
        for path, line in added_lines
        if not is_test_path(path) and not line.lstrip().startswith("//")
    )


def violations(changes, source_added, registry_added, registry_removed):
    """Core edits a source-adding change makes; `None` when it adds no source.

    `changes` is `(status, path)` pairs from `git diff --name-status`, and
    `registry_added` / `registry_removed` the lines the registry's diff adds
    and removes. The registry may only gain declarations of modules the change
    adds; an existing declaration is core wiring and may not change.
    """
    if not source_added:
        return None
    added = {p for s, p in changes if s == "A"}
    found = []
    for status, path in changes:
        if not path.startswith(EVENTS) or status == "A" or path == REGISTRY and status == "M":
            continue
        found.append(f"{path}: {status} (core file)")
    for line in registry_removed:
        if line.strip():
            found.append(f"{REGISTRY}: existing line changed: {line.strip()}")
    for line in registry_added:
        if not line.strip():
            continue
        declared = DECLARATION.match(line)
        if not declared:
            found.append(f"{REGISTRY}: not a module declaration: {line.strip()}")
        elif not {f"{EVENTS}{declared.group(1)}.rs", f"{EVENTS}{declared.group(1)}/mod.rs"} & added:
            found.append(f"{REGISTRY}: declares a module this change does not add: {line.strip()}")
    return found


def diff_lines(span, path, marker):
    """`(file, line)` for each line the diff of `path` adds or removes (`marker`)."""
    out, current = [], None
    for l in git("diff", "--unified=0", "--no-renames", span, "--", path).splitlines():
        if l.startswith("+++ "):
            current = l[6:] if l.startswith("+++ b/") else None
        elif l.startswith("--- "):
            continue
        elif l[:1] == marker:
            out.append((current, l[1:]))
    return out


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def main(argv):
    base = argv[1] if len(argv) > 1 else "origin/docs/ranking-1-release-line"
    span = f"{base}...HEAD"
    changes = []
    # NUL-separated so a path git would quote is read as written.
    fields = git("diff", "-z", "--name-status", "--no-renames", span, "--", EVENTS).split("\0")
    for status, path in zip(fields[0::2], fields[1::2]):
        changes.append((status[0], path))
    found = violations(
        changes,
        adds_source(diff_lines(span, "src/", "+")),
        [l for _, l in diff_lines(span, REGISTRY, "+")],
        [l for _, l in diff_lines(span, REGISTRY, "-")],
    )
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
