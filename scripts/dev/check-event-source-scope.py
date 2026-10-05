#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A change that adds an event source leaves the events core alone (MIK-7720 U10).

Each new source is one `EventSource` implementation and nothing else
(docs/design/2026-10-01-mik-7630-event-sources-4.0.0.md section 1). A change
counts as adding a source when a Rust file under `src/` ends it with more
`impl ... EventSource for` blocks than it started with (a new file or an
existing one; a split header or an aliased import counts). Such a change may
add files under `src/events/` and add bare module declarations in
`src/events/mod.rs` for the modules it adds (the registry line). Any other
edit under `src/events/` is a core change and fails. A source impl in test
code (`*_tests.rs`, `tests/`) or a comment does not count as adding one.
An impl a macro generates is not seen. A change that adds no source is not judged: core fixes land through
their own review.

Usage: check-event-source-scope.py [BASE]   (default: origin/docs/ranking-1-release-line)
"""

from __future__ import annotations

import re
import subprocess
import sys

EVENTS = "src/events/"
REGISTRY = "src/events/mod.rs"
# The registry line: a bare module declaration, nothing else.
DECLARATION = re.compile(r"^\s*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)\s*;\s*$")


def is_test_path(path):
    """Test code may mock a source without adding one."""
    name = path.rsplit("/", 1)[-1]
    return path.startswith("tests/") or "/tests/" in path or name == "tests.rs" or name.endswith("_tests.rs")


def impl_count(text):
    """`impl ... EventSource for` blocks in `text`, header lines joined, aliases
    (`use ...::EventSource as Alias;`) followed. Comments are dropped first."""
    code = re.sub(r"//[^\n]*", "", text)
    names = ["EventSource", *re.findall(r"\bEventSource\s+as\s+(\w+)", code)]
    header = r"\bimpl\b[^{};]*?\b(?:%s)\s+for\b" % "|".join(map(re.escape, names))
    return len(re.findall(header, code))


def adds_source(files):
    """Whether any non-test `(path, before, after)` gains an EventSource impl."""
    return any(
        impl_count(after) > impl_count(before) for path, before, after in files if not is_test_path(path)
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
    """Lines the diff of `path` adds or removes (`marker`)."""
    return [
        l[1:]
        for l in git("diff", "--unified=0", "--no-renames", span, "--", path).splitlines()
        if l[:1] == marker and not l.startswith(("+++", "---"))
    ]


def show(rev, path):
    found = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    return found.stdout if found.returncode == 0 else ""


def rust_files(span, base):
    """`(path, text at the merge base, text at HEAD)` for each changed `src/` Rust file."""
    fork = git("merge-base", base, "HEAD").strip()
    fields = git("diff", "-z", "--name-only", "--no-renames", span, "--", "src/").split("\0")
    return [(p, show(fork, p), show("HEAD", p)) for p in fields if p.endswith(".rs")]


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
        adds_source(rust_files(span, base)),
        diff_lines(span, REGISTRY, "+"),
        diff_lines(span, REGISTRY, "-"),
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
