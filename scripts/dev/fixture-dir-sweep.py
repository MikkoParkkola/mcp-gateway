#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rewrite tests that hold a router fixture's directory as a plain TempDir to FixtureDir.

The router test fixtures hand back `FixtureDir` (an `Arc<TempDir>` shared with the task
store, so a worker's late write cannot land while the test removes the directory).
Callers that still name `tempfile::TempDir` fail with E0308 "expected `TempDir`, found
`Arc<TempDir>`". rustc points at the value, not at the annotation that expects TempDir,
so this finds the annotation from the value's shape:
- a struct field initialiser (`name: value`, or a tuple of values): that field's declared
  type in the same file, the element at the value's position;
- anything else (a returned tuple, a returned fixture call): the enclosing function's
  return type;
and rewrites that `TempDir` to `crate::gateway::router::tests::FixtureDir`.

Usage, on a tip where callers still name TempDir:
  1. cargo clippy --all-targets --all-features --message-format=json > waves.json
  2. python3 scripts/dev/fixture-dir-sweep.py . waves.json
  3. cargo fmt --all
  4. repeat until clippy reports no such mismatch (each wave exposes the helpers one
     level further out; the first sweep took six waves: 102, 39, 20, 7, 1, 0).

What it cannot place it prints as UNPLACED, for a hand edit. Shapes it does not handle:
a field name declared in more than one struct of the file; a field initialised by
shorthand (`store,`); a fixture value passed as a function parameter; a line or return
type holding more than one TempDir (tuple pairs such as `(log_dir, store)`, three- or
four-element returns, tuple type aliases); a struct declared in another file; and the
reverse case, a plain `tempdir()` assigned where FixtureDir is now expected (wrap it in
`Arc::new`).
"""
import json
import re
import sys

if len(sys.argv) != 3:
    sys.exit("usage: fixture-dir-sweep.py <repo root> <clippy json>")
root, report = sys.argv[1], sys.argv[2]
ALIAS = "crate::gateway::router::tests::FixtureDir"
TD = re.compile(r"(?:tempfile::)?TempDir\b")

files = {}


def lines_of(name):
    if name not in files:
        files[name] = open(f"{root}/{name}").read().split("\n")
    return files[name]


def top_level_parts(text):
    """Split a parenthesised tuple's inside at top-level commas."""
    depth, parts, cur = 0, [], ""
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def replace_nth_temp(text, index):
    """Replace the TempDir in the `index`th element of the outermost tuple in `text`."""
    open_at = text.index("(")
    close_at = text.rindex(")")
    parts = top_level_parts(text[open_at + 1 : close_at])
    if index >= len(parts) or not TD.search(parts[index]) or "FixtureDir" in parts[index]:
        return None
    parts[index] = TD.sub(ALIAS, parts[index], count=1)
    return text[: open_at + 1] + ",".join(parts) + text[close_at:]


def fix_field(name, lineno, value):
    lines = lines_of(name)
    m = re.match(r"\s*(\w+)\s*:\s*(.*?),?\s*$", lines[lineno - 1])
    if not m:
        return False
    field, init = m.group(1), m.group(2)
    decl = re.compile(rf"^\s*(?:pub(?:\([\w:]+\))?\s+)?{field}\s*:\s*(.*TempDir.*?),?\s*$")
    hits = [i for i, l in enumerate(lines) if decl.match(l) and "FixtureDir" not in l]
    if len(hits) != 1:
        return False
    i = hits[0]
    if init.startswith("("):
        index = [p.strip() for p in top_level_parts(init.strip("()"))].index(value) if value in init else -1
        if index < 0:
            return False
        new = replace_nth_temp(lines[i], index)
        if new is None:
            return False
        lines[i] = new
    else:
        lines[i] = TD.sub(ALIAS, lines[i], count=1)
    return True


def fix_return(name, lineno):
    lines = lines_of(name)
    i = lineno - 1
    while i >= 0 and not re.match(r"\s*(?:pub(?:\([\w:]+\))?\s+)?(?:async\s+)?fn\s", lines[i]):
        i -= 1
    if i < 0:
        return False
    j = i
    while j < len(lines) and "{" not in lines[j]:
        j += 1
    sig = list(range(i, j + 1))
    arrow = [k for k in sig if "->" in lines[k]]
    if not arrow:
        return False
    targets = [k for k in sig if k >= arrow[0] and TD.search(lines[k]) and "FixtureDir" not in lines[k]]
    if len(targets) != 1 or len(TD.findall(lines[targets[0]])) != 1:
        return False
    lines[targets[0]] = TD.sub(ALIAS, lines[targets[0]], count=1)
    return True


unplaced = []
for raw in open(report):
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        continue
    if msg.get("reason") != "compiler-message":
        continue
    m = msg["message"]
    if m["level"] != "error" or (m.get("code") or {}).get("code") != "E0308":
        continue
    notes = " ".join(c["message"] for c in m["children"])
    if "Arc<TempDir>" not in notes:
        continue
    span = next(s for s in m["spans"] if s["is_primary"])
    text = span["text"][0]
    value = text["text"][text["highlight_start"] - 1 : text["highlight_end"] - 1].strip()
    name, lineno = span["file_name"], span["line_start"]
    done = fix_field(name, lineno, value) or fix_return(name, lineno)
    if not done:
        unplaced.append(f"{name}:{lineno}: {text['text'].strip()[:90]}")

for name, lines in files.items():
    open(f"{root}/{name}", "w").write("\n".join(lines))
print(f"files touched: {len(files)}")
for item in unplaced:
    print("UNPLACED", item)
