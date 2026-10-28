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
It also refuses, rather than guesses: a return whose value ends an if/else branch rather
than the function body, a tuple value whose element is not a plain top-level match, and any
mismatch that is not expected-TempDir/found-Arc<TempDir>.
"""

import importlib.util
import json
import re
import sys

if len(sys.argv) != 3:
    sys.exit("usage: fixture-dir-sweep.py <repo root> <clippy json>")
root, report = sys.argv[1], sys.argv[2]
ALIAS = "crate::gateway::router::tests::FixtureDir"
TD = re.compile(r"(?:tempfile::)?TempDir\b")

# The surface inventory's bracket-aware splitter (it already skips `->`).
_spec = importlib.util.spec_from_file_location(
    "check_surface_inventory", f"{root}/scripts/release/check_surface_inventory.py"
)
if _spec is None or _spec.loader is None:
    sys.exit("fixture-dir-sweep: cannot load scripts/release/check_surface_inventory.py")
_inventory = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _inventory  # its dataclasses look the module up
_spec.loader.exec_module(_inventory)


def split_top(text):
    return [piece for _, piece in _inventory.split_top(text, text)]


files = {}


def lines_of(name):
    if name not in files:
        files[name] = open(f"{root}/{name}").read().split("\n")
    return files[name]


def tuple_inside(text):
    """The inside of `text` when it is exactly one parenthesised tuple, else None."""
    text = text.strip()
    if not (text.startswith("(") and text.endswith(")")):
        return None
    depth = 0
    for i, ch in enumerate(text):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0 and i != len(text) - 1:
            return None
    return text[1:-1] if depth == 0 else None


def replace_element(decl_line, index):
    """Rewrite the TempDir of the `index`th element of the one tuple on `decl_line`."""
    open_at, close_at = decl_line.find("("), decl_line.rfind(")")
    if open_at < 0 or close_at < open_at:
        return None
    inside = decl_line[open_at + 1 : close_at]
    parts = split_top(inside)
    if index >= len(parts) or len(TD.findall(parts[index])) != 1:
        return None
    parts[index] = TD.sub(ALIAS, parts[index])
    # split_top drops an empty last piece: keep a singleton tuple's comma.
    trailing = "," if inside.rstrip().endswith(",") else ""
    return decl_line[: open_at + 1] + ",".join(parts) + trailing + decl_line[close_at:]


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
    inside = tuple_inside(init)
    if inside is not None:
        values = [v.strip() for v in split_top(inside)]
        if values.count(value) != 1:
            return False
        new = replace_element(lines[i], values.index(value))
        if new is None:
            return False
        lines[i] = new
        return True
    # A plain initialiser: only a declaration naming exactly one TempDir.
    if len(TD.findall(lines[i])) != 1:
        return False
    lines[i] = TD.sub(ALIAS, lines[i])
    return True


def is_tail(lines, fn_line, span):
    """Whether `span` ends the function body opened at `fn_line`: the next code line
    after it is the closing brace at the function's own indentation."""
    indent = len(lines[fn_line]) - len(lines[fn_line].lstrip())
    first, last = span["text"][0], span["text"][-1]
    whole = first["highlight_start"] - 1 == len(first["text"]) - len(first["text"].lstrip()) and (
        last["highlight_end"] - 1 >= len(last["text"].rstrip())
    )
    if not whole:
        # Or one top-level element of a final tuple written on one line: `(state, store)`.
        if span["line_start"] != span["line_end"]:
            return False
        inside = tuple_inside(first["text"])
        value = first["text"][first["highlight_start"] - 1 : first["highlight_end"] - 1].strip()
        if inside is None or [v.strip() for v in split_top(inside)].count(value) != 1:
            return False
    k = span["line_end"]
    while k < len(lines) and not lines[k].strip():
        k += 1
    return k < len(lines) and lines[k] == " " * indent + "}"


def fix_return(name, span):
    lines = lines_of(name)
    i = span["line_start"] - 1
    fn = re.compile(r"\s*(?:pub(?:\([\w:]+\))?\s+)?(?:async\s+)?fn\s")
    while i >= 0 and not fn.match(lines[i]):
        i -= 1
    if i < 0 or not is_tail(lines, i, span):
        return False
    j = i
    while j < len(lines) and "{" not in lines[j]:
        j += 1
    sig = range(i, j + 1)
    arrow = [k for k in sig if "->" in lines[k]]
    if not arrow:
        return False
    targets = [k for k in sig if k >= arrow[0] and TD.search(lines[k]) and "FixtureDir" not in lines[k]]
    if len(targets) != 1 or len(TD.findall(lines[targets[0]])) != 1:
        return False
    lines[targets[0]] = TD.sub(ALIAS, lines[targets[0]])
    return True


def forward(notes):
    """The mismatch this script fixes: a TempDir expected, an Arc<TempDir> found."""
    m = re.search(r"expected ([^\n]*)\n\s*found ([^\n]*)", notes)
    if not m:
        return False
    expected, found = m.group(1), m.group(2)
    return "TempDir" in expected and "Arc<TempDir>" not in expected and "Arc<TempDir>" in found


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
    notes = "\n".join(c["message"] for c in m["children"])
    if "TempDir" not in notes:
        continue
    span = next(s for s in m["spans"] if s["is_primary"])
    text = span["text"][0]
    value = text["text"][text["highlight_start"] - 1 : text["highlight_end"] - 1].strip()
    where = f"{span['file_name']}:{span['line_start']}: {text['text'].strip()[:90]}"
    if not forward(notes):
        unplaced.append(where + "  (not expected-TempDir/found-Arc)")
        continue
    if not (fix_field(span["file_name"], span["line_start"], value) or fix_return(span["file_name"], span)):
        unplaced.append(where)

for name, lines in files.items():
    open(f"{root}/{name}", "w").write("\n".join(lines))
print(f"files read: {len(files)}")
for item in unplaced:
    print("UNPLACED", item)
