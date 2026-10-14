#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Refuse wall-clock upper bounds under 5 s in tests (MIK-8222, timing-flakes).

A test that tells two outcomes apart by elapsed time against a short window
goes red on a loaded runner. Wait on an event, or use `test_wait`, instead.

Lexical by design: the threat is a careless timing oracle, not an adversary.
A window built at run time is refused (fail closed); a spelling this misses is
an accepted miss. 5 s is a policy cutoff: `Duration::from_secs(5)` is already
the tree's hang bound, so a window at or over it is read as a hang guard.

Timeouts get the same cutoff (MIK-8247). In test code, a `timeout(W, f)`
whose expiry fails the test (`.await` then `.expect`, `.unwrap`, `?` or
`.unwrap_or_else(|_| panic!..)`, directly or through a `let` binding) is
refused when W is under 5 s or cannot be resolved. A fn on a paused clock
(`start_paused = true`, `time::pause()`) is skipped: its time is virtual.
Test code is a test path, or a product file from its first `#[cfg(test)]`.
A const reaches a file `include!`d by the file that defines it.

New or changed test code (`--base`) meets stricter rules: an elapsed bound or
failing timeout under 10 s (the floor); a `sleep` used as a window; a timeout
expected to elapse, then asserted; a poll budget under 10 s; a short product
timer slept against; and (MIK-8360) a short timeout reaching a product through
a timeout-named builder or call (`.with_x_timeout(1 s)`), a timeout-named field
(`timeout: 300 ms`), or a `timeout(W, ..)` whose result is asserted `is_ok`.
A `// timing:` tag from the closed set, a `timing-oracle:`, or a paused clock
exempts a site. For an elapsed bound, the paused clock exempts it only when
the instant measured is tokio's: a `std::time::Instant` reads real time on a
paused clock too (MIK-8360).

Stated misses: `timeout_at`; a `select!` arm on `sleep`; a `let`-bound result
first consumed over 2000 characters later; a fn that pauses the clock partway,
which is skipped whole; a commented-out `include!`, or a file included by two
files (the last includer's consts are used). A same-named binding that shadows
the timeout's result can be read as consuming it: that fails loudly, never
quietly. And, for MIK-8360 (none is lexical; the fix pattern follows each):
- a bounded wait whose clock starts before its premise holds (MIK-8359 t14):
  wait first on a premise signal that moves without the event under test;
- a bound derived from a product timeout plus a fixed margin (#3826): any
  margin can be outrun; await the event and keep the bound a hang guard;
- a literal window handed to a generic helper whose builder sees only its
  parameter, or a timing-named const passed as an argument;
- a short window as a positional constructor argument with no timing name
  (`relay_state(mock, 1)`, `transport(url, 1 s)`);
- `timeout(..).await.is_ok()` returned from a helper and asserted by the caller;
- `x.reset_timeout = ..` assignments and shorthand `timeout,` fields;
- a race between a test bound and a longer product timer told only by a
  message (messages are blanked): assert the error kind or cause instead;
- `ttl`, `interval` and `period` fields: legitimate when waited out by event,
  refused only beside a waited real-clock sleep (the product-timer rule);
- product code after a file's first `#[cfg(test)]` is read as test code.
- a bare `.timeout(D)` method (an HTTP client's request timeout): 77 test
  sites at MIK-8360's base, too many to gate without a separate decision;
  a short one bounds the success path, so prefer the 10 s floor;
- a sleep used as a window inside a helper whose caller holds the assert
  (MIK-8354's `short_window`): the rule looks for the assert in the same fn.

The allowlist is shrink-only: with `--base <ref>` a row absent from the list
at `ref` fails. The comparison is skipped only when `ref` has no list.

One row may move (MIK-8291): a new row is carried when its whole fn moved
byte-exact from a donor path that held the row at the base, the donor is spent
once (its row and its fn text are gone at head, and no same-named fn there
still holds the exact raw assertion substring, comments and literals included
with no scanner filtering), the byte-exact moved fn occurs exactly once at
the destination at head, the destination did not already hold that fn text
at the base, and the assertion's window resolves to equal seconds at both
revisions. Incomplete base or head evidence refuses carry.

Usage:
    check-timing-asserts.py               # check the tree
    check-timing-asserts.py --base <ref>  # also refuse rows added since <ref>
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from check_timing_asserts_core import (
    HANG_BOUND_HOME,
    THRESHOLD_S,
    Finding,
    Row,
    Scope,
    blank_strings_and_comments,
    format_row,
    includers_of,
    parse_allowlist,
    resolve,
    scan_text,
    scan_timeouts,
    tree_consts,
)
from check_timing_asserts_newcode import (
    ABSENCE,
    BUDGET,
    ELAPSE,
    FIELD,
    FLOOR,
    FLOOR_S,
    IS_OK,
    ORACLE,
    SETTER,
    SLEEP,
    TAG,
    TIMER,
    fn_spans,
    oracle_covers,
    scan_new,
)
from check_timing_asserts_carry import carried_rows, make_revision

ROOT = Path(__file__).resolve().parents[2]
ALLOWLIST = Path(__file__).with_name("timing-asserts-allowlist.tsv")
SCANNED = ("src", "tests", "crates")


def added_lines(base: str) -> dict[str, set[int]]:
    """Lines added or changed since the merge base with `base`, by path.

    Read from the working tree, so uncommitted edits count as new.
    """
    merge_base = subprocess.run(
        ["git", "merge-base", base, "HEAD"], cwd=ROOT, capture_output=True, text=True
    ).stdout.strip() or base
    diff = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", "--no-renames", merge_base, "--", *SCANNED],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found: dict[str, set[int]] = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@") and path:
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            first, count = int(m.group(1)), int(m.group(2) or 1)
            found.setdefault(path, set()).update(range(first, first + count))
    return {p: lines for p, lines in found.items() if lines}


def judge(found: list[Finding], rows: list[Row], base: list[Row] | None, carried=frozenset()) -> list[str]:
    """Errors: unlisted findings, stale or ambiguous rows, and rows not in `base`.

    `base` is the list at the base ref, or None when the base has none (the
    cutover), which is the one case the shrink-only comparison is skipped.
    """
    errors = []
    listed = set()
    for row in rows:
        matches = [f for f in found if (f.path, f.fn, f.assertion) == row[:3]]
        if not matches:
            errors.append(f"STALE {row.path} ({row.fn}): no such assert, drop the row: {row.assertion}")
        elif len(matches) > 1:
            lines = ", ".join(str(f.line) for f in matches)
            errors.append(f"AMBIGUOUS {row.path} ({row.fn}): the row matches lines {lines}: {row.assertion}")
        listed.update((f.path, f.line) for f in matches)
    errors += [str(f) for f in found if (f.path, f.line) not in listed]
    if base is not None:
        known = {r[:3] for r in base}
        errors += [
            f"NEW ROW {r.path} ({r.fn}): the allowlist is shrink-only; wait on an event instead: {r.assertion}"
            for r in rows
            if r[:3] not in known and r[:3] not in carried
        ]
    return errors


def rust_files():
    for top in SCANNED:
        yield from sorted((ROOT / top).rglob("*.rs"))


def read_base(ref: str) -> list[Row] | None:
    rel = ALLOWLIST.resolve().relative_to(ROOT.resolve()).as_posix()
    shown = subprocess.run(["git", "show", f"{ref}:{rel}"], cwd=ROOT, capture_output=True, text=True)
    if shown.returncode == 0:
        return parse_allowlist(shown.stdout)
    exists = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=ROOT, capture_output=True)
    if exists.returncode != 0:
        raise SystemExit(f"FAIL cannot read base {ref!r}; the shrink-only check is not skipped")
    return None


def judge_new(found, rows, texts, consts, includers, added, carried=frozenset()):
    """(findings left for the 5 s rule, new-code errors), given added lines.

    A window on a changed line that carries a well-formed `timing-oracle:` is
    excused from the 5 s rule too (C), so an oracle under 5 s is possible. A
    new-code error is dropped only where the 5 s rule already reports the
    same line as an error; an allowlisted line in a changed span is still
    judged as new, so the allowlist never covers new code (#3746 review).
    """
    kept = [
        f
        for f in found
        if not (f.line in added.get(f.path, ()) and oracle_covers(texts[f.path], f.line, f.assertion))
    ]
    listed = {r[:3] for r in rows}
    reported = {(f.path, f.line) for f in kept if (f.path, f.fn, f.assertion) not in listed}
    errors = [
        str(f)
        for path, lines in sorted(added.items())
        if path in texts
        for f in scan_new(path, texts[path], consts, includers, lines, carried=carried)
        if (f.path, f.line) not in reported
    ]
    return kept, errors


def _pinned_base(ref: str) -> str:
    """The one commit `ref` names, pinned once; `ref` itself when the pin
    fails, so `read_base` keeps its unchanged SystemExit semantics."""
    pinned = subprocess.run(
        ["git", "rev-parse", f"{ref}^{{commit}}"], cwd=ROOT, capture_output=True, text=True
    )
    if pinned.returncode == 0 and pinned.stdout.strip():
        return pinned.stdout.strip()
    return ref


def _base_revision(pin: str):
    """The complete base Revision at the pinned commit, or None.

    One `ls-tree` index and one `cat-file --batch` process; every listed
    `.rs` blob's id, type, size, and trailing newline are validated, and any
    failure means no Revision exists (carry is then empty, never partial).
    """
    try:
        listed = subprocess.run(
            ["git", "ls-tree", "-r", "-z", pin, "--", *SCANNED], cwd=ROOT, capture_output=True
        )
        if listed.returncode != 0:
            return None
        entries = []
        for record in listed.stdout.split(b"\0"):
            if not record:
                continue
            meta, _, raw_path = record.partition(b"\t")
            fields = meta.split(b" ")
            if len(fields) != 3 or not raw_path:
                return None
            _, kind, oid = fields
            try:
                path = raw_path.decode("utf-8")
                oid_text = oid.decode("ascii")
            except UnicodeDecodeError:
                return None
            if not path.endswith(".rs"):
                continue
            if kind != b"blob":
                return None
            entries.append((path, oid_text))
        raw_by_path: dict[str, bytes] = {}
        if entries:
            request = "".join(f"{oid}\n" for _, oid in entries).encode("ascii")
            batch = subprocess.run(
                ["git", "cat-file", "--batch"], cwd=ROOT, input=request, capture_output=True
            )
            if batch.returncode != 0:
                return None
            out, at = batch.stdout, 0
            for path, oid in entries:
                nl = out.find(b"\n", at)
                if nl < 0:
                    return None
                header = out[at:nl].split(b" ")
                if len(header) != 3 or header[0] != oid.encode("ascii") or header[1] != b"blob":
                    return None
                try:
                    size = int(header[2])
                except ValueError:
                    return None
                start, end = nl + 1, nl + 1 + size
                if size < 0 or end >= len(out) or out[end : end + 1] != b"\n":
                    return None
                if path in raw_by_path:
                    return None
                raw_by_path[path] = out[start:end]
                at = end + 1
            if at != len(out):
                return None
        return make_revision(pin, raw_by_path, frozenset(raw_by_path))
    except Exception:
        return None


def _head_revision():
    """The complete head Revision from `read_bytes()` on the enumerated
    filesystem set, or None when any enumerated file cannot be read."""
    try:
        raw_by_path = {}
        for path in rust_files():
            raw_by_path[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        return make_revision("head", raw_by_path, frozenset(raw_by_path))
    except Exception:
        return None


def _compute_carried(pin: str, base_rows, rows):
    """Carried triples for this run, computed once; empty unless base rows
    exist, a candidate has a same-(fn, assertion) donor, and both complete
    Revisions build. Any failure refuses carry without disturbing the scans."""
    try:
        if not base_rows:
            return frozenset()
        base_triples = {r[:3] for r in base_rows}
        donors = {(r.fn, r.assertion) for r in base_rows}
        if not any(r[:3] not in base_triples and (r.fn, r.assertion) in donors for r in rows):
            return frozenset()
        base_revision = _base_revision(pin)
        if base_revision is None:
            return frozenset()
        head_revision = _head_revision()
        if head_revision is None:
            return frozenset()
        return carried_rows(base_rows, rows, base=base_revision, head=head_revision)
    except Exception:
        return frozenset()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", metavar="REF", help="refuse allowlist rows added since REF")
    args = parser.parse_args(argv)
    texts = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8", errors="replace") for p in rust_files()}
    consts = tree_consts(texts)
    includers = includers_of(texts)
    found = [f for path, text in texts.items() for f in scan_text(path, text, consts)]
    found += [f for path, text in texts.items() for f in scan_timeouts(path, text, consts, includers)]
    rows = parse_allowlist(ALLOWLIST.read_text(encoding="utf-8")) if ALLOWLIST.exists() else []
    new_errors: list[str] = []
    base_rows = None
    carried = frozenset()
    if args.base:
        # PR-C: new or changed spans only (judge_new).
        pin = _pinned_base(args.base)
        base_rows = read_base(pin)
        if base_rows is not None:
            carried = _compute_carried(pin, base_rows, rows)
        found, new_errors = judge_new(found, rows, texts, consts, includers, added_lines(args.base), carried=carried)
    else:
        print("No --base: the new-code rules (10 s floor, sleep windows, poll budgets) were not run.")
    errors = judge(found, rows, base_rows, carried=carried) + new_errors
    for line in errors:
        print(line)
    print(f"{len(found)} timing asserts or timeouts under {THRESHOLD_S:g} s or unresolvable, {len(rows)} allowlisted.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
