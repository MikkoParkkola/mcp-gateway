#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pure whole-function carry for the timing-assert guard (MIK-8291).

The moved-row matcher over complete immutable `Revision`s. The source
factories and the factory-owned `RawInventory` count facts live in
`check_timing_asserts_source` and are re-exported here. No read callback,
no facade import, no mutable global is captured: incomplete evidence
refuses carry.
"""

from __future__ import annotations

from check_timing_asserts_core import scan_text, scan_timeouts
from check_timing_asserts_source import (
    _ABSENT,
    _ESCAPES,
    _FACTORY,
    _HEX,
    _MODIFIERS,
    _UNSUPPORTED_PREFIX,
    _UNUSABLE,
    RawFn,
    RawInventory,
    Revision,
    ValidatedSource,
    _body_end,
    _char_end,
    _escape_end,
    _is_ident_char,
    _is_ident_start,
    _mask_range,
    _modifier_start,
    _raw_string_end,
    _signature_body,
    _string_end,
    build_raw_fns,
    build_raw_inventory,
    make_revision,
    mask_strings_and_comments,
    validate_source,
)


def donor_retains(spans_D_head_same_F, A) -> bool:
    """The sole donor guard: exact raw substring, comments/literals included."""
    return any(A.encode("utf-8") in s.raw for s in spans_D_head_same_F)


def window_seconds(revision: Revision, path: str, fn: str, assertion: str) -> float | None:
    """Seconds of `(path, fn, assertion)` at `revision`, resolved on that side
    alone, or None unless exactly one matching finding resolves."""
    source = revision.sources.get(path)
    if source is None:
        return None
    consts = {name: list(entries) for name, entries in revision.consts.items()}
    includers = dict(revision.includers)
    text = source.text
    found = scan_text(path, text, consts, float("inf")) + scan_timeouts(path, text, consts, includers, float("inf"))
    matches = [f for f in found if (f.path, f.fn, f.assertion) == (path, fn, assertion)]
    if len(matches) != 1:
        return None
    return matches[0].window


def _inventory(revision: Revision, path: str, cache: dict):
    """Factory inventory for `path` at `revision`: a `RawInventory`,
    `_ABSENT` when the path is unlisted in `present`, or `_UNUSABLE`
    when listed but invalid."""
    key = (id(revision), path)
    if key not in cache:
        if path not in revision.present:
            cache[key] = _ABSENT
        else:
            source = revision.sources.get(path)
            built = build_raw_inventory(source) if source is not None else None
            if (
                built is None
                or not isinstance(built, RawInventory)
                or built.source is not source
                or any(span.source is not source for span in built.spans)
            ):
                cache[key] = _UNUSABLE
            else:
                cache[key] = built
    return cache[key]


def _named(spans, fn: str) -> list:
    return [span for span in spans if span.name == fn]


def _valid_named(spans, fn: str) -> list:
    """Same-named spans that neither contain nor sit inside another span:
    eligibility only; never cardinality."""
    valid = []
    for span in _named(spans, fn):
        nested = any(
            other is not span
            and (
                (span.start_cp <= other.start_cp and other.end_cp <= span.end_cp)
                or (other.start_cp <= span.start_cp and span.end_cp <= other.end_cp)
            )
            for other in spans
        )
        if not nested:
            valid.append(span)
    return valid


def _triple(row) -> tuple[str, str, str]:
    return (row[0], row[1], row[2])


def carried_rows(base_rows, head_rows, *, base: Revision, head: Revision) -> frozenset[tuple[str, str, str]]:
    """New head triples carried by a byte-exact whole-fn move (frozen r4 §5).

    Candidates are processed in sorted order; a donor triple is spent once,
    only on success. Each side's evidence and window come from its own
    complete `Revision` alone.
    """
    if not isinstance(base, Revision) or not isinstance(head, Revision):
        return frozenset()
    base_triples = {_triple(row) for row in base_rows}
    head_triples = {_triple(row) for row in head_rows}
    donors: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for donor in sorted(base_triples):
        donors.setdefault((donor[1], donor[2]), []).append(donor)
    cache: dict = {}
    spent: set[tuple[str, str, str]] = set()
    carried: set[tuple[str, str, str]] = set()
    for candidate in sorted(head_triples - base_triples):
        dest, fn, assertion = candidate
        dest_inv = _inventory(head, dest, cache)
        if dest_inv is _ABSENT or dest_inv is _UNUSABLE:
            continue
        dest_all = dest_inv.named(fn)
        dest_counts = {raw: dest_inv.count_raw(fn, raw) for raw in {s.raw for s in dest_all}}
        dest_spans = _valid_named(dest_inv.spans, fn)
        if len(dest_spans) != 1 or dest_counts.get(dest_spans[0].raw) != 1:
            continue
        moved_raw = dest_spans[0].raw
        for donor in donors.get((fn, assertion), []):
            if donor in spent or donor in head_triples:
                continue
            donor_path = donor[0]
            donor_inv = _inventory(base, donor_path, cache)
            if donor_inv is _ABSENT or donor_inv is _UNUSABLE:
                continue
            donor_all = donor_inv.named(fn)
            donor_counts = {raw: donor_inv.count_raw(fn, raw) for raw in {s.raw for s in donor_all}}
            donor_spans = _valid_named(donor_inv.spans, fn)
            if len(donor_spans) != 1 or donor_counts.get(donor_spans[0].raw) != 1 or donor_spans[0].raw != moved_raw:
                continue
            blocked = False
            for revision, path in ((head, donor_path), (base, dest)):
                there = _inventory(revision, path, cache)
                if there is _UNUSABLE:
                    blocked = True
                    break
                if there is not _ABSENT and there.count_raw(fn, moved_raw) > 0:
                    blocked = True
                    break
            if blocked:
                continue
            donor_head_inv = _inventory(head, donor_path, cache)
            donor_head_named = () if donor_head_inv is _ABSENT else donor_head_inv.named(fn)
            if donor_retains(donor_head_named, assertion):
                continue
            base_window = window_seconds(base, donor_path, fn, assertion)
            head_window = window_seconds(head, dest, fn, assertion)
            if base_window is None or head_window is None or base_window != head_window:
                continue
            carried.add(candidate)
            spent.add(donor)
            break
    return frozenset(carried)
