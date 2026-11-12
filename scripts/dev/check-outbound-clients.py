#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fail when product code can open an outbound connection from a place
PRIVACY.md does not list.

PRIVACY.md states that the gateway sends nothing anywhere the operator did not
configure or ask for, and names each call site. That statement stays true only
if a new HTTP, WebSocket, TCP or UDP client cannot appear unnoticed, so this
counts, per source file and per constructor kind, the lines of product code
that build one, and compares the counts with scripts/dev/outbound-sites.tsv.
A count that grows or shrinks, one kind replacing another, or a new file
fails until the list and PRIVACY.md are updated; every listed file must be
named in PRIVACY.md.

What it does not see: a new caller of a client an existing site builds, a
DNS lookup, a child process's traffic, or a request the browser makes. Those
are reviewed by hand; PRIVACY.md says so.

Test code is excluded the way the other gates exclude it: files compiled only
under test, and `#[cfg(test)]` items inside product files, both found by the
orphan checker's resolver and cfg reader. Comments and string literals are
blanked first, so a mention is not a site. A doubtful cfg extent counts as
product code: a privacy list errs toward listing.

  check-outbound-clients.py        exit 1 naming each difference
"""
from __future__ import annotations

import collections
import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "orphan_test_modules", Path(__file__).resolve().with_name("check-orphan-test-modules.py")
)
guard = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(guard)

ROOT = Path(__file__).resolve().parents[2]
LISTING = "scripts/dev/outbound-sites.tsv"
PRIVACY = "docs/PRIVACY.md"

# Constructors that open, or build a client that opens, an outbound
# connection. Each must start at an identifier boundary: `HttpClient::builder(`
# is not reqwest's `Client::builder(`.
NEEDLES = (
    "reqwest::Client::new(",
    "reqwest::get(",
    "ClientBuilder::new(",
    "Client::builder(",
    "TcpStream::connect",
    "UdpSocket::bind",
    "connect_async",
    "client_async_tls",
    "hyper_util::client",
    "ureq::",
)


def _starts_at_boundary(line: str, at: int) -> bool:
    return at == 0 or not (line[at - 1].isalnum() or line[at - 1] == "_")


def site_kind(line: str) -> str | None:
    """The first constructor on `line`, without its `(`, or None."""
    for needle in NEEDLES:
        at = line.find(needle)
        while at != -1:
            if _starts_at_boundary(line, at):
                return needle.rstrip("(")
            at = line.find(needle, at + 1)
    return None


def site_counts() -> dict[str, collections.Counter]:
    """Product-code lines building an outbound client, per file under src/ and
    per constructor kind: one kind replacing another in a file changes it."""
    test_only = {path.resolve() for path in guard.test_only_files()}
    counts: dict[str, int] = {}
    for path in guard.src_sources():
        if path.resolve() in test_only:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        code, _ = guard.blank(text)
        lines = {n: k for n, line in enumerate(code.split("\n"), 1) if (k := site_kind(line))}
        if not lines:
            continue
        rel = str(path.relative_to(guard.ROOT))
        tests = guard.cfg_items(text, guard.SafeSide.LEAN_SHORT, path=rel).items
        kept = collections.Counter(k for n, k in lines.items() if not any(i.first_line <= n <= i.last_line for i in tests))
        if kept:
            counts[rel] = kept
    return counts


def kinds(field: str) -> collections.Counter:
    """`Client::builder=2 TcpStream::connect=1` as a counter."""
    return collections.Counter({k: int(n) for k, n in (item.rsplit("=", 1) for item in field.split())})


def shown(counter: collections.Counter) -> str:
    return " ".join(f"{k}={n}" for k, n in sorted(counter.items())) or "none"


def listed() -> dict[str, collections.Counter]:
    rows = (ROOT / LISTING).read_text(encoding="utf-8").splitlines()[1:]
    return {f: kinds(field) for f, field, *_ in (row.split("\t") for row in rows if row.strip())}


def problems() -> list[str]:
    found, wanted = site_counts(), listed()
    none = collections.Counter()
    out = [
        f"{f}: {found.get(f, none).total()} sites, listed {wanted.get(f, none).total()}; "
        f"found {shown(found.get(f, none))}, listed {shown(wanted.get(f, none))}"
        for f in sorted(set(found) | set(wanted))
        if found.get(f, none) != wanted.get(f, none)
    ]
    privacy = (ROOT / PRIVACY).read_text(encoding="utf-8")
    out += [f"{PRIVACY} does not name {f}" for f in sorted(wanted) if f"`{f}`" not in privacy]
    return out


def main(argv: list[str]) -> int:
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    found = problems()
    for line in found:
        print(f"outbound clients: {line}", file=sys.stderr)
    if found:
        print(
            f"Each place product code can open an outbound connection is listed in {LISTING} "
            f"and named in {PRIVACY}, with what triggers it and where it connects. Update both.",
            file=sys.stderr,
        )
        return 1
    print(f"outbound clients: {sum(c.total() for c in listed().values())} sites in {len(listed())} files, all listed in {PRIVACY}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
