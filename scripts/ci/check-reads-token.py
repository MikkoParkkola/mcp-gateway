#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Only the judge can build a read token: a build that forges one must fail.

`Firewall::reads` and `ReadHistory::reserve` take a `ReadsToken`, whose one
field is private to the outbound judge, so no other code can reach the
process's read history. This check proves that on the compiler, not on a scan:
it builds the library with `--cfg reads_token_probe`, which compiles
`src/gateway/outbound/reads_token_probe.rs`, a sibling of the judge holding
one forgery per `fn pN`, and passes only if the build fails with exactly the
expected error in each probe and no error anywhere else.

Each error is matched by code and by a fragment of its rendered text that
names the item, so a privacy error about a module or an import, a wrong
argument count, or a probe that compiles all fail the check. An error raised
inside a macro is attributed through its expansion to the call site in the
probe. The cfg reaches this crate only (`cargo rustc ... -- --cfg`), so no
dependency is rebuilt.

Usage: check-reads-token.py [--self-test]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROBE = "src/gateway/outbound/reads_token_probe.rs"

# Per probe, the errors it must raise: (code, fragment of the rendered text).
# Pinned from the first observed run of the probe against the token.
EXPECTED: dict[str, list[tuple[str, str]]] = {
    "p1_reads": [("E0423", "a struct named `ReadsToken`")],
    "p2_reserve": [("E0423", "a struct named `ReadsToken`")],
    "p3a_later_reads": [("E0423", "a struct named `ReadsToken`")],
    "p3b_later_reserve": [("E0423", "a struct named `ReadsToken`")],
    "p4a_frag_reads": [("E0423", "a struct named `ReadsToken`")],
    "p4b_frag_reserve": [("E0423", "a struct named `ReadsToken`")],
    "p5_test_token": [("E0425", "function `test_token`")],
    "p6a_reads_unit": [("E0308", "expected `&ReadsToken`")],
    "p6b_reserve_unit": [("E0308", "expected `&ReadsToken`")],
}
# P7 and P8 are trait impls, not fns: each is named by a marker comment line
# `// probe: <name>` above it, and its errors fall on the lines that follow.
EXPECTED_IMPLS: dict[str, list[tuple[str, str]]] = {
    "p7_copy": [("E0204", "does not implement `std::marker::Copy`")],
    # `Self(..)` outside the judge: the constructor is private (E0603), and so is
    # the field it reads (E0616); both name the token.
    "p8_clone": [
        ("E0603", "`ReadsToken` is private"),
        ("E0616", "of struct `ReadsToken` is private"),
    ],
}


def probe_ranges(source: str) -> list[tuple[str, int, int]]:
    """`(name, first line, last line)` of each probe, 1-based: a `fn pN` or a
    `// probe: pN` marker opens one, and it runs to the next or to the end."""
    starts: list[tuple[str, int]] = []
    for number, line in enumerate(source.splitlines(), 1):
        text = line.strip()
        if text.startswith("fn p") and text[4:5].isdigit():
            starts.append((text[3:].split("(", 1)[0], number))
        elif text.startswith("// probe: "):
            starts.append((text.removeprefix("// probe: ").strip(), number))
    total = len(source.splitlines())
    return [
        (name, line, (starts[i + 1][1] - 1) if i + 1 < len(starts) else total)
        for i, (name, line) in enumerate(starts)
    ]


def call_site(span: dict) -> dict:
    """The outermost call site of a span raised inside a macro expansion."""
    while span.get("expansion"):
        span = span["expansion"]["span"]
    return span


def structured_text(message: dict) -> str:
    """A diagnostic's message, its span labels and its children's messages."""
    parts = [message.get("message", "")]
    parts += [s.get("label") or "" for s in message.get("spans", [])]
    parts += [c.get("message", "") for c in message.get("children", [])]
    return "\n".join(parts)


def judge(messages: list[dict], build_failed: bool, source: str) -> list[str]:
    """Problems with one probe build; empty when the restriction holds."""
    problems: list[str] = []
    if not build_failed:
        problems.append("the probe build succeeded: a forged token compiled")
    ranges = probe_ranges(source)
    got: dict[str, list[tuple[str, str]]] = {name: [] for name, _, _ in ranges}
    for message in messages:
        if message.get("level") != "error":
            continue
        code = (message.get("code") or {}).get("code") or "no code"
        # The diagnostic's own words: its message, span labels and child
        # notes. Never the rendered text, whose source excerpt would let an
        # unrelated error on a line naming the token pass.
        rendered = structured_text(message)
        primary = [s for s in message.get("spans", []) if s.get("is_primary")]
        if not primary:
            problems.append(f"an error with no span: {message.get('message')}")
            continue
        site = call_site(primary[0])
        if site.get("file_name") != PROBE:
            problems.append(f"an error outside the probe: {site.get('file_name')}: {code}")
            continue
        line = site.get("line_start", 0)
        owner = next((name for name, a, b in ranges if a <= line <= b), None)
        if owner is None:
            problems.append(f"an error outside every probe, line {line}: {code}")
            continue
        got[owner].append((code, rendered))
    want = EXPECTED | EXPECTED_IMPLS
    for name in sorted(set(want) | set(got)):
        expected = want.get(name)
        if expected is None:
            problems.append(f"{name}: a probe this check does not know")
            continue
        errors = got.get(name, [])
        if name not in got:
            problems.append(f"{name}: no such probe in {PROBE}")
            continue
        if len(errors) != len(expected):
            problems.append(f"{name}: {len(errors)} errors, want {len(expected)}")
            continue
        remaining = list(errors)
        for code, fragment in expected:
            hit = next(
                (e for e in remaining if e[0] == code and fragment in e[1]), None
            )
            if hit is None:
                problems.append(f"{name}: no {code} naming `{fragment}`")
            else:
                remaining.remove(hit)
    return problems


def run_probe() -> tuple[list[dict], bool]:
    """Build the library with the probe; return its error messages and
    whether the build failed."""
    result = subprocess.run(
        [
            "cargo", "rustc", "--lib", "--profile", "check", "--features", "firewall",
            "--message-format=json", "--", "--cfg", "reads_token_probe",
        ],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    messages = []
    for line in result.stdout.splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("reason") == "compiler-message":
            messages.append(record["message"])
    return messages, result.returncode != 0


# Self-test: a probe source and messages shaped as Cargo emits them.
_SOURCE = "\n".join(
    [
        "use super::*;",
        "fn p1_reads() {",
        "    forged();",
        "}",
        "// probe: p7_copy",
        "impl Copy for ReadsToken {}",
    ]
)


def _err(code: str, text: str, line: int, file: str = PROBE, expansion: dict | None = None) -> dict:
    span = {"is_primary": True, "file_name": file, "line_start": line}
    if expansion:
        span["expansion"] = expansion
    return {
        "level": "error",
        "code": {"code": code},
        "message": text,
        "rendered": f"error[{code}]: {text}",
        "spans": [span],
        "children": [],
    }


def self_test() -> int:
    global EXPECTED, EXPECTED_IMPLS
    saved = (EXPECTED, EXPECTED_IMPLS)
    EXPECTED = {"p1_reads": [("E0423", "ReadsToken")]}
    EXPECTED_IMPLS = {"p7_copy": [("E0204", "ReadsToken")]}
    good = [
        _err("E0423", "cannot initialize `ReadsToken`: private fields", 3),
        _err("E0204", "Copy cannot be implemented for `ReadsToken`", 6),
    ]
    macro_site = {"span": {"file_name": PROBE, "line_start": 3}}
    cases = {
        "green": (good, True, 0),
        "the build succeeded": (good, False, 1),
        "an error in another file": (good + [_err("E0425", "x", 9, "src/lib.rs")], True, 1),
        "a probe without its error": (good[1:], True, 1),
        # The probe's own error is missing; another file's error with the right
        # code, text and line number must not stand in for it.
        "the probe's error only in another file": (
            [_err("E0423", "cannot initialize `ReadsToken`: private fields", 3, "src/lib.rs"), good[1]],
            True,
            2,
        ),
        "a wrong code": ([_err("E0061", "ReadsToken args", 3), good[1]], True, 1),
        "the right code naming a module": (
            [_err("E0423", "module `judge` is private", 3), good[1]],
            True,
            1,
        ),
        "an error outside every probe": (good + [_err("E0425", "x", 1)], True, 1),
        "an error in the wrong probe": (
            [good[0], _err("E0423", "cannot initialize `ReadsToken`", 6)],
            True,
            1,
        ),
        "a macro error attributed to its call site": (
            [
                _err("E0423", "cannot initialize `ReadsToken`", 40, "src/macros.rs", macro_site),
                good[1],
            ],
            True,
            0,
        ),
        "the name only in the source excerpt": (
            [
                {**_err("E0423", "cannot find value `missing`", 3),
                 "rendered": "error[E0423]: ... forged(ReadsToken(Cell::new(())))"},
                good[1],
            ],
            True,
            1,
        ),
        "a spanless error": (good + [{"level": "error", "message": "x", "spans": []}], True, 1),
    }
    failed = 0
    for name, (messages, build_failed, want) in cases.items():
        got = judge(messages, build_failed, _SOURCE)
        if len(got) != want:
            failed += 1
            print(f"self-test {name}: {len(got)} problems, want {want}: {got}")
    EXPECTED, EXPECTED_IMPLS = saved
    print("self-test ok" if not failed else f"self-test: {failed} failed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    source = (ROOT / PROBE).read_text()
    messages, build_failed = run_probe()
    problems = judge(messages, build_failed, source)
    for problem in problems:
        print(f"::error::read token probe: {problem}")
    if not problems:
        print(f"read token probe: every forgery refused ({len(messages)} errors)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
