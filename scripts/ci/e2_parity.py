#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""E2 parity for the lib test split's run mode (throwaway only, never merged).

compare DIR: DIR holds the unsplit run's evidence (unsplit.json, cargo's --message-format=json for today's single
`cargo test --no-run`; unsplit-lib.txt, its lib binary's `--list`) and the split run's (pK.json and pK.txt for each
part K, rest.json for the other targets). Fails unless:
  - the non-lib test targets the unsplit build compiled (name, kind) equal those the rest call compiled;
  - the parts' lists, each taken right after its own build, union to the unsplit lib list with no test in two parts;
  - every part list is non-empty.
--self-test: the negative controls, one lib test given no part and one non-lib target dropped, must both fail."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


def artifacts(path: Path) -> set[tuple[str, str]]:
    """(name, kind) of every test executable cargo reported."""
    out = set()
    for line in path.read_text().splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
            out.add((m["target"]["name"], ",".join(m["target"]["kind"])))
    return out


def tests(path: Path) -> list[str]:
    """Test names from a libtest `--list` (the `: test` lines)."""
    return [line[: -len(": test")] for line in path.read_text().splitlines() if line.endswith(": test")]


def compare(d: Path) -> list[str]:
    problems = []
    unsplit = artifacts(d / "unsplit.json")
    nonlib = {a for a in unsplit if a[1] != "lib"}
    rest = artifacts(d / "rest.json")
    if nonlib != rest:
        problems.append(f"non-lib targets differ: missing {sorted(nonlib - rest)}, extra {sorted(rest - nonlib)}")
    parts = sorted(d.glob("p*.txt"), key=lambda p: int(p.stem[1:]))
    if not parts:
        problems.append("no part lists")
    seen: dict[str, str] = {}
    for p in parts:
        names = tests(p)
        if not names:
            problems.append(f"{p.name} lists no test")
        for n in names:
            if n in seen:
                problems.append(f"{n} is in {seen[n]} and {p.name}")
            seen[n] = p.name
    want = set(tests(d / "unsplit-lib.txt"))
    if set(seen) != want:
        problems.append(f"lib tests differ: missing {sorted(want - set(seen))[:20]}, extra {sorted(set(seen) - want)[:20]}")
    return problems


def self_test() -> int:
    art = lambda name, kind: json.dumps({"reason": "compiler-artifact", "profile": {"test": True}, "executable": "/x",
                                         "target": {"name": name, "kind": [kind]}})
    def fixture(d: Path, drop_test: bool, drop_target: bool) -> None:
        (d / "unsplit.json").write_text("\n".join([art("mcp_gateway", "lib"), art("a", "test"), art("b", "test")]))
        (d / "rest.json").write_text("\n".join([art("a", "test")] + ([] if drop_target else [art("b", "test")])))
        (d / "unsplit-lib.txt").write_text("m::one: test\nm::two: test\n")
        (d / "p1.txt").write_text("m::one: test\n")
        (d / "p2.txt").write_text("" if drop_test else "m::two: test\n")
    wrong = 0
    for label, drop_test, drop_target, want_bad in [("clean", False, False, False), ("a lib test in no part", True, False, True),
                                                    ("a non-lib target dropped", False, True, True)]:
        with tempfile.TemporaryDirectory() as t:
            fixture(Path(t), drop_test, drop_target)
            bad = bool(compare(Path(t)))
        ok = bad == want_bad
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: {'fails' if bad else 'passes'}")
    return 1 if wrong else 0


def counts(d: Path, skips: list[str]) -> list[str]:
    """Each lib part's run (the Nth `Running unittests src/lib.rs` summary in run.log) ran exactly its listed tests
    minus the skipped ones: passed + failed + ignored equals that, and `filtered out` equals the skipped count."""
    import re
    names = [s for flag, s in zip(skips[::2], skips[1::2]) if flag == "--skip"]
    summaries, current = [], None
    for line in (d / "run.log").read_text().splitlines():
        if "Running unittests src/lib.rs" in line:
            current = "lib"
        elif re.search(r"\bRunning\b", line):
            current = "other"
        m = re.search(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; \d+ measured; (\d+) filtered out", line)
        if m and current == "lib":
            summaries.append(tuple(int(x) for x in m.groups()))
            current = None
    parts = sorted(d.glob("p*.txt"), key=lambda p: int(p.stem[1:]))
    problems = [] if len(summaries) == len(parts) else [f"{len(summaries)} lib summaries for {len(parts)} parts"]
    for p, (passed, failed, ignored, filtered) in zip(parts, summaries):
        listed = tests(p)
        skipped = sum(1 for t in listed if any(s in t for s in names))
        if passed + failed + ignored != len(listed) - skipped or filtered != skipped:
            problems.append(f"{p.name}: ran {passed}+{failed}+{ignored}, filtered {filtered}; listed {len(listed)}, "
                            f"skipped {skipped}")
        print(f"e2 counts {p.name}: listed {len(listed)}, skipped {skipped}, passed {passed}, failed {failed}, "
              f"ignored {ignored}")
    return problems


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:2] == ["compare"]:
        found = compare(Path(sys.argv[2]))
    elif sys.argv[1:2] == ["counts"]:
        found = counts(Path(sys.argv[2]), sys.argv[3:])
    else:
        found = ["usage: e2_parity.py compare DIR | counts DIR [--skip NAME]... | --self-test"]
    for p in found:
        print(f"::error::e2: {p}")
    print("E2 parity: OK" if not found else f"E2 parity: {len(found)} problem(s)")
    sys.exit(1 if found else 0)
