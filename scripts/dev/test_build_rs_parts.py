#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""R-BUILDRS: build.rs emits exactly the lib test split's cfgs for every value of MCP_GATEWAY_TEST_PART.

Compiles build.rs alone with rustc (it uses std only) and runs it with the variable unset, 0, each of 1..=N, N+1,
empty and `abc`. Valid values print exactly the expected `cargo::` lines; the others fail naming the variable. Then
the same check runs on two seeded broken copies (an empty value read as unset; a value above N accepted) and must
refuse both, so the check cannot pass vacuously. N is read from build.rs's `const N`.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VAR = "MCP_GATEWAY_TEST_PART"


def expected(n: int, value: str | None) -> list[str]:
    head = [f"cargo::rerun-if-env-changed={VAR}"] + [f"cargo::rustc-check-cfg=cfg(tp{k})" for k in range(1, n + 1)]
    head.append("cargo::rustc-check-cfg=cfg(tp_partial)")
    if value is None:
        return head + [f"cargo::rustc-cfg=tp{k}" for k in range(1, n + 1)]
    k = int(value)
    return head + ([f"cargo::rustc-cfg=tp{k}"] if k > 0 else []) + ["cargo::rustc-cfg=tp_partial"]


def problems(source: str, workdir: Path) -> list[str]:
    n = int(re.search(r"\bconst\s+N\s*:\s*u32\s*=\s*([0-9]+)\s*;", source).group(1))
    src, exe = workdir / "build.rs", workdir / "build-script"
    src.write_text(source, encoding="utf-8")
    built = subprocess.run(["rustc", "--edition", "2021", "-O", str(src), "-o", str(exe)], capture_output=True, text=True)
    if built.returncode != 0:
        return [f"build.rs does not compile: {built.stderr.strip()[:400]}"]
    out = []
    valid = [None, *[str(k) for k in range(0, n + 1)]]
    for value in valid + [str(n + 1), "", "abc"]:
        env = {k: v for k, v in os.environ.items() if k != VAR}
        if value is not None:
            env[VAR] = value
        run = subprocess.run([str(exe)], env=env, capture_output=True, text=True)
        if value in valid:
            got = run.stdout.splitlines()
            if run.returncode != 0 or got != expected(n, value):
                out.append(f"{VAR}={value!r}: rc {run.returncode}, printed {got}, expected {expected(n, value)}")
        elif run.returncode == 0 or VAR not in run.stderr:
            out.append(f"{VAR}={value!r}: rc {run.returncode}; expected a panic naming {VAR}")
    return out


def main() -> int:
    source = (ROOT / "build.rs").read_text(encoding="utf-8")
    seeded = {
        "an empty value read as unset": source.replace(
            'match std::env::var("MCP_GATEWAY_TEST_PART") {',
            'match std::env::var("MCP_GATEWAY_TEST_PART")'
            ".ok().filter(|v| !v.is_empty()).ok_or(std::env::VarError::NotPresent) {",
        ),
        "a value above N accepted": source.replace(".filter(|k| *k <= N)", ""),
    }
    with tempfile.TemporaryDirectory() as tmp:
        real = problems(source, Path(tmp))
        for problem in real:
            print(f"build.rs: {problem}", file=sys.stderr)
        caught = []
        for name, broken in seeded.items():
            if broken == source:
                print(f"seeded copy '{name}' did not change build.rs: update the seed", file=sys.stderr)
                return 1
            found = problems(broken, Path(tmp))
            # A seed counts only when it compiles and then fails on a value; a compile error proves nothing.
            caught.append(bool(found) and not found[0].startswith("build.rs does not compile"))
            if not caught[-1]:
                print(f"seeded copy '{name}' was not refused on a value: {found}", file=sys.stderr)
    if real or not all(caught):
        return 1
    print(f"build.rs: every value of {VAR} emits exactly its cfgs; both seeded copies refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
