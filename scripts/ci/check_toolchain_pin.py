#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Every CI toolchain step must install the one pinned compiler (PINNED below).

rustc 1.100.0 moved the Unicode tables from 17 to 18 and failed key_server::email_hash's pinned-table test on every runner
that picked it up (2026-11-12); `dtolnay/rust-toolchain` with no `toolchain:` installs whatever `stable` is that day.
Each workflow step that uses the action must name PINNED, as a literal or as `${{ env.NAME }}` where every definition of NAME
in that file equals it. To move the compiler, change PINNED, every step and the Dockerfile's builder in one deliberate change.
The Dockerfile's Rust builder image must carry PINNED exactly (`rust:<pin>[-variant]`), so the published image is compiled by
the compiler CI tests with; the builder had drifted a minor version behind CI with nothing turning red. If a rust-toolchain.toml
exists it must pin the same version and the Docker build context must leave it out (a commented line does not count), so
the image's own compiler is not overridden.
Workflows and local composite actions are scanned: a toolchain step the line scan does not recognise (a flow-style mapping),
`RUSTUP_TOOLCHAIN`, `rustup default|override|toolchain install`, and `cargo +<name>` with a name other than the pin (or a
`$`/`${{` expression, which is allowed) are errors, and finding no toolchain step at all is an error. `--runtime` also checks that
the compiler on PATH is that channel (a job log line proves the pin took effect). `--self-test` runs fixtures.
Standard library only.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PINNED = "1.99.1"
USES = re.compile(r"^(\s*)(- )?uses:\s*[\"']?dtolnay/rust-toolchain@", re.I)


def channel(root: Path) -> str:
    toml = root / "rust-toolchain.toml"
    if toml.is_file():
        m = re.search(r'^channel\s*=\s*"([^"]+)"', toml.read_text(), re.M)
        if not m or m.group(1) != PINNED:
            raise SystemExit(f"rust-toolchain.toml must pin {PINNED} (the PINNED constant of this script), found {m and m.group(1)!r}")
    return PINNED


def check_workflow(text: str, want: str) -> list[tuple[int, str]]:
    """(line, problem) for each toolchain step that does not install `want`."""
    lines = text.split("\n")
    env: dict[str, set[str]] = {}
    for name, val in re.findall(r"^\s+([A-Z][A-Z0-9_]*):\s*[\"']?([^\"'\s#]+)[\"']?", text, re.M):
        env.setdefault(name, set()).add(val)
    bad = []
    for i, line in enumerate(lines):
        m = USES.match(line)
        if not m:
            continue
        indent = len(m.group(1)) + (2 if m.group(2) else 0)
        body = []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                continue
            if (len(nxt) - len(nxt.lstrip())) < indent or nxt.lstrip().startswith("- "):
                break
            body.append(nxt)
        tc = next((((re.match(r"\s*toolchain:\s*(.*?)\s*(?:#.*)?$", b).group(1)) or "").strip("\"'") for b in body if re.match(r"\s*toolchain:", b)), None)
        if tc == "":
            bad.append((i + 1, "empty toolchain: value"))
            continue
        if tc is None:
            bad.append((i + 1, "no toolchain: input (installs whatever `stable` is today)"))
            continue
        e = re.fullmatch(r"\$\{\{\s*env\.([A-Z0-9_]+)\s*\}\}", tc)
        vals = env.get(e.group(1), set()) if e else {tc}
        if vals != {want}:
            bad.append((i + 1, f"installs {sorted(vals) or tc!r}, the pin is {want!r} (an env name must have one definition in the file, equal to the pin)"))
    return bad


# `rustup toolchain install --profile minimal` (what the action runs) has no clippy, rustfmt or llvm-tools: a job that runs
# one must list it, or it fails on a fresh runner that does not carry the component (Windows clippy, 2026-11-12).
COMPONENT_USE = {
    "clippy": re.compile(r"\bcargo\s+clippy\b"),
    "rustfmt": re.compile(r"\bcargo\s+fmt\b|\brustfmt\b"),
    "llvm-tools": re.compile(r"\bcargo\s+llvm-cov\b"),
}


def check_components(text: str) -> list[tuple[int, str]]:
    """(line, problem) for each job that runs a component's command without installing the component."""
    lines = text.split("\n")
    starts = [i for i, l in enumerate(lines) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", l)]
    if "jobs:" not in lines:
        return []
    starts = [i for i in starts if i > lines.index("jobs:")]
    bad = []
    for k, i in enumerate(starts):
        job = lines[i : starts[k + 1] if k + 1 < len(starts) else len(lines)]
        code = "\n".join(l for l in job if not l.lstrip().startswith("#"))
        if not re.search(r"dtolnay/rust-toolchain@", code, re.I):
            continue
        have = " ".join(re.findall(r"components:\s*(.+)", code))
        for comp, use in COMPONENT_USE.items():
            if use.search(code) and comp not in have:
                bad.append((i + 1, f"job {lines[i].strip().rstrip(':')} runs a {comp} command but its toolchain step does not install {comp} (components: ...)"))
    return bad


OVERRIDE = re.compile(r"RUSTUP_TOOLCHAIN|\brustup\s+(?:default|override\s+set)\b|\bcargo\s+\+([^\s]+)")


def check_dockerfile(text: str, want: str) -> list[str]:
    """Problems with the Dockerfile's Rust builder images. Each must carry the pin exactly (`rust:<pin>[-variant]`), so the
    published image is compiled by the compiler CI tests with; a minor-only tag such as `rust:1.99-slim` moves with every
    patch release, and an untagged `rust` with every release. A digest picks the image instead of the tag and this check
    cannot tell its compiler, so a Rust builder with a digest is refused. No Rust image at all is a problem too."""
    # Join backslash-continued lines (the Dockerfile default escape), keeping each instruction's first line number.
    joined, buf, start = [], "", 0
    for n, line in enumerate(text.split("\n"), 1):
        start = start if buf else n
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        joined.append((start, buf + line))
        buf = ""
    if buf:
        joined.append((start, buf))
    found, bad, stages = 0, [], set()
    for n, line in joined:
        m = re.match(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        image, _, digest = ref.partition("@")
        # The tag follows the last `:` of the last path part; a registry port (`host:5000/...`) is not a tag.
        name, _, tag = image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "")
        stage_ref = not tag and not digest and image.lower() in stages  # `FROM <earlier stage>`, not an image
        if alias:
            stages.add(alias.lower())
        if stage_ref or name.rsplit("/", 1)[-1].lower() != "rust":
            continue
        found += 1
        if digest:
            bad.append(f"line {n}: the builder image {ref} names a digest, which picks the image instead of its tag; "
                       f"this check cannot tell that image's compiler (name rust:{want}-<variant> without a digest)")
        elif tag.split("-", 1)[0] != want:
            bad.append(f"line {n}: the builder image is {image}; the pin is {want} (use rust:{want}-<variant>)")
    if not found:
        bad.append("no rust builder image: the compiler of the image is unchecked")
    return bad


def check_overrides(text: str, want: str) -> list[tuple[int, str]]:
    """(line, problem) for each place a run step or env var picks a compiler other than `want`."""
    bad = []
    for n, line in enumerate(text.split("\n"), 1):
        code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
        for m in OVERRIDE.finditer(code):
            name = m.group(1)
            if name is not None and (name == want or "$" in name):
                continue
            bad.append((n, f"`{m.group(0)}` can select a compiler other than {want}"))
    return bad


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[2]
    want = channel(root)
    problems, steps = [], 0
    files = sorted((root / ".github" / "workflows").glob("*.yml")) + sorted((root / ".github" / "actions").glob("**/*.yml"))
    for wf in files:
        text = wf.read_text()
        seen = len(re.findall(r"^\s*(?:- )?uses:\s*dtolnay/rust-toolchain@", text, re.M))
        steps += seen
        if text.count("dtolnay/rust-toolchain@") != seen:
            problems.append(f"{wf.relative_to(root)}: a dtolnay/rust-toolchain reference is not a plain `uses:` step line (flow-style or quoted); write it as a block step")
        problems += [f"{wf.relative_to(root)}:{n}: {why}" for n, why in check_workflow(text, want) + check_overrides(text, want) + check_components(text)]
    if steps == 0:
        problems.append("no dtolnay/rust-toolchain step found in any workflow: the scan checked nothing")
    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        problems += [f"Dockerfile: {p}" for p in check_dockerfile(dockerfile.read_text(), want)]
    else:
        problems.append("Dockerfile is missing: the image's compiler is unchecked")
    ignore = root / ".dockerignore"
    ignored = False  # the last rule naming the file wins; `!` re-includes it
    for r in (ignore.read_text().splitlines() if ignore.is_file() else []):
        r = r.strip()
        if r and not r.startswith("#") and r.lstrip("!").lstrip("/") == "rust-toolchain.toml":
            ignored = not r.startswith("!")
    if (root / "rust-toolchain.toml").is_file() and not ignored:
        problems.append(".dockerignore: rust-toolchain.toml is not listed; the image build would try to install the pinned channel")
    if "--runtime" in argv:
        out = subprocess.run(["rustc", "--version"], capture_output=True, text=True, cwd=root).stdout
        if not out.startswith(f"rustc {want} "):
            problems.append(f"rustc on PATH is `{out.strip()}`, the pin is {want}")
        else:
            print(f"runtime: {out.strip()}")
    for p in problems:
        print(f"::error::{p}")
    print(f"toolchain pin: {steps} step(s) checked against {want}, {len(problems)} problem(s)")
    return 1 if problems else 0


def self_test() -> int:
    want = "1.99.1"
    wf = lambda step, env="": f"env:\n{env}jobs:\n  a:\n    steps:\n{step}"
    cases = [
        ("a literal that matches", wf("      - uses: dtolnay/rust-toolchain@abc # stable\n        with:\n          toolchain: 1.99.1\n"), 0),
        ("no toolchain input", wf("      - uses: dtolnay/rust-toolchain@abc # stable\n      - run: x\n"), 1),
        ("with: block but no toolchain", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          components: clippy\n"), 1),
        ("a literal that differs", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: 1.100.0\n"), 1),
        ("stable named explicitly", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: stable\n"), 1),
        ("an env reference that matches", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: ${{ env.RUST }}\n", '  RUST: "1.99.1"\n'), 0),
        ("an env reference that differs", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: ${{ env.RUST }}\n", '  RUST: "1.100.0"\n'), 1),
        ("an env reference that is undefined", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: ${{ env.RUST }}\n"), 1),
        ("the next step's toolchain key is not this step's", wf("      - uses: dtolnay/rust-toolchain@abc\n      - uses: other/x@1\n        with:\n          toolchain: 1.99.1\n"), 1),
        ("a quoted literal and a trailing comment", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: \"1.99.1\" # pinned\n"), 0),
        ("two steps, one wrong", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: 1.99.1\n      - uses: dtolnay/rust-toolchain@abc\n"), 1),
        ("no toolchain step at all", wf("      - run: x\n"), 0),
        ("a quoted uses with different case", wf("      - uses: \"Dtolnay/Rust-Toolchain@abc\"\n        with:\n          toolchain: stable\n"), 1),
        ("a job-level env redefining the name", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: ${{ env.RUST }}\n", '  RUST: "1.99.1"\n    env:\n      RUST: stable\n'), 1),
        ("an empty toolchain value", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain:\n"), 1),
        ("a blank line before the toolchain key", wf("      - uses: dtolnay/rust-toolchain@abc\n        with:\n\n          toolchain: 1.99.1\n"), 0),
    ]
    wrong = 0
    over = [
        ("cargo +stable", "      - run: cargo +stable test\n", 1),
        ("cargo +the pin", "      - run: cargo +1.99.1 test\n", 0),
        ("cargo +a variable", "      - run: cargo +$TOOLCHAIN build\n", 0),
        ("RUSTUP_TOOLCHAIN set", "    env:\n      RUSTUP_TOOLCHAIN: stable\n", 1),
        ("rustup default", "      - run: rustup default nightly\n", 1),
        ("a comment naming them", "      # cargo +stable and RUSTUP_TOOLCHAIN are banned\n", 0),
        ("a trailing comment after a clean command", "      - run: cargo test # not cargo +stable\n", 0),
    ]
    comp = [
        ("clippy run without the component", "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n      - run: cargo clippy -- -D warnings\n", 1),
        ("clippy run with the component", "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n          components: clippy\n      - run: cargo clippy\n", 0),
        ("clippy only in a comment", "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n      # cargo clippy runs elsewhere\n      - run: cargo test\n", 0),
        ("fmt needs rustfmt, another job has it", "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n          components: rustfmt\n      - run: cargo fmt --check\n  b:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n      - run: cargo fmt --check\n", 1),
        ("llvm-cov with llvm-tools-preview", "jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@x\n        with:\n          toolchain: 1.99.1\n          components: llvm-tools-preview\n      - run: cargo llvm-cov\n", 0),
    ]
    for label, text, n in comp:
        got = len(check_components(text))
        ok = got == n
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} component scan, {label}: {got} problem(s), want {n}")
    for label, text, n in over:
        got = len(check_overrides(text, want))
        ok = got == n
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} override scan, {label}: {got} problem(s), want {n}")
    for label, text, n in cases:
        got = len(check_workflow(text, want))
        ok = got == n
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} {label}: {got} problem(s), want {n}")
    dock = [
        ("the mirrored builder on the pin", "FROM mirror.gcr.io/library/rust:1.99.1-slim AS builder\nFROM debian:trixie-slim\n", 0),
        ("a plain image on the pin", "FROM rust:1.99.1\n", 0),
        ("a platform flag before the pinned image", "FROM --platform=$BUILDPLATFORM rust:1.99.1-slim AS b\n", 0),
        ("a registry port, the pinned tag", "FROM localhost:5000/library/rust:1.99.1-slim\n", 0),
        ("a commented-out older image", "# FROM rust:1.98-slim\nFROM rust:1.99.1-slim\n", 0),
        ("stage references only beside the pinned image", "FROM rust:1.99.1-slim AS builder\nFROM builder AS test\n", 0),
        ("a stage named rust, referenced later", "FROM rust:1.99.1-slim AS rust\nFROM rust AS final\n", 0),
        ("the pinned image on a continued line", "FROM \\\n  rust:1.99.1-slim AS builder\n", 0),
        ("a digest after the pinned tag (the digest picks the image)", "FROM rust:1.99.1-slim@sha256:0123abcd AS b\n", 1),
        ("an older image hidden behind a continued line", "FROM rust:1.99.1 AS ok\nFROM \\\n  rust:1.98-slim AS builder\n", 1),
        ("a tagged image named like an earlier stage", "FROM rust:1.99.1-slim AS rust\nFROM rust:1.98-slim\n", 1),
        ("an older minor (today's drift)", "FROM mirror.gcr.io/library/rust:1.98-slim AS builder\nFROM debian:trixie-slim\n", 1),
        ("the pin's minor only, a floating tag", "FROM rust:1.99-slim AS builder\n", 1),
        ("another patch of the pinned minor", "FROM rust:1.99.2-slim\n", 1),
        ("an untagged rust image", "FROM rust AS builder\n", 1),
        ("rust:latest", "FROM rust:latest\n", 1),
        ("lowercase from on an older image", "from rust:1.98-slim\n", 1),
        ("a second rust stage that differs", "FROM rust:1.99.1-slim AS a\nFROM rust:1.100.0-slim AS b\n", 1),
        ("no rust image", "FROM debian:trixie-slim\n", 1),
    ]
    for label, text, n in dock:
        got = len(check_dockerfile(text, want))
        ok = got == n
        wrong += not ok
        print(f"{'ok   ' if ok else 'WRONG'} dockerfile, {label}: {got} problem(s), want {n}")
    print(f"self-test: {len(cases) + len(over) + len(comp) + len(dock) - wrong} ok, {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(self_test() if sys.argv[1:] == ["--self-test"] else main(sys.argv[1:]))
