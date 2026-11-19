#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Check that a man page documents the binary it ships with.

    python3 scripts/release/check_man_page.py PAGE BINARY

The page's SUBCOMMANDS entries must be exactly the commands the binary's own `--help` lists, and the page's .TH
version must be the binary's package version (its `--version` line without the UI API suffix). Run on the release
build leg and again on the collected files before signing. Exit 0 when they agree, 1 with one line per fault.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def help_commands(text: str) -> list[str]:
    lines = text.splitlines()
    if "Commands:" not in lines:
        return []
    out = []
    for line in lines[lines.index("Commands:") + 1 :]:
        if not line.strip():
            break
        out.append(line.split()[0])
    return out


def page_commands(text: str) -> list[str]:
    lines = text.splitlines()
    out = []
    for first, second in zip(lines, lines[1:]):
        if first == ".TP":
            entry = second.replace("\\-", "-")
            match = re.fullmatch(r"mcp-gateway-(.+)\(1\)", entry)
            if match:
                out.append(match.group(1))
    return out


def page_version(text: str) -> str | None:
    for line in text.splitlines():
        match = re.match(r'\.TH \S+ 1  "\S+ (\S+)"', line)
        if match:
            return match.group(1)
    return None


def run(binary: str, flag: str) -> tuple[int | None, str, str]:
    try:
        done = subprocess.run([binary, flag], capture_output=True, text=True, timeout=60)
    except OSError as exc:
        return None, "", f"{binary}: cannot run ({exc.__class__.__name__})"
    return done.returncode, done.stdout, ""


def problems(page_path: Path, binary: str) -> list[str]:
    code, help_text, error = run(binary, "--help")
    if code is None:
        return [error]
    if code != 0:
        return [f"{binary}: --help exited {code}"]
    found = []
    page = page_path.read_text(encoding="utf-8")
    listed = help_commands(help_text)
    documented = page_commands(page)
    if not documented:
        found.append("no commands found in the page")
    if not listed:
        found.append("no commands found in the binary's help")
    if documented and listed:
        found += [f"the page lacks {name}" for name in listed if name not in documented]
        found += [f"the page lists {name}" for name in documented if name not in listed]
    code, version_text, error = run(binary, "--version")
    if code is None:
        return found + [error]
    match = re.match(r"\S+ (\S+)", version_text.strip())
    binary_version = match.group(1) if match else None
    if page_version(page) != binary_version:
        found.append(f"the page names version {page_version(page)}, the binary {binary_version}")
    return found


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: check_man_page.py PAGE BINARY", file=sys.stderr)
        return 2
    found = problems(Path(args[0]), args[1])
    for line in found:
        print(line)
    if not found:
        print(f"{args[0]}: documents the commands and version of {args[1]}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
