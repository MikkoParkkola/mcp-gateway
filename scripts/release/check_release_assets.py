#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Check that a directory of release assets is complete before it is published.

Every release binary must ship with an SPDX SBOM and a Sigstore bundle, every
SBOM with its own bundle, and SHA256SUMS.txt must list every binary and SBOM
and carry a bundle too. Signatures themselves are verified by `cosign
verify-blob` (sign-release-assets.sh); this checks that nothing is missing and
that each SBOM describes this crate, so a release cannot go out with a binary
that has no signature or an SBOM of some other build.

    python3 scripts/release/check_release_assets.py DIR --version V NAME...
    python3 scripts/release/check_release_assets.py DIR --version V --sbom-only NAME...

NAME is each expected binary asset name (mcp-gateway-linux-x86_64, ...).
Exit 0 when complete, 1 with one line per problem otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SBOM = ".spdx.json"
BUNDLE = ".sigstore.json"
SUMS = "SHA256SUMS.txt"


def is_sidecar(name: str) -> bool:
    return name.endswith(SBOM) or name.endswith(BUNDLE)


def binaries(directory: Path) -> list[str]:
    return sorted(
        p.name
        for p in directory.iterdir()
        if p.is_file()
        and p.name.startswith("mcp-gateway-")
        and not is_sidecar(p.name)
    )


def sbom_problems(path: Path, version: str) -> list[str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"{path.name}: not readable SPDX JSON ({exc.__class__.__name__})"]
    if not isinstance(doc, dict) or "spdxVersion" not in doc:
        return [f"{path.name}: not an SPDX document (no spdxVersion)"]
    purls = [
        ref.get("referenceLocator", "")
        for package in doc.get("packages") or []
        if isinstance(package, dict)
        for ref in package.get("externalRefs") or []
        if isinstance(ref, dict)
    ]
    cargo = [p for p in purls if p.startswith("pkg:cargo/")]
    problems = []
    if not cargo:
        # No crate list at all: the binary was not built with cargo auditable.
        problems.append(f"{path.name}: lists no pkg:cargo package (binary not built with cargo auditable?)")
    elif f"pkg:cargo/mcp-gateway@{version}" not in cargo:
        problems.append(f"{path.name}: does not describe mcp-gateway {version}")
    return problems


def sums_listed(path: Path) -> set[str]:
    listed = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            listed.add(parts[1].lstrip("*"))
    return listed


def problems(directory: Path, version: str, expected: list[str]) -> list[str]:
    found = []
    present = {p.name for p in directory.iterdir() if p.is_file()}
    bins = binaries(directory)
    if not bins:
        return [f"{directory}: no release binaries"]
    for name in expected:
        if name not in bins:
            found.append(f"{name}: expected binary is missing")
    for name in bins:
        for suffix in (SBOM, BUNDLE):
            if name + suffix not in present:
                found.append(f"{name}: no {suffix}")
        if name + SBOM in present:
            if name + SBOM + BUNDLE not in present:
                found.append(f"{name}{SBOM}: no {BUNDLE}")
            found.extend(sbom_problems(directory / (name + SBOM), version))
    if SUMS not in present:
        found.append(f"{SUMS}: missing")
    else:
        if SUMS + BUNDLE not in present:
            found.append(f"{SUMS}: no {BUNDLE}")
        listed = sums_listed(directory / SUMS)
        for name in bins:
            for entry in (name, name + SBOM):
                if entry in present and entry not in listed:
                    found.append(f"{SUMS}: does not list {entry}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("expected", nargs="+", help="expected binary asset names")
    parser.add_argument(
        "--sbom-only",
        action="store_true",
        help="check only that each named binary's SBOM describes this crate (per-target build check)",
    )
    args = parser.parse_args(argv)
    if args.sbom_only:
        found = []
        for name in args.expected:
            path = args.directory / (name + SBOM)
            found.extend(sbom_problems(path, args.version) if path.is_file() else [f"{name}: no {SBOM}"])
        for line in found:
            print(line)
        if not found:
            print(f"{args.directory}: SBOM of each of {len(args.expected)} binaries lists its crates")
        return 1 if found else 0
    found = problems(args.directory, args.version, args.expected)
    for line in found:
        print(line)
    if found:
        return 1
    print(f"{args.directory}: {len(binaries(args.directory))} binaries signed, each with an SBOM")
    return 0


if __name__ == "__main__":
    sys.exit(main())
