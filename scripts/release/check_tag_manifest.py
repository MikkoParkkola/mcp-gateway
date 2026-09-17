#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Require the tag being published to match the version in Cargo.toml/Cargo.lock.

Three workflows publish independently on a `v*` tag (release.yml, ci.yml,
docker.yml) and none can read another's job outputs, so each calls this script
before its first publishing step. Without it, `cargo publish` takes its version
from the manifest rather than the tag: a `v4.0.0-rc.1` tag cut from a commit
whose manifest still says `4.0.0` publishes the release candidate to crates.io
as the final 4.0.0, resolvable by every `^4` requirement. The mismatch is
equally wrong in reverse — a stable tag cut from an `-rc.1` manifest.

It also classifies the tag, so callers do not each re-derive the predicate.
The prerelease test is taken on the part of the version preceding the first
`+`: `4.0.0+build-linux` is a stable version that carries a hyphen (semver §10).

The effective tag is --tag when non-empty, else $GITHUB_REF_NAME. On
workflow_dispatch, GITHUB_REF_NAME is the dispatch *branch*, so a workflow that
accepts a tag input must pass it here or an rc classifies as final.

Writes `tag`, `version` and `is_prerelease` to $GITHUB_OUTPUT when set.
Exit 0: tag and manifest agree. Exit 1: mismatch. Exit 2: unusable input.
"""

import argparse
import os
import pathlib
import re
import sys
import tomllib

MANIFEST = pathlib.Path("Cargo.toml")
LOCKFILE = pathlib.Path("Cargo.lock")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def is_prerelease(version: str) -> bool:
    """True iff the version carries a prerelease identifier."""
    return "-" in version.split("+", 1)[0]


def lock_version(text: str, crate: str) -> str | None:
    """The version of `crate` in a Cargo.lock, or None if it has no entry."""
    # Parse the whole document once rather than splitting on "[[package]]":
    # that delimiter can appear inside a string value, and a split would make
    # the surrounding block unparseable.
    for entry in tomllib.loads(text).get("package", []):
        if entry.get("name") == crate:
            return entry.get("version")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        default="",
        help="effective tag; falls back to $GITHUB_REF_NAME when empty",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=pathlib.Path.cwd(),
        help="repository root holding Cargo.toml and Cargo.lock",
    )
    args = parser.parse_args()

    tag = args.tag.strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    if not tag:
        print(
            "No tag to check: pass --tag or set GITHUB_REF_NAME.",
            file=sys.stderr,
        )
        return 2
    if not tag.startswith("v"):
        print(
            f"Tag {tag!r} does not start with 'v'; this gate only guards v* tags.",
            file=sys.stderr,
        )
        return 2

    version = tag[1:]
    if not SEMVER.match(version):
        print(f"Tag {tag!r} is not a semver version.", file=sys.stderr)
        return 2

    manifest_path = args.root / MANIFEST
    lock_path = args.root / LOCKFILE
    try:
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"Cannot read {manifest_path}: {exc}", file=sys.stderr)
        return 2
    package = manifest.get("package", {})
    crate = package.get("name")
    manifest_version = package.get("version")
    if not crate or not manifest_version:
        print(
            f"{manifest_path} has no [package] name/version.",
            file=sys.stderr,
        )
        return 2

    errors = []
    if manifest_version != version:
        errors.append(
            f"Cargo.toml version is {manifest_version!r}, tag {tag!r} says {version!r}"
        )
    try:
        locked = lock_version(lock_path.read_text(encoding="utf-8"), crate)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"Cannot read {lock_path}: {exc}", file=sys.stderr)
        return 2
    if locked is None:
        errors.append(f"Cargo.lock has no entry for {crate!r}")
    elif locked != version:
        errors.append(f"Cargo.lock has {crate} at {locked!r}, tag says {version!r}")

    if errors:
        print(
            "Tag and manifest disagree; refusing to publish:\n  "
            + "\n  ".join(errors)
            + "\nBump the manifest in the tagged commit, or retag.",
            file=sys.stderr,
        )
        return 1

    prerelease = is_prerelease(version)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"tag={tag}\n")
            handle.write(f"version={version}\n")
            handle.write(f"is_prerelease={str(prerelease).lower()}\n")

    channel = "prerelease" if prerelease else "stable"
    print(f"Tag {tag} matches {crate} {version} in Cargo.toml and Cargo.lock ({channel}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
