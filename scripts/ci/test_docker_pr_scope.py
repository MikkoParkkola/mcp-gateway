#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A pull request into the release line that changes an image input builds and
smoke-tests the image before merge.

docker.yml's `scope` job decides that from the changed files, but it can only
decide for events the workflow is triggered by. When the release line was
dropped from the `pull_request` trigger, the decision stopped running for those
PRs, and a change to the image or its smoke scripts was first exercised after
merge. This pins both halves: the trigger, and the paths the decision builds for.
"""

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
RELEASE_LINE = "docs/ranking-1-release-line"

BUILDS = (
    "Dockerfile",
    ".dockerignore",
    "docker/entrypoint-full.sh",
    "scripts/ci/smoke-image.sh",
    "scripts/ci/smoke-full-image.sh",
    ".github/workflows/docker.yml",
    "Cargo.lock",
)
SKIPS = ("docs/DEPLOYMENT.md", "src/lib.rs", "scripts/ci/changed-scope.sh")


def main() -> int:
    doc = yaml.safe_load((ROOT / ".github/workflows/docker.yml").read_text())
    on = doc.get(True) or doc.get("on") or {}  # PyYAML reads `on` as True
    errors = []
    branches = (on.get("pull_request") or {}).get("branches") or []
    if RELEASE_LINE not in branches:
        errors.append(f"pull_request does not fire for {RELEASE_LINE}: {branches}")
    steps = doc["jobs"]["scope"]["steps"]
    script = next(s["run"] for s in steps if s.get("id") == "decide")
    found = re.search(r"grep -Eq '([^']+)'", script)
    if not found:
        errors.append("the scope decision no longer greps the changed files")
    else:
        inputs = re.compile(found.group(1))
        errors += [f"{p} does not build the image" for p in BUILDS if not inputs.search(p)]
        errors += [f"{p} builds the image" for p in SKIPS if inputs.search(p)]
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("docker.yml builds release-line pull requests that change an image input")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
