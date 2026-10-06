#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A pull request into the release line that changes an image input builds and
smoke-tests the image before merge.

docker.yml's `scope` job decides that from the changed files, but it can only
decide for events the workflow is triggered by. When the release line was
dropped from the `pull_request` trigger, the decision stopped running for those
PRs, and a change to the image or its smoke scripts was first exercised after
merge. This pins the whole chain: the trigger, the paths the decision builds
for, the decision building on a match, the build following the decision, and
the smoke tests running inside that build on a pull request.

`DOCKER_YML` overrides the workflow path, so a mutated copy can be checked.
"""

import os
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
RELEASE_LINE = "docs/ranking-1-release-line"
GATED = "needs.scope.outputs.run_build == 'true'"

BUILDS = (
    "Dockerfile",
    ".dockerignore",
    ".trivyignore",
    "docker/entrypoint-full.sh",
    "scripts/ci/smoke-image.sh",
    "scripts/ci/smoke-full-image.sh",
    ".github/workflows/docker.yml",
    ".github/osv-scanner.toml",
    "Cargo.toml",
    "Cargo.lock",
    "deploy/helm/mcp-gateway/values.yaml",
    "scripts/dev/helm-kind-real-image.sh",
    # The documented container recipes and the script that runs them (MIK-7484).
    "README.md",
    "docs/QUICKSTART.md",
    "docs/DEPLOYMENT.md",
    "deploy/single-node/docker-compose.yaml",
    "scripts/dev/docker-smoke.sh",
)
SKIPS = ("docs/BENCHMARKS.md", "scripts/ci/changed-scope.sh")
SMOKES = ("scripts/ci/smoke-image.sh", "scripts/ci/smoke-full-image.sh")


def check(doc: dict) -> list[str]:
    errors = []
    on = doc.get(True) or doc.get("on") or {}  # PyYAML reads `on` as True
    pr = on.get("pull_request") or {}
    branches = pr.get("branches") or []
    if RELEASE_LINE not in branches or any(str(b).startswith("!") for b in branches):
        errors.append(f"pull_request does not fire for {RELEASE_LINE}: {branches}")
    # The path decision lives in `scope`; a trigger-level filter or a narrowed
    # activity list would stop it from running at all.
    for narrowing in ("paths", "paths-ignore", "types"):
        if narrowing in pr:
            errors.append(f"pull_request is narrowed by {narrowing}, so scope may never run")

    jobs = doc["jobs"]
    script = next(s["run"] for s in jobs["scope"]["steps"] if s.get("id") == "decide")
    found = re.search(r"grep -Eq '([^']+)' <<<\"\$files\"; then\s+decide true", script)
    if not found:
        errors.append("a changed image input no longer makes the scope decision build")
    else:
        inputs = re.compile(found.group(1))
        errors += [f"{p} does not build the image" for p in BUILDS if not inputs.search(p)]
        errors += [f"{p} builds the image" for p in SKIPS if inputs.search(p)]

    for name in ("security-gate", "release-criteria"):
        job = jobs[name]
        if str(job.get("if", "")).strip() != GATED or job.get("needs") != "scope":
            errors.append(f"{name} no longer runs exactly when scope decides to build")
    build = jobs["build"]
    if "if" in build:
        errors.append("build has an if: of its own, so it can skip a decided build")
    if sorted(build.get("needs", [])) != ["release-criteria", "security-gate"]:
        errors.append("build no longer follows the scope decision alone")
    for smoke in SMOKES:
        # The script must be the step's command, unconditional and fatal.
        steps = [s for s in build["steps"] if str(s.get("run", "")).strip().startswith(smoke)]
        if not any("if" not in s and not s.get("continue-on-error") for s in steps):
            errors.append(f"build no longer runs {smoke} unconditionally on every event")
    return errors


def main() -> int:
    path = pathlib.Path(os.environ.get("DOCKER_YML", ROOT / ".github/workflows/docker.yml"))
    errors = check(yaml.safe_load(path.read_text()))
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("docker.yml builds and smoke-tests release-line pull requests that change an image input")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
