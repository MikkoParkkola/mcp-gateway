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
import subprocess
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


# scope lists a pull request's files from the merge commit it checks out, against its first parent,
# so a branch behind the release line does not take the line's own image-input changes for its own.
def check_listing(doc: dict) -> list[str]:
    errors = []
    scope = doc["jobs"]["scope"]
    checkout = next((s for s in scope["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")), {})
    if (checkout.get("with") or {}).get("fetch-depth") != 2:
        errors.append("scope's checkout does not fetch depth 2, so the merge commit's parents are missing")
    decide = next(s for s in scope["steps"] if s.get("id") == "decide")
    env = decide.get("env") or {}
    if env.get("HEAD_SHA") != "${{ github.event.pull_request.head.sha }}" or env.get("MERGE_SHA") != "${{ github.sha }}":
        errors.append("scope's HEAD_SHA or MERGE_SHA is not the event's head sha and merge commit")
    script = decide["run"]
    if "git diff --name-only --no-renames HEAD^1 HEAD" not in script:
        errors.append("scope does not list the merge commit against its first parent with --no-renames")
    if '"$BASE_SHA" "$HEAD_SHA"' in script:
        errors.append("scope still diffs the base sha against the head sha")
    if 'decide true "$fail"' not in script:
        errors.append("a failed listing no longer decides build")
    return errors


def git(cwd: pathlib.Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if k not in GIT_LOCATION}
    env.update(GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


# An ambient repository location (a hook or a worktree shell) would point the harness's git at another repo.
GIT_LOCATION = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR")


def commit(repo: pathlib.Path, files: dict, message: str) -> str:
    for name, text in files.items():
        path = repo / name
        if text is None:
            git(repo, "rm", "-q", name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        git(repo, "add", name)
    git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git(repo, "rev-parse", "HEAD")


LOCK = "lock-a\nlock-b\nlock-c\n"
BASE_FILES = {"Dockerfile": "FROM x\n", "Cargo.lock": LOCK, "src/a.rs": "fn a() {}\n", "docs/x.md": "x\n"}


def decide(script: str, tmp: pathlib.Path, base_change: dict, pr_change: dict, *, depth: int = 2,
           single_parent: bool = False, merge_sha: str | None = None, head_sha: str | None = None) -> dict:
    """Run scope's Decide script for one pull request built in a throwaway origin; its outputs as a dict.

    The origin holds the base (first parent of the merge), the PR head (second parent) and refs/pull/7/{head,merge};
    the job's checkout is a fetch of refs/pull/7/merge at `depth` from a file:// URL, as actions/checkout does."""
    origin = tmp / "origin"
    origin.mkdir()
    git(origin, "init", "-q", "-b", "line")
    git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
    start = commit(origin, BASE_FILES, "start")
    base = commit(origin, base_change, "line moves on")
    git(origin, "checkout", "-q", "-b", "pr", start)
    head = commit(origin, pr_change, "the pull request")
    git(origin, "checkout", "-q", "-b", "merge", base)
    if single_parent:  # the PR's tree on top of the base, one parent: not a merge commit
        git(origin, "merge", "-q", "--squash", "pr")
        merge = commit(origin, {}, "squashed")
    else:
        git(origin, "merge", "-q", "--no-ff", "-m", "merge", "pr")
        merge = git(origin, "rev-parse", "HEAD")
    git(origin, "update-ref", "refs/pull/7/head", head)
    git(origin, "update-ref", "refs/pull/7/merge", merge)
    job = tmp / "job"
    job.mkdir()
    git(job, "init", "-q")
    git(job, "fetch", "-q", f"--depth={depth}", f"file://{origin}", "refs/pull/7/merge")
    git(job, "checkout", "-q", "--detach", "FETCH_HEAD")
    out = tmp / "github_output"
    out.write_text("")
    # Exactly the Decide step's env (review r1: a variable production no longer sets must not reach the script
    # here either, or a leftover reference passes the test and aborts under set -u in the job).
    env = {k: v for k, v in os.environ.items() if k not in GIT_LOCATION}
    env.update(EVENT="pull_request", BASE_REF=RELEASE_LINE, HEAD_REF="feature", SAME_REPO="true",
               HEAD_SHA=head_sha or head, PR_NUMBER="7", MERGE_SHA=merge_sha or merge,
               GITHUB_OUTPUT=str(out), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    run = subprocess.run(["bash", "-c", script], cwd=job, env=env, capture_output=True, text=True)
    got = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    got.update(rc=str(run.returncode), log=run.stdout + run.stderr, base=base, head=head, merge=merge, job=str(job))
    return got


NEW_LOCK = "lock-a\nlock-b\nlock-c2\n"
DOCS = {"docs/x.md": "y\n"}
NOT_MERGE = "the checkout is not the event's merge commit"
NOT_HEAD = "the checkout's second parent is not the pull request head"
CASES = (
    # name, line-side change, pull request change, decide() options, run_build, compile_check (None: no line),
    # and for a fallback the cause its log must name (review r1: each row proves its own guard fired)
    ("R1 a branch behind a line-side Cargo.lock change, docs only", {"Cargo.lock": NEW_LOCK}, DOCS, {}, "false", None, None),
    ("R2 the pull request changes Cargo.lock", {}, {"Cargo.lock": NEW_LOCK}, {}, "true", "true", None),
    ("R3 the pull request changes only src/", {}, {"src/a.rs": "fn b() {}\n"}, {}, "false", "true", None),
    ("R4 the pull request renames Dockerfile to Containerfile", {}, {"Dockerfile": None, "Containerfile": "FROM x\n"}, {}, "true", None, None),
    ("R5 line and pull request made the identical Cargo.lock change", {"Cargo.lock": NEW_LOCK}, {"Cargo.lock": NEW_LOCK}, {}, "false", None, None),
    ("R6 the checkout is not the event's merge commit", {}, DOCS, {"merge_sha": "0" * 40}, "true", "true", NOT_MERGE),
    ("R7 a depth-1 checkout without the merge commit's parents", {}, DOCS, {"depth": 1}, "true", "true", NOT_HEAD),
    ("R9 the merge sha has one parent", {}, DOCS, {"single_parent": True}, "true", "true", NOT_HEAD),
    ("R10 line and pull request changed Cargo.lock differently",
     {"Cargo.lock": "lock-a2\nlock-b\nlock-c\n"}, {"Cargo.lock": NEW_LOCK}, {}, "true", "true", None),
    ("R11 the merge commit's second parent is not the pull request head", {}, DOCS, {"head_sha": "1" * 40}, "true", "true", NOT_HEAD),
)


def check_decisions(doc: dict) -> list[str]:
    import tempfile
    script = next(s for s in doc["jobs"]["scope"]["steps"] if s.get("id") == "decide")["run"]
    errors = []
    for gone in ("BASE_SHA", "REPO_URL"):
        if re.search(r"\$\{?" + gone + r"\b", script):
            errors.append(f"the Decide script reads ${gone}, which its step no longer sets")
    for name, base_change, pr_change, opts, run_build, compile_check, cause in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            got = decide(script, pathlib.Path(tmp), base_change, pr_change, **opts)
        if ((got.get("run_build"), got.get("compile_check")) != (run_build, compile_check) or got["rc"] != "0"
                or (cause and f"run_build=true ({cause}" not in got["log"])):
            errors.append(f"{name}: got run_build={got.get('run_build')} compile_check={got.get('compile_check')} "
                          f"rc={got['rc']}, want {run_build}/{compile_check} ({cause or 'no fallback'}); log: {got['log'].strip()[-300:]}")
    # R8, the harness's own premise: the job's checkout is shallow, HEAD is the merge commit, and its parents
    # are the line's base and the pull request head.
    with tempfile.TemporaryDirectory() as tmp:
        got = decide(script, pathlib.Path(tmp), {}, DOCS)
        job = pathlib.Path(got["job"])
        premise = ((job / ".git" / "shallow").exists(), git(job, "rev-parse", "HEAD"),
                   git(job, "rev-parse", "HEAD^1"), git(job, "rev-parse", "HEAD^2"))
        if premise != (True, got["merge"], got["base"], got["head"]):
            errors.append(f"R8 premise: shallow, HEAD, HEAD^1, HEAD^2 = {premise}")
    return errors


def main() -> int:
    path = pathlib.Path(os.environ.get("DOCKER_YML", ROOT / ".github/workflows/docker.yml"))
    errors = check(yaml.safe_load(path.read_text()))
    doc = yaml.safe_load(path.read_text())
    errors += check_listing(doc) + check_decisions(doc)
    for error in errors:
        print(f"FAIL: {error}")
    if not errors:
        print("docker.yml builds and smoke-tests release-line pull requests that change an image input")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
