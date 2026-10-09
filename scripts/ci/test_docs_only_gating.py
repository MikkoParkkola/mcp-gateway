#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Docs-only gating check for ci.yml.

Evaluates every job's `if:` against the `scope` job's possible outcomes and
asserts, for a pull request into the release line:
  * docs_only=true (scope succeeded): exactly the SKIPPED set is skipped and
    every other job runs, including every job that reads documentation;
  * scope failed, was cancelled, or produced no output: nothing is skipped
    (fail-open: a broken decision never turns into a skipped required check);
  * docs_only=false, and any push: nothing is skipped.
Job sets are named here on purpose: adding a job to ci.yml makes this fail
until someone decides which side of the line it belongs on.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_throwaway_routing import REPO, RELEASE_LINE, ROOT, evaluate  # noqa: E402

SKIPPED = {
    "check", "kani", "fmt", "audit",
    "helm-chart-smoke", "helm-oci-roundtrip", "helm-supply-chain", "helm-airgap",
    "k8s-kind-rollback", "upgrade-rehearsal", "service-template-smoke",
    "usability-smoke",
    # One SDK journey test (tests/task_upstream_recovery_sdk.rs); it reads no docs file.
    "task-sdk-recovery",
    # Real gws against the gws capability files; no docs file is read.
    "gws-dry-run",
}
# Workflows with no pull_request trigger: they cannot run on a docs-only PR, so
# they need no gate. Gaining a pull_request trigger fails main() until gated.
PUSH_ONLY_WORKFLOWS = ("codeql.yml", "feature-combos.yml", "packaged-suite.yml")
# Every job that runs tests stays on docs-only PRs, except task-sdk-recovery
# and gws-dry-run (neither reads a docs file): tests read docs files
# (include_str!, doc-claim tests), in the lib/bin suite as well as tests/.
KEPT = {
    "scope", "public-repo-hygiene", "test", "windows-check", "macos-check",
    "orphan-test-modules",
    # Compiles every test target from the packaged crate: a test that reads a
    # repository file (docs included) the package leaves out only fails here.
    "package-tests", "public-claims", "release-script-tests",
    "release-criteria", "capability-pins", "secrets-scan", "secret-leak-lint",
    "file-size-ceiling", "control-drift-probes", "registry-packages",
    # A few seconds of Python; a docs-only change is simply not judged.
    "event-source-scope",
    # Release signing's own unit tests; docker-build waits for them.
    "release-signing-checks",
}
# Never run on an ordinary pull request (tag, dispatch or throwaway only).
NOT_ON_PRS = {"test-throwaway-hosted", "test-trusted", "docker-build", "docker-manifest", "publish-mcp-registry",
              "packaged-suite-rehearsal", "binary-signing-rehearsal", "binary-sbom-rehearsal",
              "helm-chart-publish"}  # dispatch-only, or a tag
BINARY_STEPS = ("Build the shipped binary", "Verify pins with cap validate (real files accepted, tampered copy refused)")

# Skipped on a push to the release line (MIK-8163, merge skew); every other job
# that runs on a pull request also runs on that push, so a check two green PRs
# break together goes red on the merge. Each skip names what covers it instead.
POST_MERGE_SKIPPED = {
    # packaged-suite.yml runs `cargo test --all-features` on every release-line push.
    # (package-tests, a build of that crate, keeps running: #1812 pins it to every ref.)
    "test",
    # Per-item properties two clean PRs cannot break together; the tag reruns them.
    "check", "kani",
    # Platform builds: scarce hosted runners; the tag workflow runs both.
    "windows-check", "macos-check",
    # Build-heavy smokes; docker.yml builds and smokes the image per merge, the tag reruns them.
    "service-template-smoke", "usability-smoke", "upgrade-rehearsal", "helm-oci-roundtrip",
    "helm-supply-chain", "helm-airgap", "k8s-kind-rollback", "gws-dry-run", "task-sdk-recovery",
}
POST_MERGE_PUSH = {"event_name": "push", "ref": f"refs/heads/{RELEASE_LINE}"}


def simulate(jobs: dict, c: dict) -> set[str]:
    """Jobs that run, resolving `needs` in order with each prerequisite's own
    simulated result, so a kept job behind a skipped one counts as skipped."""
    results: dict[str, str] = {}
    pending = dict(jobs)
    while pending:
        progressed = False
        for name, job in list(pending.items()):
            needs = job.get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            if any(n not in results for n in needs):
                continue
            outputs = {"docs_only": "false"}
            local = dict(c, needs={n: {"result": results[n], "outputs": outputs if n == "scope" else {}} for n in needs})
            results[name] = "success" if runs(job, local) else "skipped"
            del pending[name]
            progressed = True
        assert progressed, f"needs cycle among {sorted(pending)}"
    return {k for k, v in results.items() if v == "success"}


def post_merge_errors(jobs: dict) -> list[str]:
    """A release-line push runs everything but POST_MERGE_SKIPPED and NOT_ON_PRS."""
    errors = []
    unknown = POST_MERGE_SKIPPED - set(jobs)
    if unknown:
        errors.append(f"POST_MERGE_SKIPPED names jobs ci.yml lacks: {sorted(unknown)}")
    c = ctx("push", "success", "false")
    c["github"].update(POST_MERGE_PUSH)
    ran = simulate(jobs, c) - NOT_ON_PRS
    want = (SKIPPED | KEPT) - POST_MERGE_SKIPPED
    if ran != want:
        errors.append(f"release-line push: unexpected runs {sorted(ran - want)}, unexpected skips {sorted(want - ran)}")
    return errors


def ctx(event: str, scope_result: str, docs_only: str | None) -> dict:
    g = {"repository": REPO, "event_name": event, "ref": "refs/heads/x",
         "base_ref": RELEASE_LINE if event == "pull_request" else "",
         "head_ref": "feature/x" if event == "pull_request" else "",
         "event": {"pull_request": {"head": {"repo": {"full_name": REPO}}}} if event == "pull_request" else {}}
    outputs = {} if docs_only is None else {"docs_only": docs_only}
    return {"github": g, "vars": {}, "inputs": {},
            "needs": {"scope": {"result": scope_result, "outputs": outputs}},
            "_status": {"cancelled": False, "success": scope_result == "success",
                        "failure": scope_result == "failure"}}


def runs(job: dict, c: dict) -> bool:
    """GitHub's rule: the `needs` context holds only declared dependencies, and
    an `if:` that calls no status function is implicitly `success() && ...`,
    so the job is skipped when any dependency did not succeed."""
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    declared = {n: c["needs"][n] for n in needs if n in c["needs"]}
    all_ok = all(declared.get(n, {"result": "success"})["result"] == "success" for n in needs)
    local = dict(c, needs=declared)
    results = [declared.get(n, {"result": "success"})["result"] for n in needs]
    local["_status"] = dict(c["_status"], success=all_ok, failure="failure" in results)
    cond = str(job.get("if", ""))
    if not re.search(r"\b(cancelled|always|success|failure)\s*\(", cond) and not all_ok:
        return False
    return evaluate(cond, local) if cond else all_ok


def main() -> int:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    errors = []
    unclassified = set(jobs) - SKIPPED - KEPT - NOT_ON_PRS
    if unclassified:
        errors.append(f"jobs not classified for docs-only gating: {sorted(unclassified)}")
    for wf in PUSH_ONLY_WORKFLOWS:
        doc = yaml.safe_load((ROOT / ".github/workflows" / wf).read_text())
        on = doc.get(True) or doc.get("on") or {}  # PyYAML reads `on` as True
        events = {on} if isinstance(on, str) else set(on)
        if any(e.startswith("pull_request") for e in events):
            errors.append(f"{wf} gained a pull_request trigger: gate it on ci.yml's scope job")
    cases = {
        "docs-only PR": ctx("pull_request", "success", "true"),
        "code PR": ctx("pull_request", "success", "false"),
        "scope failed": ctx("pull_request", "failure", None),
        "scope failed after emitting true": ctx("pull_request", "failure", "true"),
        "scope cancelled after emitting true": ctx("pull_request", "cancelled", "true"),
        "scope cancelled": ctx("pull_request", "cancelled", None),
        "scope gave no output": ctx("pull_request", "success", None),
        "push": ctx("push", "success", "false"),
    }
    for must in ("test", "windows-check", "macos-check"):
        if must in SKIPPED:
            errors.append(f"test job {must} is in the skipped set")
    # A red Linux suite must not start a Windows run: Windows slots are the
    # scarce part of the account's concurrent-job pool.
    for outcome in ("failure", "cancelled", "skipped"):
        for name, base in cases.items():
            c = dict(base, needs=dict(base["needs"], test={"result": outcome, "outputs": {}}))
            if runs(jobs["windows-check"], c):
                errors.append(f"{name}: windows-check runs after a {outcome} Tests job")
    for name, c in cases.items():
        ran = {k for k, j in jobs.items() if k not in NOT_ON_PRS and runs(j, c)}
        want = (SKIPPED | KEPT) - (SKIPPED if name == "docs-only PR" else set())
        if ran != want:
            errors.append(f"{name}: unexpected runs {sorted(ran - want)}, unexpected skips {sorted(want - ran)}")
        steps = {st.get("name"): st for st in jobs["capability-pins"]["steps"]}
        for step in BINARY_STEPS:
            cond = steps[step].get("if")
            active = cond is None or evaluate(str(cond), c)
            if active == (name == "docs-only PR"):
                errors.append(f"{name}: capability-pins step '{step}' {'runs' if active else 'skips'}")
    errors += post_merge_errors(jobs)
    # The post-merge check must be able to fail (MIK-8163): each mutation is caught.
    import copy
    mutations = {
        "a heavy job loses its post-merge skip": lambda j: j["test"].update(
            {"if": str(j["test"]["if"]).replace(" && !(github.event_name == 'push' && github.ref == 'refs/heads/docs/ranking-1-release-line')", "")}),
        "a kept job comes to depend on a skipped one": lambda j: j["release-criteria"].update({"needs": "test"}),
        "a kept job skips the release-line push": lambda j: j["file-size-ceiling"].update(
            {"if": "${{ github.event_name != 'push' }}"}),
    }
    for label, mutate in mutations.items():
        mutated = copy.deepcopy(jobs)
        mutate(mutated)
        if not post_merge_errors(mutated):
            errors.append(f"post-merge self-test: '{label}' was not caught")
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    on = workflow.get(True) or workflow.get("on") or {}
    if RELEASE_LINE not in (on.get("push") or {}).get("branches", []):
        errors.append(f"ci.yml does not run on a push to {RELEASE_LINE}")
    # Every merge keeps its own run, so a red one names its merge commit.
    cancel = str((workflow.get("concurrency") or {}).get("cancel-in-progress", ""))
    c = ctx("push", "success", "false")
    c["github"].update(POST_MERGE_PUSH)
    if cancel in ("true", "True") or (cancel.startswith("${{") and evaluate(cancel, c)):
        errors.append("ci.yml cancels an in-progress run on a release-line push")
    for e in errors:
        print(f"docs-gating: {e}", file=sys.stderr)
    if not errors:
        print(f"docs-gating: {len(cases)} scope outcomes route {len(SKIPPED)} skippable and {len(KEPT)} kept jobs as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
