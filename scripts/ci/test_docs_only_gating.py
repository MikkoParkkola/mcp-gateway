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
              "packaged-suite-rehearsal", "binary-signing-rehearsal", "binary-sbom-rehearsal"}  # dispatch-only
BINARY_STEPS = ("Build the shipped binary", "Verify pins with cap validate (real files accepted, tampered copy refused)")


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
    for e in errors:
        print(f"docs-gating: {e}", file=sys.stderr)
    if not errors:
        print(f"docs-gating: {len(cases)} scope outcomes route {len(SKIPPED)} skippable and {len(KEPT)} kept jobs as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
