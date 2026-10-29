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
    # One keychain test against a real Secret Service; no docs file is read.
    "linux-keychain",
}
# Workflows with no pull_request trigger: they cannot run on a docs-only PR, so
# they need no gate. Gaining a pull_request trigger fails main() until gated.
PUSH_ONLY_WORKFLOWS = ("codeql.yml", "feature-combos.yml", "mingw-debs.yml", "packaged-suite.yml")
# Every job that runs tests stays on docs-only PRs, except task-sdk-recovery
# and gws-dry-run (neither reads a docs file): tests read docs files
# (include_str!, doc-claim tests), in the lib/bin suite as well as tests/.
KEPT = {
    "scope", "public-repo-hygiene", "test", "windows-check",
    # Their shards (MIK-8482): the aggregates above only read these results.
    "test-shards", "windows-shards", "windows-clippy",
    "orphan-test-modules",
    # Compiles every test target from the packaged crate: a test that reads a
    # repository file (docs included) the package leaves out only fails here.
    "package-tests", "public-claims", "release-script-tests",
    "release-criteria", "capability-pins", "secrets-scan", "secret-leak-lint",
    "file-size-ceiling", "control-drift-probes", "registry-packages",
    # A few seconds of Python; a docs-only change is simply not judged.
    "event-source-scope", "timing-asserts", "request-panics",
    # Release signing's own unit tests; docker-build waits for them.
    "release-signing-checks",
}
# Never run on an ordinary pull request (tag, dispatch or throwaway only).
NOT_ON_PRS = {"test-throwaway-hosted", "test-trusted", "docker-build", "docker-manifest", "publish-mcp-registry",
              "packaged-suite-rehearsal", "binary-signing-rehearsal", "binary-sbom-rehearsal",
              "helm-chart-publish"}  # dispatch-only, or a tag
# Runs only on a merge train: a pull request into the release line from a
# `train/` branch in this repository, and not when it is docs-only. Checked by
# its own cases below, so it is in neither SKIPPED nor KEPT.
TRAIN_ONLY = {"feature-combos-train"}
# On a pull request, macOS runs only for a merge train (a `train/` branch in
# this repository), docs-only or not, into any base; every non-PR event runs it
# as before, except the release-line push (POST_MERGE_SKIPPED). Checked by its
# own cases below, so it is in neither SKIPPED nor KEPT.
MACOS_TRAIN = {"macos-shards", "macos-check"}
# On a pull request into the release line, run only for a merge train and
# judged there by HEAVY_GATE; scripts/ci/test_heavy_train_gating.py checks
# their routing on every event, so the generic pull-request cases below leave
# them out (their docs-only membership above still applies on a train).
HEAVY_TRAIN = {
    "windows-shards", "windows-clippy", "windows-check", "release-script-tests",
    "task-sdk-recovery", "gws-dry-run", "linux-keychain", "kani", "upgrade-rehearsal",
}
HEAVY_GATE = "heavy-gate"
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
    # The shards behind test, windows-check and macos-check (MIK-8482).
    "test-shards", "windows-shards", "windows-clippy", "macos-shards",
    # Build-heavy smokes; docker.yml builds and smokes the image per merge, the tag reruns them.
    "service-template-smoke", "usability-smoke", "upgrade-rehearsal", "helm-oci-roundtrip",
    "helm-supply-chain", "helm-airgap", "k8s-kind-rollback", "gws-dry-run", "task-sdk-recovery",
    "linux-keychain",
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


def as_train(c: dict, head: str = "train/20261027-1", repo: str = REPO) -> dict:
    """`c` as a pull request from `head` in `repo` (a merge train by default)."""
    c["github"]["head_ref"] = head
    c["github"]["event"] = {"pull_request": {"head": {"repo": {"full_name": repo}}}}
    return c


def train_errors(jobs: dict) -> list[str]:
    """Each TRAIN_ONLY job runs on a code train and on nothing else."""
    cases = {
        "code train": (as_train(ctx("pull_request", "success", "false")), True),
        "scope failed on a train": (as_train(ctx("pull_request", "failure", None)), True),
        "scope failed after emitting docs-only": (as_train(ctx("pull_request", "failure", "true")), True),
        "scope gave no output on a train": (as_train(ctx("pull_request", "success", None)), True),
        "docs-only train": (as_train(ctx("pull_request", "success", "true")), False),
        "code PR": (ctx("pull_request", "success", "false"), False),
        "train branch from a fork": (as_train(ctx("pull_request", "success", "false"), repo="fork/x"), False),
        "a branch merely containing train/": (as_train(ctx("pull_request", "success", "false"), head="x/train/y"), False),
        "release-line push": (dict(ctx("push", "success", "false")), False),
        "a train into another base": (as_train(ctx("pull_request", "success", "false")), False),
    }
    cases["a train into another base"][0]["github"]["base_ref"] = "main"
    cases["release-line push"][0]["github"].update(POST_MERGE_PUSH)
    errors = [f"TRAIN_ONLY names a job ci.yml lacks: {j}" for j in sorted(TRAIN_ONLY - set(jobs))]
    for job in sorted(TRAIN_ONLY & set(jobs)):
        # The routing below is evaluated on an injected scope result, so the
        # dependency and the status function it relies on are asserted here.
        needs = jobs[job].get("needs") or []
        if "scope" not in ([needs] if isinstance(needs, str) else needs):
            errors.append(f"{job}: does not need scope")
        if not re.search(r"\b(cancelled|always)\s*\(", str(jobs[job].get("if", ""))):
            errors.append(f"{job}: its if has no status function, so a skipped scope skips it")
        target = str(jobs[job].get("uses", ""))
        called = ROOT / target.removeprefix("./")
        doc = yaml.safe_load(called.read_text()) if target.startswith("./") and called.is_file() else {}
        on = doc.get(True) or doc.get("on") or {}
        if "workflow_call" not in ({on} if isinstance(on, str) else set(on)):
            errors.append(f"{job}: calls {target!r}, which declares no workflow_call")
        for label, (c, want) in cases.items():
            if runs(jobs[job], c) != want:
                errors.append(f"{job}: {label} {'skips' if want else 'runs'}")
    return errors


def macos_train_errors(jobs: dict) -> list[str]:
    """Each MACOS_TRAIN job runs on a train pull request and on non-PR events,
    and on no other pull request; its aggregate follows its shards.

    Evaluated with each case's own scope result, not simulate()'s, so the
    docs-only and scope-failed trains pin that the macOS jobs never come to
    depend on the docs-only decision (the self-test in main() proves both)."""
    def event(name: str, ref: str) -> dict:
        c = ctx(name, "success", "false")
        c["github"]["ref"] = ref
        return c
    cases = {
        "code PR": (ctx("pull_request", "success", "false"), False),
        "docs-only PR": (ctx("pull_request", "success", "true"), False),
        "scope failed on a PR": (ctx("pull_request", "failure", None), False),
        "code train": (as_train(ctx("pull_request", "success", "false")), True),
        "docs-only train": (as_train(ctx("pull_request", "success", "true")), True),
        "scope failed on a train": (as_train(ctx("pull_request", "failure", None)), True),
        "train branch from a fork": (as_train(ctx("pull_request", "success", "false"), repo="fork/x"), False),
        "a branch merely containing train/": (as_train(ctx("pull_request", "success", "false"), head="x/train/y"), False),
        "a train into main": (as_train(ctx("pull_request", "success", "false")), True),
        "push to main": (event("push", "refs/heads/main"), True),
        "release tag": (event("push", "refs/tags/v4.0.0"), True),
        "workflow dispatch": (event("workflow_dispatch", "refs/heads/main"), True),
        "release-line push": (event("push", f"refs/heads/{RELEASE_LINE}"), False),
    }
    cases["a train into main"][0]["github"]["base_ref"] = "main"
    errors = [f"MACOS_TRAIN names a job ci.yml lacks: {j}" for j in sorted(MACOS_TRAIN - set(jobs))]
    if errors:
        return errors
    shards, check = jobs["macos-shards"], jobs["macos-check"]
    for label, (c, want) in cases.items():
        shards_ran = runs(shards, c)
        after = dict(c, needs=dict(c["needs"], **{"macos-shards": {
            "result": "success" if shards_ran else "skipped", "outputs": {}}}))
        for job, ran in (("macos-shards", shards_ran), ("macos-check", runs(check, after))):
            if ran != want:
                errors.append(f"{job}: {label} {'skips' if want else 'runs'}")
    # On a train, the aggregate runs whatever its shards did, so a failed or
    # cancelled shard turns it red rather than leaving it skipped.
    for result in ("failure", "cancelled"):
        c = as_train(ctx("pull_request", "success", "false"))
        c = dict(c, needs=dict(c["needs"], **{"macos-shards": {"result": result, "outputs": {}}}))
        if not runs(check, c):
            errors.append(f"macos-check: a train with a {result} shard skips")
    return errors


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
    unclassified = set(jobs) - SKIPPED - KEPT - NOT_ON_PRS - TRAIN_ONLY - MACOS_TRAIN - {HEAVY_GATE}
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
    # The Windows check runs alongside the Tests job, not after it, so the
    # required path is the longer job and not their sum. It must stay
    # independent of `test` (a `needs: test` would serialise them again).
    needs_of_windows = jobs["windows-check"].get("needs") or []
    needs_of_windows = [needs_of_windows] if isinstance(needs_of_windows, str) else needs_of_windows
    if "test" in needs_of_windows:
        errors.append("windows-check needs the Tests job: it must start in parallel with it")
    # The same for the shards behind both (MIK-8482).
    shard_needs = jobs["windows-shards"].get("needs") or []
    shard_needs = [shard_needs] if isinstance(shard_needs, str) else shard_needs
    if {"test", "test-shards"} & set(shard_needs):
        errors.append("windows-shards needs the Linux suite: it must start in parallel with it")
    for name, c in cases.items():
        left_out = NOT_ON_PRS | TRAIN_ONLY | MACOS_TRAIN | HEAVY_TRAIN | {HEAVY_GATE}
        ran = {k for k, j in jobs.items() if k not in left_out and runs(j, c)}
        want = (SKIPPED | KEPT) - HEAVY_TRAIN - (SKIPPED if name == "docs-only PR" else set())
        if ran != want:
            errors.append(f"{name}: unexpected runs {sorted(ran - want)}, unexpected skips {sorted(want - ran)}")
        steps = {st.get("name"): st for st in jobs["capability-pins"]["steps"]}
        for step in BINARY_STEPS:
            cond = steps[step].get("if")
            active = cond is None or evaluate(str(cond), c)
            if active == (name == "docs-only PR"):
                errors.append(f"{name}: capability-pins step '{step}' {'runs' if active else 'skips'}")
    errors += train_errors(jobs)
    errors += macos_train_errors(jobs)
    errors += post_merge_errors(jobs)
    # The macOS cases must be able to fail: each mutant is caught by the case
    # named beside it, not merely by some case.
    import copy
    gate = (" && (github.event_name != 'pull_request' || (startsWith(github.head_ref, 'train/')"
            " && github.event.pull_request.head.repo.full_name == github.repository))")
    def ungate(j: dict, job: str) -> None:
        j[job]["if"] = str(j[job]["if"]).replace(gate, "")
    def waits_on_scope(j: dict) -> None:
        j["macos-shards"]["needs"] = "scope"
    def skips_docs_only(j: dict) -> None:
        j["macos-shards"]["needs"] = "scope"
        j["macos-shards"]["if"] = str(j["macos-shards"]["if"]).replace(
            " }}", " && needs.scope.outputs.docs_only != 'true' }}")
    def fork_trains_too(j: dict) -> None:
        for job in MACOS_TRAIN:
            j[job]["if"] = str(j[job]["if"]).replace(
                " && github.event.pull_request.head.repo.full_name == github.repository))", "))")
    def check_loses_always(j: dict) -> None:
        j["macos-check"]["if"] = str(j["macos-check"]["if"]).replace("${{ always() && ", "${{ ")
    macos_mutants = {
        "macos-shards loses its train gate": (lambda j: ungate(j, "macos-shards"), "macos-shards: code PR runs"),
        "macos-check loses its train gate": (lambda j: ungate(j, "macos-check"), "macos-check: code PR runs"),
        "macOS waits on the scope job": (waits_on_scope, "macos-shards: scope failed on a train skips"),
        "macOS skips a docs-only change": (skips_docs_only, "macos-shards: docs-only train skips"),
        "a fork's train branch gets macOS": (fork_trains_too, "macos-shards: train branch from a fork runs"),
        "macos-check loses always()": (check_loses_always, "macos-check: a train with a failure shard skips"),
    }
    for label, (mutate, expected) in macos_mutants.items():
        mutated = copy.deepcopy(jobs)
        mutate(mutated)
        if expected not in macos_train_errors(mutated):
            errors.append(f"macOS self-test: '{label}' was not caught by: {expected}")
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
