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
    "event-source-scope", "timing-asserts", "request-panics", "doc-backticks",
    # Release signing's own unit tests; docker-build waits for them.
    "release-signing-checks",
}
# Never run on an ordinary pull request (tag, dispatch or throwaway only).
NOT_ON_PRS = {"test-throwaway-hosted", "test-trusted", "docker-build", "docker-manifest", "publish-mcp-registry",
              "packaged-suite-rehearsal", "binary-signing-rehearsal", "binary-sbom-rehearsal",
              "helm-chart-publish"}  # dispatch-only, or a tag
# Runs on a pull request into the release line, lane or merge train, that is not
# docs-only and not a throwaway; feature-combos.yml covers every release-line push.
# Checked by its own cases below, so it is in neither SKIPPED nor KEPT.
RELEASE_PRS = {"feature-combos-pr"}
# On a pull request, macOS runs only for a merge train (a `train/` branch in
# this repository), docs-only or not, into any base; every non-PR event runs it
# as before, except the release-line push (POST_MERGE_SKIPPED). Checked by its
# own cases below, so it is in neither SKIPPED nor KEPT.
MACOS_TRAIN = {"macos-shards", "macos-check"}
# Judged on a merge train by HEAVY_GATE (scripts/ci/test_heavy_train_gating.py).
# Each also runs on a lane pull request by its SKIPPED or KEPT rule above, so a
# Windows, feature or release-tooling break fails the pull request that made it.
HEAVY_JUDGED = {
    "windows-shards", "windows-clippy", "windows-check", "release-script-tests",
    "task-sdk-recovery", "gws-dry-run", "linux-keychain", "kani", "upgrade-rehearsal",
    "feature-combos-pr",
}
# Kani is not train-only: a lane pull request that is not docs-only runs it too, so code that
# does not compile under cfg(kani) fails its own CI, not a train (train 40l attempt 2 lost a full
# train CI to two assert!-only variables). It stays in SKIPPED and POST_MERGE_SKIPPED.
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


def simulate(jobs: dict, c: dict, keep_scope: bool = False) -> set[str]:
    """Jobs that run, resolving `needs` in order with each prerequisite's own
    simulated result, so a kept job behind a skipped one counts as skipped.
    `keep_scope`: take the scope job's result and outputs from `c` (a docs-only or
    failed decision) instead of simulating it as a successful code change."""
    results: dict[str, str] = {}
    pending = dict(jobs)
    scope_outputs = {"docs_only": "false"}
    if keep_scope and "scope" in pending:
        results["scope"] = c["needs"]["scope"]["result"]
        scope_outputs = c["needs"]["scope"]["outputs"]
        del pending["scope"]
    while pending:
        progressed = False
        for name, job in list(pending.items()):
            needs = job.get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            if any(n not in results for n in needs):
                continue
            local = dict(c, needs={n: {"result": results[n], "outputs": scope_outputs if n == "scope" else {}}
                                   for n in needs})
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


def release_pr_errors(jobs: dict) -> list[str]:
    """Each RELEASE_PRS job runs on a code pull request into the release line, lane
    or train, and on nothing else."""
    cases = {
        "code train": (as_train(ctx("pull_request", "success", "false")), True),
        "scope failed on a train": (as_train(ctx("pull_request", "failure", None)), True),
        "scope failed after emitting docs-only": (as_train(ctx("pull_request", "failure", "true")), True),
        "scope gave no output on a train": (as_train(ctx("pull_request", "success", None)), True),
        "docs-only train": (as_train(ctx("pull_request", "success", "true")), False),
        "code PR": (ctx("pull_request", "success", "false"), True),
        "scope failed on a PR": (ctx("pull_request", "failure", None), True),
        "docs-only PR": (ctx("pull_request", "success", "true"), False),
        "train branch from a fork": (as_train(ctx("pull_request", "success", "false"), repo="fork/x"), True),
        "a branch merely containing train/": (as_train(ctx("pull_request", "success", "false"), head="x/train/y"), True),
        "same-repo throwaway PR": (as_train(ctx("pull_request", "success", "false"), head="throwaway/x"), False),
        "release-line push": (dict(ctx("push", "success", "false")), False),
        "a train into another base": (as_train(ctx("pull_request", "success", "false")), False),
        "a code PR into another base": (ctx("pull_request", "success", "false"), False),
    }
    cases["a train into another base"][0]["github"]["base_ref"] = "main"
    cases["a code PR into another base"][0]["github"]["base_ref"] = "main"
    cases["release-line push"][0]["github"].update(POST_MERGE_PUSH)
    errors = [f"RELEASE_PRS names a job ci.yml lacks: {j}" for j in sorted(RELEASE_PRS - set(jobs))]
    for job in sorted(RELEASE_PRS & set(jobs)):
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
    # On a same-repo train into the release line the aggregate skips: merge-train judges its shards itself
    # from the base rules (rollups_ok). Its shards still run there.
    judged_by_merge_train = {"code train", "docs-only train", "scope failed on a train"}
    for label, (c, want) in cases.items():
        shards_ran = runs(shards, c)
        after = dict(c, needs=dict(c["needs"], **{"macos-shards": {
            "result": "success" if shards_ran else "skipped", "outputs": {}}}))
        check_want = want and label not in judged_by_merge_train
        for job, ran, w in (("macos-shards", shards_ran, want), ("macos-check", runs(check, after), check_want)):
            if ran != w:
                errors.append(f"{job}: {label} {'skips' if w else 'runs'}")
    # Where the aggregate runs (a train into main stands in for every non-release-line train), it runs
    # whatever its shards did, so a failed or cancelled shard turns it red rather than leaving it skipped.
    for result in ("failure", "cancelled"):
        c = as_train(ctx("pull_request", "success", "false"))
        c["github"]["base_ref"] = "main"
        c = dict(c, needs=dict(c["needs"], **{"macos-shards": {"result": result, "outputs": {}}}))
        if not runs(check, c):
            errors.append(f"macos-check: a train with a {result} shard skips")
    return errors


AGGREGATES = ("test", "windows-check", "macos-check", HEAVY_GATE)


def aggregate_cancel_errors(jobs: dict) -> list[str]:
    """On an os-sensitive lane PR (where all four run; on a train merge-train judges them instead) each
    aggregate runs after a failed, skipped or green shard, but a cancelled run creates no aggregate:
    always() created them after the cancel and left the run queued for a runner,
    holding the newer run in the concurrency group behind it."""
    errors = []
    for job in AGGREGATES:
        needs = jobs[job].get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        for result in ("success", "failure", "skipped"):
            for cancelled in (False, True):
                c = ctx("pull_request", "success", "false")
                c["github"]["event"]["pull_request"]["labels"] = [{"name": "os-sensitive"}]
                c["needs"] = {n: {"result": result, "outputs": {}} for n in needs}
                c["_status"] = dict(c["_status"], cancelled=cancelled)
                if runs(jobs[job], c) == cancelled:
                    run = "cancelled run" if cancelled else "run"
                    errors.append(f"{job}: a {run} with {result} shards {'runs' if cancelled else 'skips'} it")
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


def expression_value(text, github: dict):
    """A concurrency value: each `${{ }}` in `text` evaluated with GitHub's `&&`/`||` returning
    operands (Python's `and`/`or` do the same), over the subset ci.yml's concurrency block uses.
    A value that is one expression keeps its type; one mixed with literal text is a string."""
    text = str(text).strip()

    def one(expr: str):
        expr = re.sub(r"format\('pr-\{0\}',\s*github\.event\.pull_request\.number\)",
                      f"'pr-{github.get('event', {}).get('pull_request', {}).get('number', '')}'", expr)

        def name(m):
            value = github
            for part in m.group(0).split(".")[1:]:
                value = value.get(part, "") if isinstance(value, dict) else ""
            return repr(value)
        expr = re.sub(r"\bgithub(?:\.[\w-]+)+", name, expr)
        expr = re.sub(r"!(?!=)", " not ", expr).replace("&&", " and ").replace("||", " or ")
        return eval(expr, {"__builtins__": {}}, {})  # noqa: S307 - literals only after substitution

    whole = re.fullmatch(r"\$\{\{(.*)\}\}", text, re.S)
    if whole and "${{" not in whole.group(1):
        return one(whole.group(1))
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: str(one(m.group(1))), text)


def concurrency_errors(block: dict) -> list[str]:
    """Release-line pushes share one group and cancel older ones; every other non-PR event keeps
    a group of its own run and never cancels; a pull request keeps pr-<n> and cancels."""
    out = []
    line = {"event_name": "push", "ref": f"refs/heads/{RELEASE_LINE}", "run_id": "101"}
    cases = {
        "release-line push": (line, "shared", True),
        "next release-line push": ({**line, "run_id": "102"}, "shared", True),
        "tag push": ({"event_name": "push", "ref": "refs/tags/v4.0.0", "run_id": "103"}, "own", False),
        "main push": ({"event_name": "push", "ref": "refs/heads/main", "run_id": "104"}, "own", False),
        "other branch push": ({"event_name": "push", "ref": "refs/heads/x", "run_id": "105"}, "own", False),
        "dispatch on the line": ({"event_name": "workflow_dispatch", "ref": f"refs/heads/{RELEASE_LINE}",
                                  "run_id": "106"}, "own", False),
        "pull request": ({"event_name": "pull_request", "ref": "refs/pull/7/merge", "run_id": "107",
                          "event": {"pull_request": {"number": 7}}}, "pr", True),
    }
    groups = {}
    for label, (github, kind, cancels) in cases.items():
        github = {"workflow": "CI", **github}
        group = str(expression_value(block.get("group", ""), github))
        cancel = expression_value(block.get("cancel-in-progress", False), github)
        groups[label] = group
        if bool(cancel) is not cancels:
            out.append(f"concurrency: a {label} {'does not cancel' if cancels else 'cancels'} an older run")
        if kind == "own" and github["run_id"] not in group:
            out.append(f"concurrency: a {label} shares a group ({group}); it must keep a run of its own")
        if kind == "pr" and not group.endswith("pr-7"):
            out.append(f"concurrency: a pull request's group is {group}, not its pr-<n>")
    if groups["release-line push"] != groups["next release-line push"]:
        out.append("concurrency: two release-line pushes get different groups; the newer cannot cancel the older")
    return out


def main() -> int:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    errors = []
    unclassified = set(jobs) - SKIPPED - KEPT - NOT_ON_PRS - RELEASE_PRS - MACOS_TRAIN - {HEAVY_GATE}
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
        # A lane pull request runs every heavy job by the same docs-only rule (none is train-only).
        left_out = NOT_ON_PRS | RELEASE_PRS | MACOS_TRAIN | {HEAVY_GATE}
        ran = {k for k, j in jobs.items() if k not in left_out and runs(j, c)}
        want = (SKIPPED | KEPT) - (SKIPPED if name == "docs-only PR" else set())
        if ran != want:
            errors.append(f"{name}: unexpected runs {sorted(ran - want)}, unexpected skips {sorted(want - ran)}")
        steps = {st.get("name"): st for st in jobs["capability-pins"]["steps"]}
        for step in BINARY_STEPS:
            cond = steps[step].get("if")
            active = cond is None or evaluate(str(cond), c)
            if active == (name == "docs-only PR"):
                errors.append(f"{name}: capability-pins step '{step}' {'runs' if active else 'skips'}")
    errors += release_pr_errors(jobs)
    errors += macos_train_errors(jobs)
    errors += post_merge_errors(jobs)
    # The macOS cases must be able to fail: each mutant is caught by the case
    # named beside it, not merely by some case.
    import copy
    # The train gate, with the os-sensitive label's alternative inside it.
    gate = (" && (github.event_name != 'pull_request' || (startsWith(github.head_ref, 'train/')"
            " && github.event.pull_request.head.repo.full_name == github.repository)"
            " || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
            " && contains(github.event.pull_request.labels.*.name, 'os-sensitive')))")
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
                " && github.event.pull_request.head.repo.full_name == github.repository) ||", ") ||")
    def check_loses_always(j: dict) -> None:
        j["macos-check"]["if"] = str(j["macos-check"]["if"]).replace("${{ !cancelled() && ", "${{ ")
    macos_mutants = {
        "macos-shards loses its train gate": (lambda j: ungate(j, "macos-shards"), "macos-shards: code PR runs"),
        "macos-check loses its train gate": (lambda j: ungate(j, "macos-check"), "macos-check: code PR runs"),
        "macOS waits on the scope job": (waits_on_scope, "macos-shards: scope failed on a train skips"),
        "macOS skips a docs-only change": (skips_docs_only, "macos-shards: docs-only train skips"),
        "a fork's train branch gets macOS": (fork_trains_too, "macos-shards: train branch from a fork runs"),
        "macos-check loses !cancelled()": (check_loses_always, "macos-check: a train with a failure shard skips"),
    }
    for label, (mutate, expected) in macos_mutants.items():
        mutated = copy.deepcopy(jobs)
        mutate(mutated)
        if expected not in macos_train_errors(mutated):
            errors.append(f"macOS self-test: '{label}' was not caught by: {expected}")
    errors += aggregate_cancel_errors(jobs)
    # The cancel rows must be able to fail: always() back on any one aggregate is caught.
    for job in AGGREGATES:
        mutated = copy.deepcopy(jobs)
        mutated[job]["if"] = str(mutated[job]["if"]).replace("${{ !cancelled() && ", "${{ always() && ")
        expected = f"{job}: a cancelled run with failure shards runs it"
        if expected not in aggregate_cancel_errors(mutated):
            errors.append(f"cancel self-test: always() on {job} was not caught by: {expected}")
    # The feature-combination routing must be able to fail: each mutant is caught by the case named beside it.
    fc = "feature-combos-pr"
    train_only = ("${{ !cancelled() && github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
                  " && startsWith(github.head_ref, 'train/') && github.event.pull_request.head.repo.full_name == github.repository"
                  " && (needs.scope.result != 'success' || needs.scope.outputs.docs_only != 'true') }}")
    throwaway = (" && !(github.event.pull_request.head.repo.full_name == github.repository"
                 " && startsWith(github.head_ref, 'throwaway/'))")
    docs = " && (needs.scope.result != 'success' || needs.scope.outputs.docs_only != 'true')"
    def fc_set(j: dict, cond: str) -> None:
        j[fc]["if"] = cond
    fc_mutants = {
        "feature combinations stay train-only": (lambda j: fc_set(j, train_only), f"{fc}: code PR skips"),
        "feature combinations run on a throwaway": (
            lambda j: fc_set(j, str(j[fc]["if"]).replace(throwaway, "")), f"{fc}: same-repo throwaway PR runs"),
        "feature combinations run on a docs-only change": (
            lambda j: fc_set(j, str(j[fc]["if"]).replace(docs, "")), f"{fc}: docs-only PR runs"),
    }
    for label, (mutate, expected) in fc_mutants.items():
        mutated = copy.deepcopy(jobs)
        if fc not in mutated:
            errors.append(f"feature-combos self-test: ci.yml has no {fc} job")
            break
        before = str(mutated[fc].get("if", ""))
        mutate(mutated)
        if str(mutated[fc].get("if", "")) == before:
            errors.append(f"feature-combos self-test: '{label}' changed nothing (clause not found)")
        elif expected not in release_pr_errors(mutated):
            errors.append(f"feature-combos self-test: '{label}' was not caught by: {expected}")
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
    # A newer release-line tip cancels the push runs of older tips (lead decision 2026-11-09,
    # superseding the post-merge rule "every merge keeps its own run, so a red one names its merge
    # commit"):
    # a 7-merge train queued about 250 push jobs behind every PR's CI. The train already tested the
    # exact landed tree, bisecting one train's merges is local, and every PR's own CI and the train
    # run the shrink gates. Tags, dispatches (the release freeze dispatches on the line), main and
    # other branches keep a run of their own; pull requests keep their per-PR group.
    errors += concurrency_errors(workflow.get("concurrency") or {})
    for e in errors:
        print(f"docs-gating: {e}", file=sys.stderr)
    if not errors:
        print(f"docs-gating: {len(cases)} scope outcomes route {len(SKIPPED)} skippable and {len(KEPT)} kept jobs as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
