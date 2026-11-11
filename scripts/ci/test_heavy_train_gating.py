#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The heavy jobs run on lane pull requests too, and are judged on the merge train.

A lane pull request into the release line runs every HEAVY job by its docs-only
rule (SKIPPED or KEPT in test_docs_only_gating.py), so a Windows, feature or
release-tooling break fails the pull request that made it. No heavy job keeps a
train-only clause. The `heavy-gate` job ("Heavy checks (merge train)") still
fails a train (a `train/` branch in this repository) unless every heavy job
succeeded there: a train's required checks are its pull requests' own checks plus
this gate, and a pull request whose CI predates a job, or skipped it, would leave
a red one unrequired on the train. On a lane the gate passes without judging; the
lane's own checks fail it. On a same-repo train into the release line the gate itself is now skipped:
merge-train judges its needs from the base copy of this workflow (its ROLLUP_EXPECTS and
DOCS_ONLY_SKIPPABLE values). Its script still judges a train correctly, so reverting the skip
(the rollback) needs no other change.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_docs_only_gating import (  # noqa: E402
    HEAVY_GATE, HEAVY_JUDGED, POST_MERGE_SKIPPED, RELEASE_PRS, ROOT, SKIPPED, as_train, ctx, runs,
)
from test_throwaway_routing import evaluate  # noqa: E402

HEAVY = HEAVY_JUDGED
# Skipped on a docs-only change, train or not: the docs-only rule's jobs and the
# feature combinations.
DOCS_SKIPPED = (HEAVY & SKIPPED) | (HEAVY & RELEASE_PRS)
GATE = HEAVY_GATE
GATE_NAME = "Heavy checks (merge train)"
STEP = "Every heavy job succeeded on a merge train"
# The train-only clause these jobs carried before lanes ran them; none may carry it now.
CLAUSE = (" && !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
          " && !(startsWith(github.head_ref, 'train/')"
          " && github.event.pull_request.head.repo.full_name == github.repository))")
# The Windows jobs' form of it, with the os-sensitive label as its alternative.
LABEL_CLAUSE = (" && (" + CLAUSE[len(" && "):]
                + " || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
                " && contains(github.event.pull_request.labels.*.name, 'os-sensitive')))")
LANE_CONTEXTS = {"code PR", "docs-only PR", "scope failed on a PR", "train branch from a fork",
                 "a branch merely containing train/"}


def contexts() -> dict[str, tuple[dict, bool]]:
    """Each case and whether it is a lane pull request into the release line."""
    def event(name: str, ref: str) -> dict:
        c = ctx(name, "success", "false")
        c["github"]["ref"] = ref
        return c
    into_main = ctx("pull_request", "success", "false")
    into_main["github"]["base_ref"] = "main"
    train_into_main = as_train(ctx("pull_request", "success", "false"))
    train_into_main["github"]["base_ref"] = "main"
    throwaway = as_train(ctx("pull_request", "success", "false"), head="throwaway/x")
    return {
        "code PR": (ctx("pull_request", "success", "false"), True),
        "docs-only PR": (ctx("pull_request", "success", "true"), True),
        "scope failed on a PR": (ctx("pull_request", "failure", None), True),
        "train branch from a fork": (as_train(ctx("pull_request", "success", "false"), repo="fork/x"), True),
        "a branch merely containing train/": (
            as_train(ctx("pull_request", "success", "false"), head="x/train/y"), True),
        "same-repo throwaway PR": (throwaway, True),
        "code train": (as_train(ctx("pull_request", "success", "false")), False),
        "docs-only train": (as_train(ctx("pull_request", "success", "true")), False),
        "scope failed on a train": (as_train(ctx("pull_request", "failure", None)), False),
        "PR into main": (into_main, False),
        "train into main": (train_into_main, False),
        "push to main": (event("push", "refs/heads/main"), False),
        "release-line push": (event("push", "refs/heads/docs/ranking-1-release-line"), False),
        "release tag": (event("push", "refs/tags/v4.0.0"), False),
        "workflow dispatch": (event("workflow_dispatch", "refs/heads/main"), False),
    }


def with_needs(job: dict, c: dict, result: str) -> dict:
    """`c` with every dependency of `job` other than scope at `result`."""
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    extra = {n: {"result": result, "outputs": {}} for n in needs if n != "scope"}
    return dict(c, needs=dict(c["needs"], **extra))


def wanted(job: str, label: str) -> bool:
    """Whether `job` runs in the context `label` names."""
    if label == "same-repo throwaway PR":
        return False
    # A roll-up among the heavy jobs (Windows check) skips on a same-repo train into the release line:
    # merge-train judges its needs there.
    if job == "windows-check" and label in ("code train", "docs-only train", "scope failed on a train"):
        return False
    if job in RELEASE_PRS:
        # Pull requests into the release line only; feature-combos.yml covers its pushes.
        into_line = label in LANE_CONTEXTS or label in ("code train", "docs-only train", "scope failed on a train")
        return into_line and label not in ("docs-only PR", "docs-only train")
    if label in ("docs-only PR", "docs-only train") and job in DOCS_SKIPPED:
        return False
    return not (label == "release-line push" and job in POST_MERGE_SKIPPED)


def heavy_errors(jobs: dict) -> list[str]:
    """Each heavy job runs on a lane as on its train: no train-only clause, and
    every case routed by `wanted`."""
    errors = [f"HEAVY names a job ci.yml lacks: {j}" for j in sorted(HEAVY - set(jobs))]
    for job in sorted(HEAVY & set(jobs)):
        cond = str(jobs[job].get("if", ""))
        if CLAUSE in cond or LABEL_CLAUSE in cond:
            errors.append(f"{job}: its if keeps the train-only clause")
        for label, (c, _) in contexts().items():
            c = with_needs(jobs[job], c, "success")
            want = wanted(job, label)
            if runs(jobs[job], c) != want:
                errors.append(f"{job}: {label} {'skips' if want else 'runs'}")
    return errors


def gate_errors(jobs: dict) -> list[str]:
    gate = jobs.get(GATE)
    if gate is None:
        return [f"ci.yml has no {GATE} job"]
    errors = []
    if gate.get("name") != GATE_NAME:
        errors.append(f"{GATE}: name is {gate.get('name')!r}, not {GATE_NAME!r} (the merge train needs it by name)")
    needs = gate.get("needs") or []
    needs = {needs} if isinstance(needs, str) else set(needs)
    if needs != HEAVY | {"scope"}:
        errors.append(f"{GATE}: needs {sorted(needs)}, not every heavy job plus scope")
    if gate.get("permissions") != {"contents": "read"}:
        errors.append(f"{GATE}: permissions must be contents: read alone")
    run = " ".join(str(s.get("run", "")) for s in gate.get("steps", []))
    env = next((st.get("env") or {} for st in gate.get("steps", []) if st.get("name") == STEP), {})
    # The ids are data merge-train reads from the base ci.yml: the verdict passes them by env, verbatim.
    expects = str(env.get("ROLLUP_EXPECTS", "")).split()
    if set(expects) != HEAVY | {"scope"} or "$ROLLUP_EXPECTS" not in run:
        errors.append(f"{GATE}: its verdict must pass ROLLUP_EXPECTS naming exactly every heavy job plus scope")
    if "check_needs.py" not in run:
        errors.append(f"{GATE}: its verdict does not use check_needs.py")
    allowed = str(env.get("DOCS_ONLY_SKIPPABLE", ""))
    if set(allowed.split(",")) != DOCS_SKIPPED or '--allow-skipped "$DOCS_ONLY_SKIPPABLE"' not in run:
        errors.append(f"{GATE}: --allow-skipped must pass DOCS_ONLY_SKIPPABLE naming exactly {sorted(DOCS_SKIPPED)}")
    if "${{" in run:
        errors.append(f"{GATE}: a step interpolates an expression into its script; pass it through env")
    # It runs, whatever its needs did, on every pull request into the release
    # line but a throwaway one and a same-repo train (merge-train judges that), and on nothing else.
    want = {
        "code PR": True, "docs-only PR": True, "scope failed on a PR": True,
        "train branch from a fork": True, "a branch merely containing train/": True,
        "same-repo throwaway PR": False, "code train": False, "docs-only train": False,
        "scope failed on a train": False, "PR into main": False, "train into main": False,
        "push to main": False, "release-line push": False, "release tag": False,
        "workflow dispatch": False,
    }
    for label, (c, _) in contexts().items():
        for result in ("success", "skipped", "failure", "cancelled"):
            if runs(gate, with_needs(gate, c, result)) != want[label]:
                errors.append(f"{GATE}: {label} with {result} needs {'skips' if want[label] else 'runs'}")
    return errors


def run_gate_step(gate: dict, c: dict, results: dict[str, str], root: Path = ROOT) -> int:
    """Run the gate's verdict step as the runner would: each env expression
    rendered for context `c`, NEEDS built from `results`; its exit code.
    `root` is the tree its scripts are read from (a self-test passes a copy
    holding a mutated check_needs.py)."""
    step = next(st for st in gate.get("steps", []) if st.get("name") == STEP)
    # An expression renders to true/false; a plain value (DOCS_ONLY_SKIPPABLE, ROLLUP_EXPECTS) passes as written.
    env = {k: ("true" if evaluate(str(v), c) else "false") if "${{" in str(v) else str(v)
           for k, v in (step.get("env") or {}).items() if k != "NEEDS"}
    # Only the jobs the gate declares in `needs` reach toJSON(needs) on a runner, so a job the gate
    # forgot cannot be judged here either (a fixed list once let a gate without kani pass its rows).
    declared = gate.get("needs") or []
    declared = {declared} if isinstance(declared, str) else set(declared)
    needs = {job: {"result": r, "outputs": {}} for job, r in results.items() if job in declared}
    with tempfile.NamedTemporaryFile() as summary:
        env.update(NEEDS=json.dumps(needs), GITHUB_STEP_SUMMARY=summary.name, PATH=os.environ.get("PATH", ""))
        # The shell a `run:` step gets on a Linux runner.
        shell = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]]
        return subprocess.run(shell, cwd=root, env=env, capture_output=True).returncode


def gate_step_errors(jobs: dict, root: Path = ROOT) -> list[str]:
    """The gate's own script passes every lane and judges every train. A same-repo train skips the
    gate today, so this pins the script the rollback (reverting that skip) would run again."""
    gate = jobs.get(GATE)
    if gate is None:
        return [f"ci.yml has no {GATE} job"]
    step = next((st for st in gate.get("steps", []) if st.get("name") == STEP), None)
    if step is None:
        return [f"{GATE}: no step named {STEP!r}"]
    if str((step.get("env") or {}).get("NEEDS", "")).replace(" ", "") != "${{toJSON(needs)}}":
        return [f"{GATE} step: NEEDS is not ${{{{ toJSON(needs) }}}}"]
    every = sorted(HEAVY | {"scope"})
    def results(**changed: str) -> dict[str, str]:
        out = {job: "success" for job in every}
        out.update({job.replace("_", "-"): r for job, r in changed.items()})
        return out
    lane = ctx("pull_request", "success", "false")
    fork = as_train(ctx("pull_request", "success", "false"), repo="fork/x")
    train = as_train(ctx("pull_request", "success", "false"))
    docs_train = as_train(ctx("pull_request", "success", "true"))
    skipped_heavy = {job: "skipped" for job in HEAVY}
    cases = {
        "lane, heavy jobs skipped": (lane, results(**{j.replace("-", "_"): "skipped" for j in HEAVY}), True),
        "lane, a heavy job failed": (lane, results(**{"linux-keychain": "failure"}), True),
        "fork train branch, heavy jobs skipped": (fork, dict(results(), **skipped_heavy), True),
        "train, all succeeded": (train, results(), True),
        "train, a heavy job failed": (train, results(**{"linux-keychain": "failure"}), False),
        # Kani runs on lanes too, and the gate still refuses a train whose Kani failed.
        "train, Kani failed": (train, results(kani="failure"), False),
        "train, Kani skipped": (train, results(kani="skipped"), False),
        "lane, Kani failed (its own check fails the lane, not this gate)": (lane, results(kani="failure"), True),
        "docs-only train, Kani skipped": (docs_train, dict(results(), **{j: "skipped" for j in DOCS_SKIPPED}), True),
        "train, a heavy job cancelled": (train, results(windows_check="cancelled"), False),
        "train, a heavy job skipped": (train, results(linux_keychain="skipped"), False),
        "train, Windows skipped": (train, results(windows_shards="skipped"), False),
        "docs-only train, docs-only skips": (docs_train, dict(results(), **{j: "skipped" for j in DOCS_SKIPPED}), True),
        "docs-only train, Windows skipped": (docs_train, results(windows_check="skipped"), False),
        "train, a heavy job missing from needs": (train, {j: "success" for j in every if j != "linux-keychain"}, False),
        # Only `skipped` is a docs-only allowance: a docs-skipped job that ran
        # and failed, or was cancelled, still fails the train.
        "docs-only train, a docs-skipped job failed": (docs_train, results(**{"linux-keychain": "failure"}), False),
        "docs-only train, a docs-skipped job cancelled": (docs_train, results(gws_dry_run="cancelled"), False),
        # Feature combinations are judged like the rest: a lane PR whose CI predates them
        # would otherwise leave a red one unrequired on the train.
        "train, feature combinations failed": (train, results(feature_combos_pr="failure"), False),
        "train, feature combinations skipped": (train, results(feature_combos_pr="skipped"), False),
        "lane, feature combinations failed (its own check fails the lane)": (
            lane, results(feature_combos_pr="failure"), True),
    }
    errors = []
    for label, (c, res, passes) in cases.items():
        code = run_gate_step(gate, c, res, root)
        if (code == 0) != passes:
            errors.append(f"{GATE} step: {label} {'fails' if passes else 'passes'} (exit {code})")
    return errors


def main() -> int:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    errors = heavy_errors(jobs) + gate_errors(jobs) + gate_step_errors(jobs)
    # Each mutant is caught by the case named beside it.
    def keeps_clause(job: str, clause: str):
        def mutate(j: dict) -> None:
            cond = str(j[job]["if"])
            assert cond.endswith(" }}"), cond[-20:]
            j[job]["if"] = cond[:-3] + clause + " }}"
        return mutate
    def forks_count(j: dict) -> None:
        for st in j[GATE]["steps"]:
            if st.get("name") == STEP:
                st["env"]["TRAIN"] = "${{ startsWith(github.head_ref, 'train/') }}"
    def gate_forgets(job: str):
        def mutate(j: dict) -> None:
            j[GATE]["needs"] = sorted((HEAVY | {"scope"}) - {job})
        return mutate
    def docs_allowance_drops(job: str):
        def mutate(j: dict) -> None:
            for st in j[GATE]["steps"]:
                if st.get("name") == STEP:
                    st["env"]["DOCS_ONLY_SKIPPABLE"] = ",".join(
                        x for x in str(st["env"]["DOCS_ONLY_SKIPPABLE"]).split(",") if x != job)
        return mutate
    def train_runs_gate_again(j: dict) -> None:
        skip = (" && !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
                " && github.event.pull_request.head.repo.full_name == github.repository && startsWith(github.head_ref, 'train/'))")
        assert skip in str(j[GATE]["if"]), "the gate's merge-train skip clause"
        j[GATE]["if"] = str(j[GATE]["if"]).replace(skip, "")
    def train_inverted(j: dict) -> None:
        for st in j[GATE]["steps"]:
            if st.get("name") == STEP:
                st["run"] = st["run"].replace('[ "$TRAIN" != true ]', '[ "$TRAIN" = true ]')
    def docs_always(j: dict) -> None:
        for st in j[GATE]["steps"]:
            if "env" in st and "DOCS_ONLY" in st["env"]:
                st["env"]["DOCS_ONLY"] = "${{ true }}"
    fc = "feature-combos-pr"
    mutants = {
        "the gate step judges lanes and passes trains": (train_inverted, f"{GATE} step: train, a heavy job failed passes (exit 0)"),
        "the gate step always allows the docs-only skips": (docs_always, f"{GATE} step: train, a heavy job skipped passes (exit 0)"),
        "a Linux heavy job keeps its train-only clause": (keeps_clause("linux-keychain", CLAUSE), "linux-keychain: code PR skips"),
        "a Windows job keeps its train-or-label clause": (keeps_clause("windows-shards", LABEL_CLAUSE), "windows-shards: code PR skips"),
        "a fork's train branch counts as a train": (forks_count, f"{GATE} step: fork train branch, heavy jobs skipped fails (exit 1)"),
        "the gate stops waiting for a heavy job": (
            gate_forgets("linux-keychain"), f"{GATE}: needs {sorted((HEAVY | {'scope'}) - {'linux-keychain'})}, not every heavy job plus scope"),
        "the gate stops waiting for feature combinations": (
            gate_forgets(fc), f"{GATE}: needs {sorted((HEAVY | {'scope'}) - {fc})}, not every heavy job plus scope"),
        "a same-repo train runs the gate again": (train_runs_gate_again, f"{GATE}: code train with success needs runs"),
        "a docs-only train may not skip feature combinations": (
            docs_allowance_drops(fc), f"{GATE} step: docs-only train, docs-only skips fails (exit 1)"),
    }
    for label, (mutate, expected) in mutants.items():
        mutated = copy.deepcopy(jobs)
        try:
            mutate(mutated)
        except KeyError as missing:
            errors.append(f"self-test: '{label}' could not be applied: no {missing}")
            continue
        if expected not in heavy_errors(mutated) + gate_errors(mutated) + gate_step_errors(mutated):
            errors.append(f"self-test: '{label}' was not caught by: {expected}")
    # The verdict itself mutated: check_needs.py taking any result of an
    # allowed job as a skip must fail the docs-only failure row.
    with tempfile.TemporaryDirectory() as tree:
        ci = Path(tree, "scripts", "ci")
        ci.mkdir(parents=True)
        text = (ROOT / "scripts/ci/check_needs.py").read_text()
        broken = text.replace('not (result == "skipped" and job in skippable)', "not (job in skippable)")
        expected = f"{GATE} step: docs-only train, a docs-skipped job failed passes (exit 0)"
        if broken == text:
            errors.append("self-test: check_needs.py's allowance line was not found to mutate")
        else:
            (ci / "check_needs.py").write_text(broken)
            if expected not in gate_step_errors(jobs, Path(tree)):
                errors.append(f"self-test: an allowance for any result was not caught by: {expected}")
    for e in errors:
        print(f"heavy-gating: {e}", file=sys.stderr)
    if not errors:
        print(f"heavy-gating: {len(HEAVY)} heavy jobs and {GATE} route {len(contexts())} contexts as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
