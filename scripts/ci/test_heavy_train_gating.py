#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Heavy jobs run on a pull request into the release line only for a merge train.

A lane pull request into the release line skips HEAVY; the train pull request
(a `train/` branch in this repository) runs them, and the `heavy-gate` job
("Heavy checks (merge train)") fails the train unless every one succeeded.
Every other event (a pull request into another base, a push, a tag, a
dispatch) routes each heavy job exactly as it would without the train clause.

The merge train refuses a train pull request whose needed checks did not pass,
and every lane pull request passes the gate, so the gate is needed on every
train: a heavy job skipped or red there, or a gate skipped there, stops it.
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_docs_only_gating import HEAVY_GATE, HEAVY_TRAIN, ROOT, SKIPPED, as_train, ctx, runs  # noqa: E402

HEAVY = HEAVY_TRAIN
# Skipped on a docs-only change by the docs-only rule, train or not.
DOCS_SKIPPED = HEAVY & SKIPPED
GATE = HEAVY_GATE
GATE_NAME = "Heavy checks (merge train)"
CLAUSE = (" && !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
          " && !(startsWith(github.head_ref, 'train/')"
          " && github.event.pull_request.head.repo.full_name == github.repository))")


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


def heavy_errors(jobs: dict, original: dict | None = None) -> list[str]:
    """`original` is the workflow before a self-test mutation: its condition
    without the clause is what every non-lane event must still see."""
    original = original or jobs
    errors = [f"HEAVY names a job ci.yml lacks: {j}" for j in sorted(HEAVY - set(jobs))]
    for job in sorted(HEAVY & set(jobs)):
        cond = str(jobs[job].get("if", ""))
        if CLAUSE not in cond:
            errors.append(f"{job}: its if lacks the train clause")
        today = dict(jobs[job], **{"if": str(original[job].get("if", "")).replace(CLAUSE, "")})
        for label, (c, lane) in contexts().items():
            c = with_needs(jobs[job], c, "success")
            got, was = runs(jobs[job], c), runs(today, c)
            if lane and got:
                errors.append(f"{job}: {label} runs")
            if not lane and got != was:
                errors.append(f"{job}: {label} {'runs' if got else 'skips'}, unlike without the clause")
        # On a code train every heavy job runs, and on a docs-only train every
        # one the docs-only rule does not skip: the train is where they gate.
        for label, docs in (("code train", "false"), ("docs-only train", "true")):
            c = with_needs(jobs[job], as_train(ctx("pull_request", "success", docs)), "success")
            want = not (docs == "true" and job in DOCS_SKIPPED)
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
    for job in sorted(HEAVY):
        if job not in run:
            errors.append(f"{GATE}: its verdict does not name {job}")
    if "check_needs.py" not in run:
        errors.append(f"{GATE}: its verdict does not use check_needs.py")
    allowed = re.search(r"--allow-skipped (\S+?)\)", run)
    if not allowed or set(allowed.group(1).split(",")) != DOCS_SKIPPED:
        errors.append(f"{GATE}: --allow-skipped must name exactly {sorted(DOCS_SKIPPED)}")
    if "${{" in run:
        errors.append(f"{GATE}: a step interpolates an expression into its script; pass it through env")
    # It runs, whatever its needs did, on every pull request into the release
    # line but a throwaway one, and on nothing else.
    want = {
        "code PR": True, "docs-only PR": True, "scope failed on a PR": True,
        "train branch from a fork": True, "a branch merely containing train/": True,
        "same-repo throwaway PR": False, "code train": True, "docs-only train": True,
        "scope failed on a train": True, "PR into main": False, "train into main": False,
        "push to main": False, "release-line push": False, "release tag": False,
        "workflow dispatch": False,
    }
    for label, (c, _) in contexts().items():
        for result in ("success", "skipped", "failure", "cancelled"):
            if runs(gate, with_needs(gate, c, result)) != want[label]:
                errors.append(f"{GATE}: {label} with {result} needs {'skips' if want[label] else 'runs'}")
    return errors


def main() -> int:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    errors = heavy_errors(jobs) + gate_errors(jobs)
    # Each mutant is caught by the case named beside it.
    def drop_clause(j: dict) -> None:
        j["kani"]["if"] = str(j["kani"]["if"]).replace(CLAUSE, "")
    def trains_skip_too(j: dict) -> None:
        j["windows-shards"]["if"] = str(j["windows-shards"]["if"]).replace(CLAUSE, CLAUSE.replace(" && !(startsWith", " && (startsWith"))
    def forks_count(j: dict) -> None:
        j["release-script-tests"]["if"] = str(j["release-script-tests"]["if"]).replace(
            CLAUSE, CLAUSE.replace(" && github.event.pull_request.head.repo.full_name == github.repository))", "))"))
    def gate_forgets(j: dict) -> None:
        j[GATE]["needs"] = sorted((HEAVY | {"scope"}) - {"linux-keychain"})
    mutants = {
        "a heavy job loses its train clause": (drop_clause, "kani: its if lacks the train clause"),
        "the clause skips trains too": (trains_skip_too, "windows-shards: code train skips"),
        "a fork's train branch counts as a train": (
            forks_count, "release-script-tests: train branch from a fork runs"),
        "the gate stops waiting for a heavy job": (
            gate_forgets, f"{GATE}: needs {sorted((HEAVY | {'scope'}) - {'linux-keychain'})}, not every heavy job plus scope"),
    }
    for label, (mutate, expected) in mutants.items():
        mutated = copy.deepcopy(jobs)
        try:
            mutate(mutated)
        except KeyError as missing:
            errors.append(f"self-test: '{label}' could not be applied: no {missing}")
            continue
        if expected not in heavy_errors(mutated, jobs) + gate_errors(mutated):
            errors.append(f"self-test: '{label}' was not caught by: {expected}")
    for e in errors:
        print(f"heavy-gating: {e}", file=sys.stderr)
    if not errors:
        print(f"heavy-gating: {len(HEAVY)} heavy jobs and {GATE} route {len(contexts())} contexts as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
