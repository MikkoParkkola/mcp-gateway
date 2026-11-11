#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The four roll-ups skip on a merge train, and only there.

`Tests`, `macOS check`, `Windows check` and `Heavy checks (merge train)` only fold
their shards' results. On a same-repo `train/` pull request into the release line
merge-train judges those needs itself, from the base copy of this workflow, so the
roll-ups skip there instead of queueing for a runner. Everywhere else each roll-up
must route exactly as it did before the skip was added: its `if:` is its earlier
condition plus one exact clause, and the two agree in every other context (a
roll-up some context skips today still skips there; "unchanged" is the same
answer, not "runs"). Each verdict step keeps its expected ids as data
(ROLLUP_EXPECTS) and Heavy checks its docs-only allowance (DOCS_ONLY_SKIPPABLE),
because merge-train reads both from the base ci.yml.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_docs_only_gating import ROOT, as_train, ctx, runs  # noqa: E402

ROLLUPS = ("test", "macos-check", "windows-check", "heavy-gate")
SKIP = (" && !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
        " && github.event.pull_request.head.repo.full_name == github.repository"
        " && startsWith(github.head_ref, 'train/'))")


def contexts() -> dict[str, dict]:
    """Every context but the one the skip is for."""
    def event(name: str, ref: str) -> dict:
        c = ctx(name, "success", "false")
        c["github"]["ref"] = ref
        return c
    labelled = ctx("pull_request", "success", "false")
    labelled["github"]["event"]["pull_request"]["labels"] = [{"name": "os-sensitive"}]
    train_into_main = as_train(ctx("pull_request", "success", "false"))
    train_into_main["github"]["base_ref"] = "main"
    return {
        "lane PR": ctx("pull_request", "success", "false"),
        "docs-only lane PR": ctx("pull_request", "success", "true"),
        "os-sensitive lane PR": labelled,
        "fork PR with head train/x": as_train(ctx("pull_request", "success", "false"), head="train/x", repo="fork/x"),
        "same-repo train into main": train_into_main,
        "same-repo throwaway PR": as_train(ctx("pull_request", "success", "false"), head="throwaway/x"),
        "push to the release line": event("push", "refs/heads/docs/ranking-1-release-line"),
        "push to main": event("push", "refs/heads/main"),
        "release tag": event("push", "refs/tags/v4.0.0"),
    }


def with_needs(job: dict, c: dict, result: str) -> dict:
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    return dict(c, needs=dict(c["needs"], **{n: {"result": result, "outputs": {}} for n in needs if n != "scope"}))


def errors_for(jobs: dict) -> list[str]:
    errors = []
    for rid in ROLLUPS:
        job = jobs.get(rid)
        if job is None:
            errors.append(f"{rid}: missing from ci.yml"); continue
        cond = str(job.get("if", ""))
        if not cond.endswith(SKIP + " }}"):
            errors.append(f"{rid}: its if does not end in the exact merge-train skip clause"); continue
        before = dict(job, **{"if": cond[: -len(SKIP + " }}")] + " }}"})
        for label, c in contexts().items():
            for result in ("success", "failure", "skipped"):
                cc = with_needs(job, c, result)
                if runs(job, cc) != runs(before, cc):
                    errors.append(f"{rid}: {label} with {result} needs routes differently than before the skip")
        train = as_train(ctx("pull_request", "success", "false"))
        for result in ("success", "failure", "skipped"):
            if runs(job, with_needs(job, train, result)):
                errors.append(f"{rid}: a same-repo train into the release line with {result} needs runs it")
        envs = [st.get("env") or {} for st in job.get("steps", []) if "check_needs.py" in str(st.get("run", ""))]
        if len(envs) != 1 or not str(envs[0].get("ROLLUP_EXPECTS", "")).split():
            errors.append(f"{rid}: its verdict step lacks ROLLUP_EXPECTS")
        if rid == "heavy-gate" and (len(envs) != 1 or not str(envs[0].get("DOCS_ONLY_SKIPPABLE", ""))):
            errors.append(f"{rid}: its verdict step lacks DOCS_ONLY_SKIPPABLE")
    return errors


def main() -> int:
    jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
    errors = errors_for(jobs)
    # Each mutant must be caught.
    def drop_skip(j):
        j["test"]["if"] = str(j["test"]["if"]).replace(SKIP, "")
    def fork_trains_skip(j):
        j["windows-check"]["if"] = str(j["windows-check"]["if"]).replace(
            " && github.event.pull_request.head.repo.full_name == github.repository && startsWith(github.head_ref, 'train/'))",
            " && startsWith(github.head_ref, 'train/'))")
    def no_expects(j):
        next(st for st in j["macos-check"]["steps"] if "check_needs.py" in str(st.get("run", "")))["env"].pop("ROLLUP_EXPECTS")
    def lane_skips(j):
        j["heavy-gate"]["if"] = str(j["heavy-gate"]["if"]).replace("startsWith(github.head_ref, 'train/'))", "true)")
    for name, mutate in {"skip clause dropped": drop_skip, "a fork's train/x skips": fork_trains_skip,
                         "ROLLUP_EXPECTS dropped": no_expects, "the skip catches lanes": lane_skips}.items():
        j = copy.deepcopy(jobs)
        mutate(j)
        if not errors_for(j):
            errors.append(f"self-test: mutant '{name}' was not caught")
    for e in errors:
        print(f"rollup-skip: {e}", file=sys.stderr)
    if not errors:
        print(f"rollup-skip: {len(ROLLUPS)} roll-ups skip only on a merge train; {len(contexts())} other contexts unchanged")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
