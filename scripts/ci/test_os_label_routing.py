#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The `os-sensitive` label runs the train's macOS jobs on a lane pull request.

A lane pull request into the release line runs the Windows jobs itself and skips
the macOS ones; only the merge train runs macOS. With the `os-sensitive` label,
the lane runs the train's own macOS jobs (LABEL_JOBS) too, as the train would for
the same change,
and routes every other job exactly as without the label. The label changes
nothing on any other pull request: a train, a throwaway, a pull request into
another base. GitHub compares the label case-insensitively, as an exact name.

The label is read from the event payload, so it counts from the first push (or
reopen) after it is applied; CONTRIBUTING.md says so.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_docs_only_gating import ROOT, as_train, ctx, simulate as _simulate  # noqa: E402
from test_throwaway_routing import evaluate  # noqa: E402
from test_os_shards import LABEL, LABELLED_LEGS, MATRIX  # noqa: E402

# Windows runs on every lane without the label (test_heavy_train_gating.py).
LABEL_JOBS = {"macos-shards", "macos-check"}
# A labelled lane runs macOS's lib shard only: about two macOS runners serve every train.
LABELLED_MACOS = LABELLED_LEGS["macos"]


def simulate(jobs: dict, c: dict) -> set[str]:
    """Routing with the context's own scope decision (docs-only, failed) kept."""
    return _simulate(jobs, c, keep_scope=True)


def labelled(c: dict, *names: str) -> dict:
    c = copy.deepcopy(c)
    pr = c["github"].setdefault("event", {}).setdefault("pull_request", {})
    pr["labels"] = [{"name": n} for n in names]
    return c


def contexts() -> dict[str, tuple[dict, dict | None]]:
    """Each labelled case and, for a labelled lane, the train case its OS jobs follow
    (None: the label must change nothing)."""
    lane = ctx("pull_request", "success", "false")
    docs = ctx("pull_request", "success", "true")
    failed = ctx("pull_request", "failure", None)
    fork = as_train(ctx("pull_request", "success", "false"), head="feature/x", repo="fork/x")
    into_main = ctx("pull_request", "success", "false")
    into_main["github"]["base_ref"] = "main"
    return {
        "lane PR": (lane, as_train(copy.deepcopy(lane))),
        "lane PR, label in other case": (lane, as_train(copy.deepcopy(lane))),
        "docs-only lane PR": (docs, as_train(copy.deepcopy(docs))),
        "lane PR whose scope failed": (failed, as_train(copy.deepcopy(failed))),
        "lane PR from a fork": (fork, as_train(copy.deepcopy(lane))),
        "train PR": (as_train(copy.deepcopy(lane)), None),
        "throwaway PR": (as_train(copy.deepcopy(lane), head="throwaway/x"), None),
        "PR into main": (into_main, None),
    }


def routing_errors(jobs: dict) -> list[str]:
    errors = []
    for case, (base, train) in contexts().items():
        name = LABEL.upper() if "other case" in case else LABEL
        unlabelled = simulate(jobs, base)
        got = simulate(jobs, labelled(base, name))
        if train is None:
            if got != unlabelled:
                errors.append(f"{case}: the label changes {sorted(got ^ unlabelled)}")
            continue
        want = (unlabelled - LABEL_JOBS) | (simulate(jobs, train) & LABEL_JOBS)
        # On a train the macOS aggregate is skipped (merge-train judges its shards from the base rules); a
        # labelled lane has no merge-train behind it, so it runs the aggregate with the train's shards.
        if "macos-shards" in want:
            want |= {"macos-check"}
        if got != want:
            errors.append(f"{case}: labelled runs {sorted(got - want)} it should not, "
                          f"skips {sorted(want - got)} it should run")
    # Another label, or one that merely starts with this one, is no label.
    lane = ctx("pull_request", "success", "false")
    for other in ("needs-review", LABEL + "-x"):
        if simulate(jobs, labelled(lane, other)) != simulate(jobs, lane):
            errors.append(f"lane PR with label {other!r}: routed as if labelled")
    return errors


def matrix_errors(jobs: dict) -> list[str]:
    """On a labelled lane the macOS matrix resolves to LABELLED_MACOS; elsewhere to
    the train's list, the same as the Windows matrix, which never narrows."""
    errors = []
    for job, labelled_want in (("macos-shards", LABELLED_MACOS), ("windows-shards", None)):
        value = jobs.get(job, {}).get("strategy", {}).get("matrix", {}).get("shard")
        if isinstance(value, list):
            if labelled_want is not None:
                errors.append(f"{job}: a static matrix {value} runs every shard on a labelled lane, "
                              f"not {labelled_want}")
            continue
        m = MATRIX.match(str(value or ""))
        if not m:
            errors.append(f"{job}: matrix {value!r} is neither a list nor fromJSON(cond && A || B)")
            continue
        a, b = json.loads(m.group("a")), json.loads(m.group("b"))
        if labelled_want is None:
            errors.append(f"{job}: narrows its matrix to {a} on a labelled lane; it runs every shard")
        elif a != labelled_want:
            errors.append(f"{job}: a labelled lane runs {a}, not {labelled_want}")
        if LABEL not in m.group("cond"):
            errors.append(f"{job}: the matrix condition does not test the label")
        # The condition picks the labelled list on a labelled lane only: a labelled
        # train, or any unlabelled run, keeps every shard (B, test_os_shards.py's).
        lane = ctx("pull_request", "success", "false")
        for case, c, want in (
            ("labelled lane", labelled(lane, LABEL), True),
            ("labelled fork lane", labelled(as_train(copy.deepcopy(lane), head="feature/x", repo="fork/x"), LABEL), True),
            ("labelled train", labelled(as_train(copy.deepcopy(lane)), LABEL), False),
            ("unlabelled lane", lane, False),
            ("unlabelled train", as_train(copy.deepcopy(lane)), False),
        ):
            if bool(evaluate(m.group("cond"), c)) != want:
                errors.append(f"{job}: a {case} runs {a if not want else b}, not {a if want else b}")
    return errors


def evaluator_errors() -> list[str]:
    """The evaluator's label reading, apart from any workflow."""
    expr = f"contains(github.event.pull_request.labels.*.name, '{LABEL}')"
    cases = {
        "no labels": ({"labels": []}, False),
        "no labels key": ({}, False),
        "several labels": ({"labels": [{"name": "a"}, {"name": LABEL}, {"name": "b"}]}, True),
        "label in other case": ({"labels": [{"name": LABEL.title()}]}, True),
        "label prefix only": ({"labels": [{"name": LABEL + "-x"}]}, False),
    }
    errors = [f"evaluator: {case} reads {not want}"
              for case, (pr, want) in cases.items()
              if bool(evaluate(expr, {"github": {"event": {"pull_request": pr}}, "_status": {}})) != want]
    if evaluate("contains(o.*, 'v')", {"o": {"k": "v"}, "_status": {}}) is not True:
        errors.append("evaluator: an object projection does not list its values")
    return errors


def self_test(jobs: dict) -> list[str]:
    """Planted mistakes each fail: the label clause on a job outside LABEL_JOBS, a
    label job that ignores it, a matrix that narrows labelled trains too, and a
    label that skips docs-only changes where the train runs them."""
    missing = sorted({"feature-combos-pr", "macos-check", "macos-shards"} - set(jobs))
    if missing:
        return [f"self-test: ci.yml lacks {missing}, which the planted mistakes need"]
    errors = []
    narrow_trains = copy.deepcopy(jobs)
    shard = narrow_trains["macos-shards"]["strategy"]["matrix"]
    no_train_exclusion = str(shard["shard"]).replace(
        " && !(startsWith(github.head_ref, 'train/') && github.event.pull_request.head.repo.full_name == github.repository)", "")
    if no_train_exclusion == str(shard["shard"]):
        errors.append("self-test: the matrix's train exclusion was not found to remove")
    else:
        shard["shard"] = no_train_exclusion
        if not any("labelled train runs" in e for e in matrix_errors(narrow_trains)):
            errors.append("self-test: a matrix narrowing labelled trains was not caught")
    docs_skip = copy.deepcopy(jobs)
    alt = f"contains(github.event.pull_request.labels.*.name, '{LABEL}'))"
    job = docs_skip["macos-shards"]
    if alt not in str(job["if"]):
        errors.append("self-test: the macos-shards label alternative was not found")
    else:
        job["needs"] = ["scope"]
        job["if"] = str(job["if"]).replace(alt, alt[:-1] + " && needs.scope.outputs.docs_only != 'true')")
        if not any(e.startswith("docs-only lane PR:") for e in routing_errors(docs_skip)):
            errors.append("self-test: a label that skips docs-only changes was not caught")
    clause = (f" || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
              f" && contains(github.event.pull_request.labels.*.name, '{LABEL}'))")
    widened = copy.deepcopy(jobs)
    # Feature combinations skip a docs-only lane; the label must not run them there.
    widened["feature-combos-pr"]["if"] = (
        "${{ (" + str(widened["feature-combos-pr"]["if"]).strip()[3:-2].strip() + ")" + clause + " }}")
    if not any(e.startswith("docs-only lane PR:") and "feature-combos-pr" in e for e in routing_errors(widened)):
        errors.append("self-test: the label clause on feature-combos-pr was not caught")
    narrowed = copy.deepcopy(jobs)
    narrowed["macos-check"]["if"] = str(jobs["macos-check"]["if"]).replace(f"'{LABEL}'", "'other'")
    if routing_errors(narrowed) == routing_errors(jobs):
        errors.append("self-test: macos-check ignoring the label was not caught")
    return errors


def main() -> int:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    jobs = yaml.safe_load(text)["jobs"]
    errors = evaluator_errors() + routing_errors(jobs) + matrix_errors(jobs) + self_test(jobs)
    for e in errors:
        print(f"os-label: {e}", file=sys.stderr)
    if not errors:
        print(f"os-label: {len(LABEL_JOBS)} macOS jobs follow the train on a labelled lane, "
              f"{len(contexts())} contexts as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
