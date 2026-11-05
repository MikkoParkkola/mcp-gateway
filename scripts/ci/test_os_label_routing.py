#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The `os-sensitive` label runs the train's OS jobs on a lane pull request.

A lane pull request into the release line skips the Windows and macOS jobs; only
the merge train runs them. With the `os-sensitive` label, the lane runs the
train's own OS jobs (LABEL_JOBS) too, as the train would for the same change,
and routes every other job exactly as without the label. The label changes
nothing on any other pull request: a train, a throwaway, a pull request into
another base. GitHub compares the label case-insensitively, as an exact name.

The label is read from the event payload, so it counts from the first push (or
reopen) after it is applied; CONTRIBUTING.md says so.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_docs_only_gating import ROOT, as_train, ctx, simulate  # noqa: E402

LABEL = "os-sensitive"
LABEL_JOBS = {"windows-shards", "windows-clippy", "windows-check", "macos-shards", "macos-check"}
# A labelled lane runs macOS's lib shard only: about two macOS runners serve every train.
LABELLED_MACOS = ["lib"]
MATRIX = re.compile(
    r"^\$\{\{\s*fromjson\(\s*(?P<cond>.+?)\s*&&\s*'(?P<a>\[[^']*\])'\s*\|\|\s*'(?P<b>\[[^']*\])'\s*\)\s*\}\}$",
    re.IGNORECASE | re.DOTALL,
)


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
        del b  # the train list is test_os_shards.py's to check against shard_tests.py
    return errors


def self_test(jobs: dict) -> list[str]:
    """Planted mistakes each fail: the label clause on a sixth heavy job, and a label
    job that ignores it."""
    errors = []
    clause = (f" || (github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line'"
              f" && contains(github.event.pull_request.labels.*.name, '{LABEL}'))")
    widened = copy.deepcopy(jobs)
    if "kani" in widened:
        widened["kani"]["if"] = "${{ (" + str(widened["kani"]["if"]).strip()[3:-2].strip() + ")" + clause + " }}"
        if not any(e.startswith("lane PR:") and "kani" in e for e in routing_errors(widened)):
            errors.append("self-test: the label clause on kani was not caught")
    narrowed = copy.deepcopy(jobs)
    if "windows-check" in narrowed:
        narrowed["windows-check"]["if"] = jobs.get("windows-check", {}).get("if", "")
        narrowed["windows-check"]["if"] = str(narrowed["windows-check"]["if"]).replace(f"'{LABEL}'", "'other'")
        if routing_errors(narrowed) == routing_errors(jobs):
            errors.append("self-test: windows-check ignoring the label was not caught")
    return errors


def main() -> int:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    jobs = yaml.safe_load(text)["jobs"]
    errors = routing_errors(jobs) + matrix_errors(jobs) + self_test(jobs)
    for e in errors:
        print(f"os-label: {e}", file=sys.stderr)
    if not errors:
        print(f"os-label: {len(LABEL_JOBS)} OS jobs follow the train on a labelled lane, "
              f"{len(contexts())} contexts as expected")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
