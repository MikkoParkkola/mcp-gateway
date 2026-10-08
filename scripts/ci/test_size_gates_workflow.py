#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shape checks for .github/workflows/size-gates.yml (MIK-8163).

The PR-time size gates in ci.yml see each PR against the base it was tested
on. Two PRs that each pass can merge into a file over its ceiling; nothing
runs ci.yml on a push to the release line. size-gates.yml runs both gates on
every such push. This test fails if the workflow stops doing that: a trigger,
a step, the pin or a property that keeps every run is removed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/size-gates.yml"
CI = ROOT / ".github/workflows/ci.yml"
RELEASE_LINE = "docs/ranking-1-release-line"
COMMANDS = (
    "python3 scripts/dev/test_check_file_size.py",
    "python3 scripts/dev/check-file-size.py",
    "scripts/ci/check-loc-ceiling.sh --self-test",
    "scripts/ci/check-loc-ceiling.sh",
)


def checkout_pin(doc: dict) -> set[str]:
    return {
        step["uses"]
        for job in doc["jobs"].values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/checkout@")
    }


def problems(doc: dict, ci: dict) -> list[str]:
    """Every way `doc` falls short of a post-merge size gate; empty when sound."""
    out = []
    on = doc.get(True) or doc.get("on") or {}  # PyYAML reads `on` as True
    events = {on} if isinstance(on, str) else set(on)
    if any(str(e).startswith("pull_request") for e in events):
        out.append("has a pull_request trigger: it must be post-merge only")
    push = on.get("push") if isinstance(on, dict) else None
    if not isinstance(push, dict) or push != {"branches": [RELEASE_LINE]}:
        # Exactly this branch, nothing else: a path filter, an exclusion
        # pattern or a tag list can each stop a release-line push from running.
        out.append(f"push trigger is not exactly branches: [{RELEASE_LINE}]")
    if "concurrency" in doc or any("concurrency" in j for j in doc["jobs"].values()):
        out.append("has a concurrency group: a later merge would cancel an earlier one's run")
    if doc.get("permissions") != {"contents": "read"}:
        out.append("permissions are not exactly contents: read")
    runs = []
    for name, job in doc["jobs"].items():
        if "if" in job or job.get("continue-on-error"):
            out.append(f"job {name} can be skipped or ignored")
        for step in job.get("steps", []):
            if "if" in step or step.get("continue-on-error"):
                out.append(f"step {step.get('name', step)} can be skipped or ignored")
            run = step.get("run")
            if run is not None:
                if "|| true" in run or "set +e" in run:
                    out.append(f"step {step.get('name')} swallows its exit status")
                runs.append(run.strip())
    for command in COMMANDS:
        if command not in runs:
            out.append(f"no step runs exactly `{command}`")
    if checkout_pin(doc) != checkout_pin(ci) or not checkout_pin(doc):
        out.append("checkout is not pinned to the same SHA as ci.yml")
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            ref = (step.get("with") or {}).get("ref")
            if str(step.get("uses", "")).startswith("actions/checkout@") and ref not in (None, "${{ github.sha }}"):
                out.append("checkout overrides ref: a queued run would judge another commit than its merge")
    return out


def main() -> int:
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    if not WORKFLOW.exists():
        print(f"FAIL {WORKFLOW.relative_to(ROOT)} does not exist")
        return 1
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    errors = problems(doc, ci)
    # The check must be able to fail: each mutation of the real file is caught.
    def on(d):
        return d[True] if True in d else d["on"]

    mutations = {
        "pull_request added": lambda d: on(d).update({"pull_request": {}}),
        "push trigger dropped": lambda d: on(d).pop("push"),
        "branch exclusion added": lambda d: on(d)["push"]["branches"].append("!docs/**"),
        "path filter added": lambda d: on(d)["push"].update({"paths": ["src/**"]}),
        "checkout ref overridden": lambda d: next(iter(d["jobs"].values()))["steps"][0].update(
            {"with": {"ref": "docs/ranking-1-release-line"}}
        ),
        "concurrency added": lambda d: d.update({"concurrency": {"group": "x"}}),
        "permissions widened": lambda d: d.update({"permissions": {"contents": "write"}}),
        "gate step dropped": lambda d: next(iter(d["jobs"].values()))["steps"].pop(),
        "step made optional": lambda d: next(iter(d["jobs"].values()))["steps"][-1].update({"continue-on-error": True}),
        "status swallowed": lambda d: next(iter(d["jobs"].values()))["steps"][-1].update(
            {"run": next(iter(d["jobs"].values()))["steps"][-1]["run"] + " || true"}
        ),
        "job made conditional": lambda d: next(iter(d["jobs"].values())).update({"if": "false"}),
    }
    for label, mutate in mutations.items():
        mutated = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        mutate(mutated)
        if not problems(mutated, ci):
            errors.append(f"self-test: '{label}' was not caught")
    for e in errors:
        print(f"FAIL size-gates.yml {e}")
    if not errors:
        print("size-gates.yml runs both size gates on every release-line merge")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
