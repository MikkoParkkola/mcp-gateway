#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows W4 and W5: the lib test part checker (and its exact lists) and the orphan gate run on every pull request.

The union job's exact lists rest on both: the part checker refuses a test no part names, the orphan gate a test file
no module declares. A skipped gate reads as green, so neither step may carry an `if`, neither job may be scoped by the
docs-only decision, and neither workflow may filter pull requests by path."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
GATES = ("scripts/dev/test_parts.py check", "scripts/dev/check-orphan-test-modules.py")


def gate_sites(workflows: Path = WORKFLOWS):
    """(workflow file, workflow, job id, job, step) for every step that runs one of GATES."""
    for path in sorted(workflows.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps", []) if isinstance(job, dict) else []:
                if isinstance(step, dict) and any(g in str(step.get("run", "")) for g in GATES):
                    yield path.name, doc, job_id, job, step


def problems(workflows: Path = WORKFLOWS) -> list[str]:
    out, found = [], set()
    for file, doc, job_id, job, step in gate_sites(workflows):
        gate = next(g for g in GATES if g in str(step.get("run", "")))
        found.add(gate)
        where = f"{file}:{job_id} ({gate})"
        if "if" in step:
            out.append(f"{where}: the step carries if: {step['if']!r}")
        if "docs_only" in str(job.get("if", "")):
            out.append(f"{where}: the job is scoped by the docs-only decision")
        triggers = doc.get(True, doc.get("on")) or {}
        pr = triggers.get("pull_request") if isinstance(triggers, dict) else None
        if isinstance(pr, dict) and ("paths" in pr or "paths-ignore" in pr):
            out.append(f"{where}: the workflow filters pull requests by path")
    out += [f"no workflow step runs {g}" for g in GATES if g not in found]
    return out


class GatesRunEveryPullRequest(unittest.TestCase):
    def test_the_part_checker_and_the_orphan_gate_cannot_be_skipped(self):
        self.assertEqual(problems(), [])

    def test_each_way_to_skip_a_gate_is_caught(self):
        steps = "      - run: python3 scripts/dev/test_parts.py check\n      - run: python3 scripts/dev/check-orphan-test-modules.py\n"
        sound = f"on:\n  pull_request:\njobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"
        cases = {
            "sound": (sound, None),
            "an if on a gate step": (sound.replace("      - run: python3 scripts/dev/test_parts.py",
                                                   "      - if: github.event_name == 'push'\n        run: python3 scripts/dev/test_parts.py"), "carries if"),
            "a job scoped by the docs-only decision": (sound.replace("    runs-on:", "    if: needs.scope.outputs.docs_only != 'true'\n    runs-on:"), "docs-only"),
            "pull requests filtered by path": (sound.replace("  pull_request:\n", "  pull_request:\n    paths: ['src/**']\n"), "by path"),
            "a gate run by no workflow": (sound.replace("      - run: python3 scripts/dev/check-orphan-test-modules.py\n", ""), "no workflow step"),
        }
        for label, (text, want) in cases.items():
            with self.subTest(label), TemporaryDirectory() as tmp:
                (Path(tmp) / "ci.yml").write_text(text, encoding="utf-8")
                found = problems(Path(tmp))
                if want is None:
                    self.assertEqual(found, [])
                else:
                    self.assertTrue(any(want in f for f in found), found)


if __name__ == "__main__":
    unittest.main()
