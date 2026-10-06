# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Windows coverage is counted only for what the `windows-check` job runs.

The job runs every test target and skips one test by name: the MRTR.7b full
burst (MIK-7644), which runs in full on Linux in `mrtr7b-full-burst`, while the
194-call terminal-frame check stays on Windows. The ledger must not claim
Windows evidence beyond that. Any other `--skip` filter or a narrower target
list would silently shrink what "covered on Windows" means, so both fail here.
"""

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def windows_job() -> str:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    m = re.search(r"^  windows-check:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.S | re.M)
    assert m, "windows-check job not found"
    return m.group(1)


def test_the_job_runs_every_test_target_skipping_only_the_full_burst():
    job = windows_job()
    assert "cargo test --all-features --tests --no-fail-fast" in job
    # Exact match on purpose: any change to the command must revisit this guard.
    runs = [l for l in job.splitlines() if "cargo test" in l]
    # Any spelling of a skip counts (`--skip NAME`, `--skip=NAME`); only the
    # ruled one may appear, once.
    assert sum(l.count("--skip") for l in runs) == 1, runs
    assert any(re.search(r"--skip[ =]mik_7479_full_burst(\s|$)", l) for l in runs), runs


def test_no_met_criterion_cites_windows_execution_evidence():
    data = json.loads((ROOT / "docs/requirements/RELEASE-4.0.0-scope-status.json").read_text())
    for c in data["criteria"]:
        if c.get("status") != "met":
            continue
        for ev in c.get("evidence", []):
            assert "windows" not in ev.lower(), f"{c['id']} cites Windows evidence: {ev}"


if __name__ == "__main__":
    test_the_job_runs_every_test_target_skipping_only_the_full_burst()
    test_no_met_criterion_cites_windows_execution_evidence()
    print("ok")
