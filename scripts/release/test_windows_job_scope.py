# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Windows coverage is counted only for what the Windows suite runs.

The suite (the `windows-shards` job, scripts/ci/shard_tests.py, MIK-8482)
runs every test target and skips one test by name: the MRTR.7b full
burst (MIK-7644), which runs in full on Linux in `mrtr7b-full-burst`, while the
194-call terminal-frame check stays on Windows. The ledger must not claim
Windows evidence beyond that. Any other `--skip` filter or a narrower target
list would silently shrink what "covered on Windows" means, so both fail here.
"""

import importlib.util
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def windows_job() -> str:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    m = re.search(r"^  windows-shards:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.S | re.M)
    assert m, "windows-shards job not found"
    return m.group(1)


def shard_table():
    spec = importlib.util.spec_from_file_location("shard_tests", ROOT / "scripts/ci/shard_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_job_runs_every_test_target_skipping_only_the_full_burst():
    # Since MIK-8482 the suite is four shards; together they are exactly
    # `cargo test --all-features --tests --no-fail-fast -- --skip mik_7479_full_burst`.
    job = windows_job()
    # Exact match on purpose: any change to the command must revisit this guard.
    assert "python scripts/ci/shard_tests.py run windows ${{ matrix.shard }}" in job
    assert "shard: [lib-a, lib-b, int-a, int-b]" in job
    assert "cargo test" not in job.split("Privileged owner-only rows")[0], "a suite command outside the runner"
    st = shard_table()
    assert st.BASE == ["test", "--all-features", "--no-fail-fast"]
    shards = st.SHARDS["windows"]
    assert sorted(shards) == ["int-a", "int-b", "lib-a", "lib-b"], sorted(shards)
    cmds = {name: [(a, t) for _, a, t, _ in steps] for name, steps in shards.items()}
    assert cmds == {
        "lib-a": [(["--lib"], ["gateway::"])],
        "lib-b": [(["--lib"], ["--skip", "gateway::"])],
        "int-a": [(["--bins", "--test", "[a-l]*"], [])],
        "int-b": [(["--test", "[!a-l]*"], [])],
    }, cmds
    # Any spelling of a skip counts; only the ruled one may appear, once.
    assert st.SKIPS["windows"] == ["--skip", "mik_7479_full_burst"], st.SKIPS["windows"]


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
