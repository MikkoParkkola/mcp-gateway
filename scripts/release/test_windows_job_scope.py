# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Windows coverage is counted only for what the Windows suite runs.

The suite (the `windows-shards` and `windows-lib-shards` jobs, scripts/ci/shard_tests.py)
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


def windows_job(name: str = "windows-shards") -> str:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    m = re.search(rf"^  {name}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.S | re.M)
    assert m, f"{name} job not found"
    return m.group(1)


def shard_table():
    spec = importlib.util.spec_from_file_location("shard_tests", ROOT / "scripts/ci/shard_tests.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_job_runs_every_test_target_skipping_only_the_full_burst():
    # The suite is sharded: two int shards that compile what they run, and four lib legs
    # running one shared exe. Together they make up
    # `cargo test --all-features --tests --no-fail-fast -- --skip mik_7479_full_burst`.
    job, lib_job = windows_job(), windows_job("windows-lib-shards")
    # Exact match on purpose: any change to the command must revisit this guard.
    assert "python scripts/ci/shard_tests.py run windows ${{ matrix.shard }}" in job
    assert "shard: [int-a, int-b]" in job
    assert "shard_tests.py run-prebuilt windows ${{ matrix.shard }}" in lib_job
    assert "shard: [lib-a, lib-b, lib-c, lib-d]" in lib_job
    for text in (job, lib_job):
        assert "cargo test" not in text, "a suite command outside the runner"
    st = shard_table()
    assert st.BASE == ["test", "--all-features", "--no-fail-fast"]
    shards = st.SHARDS["windows"]
    assert sorted(shards) == ["int-a", "int-b", "lib-a", "lib-b", "lib-c", "lib-d"], sorted(shards)
    cmds = {name: [(a, t) for _, a, t, _ in steps] for name, steps in shards.items()}
    assert cmds == {
        "lib-a": [(["--lib"], ["gateway::router::", "gateway::server::"])],
        "lib-d": [(["--lib"], ["gateway::", *FIRST])],
        "lib-c": [(["--lib"], ["security::", *FIRST, "--skip", "gateway::"])],
        "lib-b": [(["--lib"], [*FIRST, "--skip", "gateway::", "--skip", "security::"])],
        "int-a": [(["--bins", "--test", "[a-l]*"], [])],
        "int-b": [(["--test", "[!a-l]*"], [])],
    }, cmds
    # Any spelling of a skip counts; only the ruled one may appear, once.
    assert st.SKIPS["windows"] == ["--skip", "mik_7479_full_burst"], st.SKIPS["windows"]


# lib-a's two gateway:: modules, which every later leg skips.
FIRST = ["--skip", "gateway::router::", "--skip", "gateway::server::"]


def test_the_privileged_rows_run_their_script_under_pwsh():
    """The privileged rows moved from an inline step to scripts/ci/windows-privileged-rows.ps1: exactly one
    workflow step runs it, in pwsh, on lib-a, and the script stops on the first failing cmdlet."""
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert text.count("windows-privileged-rows.ps1") == 1, "the script is run by more or fewer than one step"
    step = re.search(r"^      - name: Privileged owner-only rows\n(.*?)(?=^      - |\Z)",
                     windows_job("windows-lib-shards"), re.S | re.M)
    assert step, "windows-lib-shards has no Privileged owner-only rows step"
    body = step.group(1)
    assert "        shell: pwsh\n" in body, body
    assert "matrix.shard == 'lib-a'" in body, body
    assert re.search(r"^        run: scripts/ci/windows-privileged-rows\.ps1 ", body, re.M), body
    lines = (ROOT / "scripts/ci/windows-privileged-rows.ps1").read_text().splitlines()
    code = [l.strip() for l in lines if l.strip() and not l.lstrip().startswith("#")]
    assert code[0].startswith("param("), code[:2]
    assert code[1] == "$ErrorActionPreference = 'Stop'", code[:2]
    # The rows run from the checkout the exe was built for, and fewer than five passing is a failure; the count
    # comes from the harness's last line-anchored summary, never a line a test printed.
    assert any(l.startswith("$env:CARGO_MANIFEST_DIR = ") for l in code), "the manifest dir is not set"
    floor = [l for l in code if "-lt 5" in l]
    assert len(floor) == 1 and "exit 1" in floor[0], floor
    assert any("(?m)^test result: ok" in l for l in code), "the count is not anchored to the harness summary"
    assert any("$summaries.Count - 1" in l for l in code), "the count does not take the last summary"


def libtest_selects(name, args):
    """libtest's rule: positive filters (any substring) unless none, then no --skip substring."""
    filters, skips, it = [], [], iter(args)
    for a in it:
        if a == "--skip":
            skips.append(next(it))
        else:
            filters.append(a)
    return (not filters or any(f in name for f in filters)) and not any(s in name for s in skips)


def test_the_windows_lib_shards_split_the_library_exactly_once():
    st = shard_table()
    lib = {n: steps[0][2] for n, steps in st.SHARDS["windows"].items() if n.startswith("lib-")}
    assert sorted(lib) == ["lib-a", "lib-b", "lib-c", "lib-d"], sorted(lib)
    names = [
        "gateway::server::tests::a", "gateway::security::x", "security::firewall::t", "capability::parser::t",
        "events::bus::t", "backend::http::t", "transport::stdio::t", "oauth::storage::t",
        "config::tests::t", "config_reload::events::t", "personal_accounts::t", "protocol::t", "trust::t",
        "cost_accounting::t", "x::transport::y", "eventsource::t", "security::transport::tests::x",
    ]
    for name in names:
        hits = [n for n, args in lib.items() if libtest_selects(name, args)]
        assert len(hits) == 1, f"{name} runs in {hits}, not exactly one Windows lib shard"


def test_no_met_criterion_cites_windows_execution_evidence():
    data = json.loads((ROOT / "docs/requirements/RELEASE-4.0.0-scope-status.json").read_text())
    for c in data["criteria"]:
        if c.get("status") != "met":
            continue
        for ev in c.get("evidence", []):
            assert "windows" not in ev.lower(), f"{c['id']} cites Windows evidence: {ev}"


if __name__ == "__main__":
    test_the_job_runs_every_test_target_skipping_only_the_full_burst()
    test_the_windows_lib_shards_split_the_library_exactly_once()
    test_the_privileged_rows_run_their_script_under_pwsh()
    test_no_met_criterion_cites_windows_execution_evidence()
    print("ok")
