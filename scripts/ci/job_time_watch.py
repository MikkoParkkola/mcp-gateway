#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Warn when a shard job of this run used over 80% of its time limit.

A shard that creeps toward its `timeout-minutes` gets cut off mid-test one
day, and takes the whole merge train with it. This prints a GitHub
`::warning::` for each job of `<job-key>`'s matrix whose wall clock passed
80% of that job's limit in .github/workflows/ci.yml, so the next one is
seen before it cuts a train off. It warns, never fails: failing would void
a green train for one slow runner. A job it cannot read is named in a
warning too, never skipped silently.

  job_time_watch.py <job-key>     read this run attempt's jobs (needs gh,
                                  GH_TOKEN with actions: read)
  job_time_watch.py --self-test   check the rule against fixed jobs
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHARE = 0.8


def minutes(job: dict) -> float | None:
    """Wall-clock minutes of a finished job, or None when it lacks a time."""
    try:
        start = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, AttributeError, ValueError):
        return None
    return (end - start).total_seconds() / 60


def warnings(jobs: list[dict], prefix: str, limit: float) -> list[str]:
    """One line per job named `prefix...` over SHARE of `limit` or unreadable."""
    out = []
    for job in jobs:
        name = job.get("name", "")
        if not name.startswith(prefix) or job.get("conclusion") == "skipped":
            continue
        took = minutes(job)
        if took is None:
            out.append(f"{name}: no start or end time, so its use of the {limit:g} min limit is unknown")
        elif took > SHARE * limit:
            out.append(f"{name}: took {took:.0f} of its {limit:g} min limit ({took / limit:.0%})")
    return out


def job_limit(key: str) -> tuple[str, float]:
    """(name prefix, timeout-minutes) of ci.yml job `key`."""
    import yaml  # here, not at the top: a failed PyYAML install is a warning, not a crash

    job = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"][key]
    return job["name"].split("${{")[0], float(job["timeout-minutes"])


def run(key: str) -> int:
    """Advisory: any failure to read ci.yml or the run is a warning, exit 0."""
    try:
        return watch(key)
    except Exception as error:  # noqa: BLE001 - warn-only by design
        print(f"::warning::{key}: the limit watch could not run, so no limit was watched: {error!r}"[:300])
        return 0


def watch(key: str) -> int:
    prefix, limit = job_limit(key)
    path = (f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
            f"/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}/jobs?per_page=100")
    got = subprocess.run(
        ["gh", "api", "--paginate", path, "--jq", ".jobs[]"], capture_output=True, text=True, timeout=120
    )
    if got.returncode != 0:
        print(f"::warning::{key}: could not read this run's jobs, so no limit was watched: {got.stderr.strip()[:200]}")
        return 0
    jobs = [json.loads(line) for line in got.stdout.splitlines() if line.strip()]
    if not any(j.get("name", "").startswith(prefix) for j in jobs):
        print(f"::warning::{key}: no job named {prefix!r} in this run, so no limit was watched")
    for line in warnings(jobs, prefix, limit):
        print(f"::warning::{line}")
    print(f"{key}: {len([j for j in jobs if j.get('name', '').startswith(prefix)])} jobs checked against "
          f"{SHARE:.0%} of {limit:g} min")
    return 0


def self_test() -> int:
    def job(name, start, end, conclusion="success"):
        return {"name": name, "started_at": start, "completed_at": end, "conclusion": conclusion}

    jobs = [
        job("macOS shard lib", "2026-11-02T20:00:00Z", "2026-11-02T22:01:00Z"),  # 121 of 150: over 80%
        job("macOS shard int", "2026-11-02T20:00:00Z", "2026-11-02T20:20:00Z"),  # 20: fine
        job("macOS shard x", "2026-11-02T20:00:00Z", None),  # still running or cut: unknown
        job("macOS shard y", None, None, "skipped"),  # skipped: not judged
        job("Linux shard lib-a", "2026-11-02T20:00:00Z", "2026-11-02T23:00:00Z"),  # another prefix
    ]
    got = warnings(jobs, "macOS shard ", 150)
    assert got == [
        "macOS shard lib: took 121 of its 150 min limit (81%)",
        "macOS shard x: no start or end time, so its use of the 150 min limit is unknown",
    ], got
    # Exactly 80% is not over it.
    assert warnings([job("macOS shard z", "2026-11-02T20:00:00Z", "2026-11-02T22:00:00Z")], "macOS shard ", 150) == []
    prefix, limit = job_limit("macos-shards")
    assert prefix == "macOS shard " and limit > 0, (prefix, limit)
    # Advisory: anything that goes wrong reading the run is a warning, exit 0.
    saved = {k: os.environ.pop(k, None) for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    try:
        assert run("macos-shards") == 0, "a run with no Actions environment did not exit 0"
        assert run("no-such-job") == 0, "a job key missing from ci.yml did not exit 0"
    finally:
        os.environ.update({k: v for k, v in saved.items() if v is not None})
    # Each way the gh read can go wrong is a named warning and exit 0.
    env = {"GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
    saved_env = {k: os.environ.get(k) for k in env}
    real_run = subprocess.run
    bounds: list = []

    def stubbed(behaviour) -> tuple[int, str]:
        def fake(*args, **kwargs):
            bounds.append(kwargs.get("timeout"))
            if behaviour == "timeout":
                raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))
            if behaviour == "nonzero":
                return subprocess.CompletedProcess(args[0], 1, "", "HTTP 502")
            return subprocess.CompletedProcess(args[0], 0, "{not json\n", "")
        subprocess.run = fake
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = run("macos-shards")
        finally:
            subprocess.run = real_run
        return rc, out.getvalue()

    os.environ.update(env)
    try:
        for behaviour, says in (
            ("timeout", "could not run, so no limit was watched: TimeoutExpired"),
            ("nonzero", "could not read this run's jobs, so no limit was watched: HTTP 502"),
            ("malformed", "could not run, so no limit was watched: JSONDecodeError"),
        ):
            rc, printed = stubbed(behaviour)
            assert rc == 0 and says in printed, (behaviour, rc, printed)
        # Every gh read is bounded, so a hung gh cannot hold the check.
        assert bounds and all(b for b in bounds), f"gh called without a timeout: {bounds}"
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    # PyYAML missing (its install failed): the script itself still exits 0.
    blocked = ("import sys, runpy; sys.modules['yaml'] = None; sys.argv = [sys.argv[1], 'macos-shards']; "
               "runpy.run_path(sys.argv[0], run_name='__main__')")
    got = real_run([sys.executable, "-I", "-c", blocked, __file__], capture_output=True, text=True, timeout=60)
    assert got.returncode == 0 and "could not run" in got.stdout and "ModuleNotFoundError" in got.stdout, (
        got.returncode, got.stdout, got.stderr[-300:])
    print("job_time_watch self-test: ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) == 1:
        return run(argv[0])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
