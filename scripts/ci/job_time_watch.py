#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Warn when a shard job of this run used over 80% of its time limit.

A shard creeping toward its `timeout-minutes` is cut off mid-test one day,
taking the merge train with it. This warns (never fails: one slow runner
must not void a green train) for each job of `<job-key>`'s matrix past 80%
of its ci.yml limit, and names any job or run it cannot read.

  job_time_watch.py <job-key>     read this run attempt's jobs (needs gh,
                                  GH_TOKEN with actions: read)
  job_time_watch.py --self-test   check the rule against fixed jobs
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import yaml

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
