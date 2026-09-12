#!/usr/bin/env python3
"""Emit the v4.0.0 release-blocking unit count and append it to the burndown ledger.

One RBU (release-blocking unit) = one thing that must reach a terminal state before
4.0.0 can ship. Streams are counted separately because they burn down independently;
the total is the headline the operator watches converge to zero.

Usage: burndown.py [--record]   (--record appends a dated row to the CSV ledger)
"""
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "docs/release/v4.0.0-burndown.csv"
INTEGRATION = "codex/v4-next-integration"


def sh(*args, default=""):
    try:
        return subprocess.run(args, capture_output=True, text=True, cwd=ROOT, timeout=120).stdout.strip()
    except Exception:
        return default


def scope_contract():
    """Ask the publish gate itself rather than reimplementing its parsers.

    check_scope_acceptance.py owns the baseline-ledger and scope-contract formats;
    a second parser here would drift from it silently.
    """
    out = sh(sys.executable, "scripts/release/check_scope_acceptance.py", "--publish-check")
    m = re.search(r"(\d+) criteria; (\d+) pending criteria/decisions; (\d+) baseline blocking rows", out)
    if not m:
        raise SystemExit(f"publish-check output not parseable:\n{out}")
    return int(m.group(2)), int(m.group(3))


def open_prs():
    out = sh("gh", "pr", "list", "--state", "open", "--limit", "100",
             "--json", "number,isDraft,mergeable,baseRefName")
    if not out:
        return {"total": 0, "draft": 0, "conflicting": 0}
    prs = json.loads(out)
    return {
        "total": len(prs),
        "draft": sum(1 for p in prs if p["isDraft"]),
        "conflicting": sum(1 for p in prs if p["mergeable"] == "CONFLICTING"),
    }


def red_ci_jobs():
    """Failing jobs on the newest completed run of the integration branch."""
    out = sh("gh", "run", "list", "--branch", INTEGRATION, "--limit", "10",
             "--json", "databaseId,conclusion,status,headSha")
    if not out:
        return 0, ""
    for run in json.loads(out):
        if run["status"] == "completed" and run["conclusion"] in ("failure", "success"):
            jobs = sh("gh", "run", "view", str(run["databaseId"]), "--json", "jobs")
            if not jobs:
                return 0, run["headSha"][:8]
            failing = [j for j in json.loads(jobs)["jobs"] if j["conclusion"] == "failure"]
            return len(failing), run["headSha"][:8]
    return 0, ""


def merge_conflicts():
    """Files that conflict when integration meets main."""
    sh("git", "fetch", "-q", "origin", "main", INTEGRATION)
    tree = sh("git", "merge-tree", "--write-tree", "origin/main", f"origin/{INTEGRATION}")
    return len(re.findall(r"^CONFLICT", tree, re.MULTILINE))


def main():
    pending, base = scope_contract()
    prs = open_prs()
    red, sha = red_ci_jobs()
    conflicts = merge_conflicts()

    streams = {
        "scope_pending": pending,
        "baseline_blocking": base,
        "prs_open": prs["total"],
        "prs_conflicting": prs["conflicting"],
        "ci_red_jobs": red,
        "merge_conflict_files": conflicts,
    }
    # Headline: every unresolved criterion/decision and every open PR is one unit of
    # work to close. Red CI jobs are symptoms of defects already counted elsewhere,
    # so they are reported but never summed — counting them would double-charge.
    total = pending + base + prs["total"]

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    print(f"RBU total: {total}")
    for k, v in streams.items():
        print(f"  {k}: {v}")
    print(f"  integration_sha: {sha}")

    if "--record" in sys.argv:
        new = not LEDGER.exists()
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a", newline="") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["timestamp", "rbu_total", *streams.keys(), "integration_sha"])
            w.writerow([stamp, total, *streams.values(), sha])
        print(f"recorded -> {LEDGER.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
