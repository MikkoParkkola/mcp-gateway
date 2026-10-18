#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Stage 0 probe for MIK-8482: shard the OS test jobs by test target.

Throwaway: lives only on the probe branch and is never merged.

  shard <os> <name> <out>   run one shard, record per-step counts and seconds
  baseline <os> <out>       build once, list every selection, check the globs

<os> is linux, macos or windows. Exit status is non-zero when cargo fails,
when a step selects no test, or (baseline) when the shard selections do not
reproduce the unsharded selection exactly.
"""
import json
import os
import re
import subprocess
import sys
import time

SDK = "a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result"
BURST = "mik_7479_full_burst"
SKIPS = {
    "linux": ["--skip", SDK, "--skip", BURST],
    "macos": ["--skip", SDK, "--skip", BURST],
    "windows": ["--skip", BURST],
}
F = ["--all-features", "--no-fail-fast"]
GLOB_A, GLOB_B = "[a-l]*", "[!a-l]*"


def shard_steps(os_kind, name):
    """(label, cargo args, test-binary args) for each step of one shard."""
    s = SKIPS[os_kind]
    steps = {
        "liba": [("suite", F + ["--lib"], ["gateway::"] + s)],
        "libb": [("suite", F + ["--lib"], ["--skip", "gateway::"] + s)],
        "inta": [("suite", F + ["--bins", "--test", GLOB_A], s)],
        "intb": [("suite", F + ["--test", GLOB_B], s)],
    }[name]
    if name == "intb" and os_kind != "windows":
        steps.append(("doc", F + ["--doc"], s))
    return steps


def unsharded(os_kind):
    """The selection today's job runs (ci.yml:533, :596, :613)."""
    targets = ["--tests"] if os_kind == "windows" else []
    return F + targets, SKIPS[os_kind]


RUNNING = re.compile(r"^running (\d+) tests?$")
RESULT = re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored")
LISTED = re.compile(r": (test|benchmark)$")


def cargo(args, log):
    """Run cargo, mirror its output, return (rc, lines, seconds)."""
    t0 = time.monotonic()
    p = subprocess.Popen(["cargo", *args], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, errors="replace")
    lines = []
    with open(log, "a", encoding="utf-8") as fh:
        for line in p.stdout:
            sys.stdout.write(line)
            fh.write(line)
            lines.append(line.rstrip("\n"))
    return p.wait(), lines, round(time.monotonic() - t0, 1)


def counts(lines):
    out = {"selected": 0, "passed": 0, "failed": 0, "ignored": 0}
    for line in lines:
        m = RUNNING.match(line.strip())
        if m:
            out["selected"] += int(m.group(1))
        m = RESULT.search(line)
        if m:
            out["passed"] += int(m.group(1))
            out["failed"] += int(m.group(2))
            out["ignored"] += int(m.group(3))
    return out


def listed(args, test_args, log):
    """Names libtest would select, without running them (filters apply)."""
    rc, lines, _ = cargo(["test", *args, "--", "--list", *test_args], log)
    if rc:
        sys.exit(f"list failed rc={rc}: {args} {test_args}")
    names, binary = [], "?"
    for line in lines:
        # `Running unittests src/lib.rs (...)`: the path, not the word, names the binary.
        m = re.search(r"Running (?:unittests )?(\S+)|Doc-tests (\S+)", line)
        if m:
            binary = m.group(1) or "doc:" + m.group(2)
        elif LISTED.search(line):
            names.append(binary + " " + line.rsplit(": ", 1)[0])
    return names


def test_targets(args, log):
    """Integration-test target names cargo selects for `args` (built, not run)."""
    rc, lines, _ = cargo(["test", *args, "--no-run", "--message-format=json"], log)
    if rc:
        sys.exit(f"--no-run failed rc={rc}: {args}")
    names = set()
    for line in lines:
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        t = msg.get("target", {})
        if msg.get("reason") == "compiler-artifact" and t.get("kind") == ["test"] and msg.get("executable"):
            names.add(t["name"])
    return names


def write(out, record):
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=1, sort_keys=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("```json\n" + json.dumps(record, indent=1, sort_keys=True)[:60000] + "\n```\n")


def shard(os_kind, name, out):
    log = out + ".log"
    record = {"os": os_kind, "shard": name, "steps": []}
    bad = False
    for label, args, test_args in shard_steps(os_kind, name):
        rc, lines, secs = cargo(["test", *args, "--", *test_args], log)
        c = counts(lines)
        record["steps"].append({"step": label, "rc": rc, "seconds": secs, **c})
        bad |= rc != 0 or c["selected"] == 0
    if name == "intb" and os_kind != "windows":
        # The default `cargo test` target set builds examples (validator_demo.rs).
        rc, _, secs = cargo(["build", "--all-features", "--examples"], log)
        record["steps"].append({"step": "examples", "rc": rc, "seconds": secs})
        bad |= rc != 0
    write(out, record)
    return 1 if bad else 0


def baseline(os_kind, out):
    log = out + ".log"
    args, skips = unsharded(os_kind)
    rc, _, build_secs = cargo(["test", *args, "--no-run", "--timings"], log)
    if rc:
        sys.exit(f"build failed rc={rc}")
    full = listed(args, skips, log)
    per_shard = {}
    for name in ("liba", "libb", "inta", "intb"):
        sel = []
        for label, sargs, targs in shard_steps(os_kind, name):
            sargs = [a for a in sargs if a != "--no-fail-fast"]
            sel += listed(sargs, targs, log)
        per_shard[name] = sel
    union = [n for sel in per_shard.values() for n in sel]
    problems = []
    if sorted(union) != sorted(full):
        problems.append(f"shard union {len(union)} != unsharded {len(full)}; "
                        f"missing {sorted(set(full) - set(union))[:20]} extra {sorted(set(union) - set(full))[:20]}")
    if len(union) != len(set(union)):
        problems.append("a test is selected by two shards")
    a = test_targets(["--all-features", "--test", GLOB_A], log)
    b = test_targets(["--all-features", "--test", GLOB_B], log)
    every = test_targets(["--all-features", "--tests"], log)
    if not a or not b or a & b or (a | b) != every:
        problems.append(f"glob split: |a|={len(a)} |b|={len(b)} overlap={sorted(a & b)} "
                        f"missing={sorted(every - (a | b))}")
    aux = {}
    if os_kind == "linux":
        aux["upgrading_test"] = len(listed(["--all-features", "--test", "upgrading_summary_rows"], [], log))
        aux["upgrading_bin"] = len(listed(["--all-features", "--bin", "mcp-gateway"], ["upgrade_notice_tests"], log))
    if os_kind == "windows":
        aux["privileged"] = len(listed(["--all-features", "--lib"], ["--ignored", "win_privileged::"], log))
    write(out, {"os": os_kind, "build_seconds": build_secs, "unsharded": len(full),
                "per_shard": {k: len(v) for k, v in per_shard.items()},
                "glob_a": len(a), "glob_b": len(b), "test_targets": len(every),
                "aux": aux, "problems": problems})
    return 1 if problems else 0


def main(argv):
    if len(argv) == 5 and argv[1] == "shard":
        return shard(argv[2], argv[3], argv[4])
    if len(argv) == 4 and argv[1] == "baseline":
        return baseline(argv[2], argv[3])
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
