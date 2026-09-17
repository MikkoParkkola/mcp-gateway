# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""NFR.DEMO.1 recording gate.

Reads the recording manifest (docs/release/nfr-demo-1-recordings.json) plus each
scenario's committed transcript and driver results.json, and fails when the
evidence does not actually support the criterion.

The criterion (docs/requirements/RELEASE-4.0.0-scope-update.md): "Recorded
demonstrations prove mixed-era interaction, reconnectable tasks, isolated
personal accounts, useful large-catalogue discovery and error-budget
diagnosis/recovery."  Test plan (docs/requirements/RELEASE-4.0.0-scope-tests.md):
"Record mixed-era interaction, reconnectable task, two personal accounts,
large-catalogue discovery and error-budget diagnosis/recovery; include versions,
expected observations and actual outcomes."

Every rule below answers a word in one of those two sentences; the mapping is in
docs/release/nfr-demo-1-recordings.md.  Deliberately not a claim-checked-against
-itself gate: the manifest's `actual` is cross-checked against the row the driver
itself wrote, so a hand-edited manifest fails.

Usage:  python3 scripts/release/check_nfr_demo_1_recordings.py [--repo-root DIR]
Exit 0 when the evidence holds, 1 otherwise.
"""

import argparse
import json
import pathlib
import re
import sys

MANIFEST_REL = "docs/release/nfr-demo-1-recordings.json"
VERDICT_DOC_REL = "docs/release/nfr-demo-1-recordings.md"

# The five scenario phrases, spelled as the criterion spells them. A manifest
# that drops one, renames one or adds a sixth is not answering this criterion.
REQUIRED_PHRASES = (
    "mixed-era interaction",
    "reconnectable task",
    "two personal accounts",
    "large-catalogue discovery",
    "error-budget diagnosis/recovery",
)

# Ruling 3, carried in the artifact rather than only in prose.
SCENARIO_3_NON_REUSE = "MIK-6745.JOURNEY.1"

REVISION_REQUIRED = ("gateway_version", "binary_sha256", "build_sha_confidence")


def _fail(failures, scenario, message):
    prefix = f"scenario {scenario}: " if scenario is not None else ""
    failures.append(prefix + message)


def _read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def check_rows(scenario, rows, driver_rows, failures):
    """Expected/actual per row, cross-checked against the driver's own output."""
    sid = scenario.get("criterion_phrase", scenario.get("id"))
    if not rows:
        _fail(failures, sid, "no expected/actual rows; the criterion asks for "
                             "expected observations and actual outcomes")
        return
    by_id = {r.get("id"): r for r in driver_rows}
    for row in rows:
        rid = row.get("id")
        if not rid:
            _fail(failures, sid, "a row has no id")
            continue
        for field in ("expected", "actual"):
            if not row.get(field):
                _fail(failures, sid, f"row {rid} has no {field}")
        if row.get("expected") != row.get("actual"):
            _fail(failures, sid,
                  f"row {rid} expected != actual: "
                  f"{row.get('expected')!r} != {row.get('actual')!r}")
        if row.get("status") != "PASS":
            _fail(failures, sid, f"row {rid} status is {row.get('status')!r}, not PASS")
        driver_row = by_id.get(rid)
        if driver_row is None:
            _fail(failures, sid, f"row {rid} is in the manifest but not in the "
                                 f"driver's results.json")
            continue
        for field in ("expected", "actual", "status"):
            if driver_row.get(field) != row.get(field):
                _fail(failures, sid,
                      f"row {rid} {field} in the manifest ({row.get(field)!r}) "
                      f"does not match the driver's own row "
                      f"({driver_row.get(field)!r})")
    manifest_ids = {r.get("id") for r in rows}
    for rid in by_id:
        if rid not in manifest_ids:
            _fail(failures, sid, f"driver recorded row {rid}, manifest omits it")


def check_scenario(root, scenario, failures):
    sid = scenario.get("criterion_phrase", scenario.get("id"))
    status = scenario.get("status")

    if not scenario.get("versions"):
        _fail(failures, sid, "no versions block; the criterion asks the "
                             "recording to carry the versions in play")
    if not scenario.get("negative_control"):
        _fail(failures, sid, "no negative_control; a recording nothing can fail "
                             "does not prove anything")

    if status == "blocked":
        if not scenario.get("blocked_on"):
            _fail(failures, sid, "status is blocked but no blocked_on reference")
        if scenario.get("transcript"):
            _fail(failures, sid, "status is blocked but a transcript is cited; a "
                                 "blocked scenario must not read as recorded")
        if scenario.get("rows"):
            _fail(failures, sid, "status is blocked but expected/actual rows are "
                                 "present")
        return
    if status != "recorded":
        _fail(failures, sid, f"status {status!r} is neither 'recorded' nor 'blocked'")
        return

    driver_rows = []
    for key in ("driver", "transcript", "results_json"):
        rel = scenario.get(key)
        if not rel:
            _fail(failures, sid, f"recorded scenario has no {key}")
            continue
        path = root / rel
        if not path.is_file():
            _fail(failures, sid, f"{key} {rel} does not exist")
            continue
        if path.stat().st_size == 0:
            _fail(failures, sid, f"{key} {rel} is empty")
            continue
        if key == "results_json":
            try:
                driver_rows = _read_json(path)
            except json.JSONDecodeError as exc:
                _fail(failures, sid, f"results_json {rel} is not valid JSON: {exc}")

    check_rows(scenario, scenario.get("rows") or [], driver_rows, failures)


def check_manifest(root, manifest, failures):
    revision = manifest.get("revision_under_test") or {}
    for field in REVISION_REQUIRED:
        if not revision.get(field):
            _fail(failures, None, f"revision_under_test.{field} is missing")

    scenarios = manifest.get("scenarios") or []
    phrases = [s.get("criterion_phrase") for s in scenarios]
    for phrase in REQUIRED_PHRASES:
        if phrases.count(phrase) != 1:
            _fail(failures, None,
                  f"criterion phrase {phrase!r} appears {phrases.count(phrase)} "
                  f"times in the manifest, expected exactly 1")
    for phrase in phrases:
        if phrase not in REQUIRED_PHRASES:
            _fail(failures, None, f"unknown criterion phrase {phrase!r}")

    for scenario in scenarios:
        check_scenario(root, scenario, failures)
        if scenario.get("criterion_phrase") == "two personal accounts":
            non_reuse = scenario.get("not_evidence_for") or []
            hit = [n for n in non_reuse
                   if n.get("criterion") == SCENARIO_3_NON_REUSE and n.get("reason")]
            if not hit:
                _fail(failures, "two personal accounts",
                      f"ruling 3 requires a machine-readable not_evidence_for entry "
                      f"for {SCENARIO_3_NON_REUSE} with a reason")

    blocked = [s for s in scenarios if s.get("status") == "blocked"]
    verdict = manifest.get("verdict") or ""
    if not verdict:
        _fail(failures, None, "no verdict line")
    elif blocked and not re.search(r"\bBLOCKED\b", verdict):
        _fail(failures, None,
              f"{len(blocked)} scenario(s) are blocked but the verdict {verdict!r} "
              f"does not say BLOCKED")

    doc = root / VERDICT_DOC_REL
    if not doc.is_file():
        _fail(failures, None, f"{VERDICT_DOC_REL} does not exist")
    elif verdict and verdict not in doc.read_text(encoding="utf-8"):
        _fail(failures, None,
              f"{VERDICT_DOC_REL} does not carry the manifest verdict {verdict!r}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root",
                        default=str(pathlib.Path(__file__).resolve().parents[2]))
    args = parser.parse_args(argv)
    root = pathlib.Path(args.repo_root)

    failures = []
    manifest_path = root / MANIFEST_REL
    if not manifest_path.is_file():
        print(f"FAIL: manifest {MANIFEST_REL} does not exist", file=sys.stderr)
        return 1
    try:
        manifest = _read_json(manifest_path)
    except json.JSONDecodeError as exc:
        print(f"FAIL: manifest {MANIFEST_REL} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    check_manifest(root, manifest, failures)

    if failures:
        print(f"NFR.DEMO.1 recording gate: FAIL ({len(failures)} problem(s))")
        for failure in failures:
            print(f"  FAIL: {failure}")
        return 1
    recorded = sum(1 for s in manifest.get("scenarios", []) if s.get("status") == "recorded")
    blocked = sum(1 for s in manifest.get("scenarios", []) if s.get("status") == "blocked")
    print(f"NFR.DEMO.1 recording gate: PASS "
          f"({recorded} recorded, {blocked} blocked, verdict: {manifest.get('verdict')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
