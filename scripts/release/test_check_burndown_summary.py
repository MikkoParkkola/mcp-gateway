# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The burndown summary must agree with the two ledger checks (MIK-7730)."""

import importlib.util
import pathlib
import sys
import traceback

_spec = importlib.util.spec_from_file_location(
    "check_burndown_summary",
    pathlib.Path(__file__).with_name("check_burndown_summary.py"),
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

TRACKER = """
| Ledger | File | Rows | Met or non-blocking | Blocking / pending |
|---|---|---|---|---|
| Core release criteria | `x.md` | 193 rows over 149 criteria | 193 (`NFR.PERF.1` is open) | **0** blocking (`A` met) |
| Scope-update criteria | `y.json` | 134 | 104 (103 met, 1 waived) | **30** |
"""
CORE = "Coverage: 149 criteria, 193 rows, 193 met or non-blocking, 0 blocking.\n"
SCOPE = "Scope contract consistent: 134 criteria (103 met / 1 waived / 30 pending); x\n"


def measured(core=CORE, scope=SCOPE):
    return {**check.core_counts(core), **check.scope_counts(scope)}


def test_a_summary_that_matches_both_checks_passes():
    stated = check.tracker_counts(TRACKER)
    assert stated, "the tracker table parses"
    assert check.mismatches(stated, measured()) == []


def test_a_stale_scope_row_is_flagged():
    stale = SCOPE.replace("103 met / 1 waived / 30 pending", "104 met / 1 waived / 29 pending")
    problems = check.mismatches(check.tracker_counts(TRACKER), measured(scope=stale))
    assert any("scope_met" in p for p in problems), problems
    assert any("scope_pending" in p for p in problems), problems


def test_a_stale_core_row_is_flagged():
    stale = CORE.replace("193 met or non-blocking, 0 blocking", "192 met or non-blocking, 1 blocking")
    problems = check.mismatches(check.tracker_counts(TRACKER), measured(core=stale))
    assert any("core_blocking" in p for p in problems), problems


def test_an_unparseable_summary_fails_closed():
    problems = check.mismatches(check.tracker_counts("no table here"), measured())
    assert problems, "a missing summary must not pass"


def test_a_malformed_count_fails_closed():
    for bad in ("193-192", "193.5"):
        broken = TRACKER.replace("| 193 (`NFR.PERF.1`", f"| {bad} (`NFR.PERF.1`")
        problems = check.mismatches(check.tracker_counts(broken), measured())
        assert any("core_ok" in p for p in problems), (bad, problems)


def test_conflicting_duplicate_rows_fail_closed():
    doubled = TRACKER + TRACKER.replace("| 134 |", "| 135 |")
    problems = check.mismatches(check.tracker_counts(doubled), measured())
    assert problems, "two disagreeing summary rows must not pass"


if __name__ == "__main__":
    # CI runs this file as a script; without this it would assert nothing.
    failed = []
    names = [n for n, fn in sorted(globals().items()) if n.startswith("test_") and callable(fn)]
    for name in names:
        try:
            globals()[name]()
        except AssertionError:
            failed.append(name)
            traceback.print_exc()
    print(f"{len(failed)} failed of {len(names)}")
    sys.exit(1 if failed else 0)
