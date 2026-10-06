# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The burndown summary must agree with the ledger checks (MIK-7730, MIK-7932)."""

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
GATE_SECTION = """
Run in the context that matters, it fails on **three** ids, all pending:

```
# Release acceptance incomplete: then the 3 ids below; exit 1
```

- `NFR.BUILD.1`
- `MIK-7211.PARENT.1`
- `MIK-7630.EVENTS.8`

The run before this change listed two ids.
"""
PUBLISH = """Release acceptance incomplete:
  NFR.BUILD.1
  MIK-7211.PARENT.1
  MIK-7630.EVENTS.8
Scope contract consistent: 134 criteria (103 met / 1 waived / 30 pending); x
"""


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


def test_a_duplicate_row_with_extra_whitespace_fails_closed():
    # MIK-7847.SCRIPT.5: the label count must not need single spaces. Only the
    # spaced row is duplicated, so nothing else can trip the check.
    rows = {line.split("|")[1].strip(): line for line in TRACKER.splitlines() if line.startswith("| ")}
    for label, spaced in (
        ("Core release criteria", "|  Core release criteria |"),
        ("Core release criteria", "| Core release criteria  |"),
        ("Core release criteria", "|\tCore release criteria |"),
        ("Scope-update criteria", "|  Scope-update criteria   |"),
    ):
        extra = rows[label].replace(f"| {label} |", spaced, 1)
        problems = check.mismatches(check.tracker_counts(TRACKER + extra + "\n"), measured())
        assert any("more than one summary row" in p for p in problems), (spaced, problems)


def test_a_malformed_duplicate_row_fails_closed():
    doubled = TRACKER + TRACKER.replace("| 134 |", "| 135.5 |")
    problems = check.mismatches(check.tracker_counts(doubled), measured())
    assert problems, "a valid row plus a malformed duplicate must not pass"


def gate_problems(section=GATE_SECTION, publish=PUBLISH):
    return check.publish_gate_mismatches(check.tracker_publish_gate(section), check.publish_ids(publish))


def test_a_publish_gate_that_matches_the_check_passes():
    assert gate_problems() == []


def test_a_stale_publish_count_is_flagged():
    stale = GATE_SECTION.replace("**three**", "**two**")
    problems = gate_problems(section=stale)
    assert any("publish-gate count" in p for p in problems), problems


def test_a_count_matching_the_list_but_not_the_check_is_flagged():
    shorter = PUBLISH.replace("  MIK-7630.EVENTS.8\n", "")
    problems = gate_problems(publish=shorter)
    assert any("publish-gate count" in p for p in problems), problems
    assert any("MIK-7630.EVENTS.8" in p and "--publish-check does not" in p for p in problems), problems


def test_an_id_the_tracker_omits_is_flagged():
    stale = GATE_SECTION.replace("- `MIK-7211.PARENT.1`\n", "").replace("**three**", "**two**")
    problems = gate_problems(section=stale)
    assert any("MIK-7211.PARENT.1" in p and "tracker does not" in p for p in problems), problems


def test_an_id_swapped_for_another_is_flagged_both_ways():
    stale = GATE_SECTION.replace("`NFR.BUILD.1`", "`NFR.WORKLOAD.1`")
    problems = gate_problems(section=stale)
    assert any("NFR.BUILD.1" in p for p in problems), problems
    assert any("NFR.WORKLOAD.1" in p for p in problems), problems


def test_an_extra_id_after_a_blank_line_is_flagged():
    stale = GATE_SECTION.replace("- `MIK-7630.EVENTS.8`\n", "- `MIK-7630.EVENTS.8`\n\n- `NFR.WORKLOAD.1`\n")
    problems = gate_problems(section=stale)
    assert any("NFR.WORKLOAD.1" in p and "--publish-check does not" in p for p in problems), problems


def test_an_id_under_a_later_heading_is_not_read_as_the_list():
    later = GATE_SECTION + "\n## Burndown\n\n- `NFR.WORKLOAD.1`\n"
    assert gate_problems(section=later) == []


def test_a_publish_check_result_is_trusted_only_in_its_two_shapes():
    complete = "Release acceptance complete.\n"
    assert check.publish_gate_trust(PUBLISH, 1) is None
    assert check.publish_gate_trust(complete, 0) is None
    for output, rc in ((PUBLISH, 0), (PUBLISH, 2), ("Traceback ...\n", 1),
                       ("Plan check only; not release approval.\n", 0), (complete, 1)):
        assert check.publish_gate_trust(output, rc), (output, rc)


def test_a_missing_publish_gate_section_fails_closed():
    assert gate_problems(section="no gate here"), "a missing publish-gate section must not pass"


def test_a_ledger_check_that_exits_nonzero_fails_main():
    real_run, real_tracker = check.run, check.TRACKER
    tracker = pathlib.Path(__file__).with_name("_burndown_fixture.md")
    tracker.write_text(TRACKER + GATE_SECTION, encoding="utf-8")
    outputs = {
        "--check": (CORE, 0),
        "--check-scope": (SCOPE, 2),
        "--publish-check": (PUBLISH, 1),
    }
    envs = []

    def fake_run(script, *args, env=None):
        envs.append((args[0], env))
        if script == "check_scope_acceptance.py" and args == ("--check",):
            return outputs["--check-scope"]
        return outputs[args[0]]

    check.run = fake_run
    check.TRACKER = tracker
    try:
        assert check.main() == 1, "a failing ledger check must fail the comparison"
        outputs["--check-scope"] = (SCOPE, 0)
        assert check.main() == 0, "matching counts and clean exits pass"
        assert ("--publish-check", check.TAG_CONTEXT) in envs, envs
        assert check.TAG_CONTEXT == {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/tags/v4.0.0"}
        outputs["--publish-check"] = (PUBLISH, 2)
        assert check.main() == 1, "a publish check that failed for another reason must fail"
        outputs["--publish-check"] = (PUBLISH, 1)
        outputs["--publish-check"] = (PUBLISH.replace("  NFR.BUILD.1\n", ""), 1)
        assert check.main() == 1, "a publish-gate list the check no longer prints must fail"
    finally:
        check.run, check.TRACKER = real_run, real_tracker
        tracker.unlink()


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
