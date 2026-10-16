// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 rows PR-A leaves out (lead ruling on stage 1), named rather than
//! dropped: each states where it would act and why it has no row here. A
//! row written for one, or a new gap, moves the pin below. The follow-up
//! ticket is the lead's to file.

/// A row the design names that PR-A does not drive.
#[derive(Debug, PartialEq, Eq)]
struct ExpectedGap {
    row: &'static str,
    site: &'static str,
    reason: &'static str,
}

const GAPS: &[ExpectedGap] = &[
    ExpectedGap {
        row: "S7a per-user stored read",
        site: "task_replay.rs:221-223 (`touch_caller_slot`) before :244 \
               (`refused_without_catalogue`)",
        reason: "a warm per-user slot of an out-of-scope backend is touched before \
                 the scope check; reaching it needs one principal holding that slot \
                 across two credentials of different scope (per-user identity plus \
                 scoped key fixture). The effect is a slot touch, not a wire answer",
    },
    ExpectedGap {
        row: "FW1 response targets",
        site: "response_security.rs:127-142 (`without_withheld`)",
        reason: "needs a response-firewall rule whose verdict differs by attributed \
                 target on the miss answer; no such rule shape is established",
    },
    ExpectedGap {
        row: "C2 capability provider out of scope",
        site: "chokepoint.rs:204, gate.rs:474-486 (capability arms)",
        reason: "this fixture registers no capability provider",
    },
    ExpectedGap {
        row: "R3 stored-read scope reason",
        site: "authz.rs:251-266 (`audit_refusal`, a WARN line only)",
        reason: "needs tracing capture of the WARN; the stored path writes no log \
                 record for it (step 1c)",
    },
];

/// The gap set is exactly these four rows.
#[test]
fn pr_a_names_its_expected_gaps() {
    let rows: Vec<&str> = GAPS.iter().map(|gap| gap.row).collect();
    assert_eq!(
        rows,
        [
            "S7a per-user stored read",
            "FW1 response targets",
            "C2 capability provider out of scope",
            "R3 stored-read scope reason",
        ],
        "the gap set moved: update the table, this pin and the PR body"
    );
    assert!(
        GAPS.iter()
            .all(|gap| !gap.site.is_empty() && !gap.reason.is_empty()),
        "every gap names its site and reason: {GAPS:?}"
    );
}
