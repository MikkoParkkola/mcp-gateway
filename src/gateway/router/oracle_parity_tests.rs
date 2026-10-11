// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 parity rows on `/mcp` and the direct route (test plan v3):
//! ORACLE.2 per reason and entry, the firewall row F2, and the catalogue-state
//! rows S1-S6. The twins are `oracle_parity_fixture`'s; each panics
//! "premise" when its setup does not hold.

use serde_json::json;

use super::oracle_parity_fixture::{
    Answered, Args, Entry, List, Reason, STATE_ENTRIES, Side, State, TOOL, Twin, assert_cells,
    mismatch, pair, twin,
};
use crate::config::InputSchemaEnforcement;

/// ORACLE.2, policy reason, the entries that name a backend: a denied tool
/// answers exactly as the missing name, clean or firewall-tripping, and is
/// never sent. RED on base (probe: 403 policy refusal vs absent / firewall).
#[tokio::test]
async fn oracle2_policy_backend_entries_answer_as_the_missing_name() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Execute, Entry::Direct] {
        for args in [Args::Clean, Args::Tripping] {
            let (withheld, absent) = pair(entry, args, State::WARM).await;
            cells.extend(mismatch(&format!("{entry:?}/{args:?}"), &withheld, &absent));
        }
    }
    assert_cells("ORACLE.2 policy", &cells);
}

/// ORACLE.2, the surfaced name: a denied surfaced tool and a name that maps
/// to no backend both answer `Unknown tool`, clean or tripping (MIK-8340
/// keeps this; green on base, mutant MS1).
#[tokio::test]
async fn oracle2_policy_surfaced_name_answers_as_an_unmapped_name() {
    let mut cells = Vec::new();
    for args in [Args::Clean, Args::Tripping] {
        let (withheld, absent) = pair(Entry::Surfaced, args, State::WARM).await;
        cells.extend(mismatch(&format!("Surfaced/{args:?}"), &withheld, &absent));
    }
    assert_cells("ORACLE.2 surfaced", &cells);
}

/// ORACLE.2, the other backend reasons (schema, descriptor, profile R6) on
/// every entry, clean and tripping: the withheld tool answers exactly as the
/// missing name and is never sent. Surfaced cells are MIK-8340's.
#[tokio::test]
async fn oracle2_schema_descriptor_profile_answer_as_the_missing_name() {
    let mut cells = Vec::new();
    for reason in [Reason::Schema, Reason::Descriptor, Reason::Profile] {
        let state = State {
            reason,
            ..State::WARM
        };
        for entry in [Entry::Invoke, Entry::Execute, Entry::Direct, Entry::Surfaced] {
            for args in [Args::Clean, Args::Tripping] {
                let (withheld, absent) = Box::pin(pair(entry, args, state)).await;
                let cell = format!("{reason:?} {entry:?}/{args:?}");
                cells.extend(mismatch(&cell, &withheld, &absent));
            }
        }
    }
    assert_cells("ORACLE.2 reasons", &cells);
}

/// F1/F2: the firewall judges the withheld and the missing name alike. A
/// tripping call gets the same block (F1, in the ORACLE.2 row) and writes
/// the same request audit rows; a clean call is scanned and recorded alike
/// (its stateful controls are charged alike). RED on base: the denied call
/// stops at authorize and never reaches the firewall.
#[tokio::test]
async fn f2_the_firewall_records_both_names_alike() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        for args in [Args::Clean, Args::Tripping] {
            let withheld = twin(Side::Withheld, State::WARM).await;
            let absent = twin(Side::Absent, State::WARM).await;
            withheld.call(entry, args.value()).await;
            absent.call(entry, args.value()).await;
            let rows = |twin: &Twin| {
                twin.audit_rows("request")
                    .into_iter()
                    .filter(|row| row["tool"] == TOOL)
                    .map(|row| (row["action"].clone(), row["findings_count"].clone()))
                    .collect::<Vec<_>>()
            };
            let (w, a) = (rows(&withheld), rows(&absent));
            if w != a || a.is_empty() {
                cells.push(format!("{entry:?}/{args:?}: request rows withheld {w:?} vs absent {a:?}"));
            }
        }
    }
    assert_cells("F2", &cells);
}


/// Every cell of `state` on [`STATE_ENTRIES`], clean arguments.
async fn state_cells(row: &str, state: State) -> Vec<(String, Answered, Answered)> {
    let mut out = Vec::new();
    for entry in STATE_ENTRIES {
        let (withheld, absent) = pair(entry, Args::Clean, state).await;
        out.push((format!("{row} {entry:?}"), withheld, absent));
    }
    out
}

/// S1, Standard with a complete fresh list: both get text A and the missing
/// name is not forwarded (the upgrading.d behaviour row). RED on base.
#[tokio::test]
async fn s1_standard_complete_answers_both_and_forwards_neither() {
    let state = State {
        mode: InputSchemaEnforcement::Standard,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S1", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
        if absent.calls != 0 {
            cells.push(format!("{cell}: the missing name was forwarded: {}", absent.body));
        }
    }
    assert_cells("S1", &cells);
}

/// S2, cold, filled at the gate: both answered after one list fetch each.
#[tokio::test]
async fn s2_cold_catalogue_fills_once_and_answers_both_alike() {
    let state = State {
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S2", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
        if withheld.lists != absent.lists || absent.lists != 1 {
            cells.push(format!(
                "{cell}: list fetches withheld {} vs absent {}",
                withheld.lists, absent.lists
            ));
        }
    }
    assert_cells("S2", &cells);
}

/// S3, Closed, the fill fails: both get the same backend-unavailable answer.
#[tokio::test]
async fn s3_failed_fill_closed_answers_both_alike() {
    let state = State {
        list: List::Fails,
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S3", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
    }
    assert_cells("S3", &cells);
}

/// S4, Closed, the list is truncated at the page cap: both get text P,
/// byte-identical.
#[tokio::test]
async fn s4_truncated_closed_answers_both_with_text_p() {
    let state = State {
        list: List::Truncated,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells("S4", state).await {
        cells.extend(mismatch(&cell, &withheld, &absent));
    }
    assert_cells("S4", &cells);
}

/// The residual rows (S5, S6, S3b): the withheld name is never sent; the
/// missing name is forwarded (pinned, not parity).
async fn assert_residual(row: &str, state: State) {
    let mut cells = Vec::new();
    for (cell, withheld, absent) in state_cells(row, state).await {
        if withheld.calls != 0 {
            cells.push(format!("{cell}: the withheld name was sent: {}", withheld.body));
        }
        if absent.calls != 1 {
            cells.push(format!(
                "{cell}: the residual moved, missing name sends {}: {}",
                absent.calls, absent.body
            ));
        }
    }
    assert_cells(row, &cells);
}

/// S5, Standard, truncated: stated residual.
#[tokio::test]
async fn s5_truncated_standard_withholds_and_forwards_the_missing_name() {
    let state = State {
        list: List::Truncated,
        mode: InputSchemaEnforcement::Standard,
        ..State::WARM
    };
    assert_residual("S5", state).await;
}

/// S6, Off: stated residual.
#[tokio::test]
async fn s6_off_withholds_and_forwards_the_missing_name() {
    let state = State {
        mode: InputSchemaEnforcement::Off,
        ..State::WARM
    };
    assert_residual("S6", state).await;
}

/// S3b, Standard, the fill fails: stated residual.
#[tokio::test]
async fn s3b_failed_fill_standard_withholds_and_forwards_the_missing_name() {
    let state = State {
        list: List::Fails,
        mode: InputSchemaEnforcement::Standard,
        warm: false,
        ..State::WARM
    };
    assert_residual("S3b", state).await;
}

