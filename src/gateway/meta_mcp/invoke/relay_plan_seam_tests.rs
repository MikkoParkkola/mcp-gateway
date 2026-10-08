// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8043.SEAM.3`: two short leaves the plan delivered side by side, one
//! from each of two steps, are text the caller received contiguously, so a
//! relay of them together is matched; engine text between them breaks it.

use serde_json::json;

use super::{deliver_plan, plan_answer, refused, relay_meta};

/// Step A's field and step B's field, each under a k-gram, so every
/// fingerprint across them spans the two steps.
const FIELD_A: &str = "north slope rows seven to twelve, late pears";
const FIELD_B: &str = "south terrace rows one to six, early quinces";

/// Two steps whose short fields the plan delivers adjacent: bob relaying the
/// two together is refused, alice (who received them) is not.
#[tokio::test]
async fn short_fields_of_two_steps_delivered_adjacent_keep_their_seam() {
    let (meta, firewall) = relay_meta();
    let both = plan_answer(&json!({"a": FIELD_A, "b": FIELD_B}));
    deliver_plan(&meta, &[("a", FIELD_A), ("b", FIELD_B)], &both, &both).await;
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !refused(&firewall, "bob", FIELD_A) && !refused(&firewall, "bob", FIELD_B),
        "premise: neither field alone is matched"
    );
    assert!(!refused(&firewall, "alice", &pair), "the holder is excused");
    assert!(
        refused(&firewall, "bob", &pair),
        "the seam was not receipted"
    );
}

/// The same fields with engine text between them in the answer: no seam,
/// since no fingerprint may join text no backend produced.
#[tokio::test]
async fn engine_text_between_two_steps_breaks_the_seam() {
    let (meta, firewall) = relay_meta();
    let answer = plan_answer(&json!({
        "a": FIELD_A,
        "b": "Step b was skipped; the playbook used its fallback text here.",
        "c": FIELD_B,
    }));
    deliver_plan(&meta, &[("a", FIELD_A), ("c", FIELD_B)], &answer, &answer).await;
    let pair = format!("{FIELD_A}{FIELD_B}");
    assert!(
        !refused(&firewall, "bob", &pair),
        "a seam across engine text"
    );
}
