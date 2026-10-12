// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` PR 2b plan rows through the router: an answer over the 1 MiB
//! bound is read as a view, and one past the answer text cap fails closed.

use super::*;

/// Migrated by `MIK-8066` 2b: an answer over the 1 MiB bound (and under the
/// answer text cap) is read as a view, not dropped: its step's holder is
/// excused and nothing is counted as a drop.
#[tokio::test]
async fn an_answer_over_the_bound_is_read_as_a_view() {
    let (meta, firewall) = relay_meta();
    let huge = "x ".repeat(600 * 1024);
    let answer = plan_answer(&json!({"a": text_result(PROSE), "pad": huge}));
    deliver_plan(&meta, &[("a", PROSE)], &answer, &answer).await;
    carol_holds(&firewall, "a", PROSE);

    assert!(
        !refused(&firewall, "alice", PROSE),
        "an over-bound answer's holder was refused (still dropped)"
    );
    assert_eq!(
        firewall.relay_plan_drops(),
        0,
        "an over-bound answer was dropped"
    );
}

/// `MIK-8066` 2b (D6), through the router: an answer past the answer text
/// cap is unread. Its step is still evidence (bob is refused before anyone
/// else holds the text), and its caller is not excused.
#[tokio::test]
async fn an_answer_past_the_text_cap_fails_closed_through_the_router() {
    let (meta, firewall) = relay_meta();
    firewall
        .collusion_detector()
        .expect("relay detection on")
        .set_answer_text_cap(512 * 1024);
    let huge = "x ".repeat(600 * 1024);
    let answer = plan_answer(&json!({"a": text_result(PROSE), "pad": huge}));
    deliver_plan(&meta, &[("a", PROSE)], &answer, &answer).await;
    assert!(
        refused(&firewall, "bob", PROSE),
        "an unread plan's step was not evidence (fail-open)"
    );
    carol_holds(&firewall, "a", PROSE);
    assert!(
        refused(&firewall, "alice", PROSE),
        "an unread plan's caller was excused"
    );
}
