// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: residual gaps, stated as gaps. Each row passes today BECAUSE the
//! gap exists and fails loudly the day it is closed or widened, so nobody
//! mistakes either for a pass of the behaviour. They are not assertions that
//! the behaviour is right.

use super::decision_tests::{Fake, auth, view};
use super::*;

/// GAP (MIK-8422): two streams of one session and subject share one told
/// record, so the first to write a hint consumes it and the sibling's copy of
/// the same hint is skipped. Fails when the sibling is told (the gap closed).
#[tokio::test]
async fn gap_two_streams_of_one_session_share_one_hint() {
    let judge = Fake::answering("s0", "x");
    let first = view(&judge);
    let second = first.clone();
    judge.say("s1", "x2");
    assert_eq!(first.decide(&auth(), None, "", "a").await, Decision::Write);
    assert_eq!(
        second.decide(&auth(), None, "", "a").await,
        Decision::Skip,
        "GAP closed or changed: the sibling stream is now told (MIK-8422)"
    );
}

/// GAP (MIK-8421): the `tools/list` refresh is recorded by one `settle` call in
/// the handler, before the answer is replaced or written. Fails when that call
/// moves out of the handler (the gap closed) or is duplicated (widened).
#[test]
fn gap_the_listing_refresh_settles_before_the_final_emit() {
    let handler = include_str!("router/handlers.rs");
    assert_eq!(
        handler.matches("pending_view.settle(").count(),
        1,
        "GAP closed or widened: the refresh no longer settles once in the handler (MIK-8421)"
    );
    let settle = handler.find("pending_view.settle(");
    let receipt = handler.find("rebuild_receipt_from_final");
    assert!(
        matches!((settle, receipt), (Some(s), Some(r)) if s < r),
        "GAP closed or moved: the settle no longer precedes the receipt rebuild (MIK-8421)"
    );
}
