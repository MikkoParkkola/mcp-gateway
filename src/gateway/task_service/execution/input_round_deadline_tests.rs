// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `round_deadline`: the stored deadline of a continuation envelope.

use super::round_deadline;
use crate::protocol::continuation::{ContinuationState, now_unix_secs};

/// Mutant: a resume refused after expiry settles `failed`, or any refusal
/// is read as expiry.
#[test]
fn only_a_refusal_after_the_envelope_expired_is_read_as_expiry() {
    use super::{CONTINUATION_DEADLINE_MARGIN_SECS as MARGIN, rejected_after_expiry};
    use crate::protocol::continuation::ContinuationError;
    use crate::protocol::{JsonRpcResponse, RequestId};
    let refused = JsonRpcResponse::error(
        Some(RequestId::Number(0)),
        -32602,
        ContinuationError::Expired.client_message(),
    );
    assert!(rejected_after_expiry(&refused, 100, 100 + MARGIN + 1));
    assert!(!rejected_after_expiry(&refused, 100, 100 + MARGIN));
    let other = JsonRpcResponse::error(Some(RequestId::Number(0)), -32602, "bad params");
    assert!(!rejected_after_expiry(&other, 100, 100 + MARGIN + 1));
}

/// Mutant: an envelope that does not open is parked with no deadline.
#[test]
fn an_unopenable_continuation_has_no_deadline_to_park_with() {
    let state = ContinuationState::new();
    let refused = round_deadline(state.keyring(), Some("not-an-envelope"), now_unix_secs());
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(
        round_deadline(state.keyring(), None, now_unix_secs()).ok(),
        Some(None)
    );
}

/// Mutant: a round whose continuation is already inside the margin is
/// parked with a deadline in the past, or without one.
#[test]
fn a_continuation_inside_the_margin_is_refused_and_one_outside_it_parks() {
    use super::CONTINUATION_DEADLINE_MARGIN_SECS as MARGIN;
    use crate::protocol::continuation::{ContinuationError, Payload};
    let state = ContinuationState::new();
    let now = now_unix_secs();
    let seal = |expires_at: u64| {
        let mut payload = Payload::mint(
            "b".into(),
            None,
            "f".into(),
            "d".into(),
            "r".into(),
            "h".into(),
            now,
        );
        payload.expires_at = expires_at;
        state.keyring().mint(&payload).expect("seals")
    };
    for inside in [now + MARGIN, now + MARGIN - 1] {
        let due = round_deadline(state.keyring(), Some(&seal(inside)), now);
        assert!(matches!(due, Err(ContinuationError::Expired)), "{due:?}");
    }
    // Positive control: one second more room parks at expiry less margin.
    let room = round_deadline(state.keyring(), Some(&seal(now + MARGIN + 1)), now);
    assert_eq!(room.ok(), Some(Some(now + 1)));
}
