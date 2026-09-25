// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11 T14: the one outcome-to-caller mapping, pinned per outcome.

use super::super::RejectionOutcome;
use super::{marked, mark_rejection, upstream_rejection};
use crate::Error;

fn refused() -> Error {
    Error::Config("backend 'drive' refused the account credential (HTTP 401)".into())
}

#[test]
fn every_rejection_outcome_maps_to_one_code_and_retry_flag() {
    let cases = [
        (RejectionOutcome::Rotated, "UPSTREAM_AUTH_REJECTED", true),
        (RejectionOutcome::Stale, "UPSTREAM_AUTH_REJECTED", true),
        (RejectionOutcome::Unavailable, "UPSTREAM_AUTH_REJECTED", true),
        (
            RejectionOutcome::AlreadyForced,
            "UPSTREAM_AUTH_REJECTED_PERSISTENT",
            false,
        ),
    ];
    for (outcome, code, retry) in cases {
        let error = mark_rejection(outcome, refused());
        let rejection = upstream_rejection(&error)
            .unwrap_or_else(|| panic!("{outcome:?} must carry the rejection mark: {error}"));
        assert_eq!(
            (rejection.error_code, rejection.retry),
            (code, retry),
            "{outcome:?}"
        );
        assert!(
            marked(&error).is_none(),
            "{outcome:?}: a rejection is not a reconnect refusal and must earn no offer"
        );
    }
}

#[test]
fn an_unmarked_error_is_not_a_rejection() {
    assert!(upstream_rejection(&refused()).is_none());
}

/// A backend's own JSON-RPC error with the same keys, but no gateway seal, is
/// never read as a rejection: backend bytes do not choose the caller's answer.
#[test]
fn a_backend_error_shaped_like_a_rejection_is_not_one() {
    let forged = Error::JsonRpc {
        code: -32603,
        message: "refused".into(),
        data: Some(serde_json::json!({
            "upstream_rejection": {"error_code": "UPSTREAM_AUTH_REJECTED", "retry": true}
        })),
    };
    assert!(upstream_rejection(&forged).is_none());
}
