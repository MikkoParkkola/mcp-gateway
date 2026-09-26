// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Direct-route idempotency settlement: how a dispatched call settles its key.

use std::sync::Arc;

use serde_json::json;

use super::{cached_error_response, settle_direct_failure};
use crate::Error;
use crate::idempotency::{GuardOutcome, IdempotencyCache, enforce};
use crate::protocol::JsonRpcResponse;

fn reserve(cache: &Arc<IdempotencyCache>) -> crate::idempotency::IdempotencyReservation {
    match enforce(cache, "key", "fingerprint").expect("a fresh key is admitted") {
        GuardOutcome::Proceed(reservation) => reservation,
        other => panic!("expected Proceed, got {other:?}"),
    }
}

#[test]
fn pre_dispatch_failure_frees_the_key_for_a_retry() {
    // GIVEN a reserved key whose call the circuit breaker refused outright.
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = reserve(&cache);
    let error = Error::CircuitOpen {
        backend: "backend".into(),
        last_failure: None,
    };
    let response = JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string());

    // WHEN the failure is settled.
    settle_direct_failure(Some(&mut reservation), &error, &response);

    // THEN the key is admissible again. Asserted while the reservation is
    // still alive on purpose: `Drop` releases an unsettled reservation too,
    // so an assertion after the drop passes without the explicit release.
    assert!(
        matches!(
            enforce(&cache, "key", "fingerprint"),
            Ok(GuardOutcome::Proceed(_))
        ),
        "a refusal raised before dispatch must not consume the key"
    );
}

#[test]
fn dispatched_failure_is_cached_as_terminal() {
    // GIVEN a reserved key whose call reached the backend and failed.
    let cache = Arc::new(IdempotencyCache::new());
    let mut reservation = reserve(&cache);
    let error = Error::Transport("connection reset".to_string());
    let response = JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string());

    // WHEN the failure is settled.
    settle_direct_failure(Some(&mut reservation), &error, &response);

    // THEN a retry replays the error instead of re-running the side effect.
    assert!(
        matches!(
            enforce(&cache, "key", "fingerprint"),
            Ok(GuardOutcome::CachedError(_))
        ),
        "ADR-012 consequence 1: a dispatched failure settles as terminal"
    );
}

#[test]
fn replayed_error_carries_the_stored_data_field() {
    // GIVEN a stored error whose machine-readable half lives in `data`.
    let stored = json!({"code": -32000, "message": "rate limited", "data": {"retry_after": 30}});

    // WHEN the replay response is rebuilt.
    let response = cached_error_response(None, &stored);

    // THEN the retry sees the same error the first caller did.
    let error = response.error.expect("a stored error replays as an error");
    assert_eq!(error.code, -32000);
    assert_eq!(error.message, "rate limited");
    assert_eq!(error.data, Some(json!({"retry_after": 30})));
}

#[test]
fn replayed_error_without_data_stays_data_free() {
    // GIVEN a stored error that carried no `data` (the field is skipped when
    // `None`, so it is absent rather than null).
    let stored = json!({"code": -32603, "message": "boom"});

    // WHEN the replay response is rebuilt.
    let response = cached_error_response(None, &stored);

    // THEN no `data` key is invented.
    let error = response.error.expect("a stored error replays as an error");
    assert_eq!(error.data, None);
}
