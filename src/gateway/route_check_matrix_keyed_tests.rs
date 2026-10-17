// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `KeyedPrincipal` rows of the route x check matrix (MIK-8382). One
//! driver per route sends a keyed anonymous `tools/call` that also trips a
//! later check; the same scenario the anon-intake rows assert.

use axum::http::StatusCode;

use super::{Expect, MethodKind, Route, Stage, expect};
use crate::gateway::router::route_matrix_driver_tests::{NO_PRINCIPAL, keyed_no_principal_on};
use crate::gateway::server::route_matrix_driver_tests::stdio_keyed_calls;

/// On an Applies route the intake refusal answers, -32003 with HTTP 400, and
/// nothing reaches a backend. On a gap route a later check answers instead.
#[tokio::test]
async fn keyed_principal_rows() {
    for route in [
        Route::Invoke,
        Route::Surfaced,
        Route::Direct,
        Route::TaskSubmit,
    ] {
        let (status, answer, backend_calls) = keyed_no_principal_on(route).await;
        let message = answer
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str);
        let refused = message == Some(NO_PRINCIPAL) && status == StatusCode::BAD_REQUEST;
        match expect(MethodKind::ToolsCall, route, Stage::KeyedPrincipal) {
            Expect::Applies => {
                assert!(
                    refused,
                    "{route:?}: not refused at intake: {status} {answer}"
                );
                assert_eq!(backend_calls, 0, "{route:?}: reached its backend");
            }
            Expect::ExpectedGap(ticket) => assert!(
                !refused,
                "{route:?}: refused at intake; {ticket:?} may have closed this gap, so \
                 flip the row to Applies"
            ),
            other @ Expect::NotApplicable(_) => {
                panic!("{route:?}: the table says {other:?}; this row drives it")
            }
        }
    }
}

/// The premise of stdio's `NotApplicable(AlwaysLocalOperator)`: every stdio
/// call is admitted under the local operator whatever key it carries
/// (`stdio_dispatch.rs`, `AdmissionOwner::local_operator()`). Two keys each
/// run, and a repeated key replays, so admission owned both under one
/// principal and none was refused -32003. If stdio gains per-key owners or
/// an intake check, this row breaks and the N/A must be revisited.
#[tokio::test]
async fn stdio_owner_is_the_local_operator_for_any_key() {
    assert_eq!(
        expect(MethodKind::ToolsCall, Route::Stdio, Stage::KeyedPrincipal),
        Expect::NotApplicable(super::Na::AlwaysLocalOperator)
    );
    let ([first, again, other], backend_calls) = stdio_keyed_calls().await;
    for answer in [&first, &again, &other] {
        assert!(answer.get("error").is_none(), "refused: {answer}");
    }
    assert_eq!(again, first, "k-a was not replayed");
    assert_eq!(backend_calls, 2, "k-a once, k-b once: {first} {other}");
}
