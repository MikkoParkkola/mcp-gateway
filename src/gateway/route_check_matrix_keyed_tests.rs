// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows behind the matrix's stdio `AlwaysLocalOperator` N/A (MIK-8382).

use crate::gateway::server::route_matrix_driver_tests::stdio_keyed_calls;

/// The premise of stdio's `NotApplicable(AlwaysLocalOperator)`: every stdio
/// call is admitted under the local operator whatever key it carries
/// (`stdio_dispatch.rs`, `AdmissionOwner::local_operator()`). Two keys each
/// run, and a repeated key replays, so admission owned both under one
/// principal and none was refused -32003. If stdio gains per-key owners or
/// an intake check, this row breaks and the N/A must be revisited.
#[tokio::test]
async fn stdio_owner_is_the_local_operator_for_any_key() {
    let ([first, again, other], backend_calls) = stdio_keyed_calls().await;
    for answer in [&first, &again, &other] {
        assert!(answer.get("error").is_none(), "refused: {answer}");
    }
    assert_eq!(again, first, "k-a was not replayed");
    assert_eq!(backend_calls, 2, "k-a once, k-b once: {first} {other}");
}
