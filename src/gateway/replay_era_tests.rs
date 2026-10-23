// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8747 / MIK-8748: a keyed replay is never served across protocol
//! eras on `/mcp` or stdio. The stored delivery was shaped and sealed for
//! the era that first sent the key; serving it to the other era either
//! reshapes it after its seal (MIK-8747) or hands a legacy client modern-only
//! members (MIK-8748). The call already ran, so the refusal says so and
//! asks for the original revision, never a new key; the original era is
//! still served afterwards, and the backend runs once throughout.

use axum::http::StatusCode;
use serde_json::Value;

use crate::gateway::router::route_matrix_driver_tests::era::mcp_keyed_eras;
use crate::gateway::server::route_matrix_driver_tests::era::stdio_keyed_eras;
use crate::protocol::meta::Era;

/// The JSON-RPC error a cross-era replay answers with, checked whole.
fn assert_era_refusal(row: &str, body: &Value, stored: &str, request: &str) {
    let error = body
        .get("error")
        .unwrap_or_else(|| panic!("{row}: a cross-era replay is refused, not served: {body}"));
    assert!(
        body.get("result").is_none(),
        "{row}: nothing is delivered: {body}"
    );
    assert_eq!(error["code"], 409, "{row}: {error}");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("JSON-RPC error 409:"),
        "{row}: the sibling admission prefix: {message}"
    );
    assert!(
        message.contains("original protocol revision") && !message.contains("new key"),
        "{row}: the call already ran; the client is sent back to its revision, never to a new key: {message}"
    );
    let data = &error["data"];
    assert_eq!(data["reason"], "idempotency_era_mismatch", "{row}: {error}");
    assert_eq!(data["stored_era"], stored, "{row}: {error}");
    assert_eq!(data["request_era"], request, "{row}: {error}");
    assert_eq!(data["already_executed"], true, "{row}: {error}");
}

/// A body's result without its transport id.
fn result_of<'a>(row: &str, body: &'a Value) -> &'a Value {
    body.get("result")
        .unwrap_or_else(|| panic!("{row}: the original era is still served: {body}"))
}

/// E1 / E3: on `/mcp`, `first` stores the answer, the other era is refused
/// with HTTP 409, and `first`'s era is served the stored answer again.
async fn mcp_row(row: &str, first: Era, other: Era) {
    let (stored, request) = (era_name(first), era_name(other));
    let seen = mcp_keyed_eras(&[first, other, first]).await;
    let [(s0, b0), (s1, b1), (s2, b2)] = seen.answers.as_slice() else {
        panic!("{row}: three answers");
    };
    assert_eq!(*s0, StatusCode::OK, "{row} first: {b0}");
    assert_eq!(*s1, StatusCode::CONFLICT, "{row}: HTTP 409 on /mcp: {b1}");
    assert_era_refusal(row, b1, stored, request);
    assert_eq!(*s2, StatusCode::OK, "{row} third: {b2}");
    assert_eq!(
        result_of(row, b2),
        result_of(row, b0),
        "{row}: the stored answer"
    );
    assert_eq!(seen.calls, 1, "{row}: the backend ran once");
}

/// E2 / E4: the same on stdio, which has no HTTP status.
async fn stdio_row(row: &str, first: Era, other: Era) {
    let (stored, request) = (era_name(first), era_name(other));
    let (bodies, calls) = stdio_keyed_eras(&[first, other, first]).await;
    let [b0, b1, b2] = bodies.as_slice() else {
        panic!("{row}: three answers");
    };
    result_of(row, b0);
    assert_era_refusal(row, b1, stored, request);
    assert_eq!(
        result_of(row, b2),
        result_of(row, b0),
        "{row}: the stored answer"
    );
    assert_eq!(calls, 1, "{row}: the backend ran once");
}

/// The era as the refusal's data names it.
fn era_name(era: Era) -> &'static str {
    match era {
        Era::Modern => "modern",
        Era::Legacy => "legacy",
    }
}

/// E1, MIK-8747.ERAKEY.1: legacy stores, modern is refused on `/mcp`.
#[tokio::test]
async fn e1_mcp_a_modern_replay_of_a_legacy_answer_is_refused() {
    mcp_row("E1", Era::Legacy, Era::Modern).await;
}

/// E2, MIK-8747.ERAKEY.1: legacy stores, modern is refused on stdio.
#[tokio::test]
async fn e2_stdio_a_modern_replay_of_a_legacy_answer_is_refused() {
    stdio_row("E2", Era::Legacy, Era::Modern).await;
}

/// E3, MIK-8748.ERALEAK.1: modern stores, legacy is refused on `/mcp`.
#[tokio::test]
async fn e3_mcp_a_legacy_replay_of_a_modern_answer_is_refused() {
    mcp_row("E3", Era::Modern, Era::Legacy).await;
}

/// E4, MIK-8748.ERALEAK.1: modern stores, legacy is refused on stdio.
#[tokio::test]
async fn e4_stdio_a_legacy_replay_of_a_modern_answer_is_refused() {
    stdio_row("E4", Era::Modern, Era::Legacy).await;
}
