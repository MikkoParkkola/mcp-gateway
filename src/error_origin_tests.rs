// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Origin decisions made outside the error-count rows: each pins one
//! variant's answer so a later reclassification fails here.

use super::Error;
use crate::protocol::Origin;

/// A merge-time decision: `AmbiguousBackend` arrived with the dispatch
/// name-clash refusal after the exhaustive `Error::origin` match, and it is
/// the gateway's own refusal (built only by the gateway, sharing
/// `BackendNotFound`'s code), so it counts as the gateway's, as that does.
#[test]
fn an_ambiguous_backend_refusal_is_the_gateways_own() {
    let ambiguous = Error::AmbiguousBackend {
        server: "shared".to_owned(),
        rule: None,
    };
    assert_eq!(ambiguous.origin(), Origin::Gateway);
    assert_eq!(
        ambiguous.origin(),
        Error::BackendNotFound("shared".to_owned()).origin(),
        "classified as a missing backend is"
    );
}

/// V1: a backend's own JSON-RPC error reads exactly as the gateway's twin
/// (text, code, the frame a client receives) and only its origin differs, so
/// the variant changes the count and nothing a client sees.
#[test]
fn a_backend_json_rpc_error_reads_as_its_twin_and_is_the_backends() {
    let data = Some(serde_json::json!({"detail": 1}));
    let backend = Error::backend_json_rpc(crate::protocol::JsonRpcError {
        code: -32001,
        message: "no such record".to_owned(),
        data: data.clone(),
    });
    let gateway = Error::JsonRpc {
        code: -32001,
        message: "no such record".to_owned(),
        data,
    };
    assert_eq!(backend.to_string(), gateway.to_string());
    assert_eq!(backend.to_rpc_code(), gateway.to_rpc_code());
    assert_eq!(backend.origin(), Origin::Backend);
    assert_eq!(gateway.origin(), Origin::Gateway);
    assert!(!backend.is_pre_dispatch(), "a backend's answer was sent");
    assert!(!backend.is_lost_round());
    assert!(!backend.is_gateway_throttle());
    let id = Some(crate::protocol::RequestId::Number(1));
    let frame = |e: &Error| {
        serde_json::to_value(crate::protocol::JsonRpcResponse::of_error(id.clone(), e))
            .expect("a frame serialises")
    };
    assert_eq!(frame(&backend), frame(&gateway), "the wire differs");
}

/// A merge-time decision: `with_may_have_run` moved into its own file after
/// the backend variant was reviewed. A backend's error keeps its variant,
/// code, data and origin, and gains the note, as the gateway's twin does.
#[test]
fn a_backend_json_rpc_error_keeps_itself_under_the_may_have_run_note() {
    let backend = Error::backend_json_rpc(crate::protocol::JsonRpcError {
        code: -32001,
        message: "backend says no".to_owned(),
        data: Some(serde_json::json!({"k": 1})),
    })
    .with_may_have_run();
    let Error::BackendJsonRpc {
        code,
        ref message,
        ref data,
    } = backend
    else {
        panic!("the variant is kept: {backend:?}");
    };
    assert_eq!(code, -32001);
    assert!(
        message.starts_with("backend says no") && message.ends_with(super::MAY_HAVE_RUN),
        "{message}"
    );
    assert_eq!(data, &Some(serde_json::json!({"k": 1})));
    assert_eq!(backend.origin(), Origin::Backend);
}

/// The injected-value scrub, composed with the count: a peer's retryable
/// answer stays the backend's, redacted or not, and the scrub's refusal is the
/// gateway's whether it replaced a retryable error or a success.
#[test]
fn the_scrubs_refusal_is_the_gateways_and_a_peer_answer_the_backends() {
    use crate::protocol::{JsonRpcResponse, RequestId};
    use crate::security::needles::{NeedleSet, scrub_answer};
    let needles = NeedleSet::with_grace(std::time::Duration::from_secs(3_600));
    needles.insert("b", "0739154");
    let retryable = |code, message: &str| {
        Err(Error::JsonRpcRetryable {
            code,
            message: message.to_owned(),
            status: 503,
            data: None,
        })
    };
    let origin = |answer: crate::Result<JsonRpcResponse>| match answer {
        Err(error) => Some(error.origin()),
        Ok(_) => None,
    };
    let rows: [(&str, crate::Result<JsonRpcResponse>, Option<Origin>); 4] = [
        (
            "a clean retryable error",
            retryable(-32000, "busy"),
            Some(Origin::Backend),
        ),
        (
            "a retryable error carrying a value, redacted",
            retryable(-32000, "busy 0739154"),
            Some(Origin::Backend),
        ),
        (
            "a retryable error whose code is a value, replaced",
            retryable(739_154, "busy"),
            Some(Origin::Gateway),
        ),
        (
            "a success whose error code is a value, replaced",
            Ok(JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                739_154,
                "nope",
            )),
            Some(Origin::Gateway),
        ),
    ];
    for (name, answer, expected) in rows {
        assert_eq!(origin(scrub_answer(&needles, answer)), expected, "{name}");
    }
}
