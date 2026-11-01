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
