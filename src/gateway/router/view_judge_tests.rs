// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the answer to a caller found dead at attach is the auth layer's
//! answer to an invalid credential, byte for byte.

use axum::body::to_bytes;
use axum::response::Response;

use super::dead_attach_refusal;
use crate::gateway::middleware::bearer_unauthorized_response;

async fn parts(response: Response) -> (u16, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let (parts, body) = response.into_parts();
    let mut headers: Vec<_> = parts
        .headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = to_bytes(body, usize::MAX).await.expect("a bounded body");
    (parts.status.as_u16(), headers, body.to_vec())
}

#[tokio::test]
async fn a_dead_attach_is_answered_as_an_invalid_credential_is() {
    let dead = parts(dead_attach_refusal()).await;
    let invalid = parts(bearer_unauthorized_response("Invalid token")).await;
    assert_eq!(dead, invalid, "status, headers and body all equal");
    assert_eq!(dead.0, 401);
}

/// With no backend registered, the baseline still records the served-list
/// digest, so the first backend added later is not read as a change.
#[tokio::test]
async fn an_empty_registry_baseline_still_carries_the_served_digest() {
    use crate::gateway::streaming::{ResolvedCaller, ViewJudge, ViewSubject};
    let (state, _store) = crate::gateway::router::tests::test_router_app_state().await;
    let judge = super::OwnedViewJudge::shared(&state);
    let caller = ResolvedCaller {
        client: crate::gateway::auth::anonymous_client(),
        identity: None,
    };
    let baseline = judge.baseline(&caller, &ViewSubject::default(), "");
    let carried = baseline
        .get("")
        .expect("a nameless entry carries the digest");
    assert!(!carried.served.is_empty());
    assert!(carried.shown.is_empty(), "it shows nothing of any backend");
}
