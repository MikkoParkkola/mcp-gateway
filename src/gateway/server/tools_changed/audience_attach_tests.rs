// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: an identity that is dead by the time a stream is requested is
//! refused by ingress before any attach, with ingress's own answer. These rows
//! pin what a client sees on both routes (the attach refusal itself, which
//! answers as an invalid credential, is pinned in `view_judge_tests` and
//! reachable end to end only through a clause that outlives ingress).

use serde_json::json;

use super::audience_ear::Attach;
use super::audience_fixture::{World, adapter_assertion};
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};

const SKEW: u64 = 30;
const LIFETIME: u64 = 120;

/// `openwebui_adapter.rs`: `verify` refuses an assertion past its window.
async fn expired_adapter(route: Attach) {
    let w = World::start_adapter(|meta| meta).await;
    let issued = crate::clock::unix_secs().expect("clock after 1970");
    let assertion = adapter_assertion("alice");
    let _past = crate::clock::test_clock::at_secs(issued + LIFETIME + SKEW + 1);
    let dead = w
        .attach_raw(route, "k-std", |request| {
            super::audience_fixture::asserted(request, Some(&assertion));
        })
        .await;
    assert_eq!(
        (dead.0.as_u16(), dead.1.as_ref()),
        (403, b"Invalid identity assertion".as_slice()),
        "an expired adapter assertion on {route:?}"
    );
}

#[tokio::test]
async fn adapter_expired_at_request_is_refused_by_ingress_on_get() {
    expired_adapter(Attach::Get).await;
}

#[tokio::test]
async fn adapter_expired_at_request_is_refused_by_ingress_on_listen() {
    expired_adapter(Attach::Listen).await;
}

/// `router/identity.rs`: `cloudflare_access_identity` refuses an assertion whose
/// `exp` has passed. On the listen route that refusal is raised inside the
/// dispatch, so it is framed as one event like any dispatch answer.
async fn expired_cf(route: Attach) -> (u16, String) {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let w = super::audience_cf_tests::cf_world_on(&harness).await;
    let exp = crate::clock::unix_secs().expect("clock after 1970") + 60;
    let assertion = harness.mint(ISS_A, "alice", &json!({ "exp": exp }));
    let _past = crate::clock::test_clock::at_secs(exp + 61);
    let value: axum::http::HeaderValue = assertion.parse().expect("a header value");
    let dead = w
        .attach_raw(route, "k-std", move |request| {
            request
                .headers_mut()
                .insert("cf-access-jwt-assertion", value);
        })
        .await;
    (
        dead.0.as_u16(),
        String::from_utf8_lossy(&dead.1).into_owned(),
    )
}

const CF_REFUSAL: &str = "{\"error\":{\"code\":-32600,\"message\":\"caller identity header refused: access_assertion\"},\"id\":null,\"jsonrpc\":\"2.0\"}";

#[tokio::test]
async fn cf_expired_at_request_is_refused_by_ingress_on_get() {
    assert_eq!(expired_cf(Attach::Get).await, (401, CF_REFUSAL.to_string()));
}

#[tokio::test]
async fn cf_expired_at_request_is_refused_by_ingress_on_listen() {
    assert_eq!(
        expired_cf(Attach::Listen).await,
        (401, format!("event: message\ndata: {CF_REFUSAL}\n\n"))
    );
}
