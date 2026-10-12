// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what a client sees when the identity it presents is dead at
//! attach is what it sees for an invalid credential, on both routes. Whether
//! ingress or the attach refuses first, the bytes are the contract.

use serde_json::json;

use super::audience_ear::Attach;
use super::audience_fixture::{World, adapter_assertion};
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};

const SKEW: u64 = 30;
const LIFETIME: u64 = 120;

async fn invalid_credential(
    w: &World,
    route: Attach,
) -> (axum::http::StatusCode, axum::body::Bytes) {
    let invalid = w.attach_raw(route, "k-not-a-key", |_| {}).await;
    assert_eq!(
        invalid.0,
        axum::http::StatusCode::UNAUTHORIZED,
        "premise: an invalid credential is 401 on {route:?}"
    );
    invalid
}

async fn expired_adapter_is_refused_as_invalid(route: Attach) {
    let w = World::start_adapter(|meta| meta).await;
    let issued = crate::clock::unix_secs().expect("clock after 1970");
    let assertion = adapter_assertion("alice");
    let invalid = invalid_credential(&w, route).await;
    let _past = crate::clock::test_clock::at_secs(issued + LIFETIME + SKEW + 1);
    let dead = w
        .attach_raw(route, "k-std", |request| {
            super::audience_fixture::asserted(request, Some(&assertion));
        })
        .await;
    assert_eq!(dead, invalid, "an expired adapter assertion on {route:?}");
}

#[tokio::test]
async fn adapter_expired_at_attach_is_refused_as_invalid_on_get() {
    expired_adapter_is_refused_as_invalid(Attach::Get).await;
}

#[tokio::test]
async fn adapter_expired_at_attach_is_refused_as_invalid_on_listen() {
    expired_adapter_is_refused_as_invalid(Attach::Listen).await;
}

async fn expired_cf_is_refused_as_invalid(route: Attach) {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let w = super::audience_cf_tests::cf_world_on(&harness).await;
    let exp = crate::clock::unix_secs().expect("clock after 1970") + 60;
    let assertion = harness.mint(ISS_A, "alice", &json!({ "exp": exp }));
    let invalid = invalid_credential(&w, route).await;
    let _past = crate::clock::test_clock::at_secs(exp + 61);
    let value: axum::http::HeaderValue = assertion.parse().expect("a header value");
    let dead = w
        .attach_raw(route, "k-std", move |request| {
            request
                .headers_mut()
                .insert("cf-access-jwt-assertion", value);
        })
        .await;
    assert_eq!(dead, invalid, "an expired Access assertion on {route:?}");
}

#[tokio::test]
async fn cf_expired_at_attach_is_refused_as_invalid_on_get() {
    expired_cf_is_refused_as_invalid(Attach::Get).await;
}

#[tokio::test]
async fn cf_expired_at_attach_is_refused_as_invalid_on_listen() {
    expired_cf_is_refused_as_invalid(Attach::Listen).await;
}
