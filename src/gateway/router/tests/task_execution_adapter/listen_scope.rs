// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `subscriptions/listen` is scoped per caller (A5c, MIK-7570.NOTIFY.2).
//!
//! Every row drives the real route and the real `subscription_stream` loop: a
//! registry-level cell would test the channel and not the loop that decides.
//! A child of `notifications`, declared there with `#[path]`, so it reads the
//! same bounded stream reader and shaped assertions.
use super::super::super::*;
use super::super::support::*;
use super::helpers::{
    EventStream, StreamEvent, assert_receives_nothing, expect_message, open_listen,
};

/// A listen that asks for `tools/list_changed` and nothing else.
fn listen_tools() -> Value {
    json!({ "notifications": { "toolsListChanged": true } })
}

/// `key-a` may reach only `alpha`, `key-b` only `beta`. The subjects are the
/// suite's own pairs, so `open_listen` builds their requests unchanged.
fn split_scope_auth() -> AuthConfig {
    let mut auth = two_principal_auth();
    auth.api_keys[0].backends = vec!["alpha".to_string()];
    auth.api_keys[1].backends = vec!["beta".to_string()];
    auth
}

/// A listen presenting `bearer`, or no credential at all.
///
/// Not `open_listen`: that panics on any principal but the suite's three and on
/// any non-200 answer, and these rows are about exactly those callers.
async fn listen_as(
    state: &Arc<AppState>,
    bearer: Option<&str>,
    id: i64,
) -> axum::response::Response {
    let body = task_method(id, "subscriptions/listen", listen_tools());
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "subscriptions/listen");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = builder
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer")
}

/// A listen that must be admitted, with its acknowledgement consumed.
async fn admitted(state: &Arc<AppState>, bearer: Option<&str>, id: i64) -> EventStream {
    let response = listen_as(state, bearer, id).await;
    std::assert_eq!(
        response.status(),
        StatusCode::OK,
        "the listen must be admitted"
    );
    let mut stream = EventStream::from_response(response);
    expect_message(&mut stream, "the acknowledgement that opens the stream").await;
    stream
}

/// A key-server temporary token scoped to `backends`. Copied from
/// `webhooks/tests.rs::temporary_token`, which is private to that suite.
fn temporary_token(backends: &[&str]) -> crate::key_server::TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    use crate::key_server::oidc::VerifiedIdentity;
    use crate::key_server::store::TokenScopes;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    crate::key_server::TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: VerifiedIdentity {
            subject: "sub".to_string(),
            email: "user@issuer.test".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.test".to_string(),
        },
        scopes: TokenScopes {
            backends: backends.iter().map(|b| (*b).to_string()).collect(),
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

// L1
#[tokio::test]
async fn tools_list_changed_reaches_only_listeners_in_scope_for_the_backend() {
    let (state, _store) = fixture_state(&split_scope_auth()).await;
    let mut in_scope = open_listen(&state, "key-a", 1, listen_tools()).await;
    let mut out_of_scope = open_listen(&state, "key-b", 2, listen_tools()).await;

    state.announce_tools_changed("alpha").await;

    // Positive control: the same generation reaches the caller who may see it,
    // so the silence below is scoping and not a stream that carries nothing.
    let told = expect_message(&mut in_scope, "alpha's tools/list_changed").await;
    std::assert_eq!(told["method"], "notifications/tools/list_changed", "{told}");
    assert_receives_nothing(
        &mut out_of_scope,
        "key-b may not access alpha, so alpha's change is not its business",
    )
    .await;
}

// L2
#[tokio::test]
async fn a_listener_whose_token_is_revoked_is_closed_at_next_delivery() {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    let token = temporary_token(&["alpha"]);
    let (bearer, jti) = (token.token.clone(), token.jti.clone());
    key_server.store.insert(token).await;
    let (state, _store) = test_router_app_state_with_auth_and_key_server(
        &two_principal_auth(),
        Some(Arc::clone(&key_server)),
    )
    .await;
    let mut stream = admitted(&state, Some(&bearer), 3).await;

    std::assert!(
        key_server.store.revoke_by_jti(&jti).await,
        "the token was live"
    );
    state.announce_tools_changed("alpha").await;

    match stream.next(super::helpers::ARRIVES_WITHIN).await {
        StreamEvent::Closed => {}
        StreamEvent::Message(m) => panic!("a revoked token was still told: {m}"),
        StreamEvent::Silent => panic!("a revoked listener must be closed, not kept holding a slot"),
    }
}

// L3
#[tokio::test]
async fn an_uncredentialed_listen_under_auth_on_is_refused_before_a_permit() {
    let mut auth = two_principal_auth();
    auth.public_paths = vec!["/mcp".to_string()];
    let (state, _store) = fixture_state(&auth).await;
    let before = state.subscriptions.available();

    let response = listen_as(&state, None, 4).await;

    // Read while the response is alive: an admitted stream holds its permit
    // until its body is dropped. Status first, because an admitted stream's
    // body never ends and must not be read to the end.
    let status = response.status();
    let available = state.subscriptions.available();
    std::assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an uncredentialed listen must be refused, not streamed"
    );
    std::assert_eq!(available, before, "a refused listen must not hold a slot");
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    std::assert_eq!(body["error"]["code"], -32001, "{body}");
}

// L3 control (Revision 2): the refusal is listen-only.
#[tokio::test]
async fn an_uncredentialed_tools_call_on_public_mcp_is_still_served() {
    let mut auth = two_principal_auth();
    auth.public_paths = vec!["/mcp".to_string()];
    let (state, _store) = fixture_state(&auth).await;
    let body = task_method(
        5,
        "tools/call",
        json!({ "name": "gateway_list_servers", "arguments": {} }),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_list_servers")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let response = create_router(Arc::clone(&state))
        .oneshot(request)
        .await
        .unwrap();

    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    std::assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
}

// L4
#[tokio::test]
async fn with_auth_off_every_listener_is_told() {
    let (state, _store) = test_router_app_state().await;
    let mut first = admitted(&state, None, 6).await;
    let mut second = admitted(&state, None, 7).await;

    state.announce_tools_changed("alpha").await;

    for (who, stream) in [("first", &mut first), ("second", &mut second)] {
        let told = expect_message(stream, &format!("the {who} listener's frame")).await;
        std::assert_eq!(told["method"], "notifications/tools/list_changed", "{told}");
    }
}
