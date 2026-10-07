// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The OAuth refresh-token grant for capabilities: where the refresh token may
//! be sent (#2113), and what its errors may say.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{Router, routing::post};

use crate::capability::CapabilityExecutionContext;
use crate::capability::definition::AuthConfig;
use crate::config::CapabilityConfig;
use crate::oauth::{TokenInfo, TokenStorage};

use super::super::CapabilityExecutor;

/// A loopback listener that counts connections and answers each with a token
/// response, standing in for a token endpoint or for the proxy in front of one.
async fn recording_token_server() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let body = r#"{"access_token":"REFRESHED_AT","token_type":"Bearer","expires_in":3600}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (url, seen)
}

/// An `oauth:` capability auth block naming `token_endpoint`.
fn oauth_auth(provider: &str, token_endpoint: &str) -> AuthConfig {
    serde_yaml::from_str(&format!(
        "required: true\ntype: oauth\nkey: \"oauth:{provider}\"\ntoken_endpoint: \"{token_endpoint}\"\n"
    ))
    .unwrap()
}

/// An executor whose token store holds an expired token with a refresh token
/// for `provider`, so the next credential fetch runs the refresh grant.
fn with_expired_token(
    mut executor: CapabilityExecutor,
    provider: &str,
) -> (CapabilityExecutor, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut token = TokenInfo::from_response("OLD_AT".to_string(), None, None, None, None);
    token.expires_at = Some(0);
    token.refresh_token = Some("REFRESH_SECRET".to_string());
    storage.save(provider, provider, &token).unwrap();
    executor.token_storage = Some(storage);
    (executor, dir)
}

/// A token store holding an expired token for `provider` with `refresh_token`.
fn expired_store(provider: &str, refresh_token: &str) -> (Arc<TokenStorage>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut token = TokenInfo::from_response("OLD_AT".to_string(), None, None, None, None);
    token.expires_at = Some(0);
    token.refresh_token = Some(refresh_token.to_string());
    storage.save(provider, provider, &token).unwrap();
    (storage, dir)
}

fn through_proxy(proxy: &str) -> CapabilityExecutor {
    CapabilityExecutor::for_config(&CapabilityConfig {
        egress_proxy: Some(proxy.to_string()),
        ..CapabilityConfig::default()
    })
}

/// T1: a loopback-literal token endpoint receives no refresh token.
#[tokio::test]
async fn a_private_literal_token_endpoint_never_receives_the_refresh_token() {
    let (server, seen) = recording_token_server().await;
    let (executor, _dir) = with_expired_token(CapabilityExecutor::new(), "t1");
    let result = executor
        .fetch_credential(
            &oauth_auth("t1", &format!("{server}/token")),
            &CapabilityExecutionContext::default(),
        )
        .await;
    assert!(result.is_err(), "the refresh must fail");
    assert_eq!(seen.load(Ordering::SeqCst), 0, "the refresh token was sent");
}

/// T1b: the refusal names the SSRF rule, and nothing is sent.
#[tokio::test]
async fn the_refresh_refusal_names_the_destination_rule() {
    let (server, seen) = recording_token_server().await;
    let (storage, _dir) = expired_store("t1b", "REFRESH_SECRET");
    let err = CapabilityExecutor::new()
        .refresh_provider_token(
            "t1b",
            &format!("{server}/token"),
            &storage,
            &CapabilityExecutionContext::default(),
        )
        .await
        .expect_err("a loopback literal is refused");
    assert!(err.to_string().contains("SSRF"), "{err}");
    assert_eq!(seen.load(Ordering::SeqCst), 0, "the refresh token was sent");
}

/// T2: the metadata address is refused even where loopback is allowed, and
/// even through the configured proxy.
#[tokio::test]
async fn the_metadata_address_is_refused_even_with_loopback_egress_and_a_proxy() {
    let (proxy, seen) = recording_token_server().await;
    let (executor, _dir) = with_expired_token(through_proxy(&proxy), "t2");
    let result = executor
        .fetch_credential(
            &oauth_auth("t2", "http://169.254.169.254/token"),
            &CapabilityExecutionContext::default().with_isolated_loopback_egress(),
        )
        .await;
    assert!(result.is_err(), "the refresh must fail");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "the proxy received the refresh"
    );
}

/// T3: the isolated runtime's loopback allowance reaches the refresh, through
/// `fetch_credential`, on the production client.
#[tokio::test]
async fn the_isolated_context_reaches_a_loopback_token_endpoint() {
    let (server, seen) = recording_token_server().await;
    let (executor, _dir) = with_expired_token(CapabilityExecutor::new(), "t3");
    let token = executor
        .fetch_credential(
            &oauth_auth("t3", &format!("{server}/token")),
            &CapabilityExecutionContext::default().with_isolated_loopback_egress(),
        )
        .await
        .expect("the isolated context allows a loopback token endpoint");
    assert_eq!(token, "REFRESHED_AT");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

/// T4: a token endpoint named by hostname goes to `capabilities.egress_proxy`,
/// which resolves the name: the documented route to an identity provider on a private network.
/// It is `https://` (#3013), so the proxy sees one CONNECT and never the
/// refresh token; the stand-in proxy then cannot speak TLS, so the grant fails.
/// The `http://` spelling is refused before the proxy is reached.
#[tokio::test]
async fn a_hostname_token_endpoint_is_refreshed_through_the_configured_proxy() {
    let (proxy, seen) = recording_token_server().await;
    let (executor, _dir) = with_expired_token(through_proxy(&proxy), "t4");
    let cleartext = executor
        .fetch_credential(
            &oauth_auth("t4", "http://idp.internal.invalid/token"),
            &CapabilityExecutionContext::default(),
        )
        .await;
    assert!(cleartext.is_err(), "a cleartext token endpoint is refused");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "the proxy saw a cleartext refresh"
    );
    let tunnelled = executor
        .fetch_credential(
            &oauth_auth("t4", "https://idp.internal.invalid/token"),
            &CapabilityExecutionContext::default(),
        )
        .await;
    assert!(tunnelled.is_err(), "the stand-in proxy cannot complete TLS");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "one refresh, through the proxy"
    );
}

/// T5: a private IP literal is refused even with a proxy configured.
#[tokio::test]
async fn a_private_literal_token_endpoint_is_refused_even_through_the_proxy() {
    let (proxy, seen) = recording_token_server().await;
    let (executor, _dir) = with_expired_token(through_proxy(&proxy), "t5");
    let result = executor
        .fetch_credential(
            &oauth_auth("t5", "http://10.0.0.5/token"),
            &CapabilityExecutionContext::default(),
        )
        .await;
    assert!(result.is_err(), "the refresh must fail");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "the proxy received the refresh"
    );
}

/// GH78.RL.1 — an OAuth token-refresh transport failure must not carry the
/// token endpoint's credential into the error text.
///
/// The refresh POSTs `refresh_token` and, when the keychain holds
/// one, `client_secret`. The failure message embedded the endpoint twice: once
/// verbatim, and once more inside a `reqwest::Error`, whose `Display` appends
/// `" for url (...)"`. A token endpoint is operator-configured and a
/// query-string credential is a common shape there, so both copies reached
/// every sink the returned `Error::Config` reaches.
///
/// `send_with_retry` has stripped the URL since `redact_url` landed; this leg
/// was the one outbound call in `executor/` that had not.
#[tokio::test]
async fn an_oauth_refresh_transport_error_drops_the_endpoint_credential() {
    let executor = CapabilityExecutor::new();
    let (storage, _dir) = expired_store("gh78", "refresh-token-value");

    let err = executor
        .refresh_provider_token(
            "gh78",
            "http://127.0.0.1:1/token?api_key=CANARY",
            &storage,
            &CapabilityExecutionContext::default().with_isolated_loopback_egress(),
        )
        .await
        .expect_err("a closed port must fail the refresh");

    let rendered = err.to_string();
    assert!(
        !rendered.contains("CANARY"),
        "token-endpoint credential survived into the refresh error: {rendered}"
    );
    assert!(
        rendered.contains("127.0.0.1"),
        "redaction must keep the host an operator acts on: {rendered}"
    );
    assert!(
        rendered.contains("OAuth refresh request"),
        "the failure must be the transport error, not a refusal: {rendered}"
    );
}

#[tokio::test]
async fn an_oauth_refresh_parse_error_drops_the_endpoint_credential() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "http://{}/token?api_key=PARSE_CANARY_78491",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/token", post(|| async { "invalid-json" })),
        )
        .await
        .unwrap();
    });
    let (storage, _directory) = expired_store("parse-fixture", "fixture-refresh");
    let error = CapabilityExecutor::new()
        .refresh_provider_token(
            "parse-fixture",
            &endpoint,
            &storage,
            &CapabilityExecutionContext::default().with_isolated_loopback_egress(),
        )
        .await
        .expect_err("invalid JSON must refuse refresh");
    server.abort();
    let rendered = error.to_string();
    assert!(
        rendered.contains("Failed to parse refresh response"),
        "{rendered}"
    );
    assert!(rendered.contains("parse-fixture"));
    assert!(!rendered.contains("PARSE_CANARY_78491"));
    assert!(!rendered.contains("fixture-refresh"));
}

#[path = "rest_refresh_flight_tests.rs"]
mod flight;
