// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The authorization-server side of the cleartext rule: a client secret, an
//! authorization code or a refresh token goes only to `https://`, or to
//! `http://` on a loopback host, under every destination policy.
//!
//! Loopback is `crate::gateway::is_loopback_host`, the classifier the backend
//! guard and the transport use. Spellings it does not recognise
//! (`localhost.`, IPv4-mapped IPv6, `*.localhost`) are refused, not widened:
//! a name that has to go through a resolver is not known to stay on the
//! machine.

use std::sync::Arc;

use serde_json::json;

use super::{Hop, hop};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::{DestinationPolicy, is_ssrf_refusal};

/// Serve both discovery documents on loopback, advertising `authorization_server`,
/// `token` and `registration` (`{port}` is the mock's own port).
async fn serve(authorization_server: &str, token: &str, registration: &str) -> u16 {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fill = |template: &str| template.replace("{port}", &port.to_string());
    let origin = format!("http://127.0.0.1:{port}");
    let resource = json!({
        "resource": format!("{origin}/mcp"),
        "authorization_servers": [fill(authorization_server)],
    });
    let server = json!({
        "issuer": fill(authorization_server),
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": fill(token),
        "registration_endpoint": fill(registration),
    });
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || {
                let body = resource.clone();
                async move { axum::Json(body) }
            }),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = server.clone();
                async move { axum::Json(body) }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

async fn initialize(
    authorization_server: &str,
    token: &str,
    registration: &str,
) -> crate::Result<()> {
    let port = serve(authorization_server, token, registration).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    // `Configured`, the production default: no literal check applies, so only
    // the cleartext rule can refuse here.
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Configured,
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        "cleartext-backend".to_string(),
        format!("http://127.0.0.1:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await
}

const LOOPBACK_AS: &str = "http://127.0.0.1:{port}";

/// A refusal, as the policy refusal every OAuth fallback stops at (MIK-7701),
/// naming the endpoint and never echoing the URL.
fn assert_cleartext_refusal(result: crate::Result<()>, field: &str) {
    let error = result.expect_err(field);
    assert!(
        is_ssrf_refusal(&error),
        "{field}: not a policy refusal: {error}"
    );
    let text = error.to_string();
    assert!(
        text.contains(field),
        "{field}: the refusal must name it: {text}"
    );
    assert!(text.contains("https"), "{field}: say what to use: {text}");
    assert!(
        !text.contains("off-machine.invalid"),
        "{field}: URL echoed: {text}"
    );
}

#[tokio::test]
async fn loopback_cleartext_authorization_server_is_accepted() {
    initialize(
        LOOPBACK_AS,
        "http://localhost:{port}/token",
        "http://[::1]:{port}/register",
    )
    .await
    .expect("control: loopback http is the carve-out");
}

#[tokio::test]
async fn cleartext_token_endpoint_off_machine_is_refused() {
    let result = initialize(
        LOOPBACK_AS,
        "http://off-machine.invalid/token",
        "http://127.0.0.1:{port}/register",
    )
    .await;
    assert_cleartext_refusal(result, "token_endpoint");
}

#[tokio::test]
async fn cleartext_registration_endpoint_off_machine_is_refused() {
    let result = initialize(
        LOOPBACK_AS,
        "http://127.0.0.1:{port}/token",
        "http://off-machine.invalid/register",
    )
    .await;
    assert_cleartext_refusal(result, "registration_endpoint");
}

#[tokio::test]
async fn cleartext_authorization_server_off_machine_is_refused_before_discovery() {
    // `.invalid` never resolves: a refusal that names the field was decided
    // before any fetch, where a DNS failure would be a fetch that was tried.
    let result = initialize(
        "http://off-machine.invalid",
        "http://127.0.0.1:{port}/token",
        "http://127.0.0.1:{port}/register",
    )
    .await;
    assert_cleartext_refusal(result, "authorization server");
}

/// A 307/308 from an https token endpoint re-POSTs the client secret and the
/// refresh token to wherever it points, so every hop is held to the rule,
/// under every policy.
#[test]
fn a_redirect_to_cleartext_off_machine_is_refused_under_every_policy() {
    let url = |text: &str| url::Url::parse(text).unwrap();
    for policy in [
        DestinationPolicy::Configured,
        DestinationPolicy::Public,
        DestinationPolicy::Private,
    ] {
        for refused in [
            "http://auth.example.com/token",
            "http://localhost./token",
            "http://LOCALHOST.:8080/token",
            "http://foo.localhost/token",
            "http://localhost.localdomain/token",
            "http://[::ffff:127.0.0.1]/token",
        ] {
            assert!(
                matches!(hop(policy, 0, &url(refused)), Hop::Refuse(r) if r.starts_with("SSRF blocked")),
                "{policy:?} must refuse a hop to {refused}"
            );
        }
        assert_eq!(
            hop(policy, 0, &url("https://auth.example.com/token")),
            Hop::Follow
        );
    }
    // The url crate normalises these IPv4 spellings to 127.0.0.1 before the
    // classifier sees them, so they are loopback, as the address is.
    for spelling in ["http://127.1/", "http://0x7f.0.0.1/", "http://2130706433/"] {
        assert_eq!(url(spelling).host_str(), Some("127.0.0.1"), "{spelling}");
    }
    for loopback in [
        "http://localhost/t",
        "http://LOCALHOST/t",
        "http://[::1]/t",
        "http://127.1/t",
    ] {
        assert_eq!(
            hop(DestinationPolicy::Configured, 0, &url(loopback)),
            Hop::Follow,
            "{loopback} is loopback"
        );
    }
}

/// The loopback carve-out holds only while the request stays on the machine:
/// the proxy the client would otherwise use never sees a loopback `http://`
/// fetch (#3007's rule, applied per request to the authorization server).
/// The proxy here is explicit, standing in for an inherited `HTTP_PROXY`.
#[tokio::test]
async fn a_loopback_cleartext_authorization_server_is_never_proxied() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = proxy.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    let proxied = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let port = serve(
        LOOPBACK_AS,
        "http://127.0.0.1:{port}/token",
        "http://127.0.0.1:{port}/register",
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Configured,
        proxied,
        "loopback-backend".to_string(),
        format!("http://127.0.0.1:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    let result = client.initialize().await;
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "a loopback fetch went to the proxy"
    );
    result.expect("the loopback authorization server is reached directly");
}
