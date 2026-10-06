// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T7 and T9 of the HARDEN 4b test plan.
//!
//! T7 is a setup production never builds: an UNPINNED client carrying the
//! `Public` policy. Under the real pinned client no loopback mock is reachable
//! at all, so this is the only way to get a document served and then see the
//! literal checks refuse what it advertises. `hardened_oauth_client_is_pinned`
//! covers the production client.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use super::{Hop, hop};
use crate::oauth::{OAuthClient, OAuthClientConfig, TokenStorage};
use crate::security::ssrf::DestinationPolicy;

/// URLs the mock advertises; `{port}` is replaced with the mock's port.
struct Advertised {
    authorization_server: &'static str,
    token: &'static str,
    registration: &'static str,
}

const REACHABLE: &str = "http://localhost:{port}";

/// Serve both discovery documents on loopback; return the mock's port.
async fn serve(advertised: &Advertised) -> u16 {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fill = |template: &str| template.replace("{port}", &port.to_string());
    let reachable = fill(REACHABLE);
    let resource = json!({
        "resource": format!("{reachable}/mcp"),
        "authorization_servers": [fill(advertised.authorization_server)],
    });
    let server = json!({
        "issuer": reachable,
        "authorization_endpoint": format!("{reachable}/authorize"),
        "token_endpoint": fill(advertised.token),
        "registration_endpoint": fill(advertised.registration),
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

async fn initialize(advertised: &Advertised) -> crate::Result<()> {
    let port = serve(advertised).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Public,
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        "hardened-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await
}

async fn assert_refused(advertised: Advertised, which: &str) {
    let error = initialize(&advertised).await.expect_err(which);
    assert!(
        error.to_string().contains("SSRF blocked"),
        "{which}: {error}"
    );
    assert_eq!(error.to_rpc_code(), -32600, "{which}: {error}");
}

#[tokio::test]
async fn hardened_oauth_accepts_public_advertised_urls() {
    initialize(&Advertised {
        authorization_server: REACHABLE,
        token: "http://localhost:{port}/token",
        registration: "http://localhost:{port}/register",
    })
    .await
    .expect("control: every advertised URL is a name");
}

#[tokio::test]
async fn hardened_oauth_refuses_private_authorization_server() {
    assert_refused(
        Advertised {
            authorization_server: "http://127.0.0.1:{port}",
            token: "http://localhost:{port}/token",
            registration: "http://localhost:{port}/register",
        },
        "authorization server",
    )
    .await;
}

#[tokio::test]
async fn hardened_oauth_refuses_private_registration() {
    assert_refused(
        Advertised {
            authorization_server: REACHABLE,
            token: "http://localhost:{port}/token",
            registration: "http://10.0.0.5/register",
        },
        "registration endpoint",
    )
    .await;
}

#[tokio::test]
async fn hardened_oauth_refuses_private_token_endpoint() {
    assert_refused(
        Advertised {
            authorization_server: REACHABLE,
            token: "http://[::ffff:169.254.169.254]/token",
            registration: "http://localhost:{port}/register",
        },
        "token endpoint",
    )
    .await;
}

fn target(text: &str) -> url::Url {
    url::Url::parse(text).unwrap()
}

#[test]
fn oauth_redirect_hop_policy() {
    let private = target("http://169.254.169.254/latest");
    let public = target("https://auth.example.com/next");
    assert!(matches!(
        hop(DestinationPolicy::Public, 0, &private),
        Hop::Refuse(reason) if reason.starts_with("SSRF blocked")
    ));
    assert_eq!(hop(DestinationPolicy::Public, 0, &public), Hop::Follow);
    assert_eq!(hop(DestinationPolicy::Public, 9, &public), Hop::Follow);
    assert_eq!(hop(DestinationPolicy::Public, 10, &public), Hop::Stop);
    assert_eq!(hop(DestinationPolicy::Configured, 9, &public), Hop::Follow);
    assert_eq!(hop(DestinationPolicy::Configured, 10, &public), Hop::Stop);
    assert_eq!(
        hop(
            DestinationPolicy::Configured,
            0,
            &target("https://169.254.169.254/latest")
        ),
        Hop::Follow,
        "standard keeps today's redirects (cleartext ones are refused: cleartext_tests)"
    );
}

/// A loopback listener that counts connections and drops each at once.
pub(super) async fn counting_listener() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

#[tokio::test]
async fn hardened_oauth_client_is_pinned() {
    for (destination, reaches) in [
        (DestinationPolicy::Public, false),
        (DestinationPolicy::Configured, true),
    ] {
        let (port, accepted) = counting_listener().await;
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let mut client = OAuthClient::with_destination(
            destination,
            super::http_client(destination).unwrap(),
            "backend".to_string(),
            format!("http://localhost:{port}/mcp"),
            vec![],
            storage,
            OAuthClientConfig::default(),
        );
        client
            .initialize()
            .await
            .expect_err("nothing serves discovery here");
        let seen = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(seen > 0, reaches, "{destination:?}: {seen} connections");
    }
}

/// Answer every connection with a redirect to `location`.
pub(super) async fn redirecting_listener(location: String) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    port
}

/// [`redirecting_listener`] that also hands back the first request it read,
/// headers and body, so a test can learn what the client sent.
async fn recording_redirecting_listener(
    location: String,
) -> (u16, tokio::sync::oneshot::Receiver<String>) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        while let Ok((mut stream, _)) = listener.accept().await {
            let request = read_request(&mut stream).await;
            if let Some(tx) = tx.take() {
                let _ = tx.send(request);
            }
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (port, rx)
}

/// One read can return the headers alone: read until the body that
/// `Content-Length` announces has arrived too.
async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n @ 1..) = stream.read(&mut buf).await {
        request.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&request);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

/// The redirect policy is wired into the production OAuth client: a hop to a
/// private literal is never followed under `Public`. The first request uses a
/// literal too, which never reaches the resolver, so the pinned client can
/// reach a loopback mock at all.
#[tokio::test]
async fn hardened_oauth_client_refuses_a_literal_redirect() {
    // `Configured` sends `http://` loopback through its direct client (the
    // proxied one refuses a loopback hop: cleartext_tests), which follows.
    for (destination, client, followed) in [
        (
            DestinationPolicy::Public,
            super::http_client(DestinationPolicy::Public).unwrap(),
            false,
        ),
        (
            DestinationPolicy::Configured,
            super::loopback_client().unwrap(),
            true,
        ),
    ] {
        let (target, accepted) = counting_listener().await;
        let origin = redirecting_listener(format!("http://127.0.0.1:{target}/next")).await;
        let result = client
            .get(format!("http://127.0.0.1:{origin}/start"))
            .send()
            .await;
        let seen = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(seen > 0, followed, "{destination:?}: {seen} connections");
        if !followed {
            let error = result.expect_err("the hop is refused");
            assert!(error.is_redirect(), "{error:?}");
        }
    }
}

/// Row 13 through OAuth: a listed backend's production client (pinned, under
/// `Private`) reaches a loopback authorization server, and still refuses a
/// link-local or IPv6 metadata endpoint it is sent to, by advertisement or by a
/// redirect hop.
#[tokio::test]
async fn listed_private_backend_oauth_policy() {
    let initialize = |advertised: Advertised| async move {
        let port = serve(&advertised).await;
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let mut client = OAuthClient::with_destination(
            DestinationPolicy::Private,
            super::http_client(DestinationPolicy::Private).unwrap(),
            "listed-backend".to_string(),
            format!("http://localhost:{port}/mcp"),
            vec![],
            storage,
            OAuthClientConfig::default(),
        );
        client.initialize().await
    };
    initialize(Advertised {
        authorization_server: "http://localhost:{port}",
        token: "http://localhost:{port}/token",
        registration: "http://localhost:{port}/register",
    })
    .await
    .expect("a listed backend reaches its loopback authorization server");
    for (token, registration, which) in [
        (
            "http://169.254.169.254/token",
            "http://localhost:{port}/register",
            "link-local token endpoint",
        ),
        (
            "http://localhost:{port}/token",
            "http://[fd00:ec2::254]/register",
            "IPv6 metadata registration endpoint",
        ),
    ] {
        let error = initialize(Advertised {
            authorization_server: REACHABLE,
            token,
            registration,
        })
        .await
        .expect_err(which);
        assert!(
            error.to_string().contains("SSRF blocked"),
            "{which}: {error}"
        );
    }

    // A redirect hop: to loopback it is followed, to the metadata address not.
    let client = super::http_client(DestinationPolicy::Private).unwrap();
    let (target, accepted) = counting_listener().await;
    let origin = redirecting_listener(format!("http://127.0.0.1:{target}/next")).await;
    let _ = client
        .get(format!("http://127.0.0.1:{origin}/start"))
        .send()
        .await;
    assert!(
        accepted.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "a listed backend follows a loopback hop"
    );
    let origin = redirecting_listener("http://[fd00:ec2::254]/next".to_string()).await;
    let error = client
        .get(format!("http://127.0.0.1:{origin}/start"))
        .send()
        .await
        .expect_err("the metadata hop is refused");
    assert!(error.is_redirect(), "{error:?}");
}

/// MIK-7701: a redirect hop the destination policy refuses is a policy
/// answer, typed `-32600 SSRF blocked`, not a generic OAuth failure, both
/// from `initialize` (discovery) and from a token or registration request.
#[tokio::test]
async fn a_refused_oauth_redirect_is_typed_ssrf_blocked() {
    let origin = redirecting_listener("http://169.254.169.254/latest".to_string()).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://127.0.0.1:{origin}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    let error = client.initialize().await.expect_err("the hop is refused");
    assert!(
        error.to_string().contains("SSRF blocked"),
        "initialize: {error}"
    );
    assert_eq!(error.to_rpc_code(), -32600, "initialize: {error}");

    let sent = super::http_client(DestinationPolicy::Private)
        .unwrap()
        .post(format!("http://127.0.0.1:{origin}/token"))
        .send()
        .await
        .expect_err("the hop is refused");
    for context in ["Token request failed", "Client registration failed"] {
        let error = crate::security::http_diagnostics::oauth_request_error(context, &sent);
        assert!(
            error.to_string().contains("SSRF blocked"),
            "{context}: {error}"
        );
        assert_eq!(error.to_rpc_code(), -32600, "{context}: {error}");
    }
}

/// Serve a protected-resource document that redirects to the link-local
/// metadata address, beside a reachable authorization-server document whose
/// registration endpoint is `registration`.
async fn serve_with_refused_resource(registration: String) -> u16 {
    use axum::{Router, response::Redirect, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let server = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": registration,
    });
    let app = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(|| async { Redirect::temporary("http://169.254.169.254/latest") }),
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

fn private_client(port: u16, storage: Arc<TokenStorage>) -> OAuthClient {
    OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://127.0.0.1:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    )
}

/// The protected-resource discovery falls back to the base URL when the
/// document is missing, but a policy refusal is not a missing document: it is
/// surfaced, not walked past.
#[tokio::test]
async fn a_refused_protected_resource_redirect_is_not_walked_past() {
    let port = serve_with_refused_resource("http://127.0.0.1:1/register".to_string()).await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let error = private_client(port, storage)
        .initialize()
        .await
        .expect_err("a refused discovery hop must surface");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
}

/// Dynamic registration falls back to a generated client id when the
/// endpoint fails, but not when the destination policy refused it.
#[tokio::test]
async fn a_refused_registration_redirect_is_not_walked_past() {
    let refused = redirecting_listener("http://169.254.169.254/latest".to_string()).await;
    let port = {
        // A reachable resource document this time, so initialize succeeds.
        let advertised = Advertised {
            authorization_server: REACHABLE,
            token: "http://localhost:{port}/token",
            registration: Box::leak(
                format!("http://127.0.0.1:{refused}/register").into_boxed_str(),
            ),
        };
        serve(&advertised).await
    };
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await.expect("discovery is reachable");
    let error = client
        .ensure_client_id_with_redirect("http://localhost:1/callback")
        .await
        .expect_err("a refused registration hop must surface");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
}

/// A token refresh whose endpoint redirects to a refused address answers
/// `-32600 SSRF blocked` from the refresh entry point itself.
#[tokio::test]
async fn a_refused_token_refresh_redirect_is_typed_ssrf_blocked() {
    let refused = redirecting_listener("http://169.254.169.254/latest".to_string()).await;
    let port = serve(&Advertised {
        authorization_server: REACHABLE,
        token: Box::leak(format!("http://127.0.0.1:{refused}/token").into_boxed_str()),
        registration: "http://localhost:{port}/register",
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await.expect("discovery is reachable");
    *client.client_id.write() = Some("listed-client".to_string());
    let error = client
        .refresh_token("refresh")
        .await
        .expect_err("a refused refresh hop must surface");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
    assert_eq!(error.to_rpc_code(), -32600, "{error}");
}

/// A client whose discovery is reachable but whose token endpoint redirects
/// to a refused address, holding an expired token with a refresh token.
async fn client_with_refused_refresh(dir: &std::path::Path) -> OAuthClient {
    let refused = redirecting_listener("http://169.254.169.254/latest".to_string()).await;
    let port = serve(&Advertised {
        authorization_server: REACHABLE,
        token: Box::leak(format!("http://127.0.0.1:{refused}/token").into_boxed_str()),
        registration: "http://localhost:{port}/register",
    })
    .await;
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await.expect("discovery is reachable");
    *client.client_id.write() = Some("listed-client".to_string());
    let mut token = crate::oauth::TokenInfo::from_response(
        "expired".to_string(),
        None,
        Some("refresh".to_string()),
        None,
        None,
    );
    token.expires_at = Some(1);
    *client.current_token.write() = Some(token);
    client
}

/// Count the browser openings `client` attempts.
fn count_browsers(client: &mut OAuthClient) -> Arc<AtomicUsize> {
    let opened = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        true
    });
    opened
}

/// `get_token` answers a refused refresh with the refusal, rather than
/// starting an authorization that would meet the same policy.
#[tokio::test]
async fn get_token_surfaces_a_refused_refresh_without_authorizing() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client_with_refused_refresh(dir.path()).await;
    let opened = count_browsers(&mut client);
    let outcome = tokio::time::timeout(Duration::from_secs(10), client.get_token()).await;
    assert_eq!(opened.load(Ordering::SeqCst), 0, "no authorization starts");
    let error = outcome
        .expect("answered promptly")
        .expect_err("a refused refresh must surface");
    assert_eq!(error.to_rpc_code(), -32600, "{error}");
}

/// An authorization abandoned at a refused registration releases the
/// callback listener it had already bound.
#[tokio::test]
async fn a_refused_registration_releases_the_callback_listener() {
    let (refused, registration) =
        recording_redirecting_listener("http://169.254.169.254/latest".to_string()).await;
    let port = serve(&Advertised {
        authorization_server: REACHABLE,
        token: "http://localhost:{port}/token",
        registration: Box::leak(format!("http://127.0.0.1:{refused}/register").into_boxed_str()),
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
    let mut client = OAuthClient::with_destination(
        DestinationPolicy::Private,
        super::http_client(DestinationPolicy::Private).unwrap(),
        "listed-backend".to_string(),
        format!("http://localhost:{port}/mcp"),
        vec![],
        storage,
        OAuthClientConfig::default(),
    );
    client.initialize().await.expect("discovery is reachable");
    // No fixed callback port: the client binds an ephemeral one and names it
    // in the registration's redirect URI, so nothing reserves a port another
    // test could take before the client binds it (MIK-7984).
    client.callback_host = Some("127.0.0.1".to_string());
    client.callback_port = None;
    let opened = count_browsers(&mut client);

    let error = tokio::time::timeout(Duration::from_secs(10), client.authorize())
        .await
        .expect("refused promptly")
        .expect_err("a refused registration hop must surface");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
    assert_eq!(opened.load(Ordering::SeqCst), 0, "no browser is opened");

    let registration = registration.await.expect("the registration was sent");
    let (_, body) = registration
        .split_once("\r\n\r\n")
        .expect("a complete request");
    let body: serde_json::Value = serde_json::from_str(body).expect("a JSON registration");
    let redirect = body["redirect_uris"][0].as_str().expect("one redirect URI");
    let callback_port = url::Url::parse(redirect)
        .expect("a URL")
        .port()
        .expect("the callback URL names its port");
    assert_ne!(callback_port, 0, "the bound port, not the requested one");

    // The aborted listener drops on its next poll; until then the port is held.
    let released = async {
        while tokio::net::TcpListener::bind(("127.0.0.1", callback_port))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), released)
        .await
        .expect("the callback listener is released");
}

/// The background task stops at a refused refresh: every later attempt meets
/// the same policy, and re-authorizing is not the remedy, so the refusal is
/// what it logs (MIK-7756).
#[tokio::test]
async fn background_renewal_stops_at_a_refused_refresh() {
    let dir = tempfile::tempdir().unwrap();
    assert_renewal_stops_at_the_refusal(client_with_refused_refresh(dir.path()).await).await;
}

/// The headless `client_credentials` fallback, taken when no refresh token is
/// held, stops at the same refusal.
#[tokio::test]
async fn background_renewal_stops_at_a_refused_client_credentials_grant() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client_with_refused_refresh(dir.path()).await;
    if let Some(token) = client.current_token.write().as_mut() {
        token.refresh_token = None;
    }
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.grant_types_supported = vec!["client_credentials".to_string()];
    }
    assert_renewal_stops_at_the_refusal(client).await;
}

async fn assert_renewal_stops_at_the_refusal(mut client: OAuthClient) {
    client.token_refresh_buffer_secs = 300;
    let (guard, buffer) = crate::oauth::callback::tests::capture();
    let ended = tokio::time::timeout(
        Duration::from_secs(10),
        OAuthClient::refresh_loop(
            Arc::new(tokio::sync::Mutex::new(client)),
            "listed-backend".to_string(),
            Duration::from_millis(10),
        ),
    )
    .await;
    drop(guard);
    let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(
        ended.is_ok(),
        "the task kept retrying a refused renewal: {log}"
    );
    assert!(log.contains("SSRF blocked"), "the refusal is logged: {log}");
    assert!(
        !log.contains("manual re-authorization"),
        "a refusal is not reported as needing re-authorization: {log}"
    );
}
