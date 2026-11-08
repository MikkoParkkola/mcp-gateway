// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Rows for `dashboard-link` and `events`: token, target and link handling.

use super::{DashboardLinkTls, LinkTls, TOKEN_ENV, TokenError, read_token};

fn no_flags() -> DashboardLinkTls {
    DashboardLinkTls::default()
}

/// No TLS material: the pre-#1832 request.
async fn fetch_link(base: &str, token: &str) -> Result<String, String> {
    super::fetch_link(base, token, &LinkTls::default()).await
}

#[test]
fn the_base_url_never_falls_back_past_a_config_that_failed_to_load() {
    use super::dashboard_link_base;
    let explicit = dashboard_link_base(
        Some("http://h:1".into()),
        no_flags(),
        || Err("x".into()),
        None,
        None,
    );
    assert_eq!(
        explicit.map(|(base, _)| base).as_deref(),
        Ok("http://h:1"),
        "--url wins without a load"
    );

    let failed = dashboard_link_base(None, no_flags(), || Err("bad yaml".into()), None, None)
        .expect_err("a config that fails to load is not replaced by defaults");
    assert!(
        failed.contains("bad yaml") && failed.contains("--url"),
        "{failed}"
    );

    let mut config = mcp_gateway::config::Config::default();
    config.server.port = 4100;
    let plain = dashboard_link_base(None, no_flags(), || Ok(config.clone()), None, None);
    assert_eq!(
        plain.map(|(base, _)| base).as_deref(),
        Ok("http://127.0.0.1:4100")
    );
    config.mtls.enabled = true;
    config.mtls.require_client_cert = false;
    let tls = dashboard_link_base(None, no_flags(), || Ok(config.clone()), Some(4200), None);
    assert_eq!(
        tls.map(|(base, _)| base).as_deref(),
        Ok("https://127.0.0.1:4200")
    );
}

/// E5-T21: the credential never goes out in cleartext to the network.
#[test]
fn cleartext_is_refused_off_loopback() {
    use super::check_target;
    for refused in [
        "http://10.0.0.5:39400",
        "http://gateway.example",
        "HTTP://192.0.2.1:1",
    ] {
        let err = check_target(refused).expect_err(refused);
        assert!(err.contains("cleartext"), "{refused}: {err}");
    }
    for allowed in [
        "http://127.0.0.1:39400",
        "http://localhost:39400/",
        "http://[::1]:39400",
        "https://gateway.example",
    ] {
        assert_eq!(check_target(allowed), Ok(()), "{allowed}");
    }
    let odd = check_target("ftp://127.0.0.1:1").expect_err("an unknown scheme");
    assert!(odd.contains("unsupported scheme"), "{odd}");
}

/// E5-T21b: `fetch_link` refuses before sending anything: 192.0.2.1 is a
/// documentation address, so a request would hang, not answer.
#[tokio::test]
async fn fetch_link_refuses_cleartext_before_sending() {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        fetch_link("http://192.0.2.1:9", "tok"),
    )
    .await
    .expect("refused at once, no connection attempted");
    let err = out.expect_err("cleartext target");
    assert!(err.contains("cleartext"), "{err}");
}

#[test]
fn the_token_comes_from_the_named_variable_only() {
    let token = read_token(|name| (name == TOKEN_ENV).then(|| "tok".to_string()));
    assert_eq!(token.as_deref(), Ok("tok"));

    let missing = read_token(|_| None).expect_err("no variable, no token");
    assert_eq!(missing, TokenError::Missing);
    assert!(missing.to_string().contains(TOKEN_ENV), "{missing}");

    for value in ["", "   "] {
        let blank = read_token(|_| Some(value.to_string())).expect_err("blank credential");
        assert_eq!(blank, TokenError::Blank);
        assert_eq!(blank.to_string(), "MCP_GATEWAY_TOKEN is empty.");
    }

    let padded = read_token(|_| Some(" tok ".to_string()));
    assert_eq!(
        padded.as_deref(),
        Ok(" tok "),
        "a credential is passed as given"
    );
}

/// An in-process gateway stand-in: answers the link only for `tok`.
async fn stand_in() -> String {
    use axum::http::{HeaderMap, StatusCode};
    let app = axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(|headers: HeaderMap| async move {
            let ok =
                headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok");
            if ok {
                Ok(axum::Json(serde_json::json!({
                    "link": "http://127.0.0.1:39400/dashboard?bootstrap=abc"
                })))
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// A `--url` carrying userinfo or a query token must not reach stderr.
#[tokio::test]
async fn errors_never_echo_url_credentials() {
    for base in [
        "http://user:PW1@10.0.0.5:9/x?token=Q1",
        "http://user:PW1@127.0.0.1:1/x?token=Q1",
        "ftp://user:PW1@h/x?token=Q1",
    ] {
        let err = fetch_link(base, "tok").await.expect_err(base);
        assert!(!err.contains("PW1") && !err.contains("Q1"), "{err}");
    }
    let err = super::check_target("not a url:PW1@?token=Q1").expect_err("unparseable");
    assert!(!err.contains("PW1") && !err.contains("Q1"), "{err}");
}

#[tokio::test]
async fn the_link_is_fetched_with_the_credential_as_a_bearer() {
    let base = stand_in().await;
    assert_eq!(
        fetch_link(&base, "tok").await.as_deref(),
        Ok("http://127.0.0.1:39400/dashboard?bootstrap=abc")
    );
    let refused = fetch_link(&format!("{base}/"), "wrong")
        .await
        .expect_err("a refused credential is an error");
    assert!(refused.contains("403"), "{refused}");
}

/// A redirect is never followed: the next hop was not checked by
/// `check_target`, and a same-host, same-port hop keeps the bearer.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let hop = axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            axum::Json(serde_json::json!({ "link": "http://127.0.0.1:1/dashboard" }))
        }
    });
    let hop_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let hop_url = format!(
        "http://{}/ui/api/dashboard-link",
        hop_listener.local_addr().expect("addr")
    );
    tokio::spawn(async move { axum::serve(hop_listener, hop).await });
    let redirector = axum::Router::new().fallback(move || {
        let location = hop_url.clone();
        async move {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, location)],
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, redirector).await });

    let refused = fetch_link(&base, "tok")
        .await
        .expect_err("a redirect is an error, not a link");
    assert!(refused.contains("307"), "{refused}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the redirect was followed");
}
