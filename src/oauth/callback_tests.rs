// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the OAuth callback server (moved out of `callback.rs` to keep it
//! under the file-size ceiling).
use super::*;

// =========================================================================
// CallbackParams deserialization
// =========================================================================

#[test]
fn callback_params_success_case() {
    let params: CallbackParams =
        serde_urlencoded::from_str("code=auth_code_123&state=random_state_456").unwrap();
    assert_eq!(params.code.as_deref(), Some("auth_code_123"));
    assert_eq!(params.state.as_deref(), Some("random_state_456"));
    assert!(params.error.is_none());
    assert!(params.error_description.is_none());
}

#[test]
fn callback_params_error_case() {
    let params: CallbackParams =
        serde_urlencoded::from_str("error=access_denied&error_description=User+denied+access")
            .unwrap();
    assert_eq!(params.error.as_deref(), Some("access_denied"));
    assert_eq!(
        params.error_description.as_deref(),
        Some("User denied access")
    );
    assert!(params.code.is_none());
}

#[test]
fn callback_params_carries_the_issuer() {
    // RFC 9207: the authorization server returns `iss`. It has to survive
    // deserialization before anything can validate it.
    let params: CallbackParams =
        serde_urlencoded::from_str("code=c&state=s&iss=https%3A%2F%2Fauth.example.com").unwrap();
    assert_eq!(params.iss.as_deref(), Some("https://auth.example.com"));
}

#[tokio::test]
async fn callback_server_forwards_the_issuer_to_the_redeemer() {
    // The mix-up defence lives at redeem time, so the value the server
    // received must reach the caller rather than being read and dropped.
    let server = start_callback_server("st4te".to_string(), Some("127.0.0.1"), None, None)
        .await
        .unwrap();
    let url = format!(
        "{}?code=c0de&state=st4te&iss=https://auth.example.com",
        server.callback_url
    );

    let get = tokio::spawn(async move { reqwest::get(&url).await });
    let (_, result) = server.wait_for_callback().await.unwrap();
    get.await.unwrap().unwrap();

    assert_eq!(result.iss.as_deref(), Some("https://auth.example.com"));
}

#[test]
fn callback_params_empty_query() {
    let params: CallbackParams = serde_urlencoded::from_str("").unwrap();
    assert!(params.code.is_none());
    assert!(params.state.is_none());
    assert!(params.error.is_none());
}

#[test]
fn escape_html_escapes_provider_error_text() {
    assert_eq!(
        escape_html("<script>alert('x') & \"y\"</script>"),
        "&lt;script&gt;alert(&#39;x&#39;) &amp; &quot;y&quot;&lt;/script&gt;"
    );
}

// =========================================================================
// start_callback_server - binds and provides URL
// =========================================================================

#[tokio::test]
async fn callback_server_binds_to_random_port() {
    let server = start_callback_server("test_state".to_string(), None, None, None)
        .await
        .unwrap();
    assert!(server.callback_url.starts_with("http://localhost:"));
    assert!(server.callback_url.ends_with("/oauth/callback"));
    // Clean up
    server.stop().await;
}

/// #2578: the redirect URI names the configured callback host, as
/// `docs/OAUTH_CONFIG.md` documents (`http://<callback_host>:<port><path>`),
/// and the server answers at exactly that address. A loopback IP host
/// used to be advertised as `localhost`, which a browser resolving
/// `localhost` to the other address family could not reach.
async fn served_where_advertised(host: &str, advertised_host: &str) {
    let server = start_callback_server("s".to_string(), Some(host), None, None)
        .await
        .unwrap();
    let port = reqwest::Url::parse(&server.callback_url)
        .unwrap()
        .port()
        .unwrap();
    assert_eq!(
        server.callback_url,
        format!("http://{advertised_host}:{port}/oauth/callback")
    );
    // Follow the advertised URI as given: that is what the browser does.
    let url = format!("{}?code=c&state=s", server.callback_url);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (outcome, _) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server.wait_for_callback(), client.get(url).send())
    })
    .await
    .expect("the advertised address answers");
    assert_eq!(outcome.expect("a code").1.code, "c");
}

fn ipv6_loopback_available() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

#[tokio::test]
async fn an_ipv4_callback_host_is_advertised_as_configured() {
    served_where_advertised("127.0.0.1", "127.0.0.1").await;
}

#[tokio::test]
async fn an_ipv6_callback_host_is_advertised_bracketed_and_bound() {
    if !ipv6_loopback_available() {
        eprintln!("no IPv6 loopback on this host; skipped");
        return;
    }
    served_where_advertised("::1", "[::1]").await;
    served_where_advertised("[::1]", "[::1]").await;
    // MIK-7739: the redirect URI keeps the configured spelling. A provider
    // compares it as a string, so `[::1]` would not match a registered
    // `[0:0:0:0:0:0:0:1]`.
    served_where_advertised("0:0:0:0:0:0:0:1", "[0:0:0:0:0:0:0:1]").await;
    served_where_advertised("[0:0:0:0:0:0:0:1]", "[0:0:0:0:0:0:0:1]").await;
}

/// Any other host keeps today's behaviour: the redirect URI names
/// `localhost`, and the server answers on 127.0.0.1, never beyond loopback.
#[tokio::test]
async fn a_non_loopback_host_keeps_the_localhost_redirect_on_loopback() {
    let server = start_callback_server("s".to_string(), Some("callback.example"), None, None)
        .await
        .unwrap();
    let advertised = reqwest::Url::parse(&server.callback_url).unwrap();
    assert_eq!(advertised.host_str(), Some("localhost"));
    let port = advertised.port().unwrap();
    let url = format!("http://127.0.0.1:{port}/oauth/callback?code=c&state=s");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (outcome, _) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(server.wait_for_callback(), client.get(url).send())
    })
    .await
    .expect("the loopback address answers");
    assert_eq!(outcome.expect("a code").1.code, "c");
}

#[tokio::test]
async fn callback_server_binds_to_specified_port() {
    // Use port 0 as fallback since specific ports might be taken
    let server = start_callback_server("test_state".to_string(), None, Some(0), None)
        .await
        .unwrap();
    assert!(server.callback_url.starts_with("http://localhost:"));
    server.stop().await;
}

#[tokio::test]
async fn callback_server_custom_path() {
    let server = start_callback_server("st".to_string(), None, None, Some("/auth/cb"))
        .await
        .unwrap();
    assert!(server.callback_url.ends_with("/auth/cb"));
    server.stop().await;
}

// =========================================================================
// Full callback flow (server + HTTP request)
// =========================================================================

#[tokio::test]
async fn callback_flow_success() {
    let state = "csrf_state_123".to_string();
    let server = start_callback_server(state.clone(), None, None, None)
        .await
        .unwrap();
    let callback_url = server.callback_url.clone();

    // Simulate the OAuth provider redirecting back
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{callback_url}?code=auth_code_xyz&state={state}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // The callback should have delivered the result
    let (url, result) = server.wait_for_callback().await.unwrap();
    assert_eq!(result.code, "auth_code_xyz");
    assert_eq!(url, callback_url);
}

#[tokio::test]
async fn callback_flow_state_mismatch() {
    let server = start_callback_server("expected_state".to_string(), None, None, None)
        .await
        .unwrap();
    let callback_url = server.callback_url.clone();

    let client = reqwest::Client::new();
    let _resp = client
        .get(format!("{callback_url}?code=code123&state=wrong_state"))
        .send()
        .await
        .unwrap();

    let result = server.wait_for_callback().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn callback_flow_error_from_provider() {
    let server = start_callback_server("some_state".to_string(), None, None, None)
        .await
        .unwrap();
    let callback_url = server.callback_url.clone();

    let client = reqwest::Client::new();
    let _resp = client
        .get(format!(
            "{callback_url}?error=access_denied&error_description=User+denied"
        ))
        .send()
        .await
        .unwrap();

    let result = server.wait_for_callback().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn callback_flow_missing_code() {
    let server = start_callback_server("state123".to_string(), None, None, None)
        .await
        .unwrap();
    let callback_url = server.callback_url.clone();

    let client = reqwest::Client::new();
    let _resp = client
        .get(format!("{callback_url}?state=state123"))
        .send()
        .await
        .unwrap();

    let result = server.wait_for_callback().await;
    assert!(result.is_err());
}

/// A log capture for the current thread. A process-wide registry keeps
/// every callsite's interest open, so an event is never filtered out by an
/// interest cached on another thread before the scoped subscriber sees it.
pub(in crate::oauth) fn capture() -> (
    tracing::subscriber::DefaultGuard,
    Arc<std::sync::Mutex<Vec<u8>>>,
) {
    static INTEREST: std::sync::Once = std::sync::Once::new();
    struct W(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for W {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    INTEREST.call_once(|| {
        use tracing_subscriber::prelude::*;
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || W(Arc::clone(&writer)))
        .finish();
    (tracing::subscriber::set_default(subscriber), buffer)
}

/// MIK-7324.COV.3: the operator's log names a forged state as a possible
/// CSRF attempt, and a good callback as a success, each by its event name.
#[tokio::test]
async fn callback_outcomes_are_logged_by_event_name() {
    let (guard, buffer) = capture();

    let forged = start_callback_server("expected".to_string(), Some("127.0.0.1"), None, None)
        .await
        .unwrap();
    let url = forged.callback_url.replace("localhost", "127.0.0.1");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (outcome, _) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            forged.wait_for_callback(),
            client.get(format!("{url}?code=c&state=forged")).send()
        )
    })
    .await
    .expect("the forged callback is answered");
    assert!(outcome.is_err(), "a forged state yields no code");

    let good = start_callback_server("expected".to_string(), Some("127.0.0.1"), None, None)
        .await
        .unwrap();
    let url = good.callback_url.replace("localhost", "127.0.0.1");
    let (outcome, _) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(
            good.wait_for_callback(),
            client.get(format!("{url}?code=c&state=expected")).send()
        )
    })
    .await
    .expect("the good callback is answered");
    assert_eq!(
        outcome.expect("a matching state yields the code").1.code,
        "c"
    );

    drop(guard);
    let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    for event in [
        "oauth.callback.received",
        "oauth.callback.state_mismatch",
        "oauth.callback.success",
    ] {
        assert!(log.contains(event), "{event} missing from:\n{log}");
    }
    assert!(log.contains("possible CSRF attempt"), "{log}");
}
