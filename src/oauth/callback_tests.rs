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

/// MIK-7739: the redirect URI's host keeps the configured IPv6 spelling,
/// checked without binding, so it holds on a machine with no IPv6 loopback.
#[test]
fn an_ipv6_callback_host_keeps_its_configured_spelling() {
    let ip = "0:0:0:0:0:0:0:1".parse().ok();
    assert_eq!(url_host("0:0:0:0:0:0:0:1", ip), "[0:0:0:0:0:0:0:1]");
    assert_eq!(url_host("[0:0:0:0:0:0:0:1]", ip), "[0:0:0:0:0:0:0:1]");
    assert_eq!(url_host("::1", "::1".parse().ok()), "[::1]");
    assert_eq!(url_host("127.0.0.1", "127.0.0.1".parse().ok()), "127.0.0.1");
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
    let server = start_callback_server("expected_state".to_string(), Some("127.0.0.1"), None, None)
        .await
        .expect("the callback server binds");
    let url = server.callback_url.replace("localhost", "127.0.0.1");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a loopback client builds");

    let resp = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        client
            .get(format!("{url}?code=code123&state=wrong_state"))
            .send(),
    )
    .await
    .expect("the mismatched callback is answered")
    .expect("the mismatched callback sends");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = tokio::time::timeout(crate::test_wait::HANG_BOUND, resp.text())
        .await
        .expect("the refusal body arrives")
        .expect("the refusal body reads");
    assert!(
        body.contains("State mismatch"),
        "the refusal names the state: {body}"
    );

    let valid = format!("{url}?code=ok&state=expected_state");
    tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
        .await
        .expect("the valid callback is answered")
        .expect("the valid callback sends");

    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers after a refusal");
    match outcome {
        Ok((_, result)) => assert_eq!(result.code, "ok"),
        Err(err) => panic!("the login continues after a refusal, got: {err:?}"),
    }
}

#[tokio::test]
async fn callback_flow_error_from_provider() {
    let server = start_callback_server("some_state".to_string(), None, None, None)
        .await
        .expect("the callback server binds");
    let callback_url = server.callback_url.clone();

    let client = reqwest::Client::new();
    let _resp = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        client
            .get(format!(
                "{callback_url}?error=access_denied&error_description=User+denied&state=some_state"
            ))
            .send(),
    )
    .await
    .expect("the provider error is answered")
    .expect("the provider error sends");

    let result = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers the provider error");
    assert!(result.is_err());
}

/// MIK-8658 (K3): provider text holding the busy marker is no busy lock.
#[tokio::test]
async fn provider_error_text_with_the_busy_marker_is_not_a_busy_lock() {
    let server = start_callback_server("s".to_string(), None, None, None)
        .await
        .expect("callback server starts");
    let callback_url = server.callback_url.clone();
    reqwest::Client::new()
        .get(format!(
            "{callback_url}?error=access_denied&error_description=credential+lock+busy%3A+x&state=s"
        ))
        .send()
        .await
        .expect("callback answers");
    let error = server.wait_for_callback().await.expect_err("login ended");
    let busy = crate::oauth::client::is_credential_lock_busy(&error);
    assert!(
        matches!(&error, Error::OAuth(m) if m == "OAuth error: access_denied - credential lock busy: x"),
        "{error:?}"
    );
    assert!(!busy, "{error}");
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
    crate::test_log_capture::keep_interest_open();
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
// Current-thread on purpose: `capture()` is thread-local.
#[tokio::test(flavor = "current_thread")]
async fn callback_outcomes_are_logged_by_event_name() {
    let (guard, buffer) = capture();

    let server = start_callback_server("expected".to_string(), Some("127.0.0.1"), None, None)
        .await
        .expect("the callback server binds");
    let url = server.callback_url.replace("localhost", "127.0.0.1");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a loopback client builds");

    let resp = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        client.get(format!("{url}?code=c&state=forged")).send(),
    )
    .await
    .expect("the forged callback is answered")
    .expect("the forged callback sends");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = tokio::time::timeout(crate::test_wait::HANG_BOUND, resp.text())
        .await
        .expect("the refusal body arrives")
        .expect("the refusal body reads");
    assert!(
        body.contains("State mismatch"),
        "the refusal names the state: {body}"
    );

    let valid = format!("{url}?code=c&state=expected");
    tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
        .await
        .expect("the good callback is answered")
        .expect("the good callback sends");
    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers after a refusal");
    let code = match outcome {
        Ok((_, result)) => result.code,
        Err(err) => panic!("a matching state yields the code, got: {err:?}"),
    };
    assert_eq!(code, "c");

    drop(guard);
    let bytes = buffer.lock().expect("the log buffer locks").clone();
    let log = String::from_utf8_lossy(&bytes).into_owned();
    for event in [
        "oauth.callback.received",
        "oauth.callback.state_mismatch",
        "oauth.callback.success",
    ] {
        assert!(log.contains(event), "{event} missing from:\n{log}");
    }
    assert!(log.contains("possible CSRF attempt"), "{log}");
}

// =========================================================================
// MIK-8674: state is checked before the login ends
// =========================================================================

/// Start a callback server for the state-first rows: loopback host, the URL as
/// the browser sees it, and a client that never proxies loopback.
async fn start_test_server(expected_state: &str) -> (CallbackServer, String, reqwest::Client) {
    let server = start_callback_server(expected_state.to_string(), Some("127.0.0.1"), None, None)
        .await
        .expect("the callback server binds");
    let url = server.callback_url.replace("localhost", "127.0.0.1");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("a loopback client builds");
    (server, url, client)
}

/// GET `full_url` and assert the state-first refusal: 400 with "State mismatch".
/// Returns the refusal page for callers that check what it leaves out.
async fn assert_refused(client: &reqwest::Client, full_url: String) -> String {
    let resp = tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(full_url).send())
        .await
        .expect("the refused request is answered")
        .expect("the refused request sends");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = tokio::time::timeout(crate::test_wait::HANG_BOUND, resp.text())
        .await
        .expect("the refusal body arrives")
        .expect("the refusal body reads");
    assert!(
        body.contains("State mismatch"),
        "the refusal names the state: {body}"
    );
    body
}

/// CBSTATE.1: a wrong or missing state with an error is refused and the login
/// continues to a later valid callback.
#[tokio::test]
async fn a_wrong_or_missing_state_with_an_error_is_refused_and_the_login_continues() {
    for refused_query in [
        "?error=access_denied&error_description=x&state=wrong",
        "?error=access_denied&error_description=x",
    ] {
        let (server, url, client) = start_test_server("expected").await;
        assert_refused(&client, format!("{url}{refused_query}")).await;
        let valid = format!("{url}?code=good&state=expected");
        tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
            .await
            .expect("the valid callback is answered")
            .expect("the valid callback sends");
        let outcome =
            tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
                .await
                .expect("the login answers after a refusal");
        match outcome {
            Ok((_, result)) => assert_eq!(result.code, "good", "case {refused_query}"),
            Err(err) => panic!("case {refused_query}: the login continues, got: {err:?}"),
        }
    }
}

/// CBSTATE.2: a wrong or missing state without an error is refused and the
/// login continues to a later valid callback.
#[tokio::test]
async fn a_wrong_or_missing_state_without_an_error_is_refused_and_the_login_continues() {
    for refused_query in [
        "?code=c&state=wrong",
        "?code=c",
        "",
        "?state=wrong",
        "?code=c&state=expectedX",
        "?code=c&state=expecte",
    ] {
        let (server, url, client) = start_test_server("expected").await;
        assert_refused(&client, format!("{url}{refused_query}")).await;
        let valid = format!("{url}?code=good&state=expected");
        tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
            .await
            .expect("the valid callback is answered")
            .expect("the valid callback sends");
        let outcome =
            tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
                .await
                .expect("the login answers after a refusal");
        match outcome {
            Ok((_, result)) => assert_eq!(result.code, "good", "case {refused_query}"),
            Err(err) => panic!("case {refused_query}: the login continues, got: {err:?}"),
        }
    }
}

/// CBSTATE.3: a provider error with the right state ends the login with it.
/// (Passes today; pins the branch the fix reorders.)
#[tokio::test]
async fn a_provider_error_with_the_right_state_ends_the_login_with_it() {
    let (server, url, client) = start_test_server("expected").await;
    let full = format!("{url}?error=access_denied&error_description=User+denied&state=expected");
    let resp = tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(full).send())
        .await
        .expect("the provider error is answered")
        .expect("the provider error sends");
    let page = tokio::time::timeout(crate::test_wait::HANG_BOUND, resp.text())
        .await
        .expect("the provider error page arrives")
        .expect("the provider error page reads");
    assert!(
        page.contains("Authorization Failed")
            && page.contains("access_denied")
            && page.contains("User denied"),
        "the right-state error keeps the provider's failure page: {page}"
    );
    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers the provider error");
    let err = match outcome {
        Err(err) => err,
        Ok((_, result)) => panic!("a provider error ends the login, got code: {}", result.code),
    };
    assert!(
        matches!(err, crate::Error::OAuth(ref t) if t.contains("access_denied") && t.contains("User denied")),
        "the login ends with the provider error: {err:?}"
    );
}

/// LOG.1: a refused request logs only the mismatch (with `state_len`) and no
/// attacker text, and no `provider_error` event.
// Current-thread on purpose: `capture()` is thread-local, so the axum
// handler must run on this thread for its events to be captured.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_request_logs_only_the_mismatch_and_no_attacker_text() {
    let (guard, buffer) = capture();
    let (server, url, client) = start_test_server("expected").await;
    let page = assert_refused(
        &client,
        format!("{url}?state=STATEMARK7f3&error=ERRMARK7f3&error_description=DESCMARK7f3"),
    )
    .await;
    for marker in ["STATEMARK7f3", "ERRMARK7f3", "DESCMARK7f3"] {
        assert!(
            !page.contains(marker),
            "{marker} must not reach the page: {page}"
        );
    }
    let valid = format!("{url}?code=c&state=expected");
    tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
        .await
        .expect("the valid callback is answered")
        .expect("the valid callback sends");
    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers after a refusal");
    match outcome {
        Ok((_, result)) => assert_eq!(result.code, "c"),
        Err(err) => panic!("the login continues after a refusal, got: {err:?}"),
    }
    drop(guard);
    let bytes = buffer.lock().expect("the log buffer locks").clone();
    let log = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        log.contains("oauth.callback.state_mismatch"),
        "the mismatch is logged:\n{log}"
    );
    assert!(
        log.contains(&format!("state_len={}", "STATEMARK7f3".len())),
        "the state length is logged:\n{log}"
    );
    for absent in [
        "oauth.callback.provider_error",
        "STATEMARK7f3",
        "ERRMARK7f3",
        "DESCMARK7f3",
    ] {
        assert!(!log.contains(absent), "{absent} must not be logged:\n{log}");
    }
}

/// REPEAT.1(a): three refusals then a valid callback completes the login.
#[tokio::test]
async fn three_refusals_then_a_valid_callback_completes_the_login() {
    let (server, url, client) = start_test_server("expected").await;
    for refused_query in ["?error=x&state=wrong1", "?code=c&state=wrong2", "?code=c"] {
        assert_refused(&client, format!("{url}{refused_query}")).await;
    }
    let valid = format!("{url}?code=good&state=expected");
    tokio::time::timeout(crate::test_wait::HANG_BOUND, client.get(valid).send())
        .await
        .expect("the valid callback is answered")
        .expect("the valid callback sends");
    let outcome = tokio::time::timeout(crate::test_wait::HANG_BOUND, server.wait_for_callback())
        .await
        .expect("the login answers after refusals");
    match outcome {
        Ok((_, result)) => assert_eq!(result.code, "good"),
        Err(err) => panic!("the login completes after refusals, got: {err:?}"),
    }
}

/// REPEAT.1(b): three refusals then the window ends the wait.
#[tokio::test]
async fn three_refusals_then_the_window_ends_the_wait() {
    let (server, url, client) = start_test_server("expected").await;
    for refused_query in ["?error=x&state=wrong1", "?code=c&state=wrong2", "?code=c"] {
        assert_refused(&client, format!("{url}{refused_query}")).await;
    }
    tokio::time::pause();
    let cancel = tokio_util::sync::CancellationToken::new();
    let outcome = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        server.wait_within(std::time::Duration::from_secs(1), &cancel),
    )
    .await
    .expect("the window ends the wait");
    assert!(
        matches!(outcome, Err(Unanswered::Window)),
        "the window ends the wait after refusals: {outcome:?}"
    );
}

/// REPEAT.1(c): three refusals then cancellation ends the wait.
#[tokio::test]
async fn three_refusals_then_cancellation_ends_the_wait() {
    let (server, url, client) = start_test_server("expected").await;
    for refused_query in ["?error=x&state=wrong1", "?code=c&state=wrong2", "?code=c"] {
        assert_refused(&client, format!("{url}{refused_query}")).await;
    }
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let outcome = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        server.wait_within(crate::test_wait::HANG_BOUND, &cancel),
    )
    .await
    .expect("cancellation ends the wait");
    assert!(
        matches!(outcome, Err(Unanswered::Cancelled)),
        "cancellation ends the wait after refusals: {outcome:?}"
    );
}
