// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7982: a backend start waiting on an interactive login is bounded, its
//! callers share one login, and stop or restart ends it.
//!
//! The authorization server is a loopback stub (metadata and token endpoint);
//! the browser is the test, through the backend's OAuth test seam.

use std::sync::Mutex as StdMutex;

use super::*;
use crate::backend::OAuthTestSeam;

/// The person at the browser: every authorization URL a start handed over.
struct Browser {
    opened: StdMutex<Vec<String>>,
    signal: tokio::sync::Notify,
}

impl Browser {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            opened: StdMutex::new(Vec::new()),
            signal: tokio::sync::Notify::new(),
        })
    }

    fn opens(&self) -> usize {
        self.opened.lock().unwrap().len()
    }

    /// Wait until the browser has opened `n` times in all.
    async fn opened(&self, n: usize, what: &str) -> String {
        within(what, async {
            loop {
                let notified = self.signal.notified();
                if let Some(url) = self.opened.lock().unwrap().get(n - 1) {
                    return url.clone();
                }
                notified.await;
            }
        })
        .await
    }
}

/// Bounds a wait, so a regression fails at its assertion instead of hanging.
async fn within<T>(what: &str, wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), wait)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within 20s"))
}

/// An authorization server on loopback: its metadata, and a token endpoint
/// that refuses every code (`invalid_grant`). Returns its origin.
async fn authorization_server() -> String {
    use axum::{Json, Router, http::StatusCode, routing::get, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let metadata = json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": format!("{origin}/token"),
    });
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = metadata.clone();
                async move { Json(body) }
            }),
        )
        .route(
            "/token",
            post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_grant" })),
                )
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await });
    origin
}

/// An HTTP backend at `origin` whose OAuth client keeps tokens in `dir` and
/// opens `browser`, with `timeout` as its request (and fill) bound. A fixed
/// `callback_port` makes a held callback listener visible as a held port.
fn login_backend(
    origin: &str,
    dir: &std::path::Path,
    browser: &Arc<Browser>,
    timeout: Duration,
    callback_port: Option<u16>,
) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "login-window",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: format!("{origin}/mcp"),
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout,
            oauth: Some(crate::config::OAuthConfig {
                enabled: true,
                scopes: vec![],
                client_id: Some("login-window-client".to_string()),
                client_secret: None,
                callback_host: Some("127.0.0.1".to_string()),
                callback_port,
                callback_path: None,
                token_refresh_buffer_secs: 300,
                shared_account: false,
            }),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let seen = Arc::clone(browser);
    *backend.oauth_test_seam.lock() = Some(OAuthTestSeam {
        storage_dir: dir.to_path_buf(),
        open_browser: Arc::new(move |url: &str| {
            seen.opened.lock().unwrap().push(url.to_string());
            seen.signal.notify_waiters();
            true
        }),
    });
    backend
}

/// Start `backend` in the background, as a caller with no deadline of its own.
fn spawn_start(backend: &Arc<Backend>) -> tokio::task::JoinHandle<Result<()>> {
    let backend = Arc::clone(backend);
    tokio::spawn(async move { backend.ensure_started().await })
}

/// A loopback port nothing listens on.
async fn free_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// The callback listener on `port` is gone: the port binds again.
async fn assert_port_released(port: u16, what: &str) {
    within(what, async {
        while tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_err()
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// Play the person at the browser for the authorization URL `url`: call its
/// callback with a code and the URL's own state.
async fn approve(url: &str) {
    let parsed = url::Url::parse(url).unwrap();
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    let callback = url::Url::parse_with_params(
        &query["redirect_uri"],
        &[
            ("code", "login-window-code"),
            ("state", query["state"].as_str()),
        ],
    )
    .unwrap();
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(callback)
        .send()
        .await
        .expect("the callback answers");
}

fn variant(error: &Error) -> String {
    format!("{error:?}")
}

/// MIK-7982.BOUND.2 (T2): five starts waiting on one interactive login share
/// it: one browser, one window. When the 300 s window passes, every one ends
/// with `AuthorizationIncomplete`, the breaker counts nothing, and the next
/// start begins a fresh login.
#[tokio::test]
async fn five_starts_share_one_login_and_end_together_at_the_window() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);
    let starts: Vec<_> = (0..5).map(|_| spawn_start(&backend)).collect();
    browser
        .opened(1, "the first start opening the browser")
        .await;

    // Discovery is done; only the callback wait and timers remain, so the
    // window can pass on paused time.
    tokio::time::pause();
    let ended = tokio::time::timeout(Duration::from_secs(301), async {
        let mut ended = Vec::new();
        for start in starts {
            ended.push(start.await.expect("start task"));
        }
        ended
    })
    .await
    .expect("every start waiting on the login must end when the 300 s window passes");
    tokio::time::resume();

    for outcome in ended {
        let error = outcome.expect_err("nobody approved, so no start succeeds");
        assert!(
            variant(&error).starts_with("AuthorizationIncomplete"),
            "a login nobody finished ends as AuthorizationIncomplete: {error:?}"
        );
    }
    assert_eq!(browser.opens(), 1, "five starts, one login");
    assert_eq!(
        backend.health_metrics().failure_count,
        0,
        "an unfinished login is not a backend failure"
    );
    let sixth = spawn_start(&backend);
    browser
        .opened(2, "a start after the window beginning a fresh login")
        .await;
    sixth.abort();
}

/// MIK-7982.BOUND.3 (T3): stopping a backend whose start waits on a login
/// ends that login and frees its callback port, and the waiting start ends.
#[tokio::test]
async fn stop_ends_a_pending_login_and_frees_its_port() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let port = free_port().await;
    let backend = login_backend(
        &origin,
        dir.path(),
        &browser,
        Duration::from_secs(30),
        Some(port),
    );
    let start = spawn_start(&backend);
    browser.opened(1, "the start opening the browser").await;

    tokio::time::timeout(Duration::from_secs(60), backend.stop())
        .await
        .expect("stop returns within its own budgets")
        .expect("stop");

    assert_port_released(
        port,
        "the pending login's callback listener closing on stop",
    )
    .await;
    let ended = within("the start ending once its backend stopped", start)
        .await
        .expect("start task");
    assert!(ended.is_err(), "a stopped backend's start does not succeed");
}

/// MIK-7982.BOUND.3 (T3b): a forced restart ends the pending login before it
/// starts again, so the restart's own login binds the same fixed callback
/// port and opens the browser, rather than queueing behind the stalled start.
#[tokio::test]
async fn a_forced_restart_ends_the_pending_login_before_binding_again() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let port = free_port().await;
    let backend = login_backend(
        &origin,
        dir.path(),
        &browser,
        Duration::from_secs(30),
        Some(port),
    );
    let _start = spawn_start(&backend);
    browser.opened(1, "the start opening the browser").await;

    let restart = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.force_restart().await })
    };

    browser
        .opened(
            2,
            "the restart's own login opening the browser on the freed port",
        )
        .await;
    restart.abort();
}

/// MIK-7982 r6 HIGH 1 (R6H1): a login whose token exchange fails fails every
/// start that joined it with the same typed error, and the start after that
/// begins a fresh login: a failure is not remembered as the cohort's outcome.
#[tokio::test]
async fn a_failed_login_fails_its_joiners_and_leaves_the_next_start_fresh() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);
    let starts: Vec<_> = (0..3).map(|_| spawn_start(&backend)).collect();
    let url = browser
        .opened(1, "the first start opening the browser")
        .await;

    approve(&url).await;

    for start in starts {
        let error = within("each start sharing the failed login's outcome", start)
            .await
            .expect("start task")
            .expect_err("the token endpoint refused the code");
        assert!(
            variant(&error).starts_with("OAuth"),
            "a joiner gets the failed login's typed error: {error:?}"
        );
    }
    assert_eq!(
        browser.opens(),
        1,
        "the joiners shared the one failed login"
    );
    let next = spawn_start(&backend);
    browser
        .opened(2, "a start after a failed login beginning a fresh one")
        .await;
    next.abort();
}

/// A check-site fill on `backend`, bounded by its own call timeout.
async fn fill(
    backend: &Arc<Backend>,
) -> Result<(Arc<Vec<Tool>>, super::super::fill_check::Completeness)> {
    backend.tools_for_check(None, &[], false).await
}

/// MIK-7982 r5 HIGH 2 (R5H2b, C3): a fill that captured the pending login's
/// cohort, and is still waiting on it when its own deadline passes, ends as
/// `AuthorizationPending`: the backend did not fail, the person has not
/// finished logging in. The breaker counts nothing.
#[tokio::test]
async fn a_start_waiting_on_the_login_times_out_as_authorization_pending() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(1), None);
    let _warm = spawn_start(&backend);
    browser
        .opened(1, "the warm start opening the browser")
        .await;
    let before = backend.health_metrics().failure_count;

    let error = within("the fill's own deadline", fill(&backend))
        .await
        .expect_err("no tools while the login is pending");

    assert!(
        variant(&error).starts_with("AuthorizationPending"),
        "a deadline spent waiting on a login is AuthorizationPending: {error:?}"
    );
    assert_eq!(
        backend.health_metrics().failure_count,
        before,
        "a pending login is not a backend failure"
    );
}

/// MIK-7982 r5 MED (R5M, C4): a fill that joined another caller's fill, whose
/// owner waits on the pending login, keeps the owner's provenance at the outer
/// `tools_for_check` deadline: both read `AuthorizationPending`.
#[tokio::test]
async fn the_outer_tools_for_check_deadline_keeps_the_fill_owners_provenance() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(1), None);
    let _warm = spawn_start(&backend);
    browser
        .opened(1, "the warm start opening the browser")
        .await;
    let before = backend.health_metrics().failure_count;

    let (owner, joiner) = within("both fills' deadlines", async {
        tokio::join!(fill(&backend), fill(&backend))
    })
    .await;

    for (who, outcome) in [("owner", owner), ("joiner", joiner)] {
        let error = outcome.expect_err("no tools while the login is pending");
        assert!(
            variant(&error).starts_with("AuthorizationPending"),
            "{who}: the joined fill keeps the owner's provenance: {error:?}"
        );
    }
    assert_eq!(
        backend.health_metrics().failure_count,
        before,
        "a pending login is not a backend failure"
    );
}

/// MIK-7982 (delta review, HIGH): a start keeps the cancel epoch it set out
/// at, however late its detached OAuth task is first scheduled. A restart's
/// cancel that came in between refuses its login: no browser opens.
#[tokio::test]
async fn a_start_cancelled_before_its_login_task_runs_opens_no_login() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);
    let set_out = backend.login_gate.epoch();
    // A restart's cancel, after the start set out but before its task ran.
    backend.login_gate.cancel_and_join().await;

    let entry = backend.shared_entry();
    let started = within(
        "the cancelled start ending",
        crate::oauth::login_gate::set_out(
            set_out,
            backend.start_entry(&crate::backend::pool::PoolKey::Shared, &entry),
        ),
    )
    .await;

    assert!(
        started.is_err(),
        "a cancelled start hands over no transport"
    );
    assert_eq!(
        browser.opens(),
        0,
        "a cancelled start opens no login: {:?}",
        started.err()
    );
}

/// MIK-7982 (delta review): the health probe's rebuild with no login in
/// flight leaves the cancel epoch alone, so it cannot refuse the login of an
/// interactive start still discovering.
#[tokio::test]
async fn a_non_interactive_restart_cancels_nothing() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(5), None);
    let before = backend.login_gate.epoch();

    let _ = within(
        "the probe's rebuild",
        crate::oauth::login_gate::non_interactive(backend.force_restart()),
    )
    .await;

    assert_eq!(
        backend.login_gate.epoch(),
        before,
        "a non-interactive rebuild bumped the cancel epoch"
    );
    assert_eq!(
        browser.opens(),
        0,
        "a non-interactive rebuild opens no login"
    );
}

/// MIK-7982 C2 (NonInteractive): a health probe on an OAuth backend with no
/// token never begins a login. It answers `AuthorizationRequired` at once,
/// and the browser stays closed.
#[tokio::test]
async fn a_health_probe_never_begins_a_login() {
    let origin = authorization_server().await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(30), None);

    tokio::select! {
        outcome = backend.health_probe(Duration::from_secs(5)) => {
            let error = outcome.expect_err("no token, so the probe cannot look");
            assert!(
                variant(&error).starts_with("AuthorizationRequired"),
                "a probe that would need a login answers AuthorizationRequired: {error:?}"
            );
        }
        _ = browser.opened(1, "the probe answering") => {
            panic!("a health probe began an interactive login");
        }
    }
    assert_eq!(browser.opens(), 0, "a probe never opens the browser");
}

/// An authorization server that issues a token good for `expires_in` seconds
/// (no refresh token), and an MCP endpoint at `/mcp` that answers the
/// handshake and lists no tools. Returns its origin.
async fn issuing_server(expires_in: u64) -> String {
    use axum::{Json, Router, http::StatusCode, routing::get, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let metadata = json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": format!("{origin}/token"),
    });
    let mcp = |Json(request): Json<Value>| async move {
        let Some(id) = request.get("id").cloned() else {
            return (StatusCode::ACCEPTED, Json(Value::Null));
        };
        let body = match request["method"].as_str() {
            Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "login-window", "version": "1"},
            }}),
            Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
            _ => json!({"jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "method not found"}}),
        };
        (StatusCode::OK, Json(body))
    };
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || {
                let body = metadata.clone();
                async move { Json(body) }
            }),
        )
        .route(
            "/token",
            post(move || async move {
                Json(json!({
                    "access_token": "login-window-token",
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                }))
            }),
        )
        .route("/mcp", post(mcp));
    tokio::spawn(async move { axum::serve(listener, app).await });
    origin
}

/// MIK-7982 r6 HIGH 2 (R6H2, C3): the transport is up, its token has lapsed,
/// and a fill's request-time token step joins the login that opens. When the
/// fill's deadline passes, nothing was handed to the transport yet, so it is
/// `AuthorizationPending`, and the breaker counts nothing.
#[tokio::test]
async fn a_request_waiting_on_a_request_time_login_times_out_as_authorization_pending() {
    // 65 s, less the 60 s early-expiry margin: good for the start, gone after.
    let origin = issuing_server(65).await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(1), None);
    let start = spawn_start(&backend);
    let url = browser.opened(1, "the start opening the browser").await;
    approve(&url).await;
    within("the start completing with a token", start)
        .await
        .expect("start task")
        .expect("the approved login starts the backend");
    sleep(Duration::from_secs(6)).await;
    let before = backend.health_metrics().failure_count;

    let error = within("the fill's own deadline", fill(&backend))
        .await
        .expect_err("no tools while the request-time login is pending");

    assert_eq!(
        browser.opens(),
        2,
        "the lapsed token opened a request-time login"
    );
    assert!(
        variant(&error).starts_with("AuthorizationPending"),
        "a deadline spent on the request-time login is AuthorizationPending: {error:?}"
    );
    assert_eq!(
        backend.health_metrics().failure_count,
        before,
        "a pending login is not a backend failure"
    );
}
