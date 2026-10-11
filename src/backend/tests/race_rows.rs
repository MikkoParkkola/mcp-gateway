// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8258: the two probe-rebuild interleavings MIK-8012 named, driven
//! rather than inferred. RACE.1: a non-interactive rebuild parked past its
//! login check while a call's refresh holds the old transport's OAuth client.
//! RACE.5: a probe whose start was refused by an interactive start in flight,
//! decided only after that start published.

use super::login_window::{Browser, approve, login_backend, spawn_call, variant, within};
use super::*;

/// A token server whose `grant_type=refresh_token` requests wait until the
/// test releases them, counted as they arrive.
#[derive(Default)]
struct RefreshStall {
    arrivals: AtomicUsize,
    released: AtomicBool,
    release: tokio::sync::Notify,
}

impl RefreshStall {
    fn arrivals(&self) -> usize {
        self.arrivals.load(Ordering::SeqCst)
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.release.notify_waiters();
    }

    async fn reached(&self, n: usize, what: &str) {
        within(what, async {
            while self.arrivals() < n {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
    }
}

/// An authorization server that issues an access token good for `expires_in`
/// seconds plus a refresh token, holding every refresh as `stall` says, and an
/// MCP endpoint at `/mcp` that answers the handshake, `tools/list` and
/// `tools/call`. Returns its origin.
async fn refreshing_server(stall: Arc<RefreshStall>, expires_in: u64) -> String {
    use axum::http::StatusCode;
    use axum::{Json, Router, routing::get, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let metadata = json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/authorize"),
        "token_endpoint": format!("{origin}/token"),
    });
    let token = move |body: String| {
        let stall = Arc::clone(&stall);
        async move {
            if body.contains("grant_type=refresh_token") {
                stall.arrivals.fetch_add(1, Ordering::SeqCst);
                let released = stall.release.notified();
                if !stall.released.load(Ordering::SeqCst) {
                    released.await;
                }
            }
            Json(json!({
                "access_token": "race-token",
                "token_type": "Bearer",
                "expires_in": expires_in,
                "refresh_token": "race-refresh",
            }))
        }
    };
    let mcp = |Json(request): Json<Value>| async move {
        let Some(id) = request.get("id").cloned() else {
            return (StatusCode::ACCEPTED, Json(Value::Null));
        };
        let body = match request["method"].as_str() {
            Some("initialize") => json!({"jsonrpc": "2.0", "id": id, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "race-rows", "version": "1"},
            }}),
            Some("tools/list") => json!({"jsonrpc": "2.0", "id": id, "result": {"tools": []}}),
            Some("tools/call") => json!({"jsonrpc": "2.0", "id": id, "result": {
                "content": [{"type": "text", "text": "served"}],
            }}),
            Some("ping") => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
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
        .route("/token", post(token))
        .route("/mcp", post(mcp));
    tokio::spawn(async move { axum::serve(listener, app).await });
    origin
}

/// The transport the shared slot holds now.
fn pooled(backend: &Backend) -> Option<Arc<dyn Transport>> {
    backend.shared_entry().transport.read().clone()
}

/// Whether the slot holds exactly `expected`; an empty slot is `false`, so a
/// take-first restart fails here and not at an earlier unwrap.
fn still_pooled(backend: &Backend, expected: &Arc<dyn Transport>) -> bool {
    pooled(backend).is_some_and(|now| Arc::ptr_eq(expected, &now))
}

/// Start `backend` interactively in the background.
fn spawn_start(backend: &Arc<Backend>) -> tokio::task::JoinHandle<Result<()>> {
    let backend = Arc::clone(backend);
    tokio::spawn(async move { backend.ensure_started().await })
}

/// A backend on a fresh [`refreshing_server`], started through an approved
/// login.
async fn started(stall: &Arc<RefreshStall>) -> (Arc<Backend>, Arc<Browser>, tempfile::TempDir) {
    let origin = refreshing_server(Arc::clone(stall), 3600).await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(5), None);
    let start = spawn_start(&backend);
    approve(&browser.opened(1, "the start opening the browser").await).await;
    within("the start completing with a token", start)
        .await
        .expect("start task")
        .expect("the approved login starts the backend");
    (backend, browser, dir)
}

/// RACE.1: the stored token has lapsed. A non-interactive rebuild passes its
/// login check and parks; a call then refreshes on the pooled transport and
/// stalls at the token server, holding that transport's OAuth client. Once
/// released, the rebuild cannot authorize its replacement, and the pooled
/// transport is the same one, still connected. The call then completes on it.
#[tokio::test]
async fn a_probe_rebuild_leaves_a_transport_whose_token_is_being_refreshed() {
    let stall = Arc::new(RefreshStall::default());
    let (backend, browser, _dir) = started(&stall).await;
    let old = pooled(&backend).expect("premise: the backend started");
    super::token_lapse::lapse(&backend).await;

    let gate = Arc::new(MarkWindowGate::default());
    *backend.restart_take_gate.lock() = Some(Arc::clone(&gate));
    let restarting = {
        let backend = Arc::clone(&backend);
        // Inside the task: a spawn does not inherit the non-interactive scope.
        tokio::spawn(async move {
            crate::oauth::login_gate::non_interactive(backend.force_restart()).await
        })
    };
    within(
        "the restart reaching its take gate",
        gate.reached.notified(),
    )
    .await;
    assert!(
        !backend.login_gate.in_flight(),
        "premise: the restart passed its login check with none in flight"
    );
    assert_eq!(stall.arrivals(), 0, "premise: no refresh before the call");

    let call = spawn_call(&backend);
    stall
        .reached(1, "the call's refresh stalling at the server")
        .await;
    gate.release.notify_one();

    // A hang here names its suspect: the replacement start waiting on the
    // per-credential refresh lock the stalled refresh holds.
    let error = within(
        "the parked restart returning (did the replacement start wait on the \
         per-credential refresh lock the stalled refresh holds?)",
        restarting,
    )
    .await
    .expect("restart task")
    .expect_err("a lapsed token cannot be renewed without a login");
    assert!(
        variant(&error).starts_with("AuthorizationRequired"),
        "the replacement could not authorize: {error:?}"
    );
    assert_eq!(
        stall.arrivals(),
        1,
        "the stalled refresh is the call's alone; the rebuild refreshed nothing"
    );
    assert!(
        still_pooled(&backend, &old),
        "the rebuild must leave the transport whose token is being refreshed"
    );
    assert!(old.is_connected(), "and it must still be usable");
    assert_eq!(browser.opens(), 1, "the rebuild opened no login");

    stall.release();
    let answer = within("the call parked on the refresh", call)
        .await
        .expect("call task")
        .expect("the refreshed call is served");
    assert_eq!(
        answer.result,
        Some(json!({"content": [{"type": "text", "text": "served"}]})),
        "the call completed on the pooled transport: {answer:?}"
    );
}

/// RACE.5: an interactive start holds the start lock while its login is
/// pending, so the probe's start is refused as an authorization wait. The
/// probe parks there; the login is approved and the start publishes its
/// transport. Released, the probe must not rebuild: the published transport
/// stays pooled. The token is long-lived, so a rebuild would succeed and
/// replace it.
#[tokio::test]
async fn a_start_that_publishes_while_the_probe_waits_stays_pooled() {
    let stall = Arc::new(RefreshStall::default());
    let origin = refreshing_server(Arc::clone(&stall), 3600).await;
    let dir = tempfile::tempdir().unwrap();
    let browser = Browser::new();
    let backend = login_backend(&origin, dir.path(), &browser, Duration::from_secs(5), None);
    let start = spawn_start(&backend);
    let url = browser.opened(1, "the start opening the browser").await;

    let gate = Arc::new(MarkWindowGate::default());
    *backend.probe_error_gate.lock() = Some(Arc::clone(&gate));
    let probing = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.health_probe(Duration::from_secs(5)).await })
    };
    within("the probe's refused start", gate.reached.notified()).await;

    approve(&url).await;
    within("the start publishing", start)
        .await
        .expect("start task")
        .expect("the approved login starts the backend");
    let published = pooled(&backend).expect("the start published its transport");
    gate.release.notify_one();

    let error = within("the probe", probing)
        .await
        .expect("probe task")
        .expect_err("the probe's own start was refused");
    assert!(
        error.is_authorization_wait(),
        "the probe met the pending login: {error:?}"
    );
    assert!(
        still_pooled(&backend, &published),
        "the probe must not replace the transport the start published"
    );
    assert!(published.is_connected(), "and it must still be usable");
    assert_eq!(
        backend.rebuilds_attempted.load(Ordering::SeqCst),
        0,
        "an authorization wait is no fault to rebuild"
    );
}
