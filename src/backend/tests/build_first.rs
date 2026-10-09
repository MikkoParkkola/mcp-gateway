// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8012 / MIK-8016 (RACE.2a): a non-interactive rebuild of an HTTP
//! backend never removes the pooled transport unless its replacement
//! started. A failed replacement leaves the old transport pooled and serving.

use super::login_window::{LAPSE, Upstream, approved_start, variant, within};
use super::*;

/// The transport the shared slot holds now.
fn pooled(backend: &Backend) -> Option<Arc<dyn Transport>> {
    backend.shared_entry().transport.read().clone()
}

/// KEEP.1: the token lapsed, so a non-interactive start cannot authorize.
/// The health probe's rebuild fails, and the working transport stays.
#[tokio::test]
async fn a_failed_replacement_keeps_serving_the_old_transport() {
    let (backend, browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(5)).await;
    let old = pooled(&backend).expect("premise: the backend started");
    sleep(LAPSE).await;

    let error = within(
        "the probe's rebuild",
        Box::pin(crate::oauth::login_gate::non_interactive(
            backend.force_restart(),
        )),
    )
    .await
    .expect_err("a lapsed token cannot be renewed without a login");
    assert!(
        variant(&error).starts_with("AuthorizationRequired"),
        "the replacement could not authorize: {error:?}"
    );

    let now = pooled(&backend).expect("the old transport must stay pooled");
    assert!(
        Arc::ptr_eq(&old, &now),
        "a failed replacement must not replace the working transport"
    );
    assert!(now.is_connected(), "and it must still be usable");
    assert_eq!(browser.opens(), 1, "the rebuild opened no login");
}

/// RETIRE.1: a successful rebuild publishes the replacement at once, but the
/// old transport closes only after its last holder lets go; a call still
/// running on it is never cut off.
#[tokio::test]
async fn the_old_transport_closes_after_its_last_holder() {
    let (backend, _browser, _dir) = approved_start(Upstream::Plain, Duration::from_secs(5)).await;
    let held = pooled(&backend).expect("premise: the backend started");

    let outcome = within(
        "the probe's rebuild",
        Box::pin(crate::oauth::login_gate::non_interactive(
            backend.force_restart(),
        )),
    )
    .await
    .expect("the token is still good, so the replacement starts");
    assert!(matches!(outcome, RestartOutcome::Rebuilt), "{outcome:?}");

    let now = pooled(&backend).expect("the replacement is pooled");
    assert!(!Arc::ptr_eq(&held, &now), "the slot holds the replacement");
    sleep(Duration::from_millis(200)).await;
    assert!(
        held.is_connected(),
        "the old transport closed under a caller still holding it"
    );

    drop(now);
    let old = Arc::downgrade(&held);
    drop(held);
    within("the old transport closing", async {
        while old.upgrade().is_some() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// PACE.1: the health loop starts its next pass a full period after the
/// previous pass ENDS. A slow failing rebuild (here the first pass, three
/// periods long) is not retried with no gap, as a fixed-grid interval would.
#[tokio::test(start_paused = true)]
async fn a_slow_pass_is_followed_by_a_full_period() {
    let period = Duration::from_secs(10);
    let mut ticker = crate::backend::HealthTicker::new(period);
    let mut passes = Vec::new();
    let began = tokio::time::Instant::now();
    for pass in 0..3 {
        ticker.tick().await;
        let start = tokio::time::Instant::now();
        if pass == 0 {
            sleep(period * 3).await;
        }
        passes.push((start, tokio::time::Instant::now()));
    }
    assert_eq!(
        passes[0].0, began,
        "the first pass runs at once, as at startup today"
    );
    for pair in passes.windows(2) {
        let ((_, ended), (started, _)) = (pair[0], pair[1]);
        assert!(
            started >= ended + period,
            "a pass began {:?} after the previous one ended; the period is {period:?}",
            started - ended
        );
    }
}

/// How [`era_stub`] answers `server/discover`.
const DISCOVER_MODERN: u8 = 0;
const DISCOVER_HELD: u8 = 1;
const DISCOVER_LEGACY: u8 = 2;

/// Control of an [`era_stub`]: its discovery answer, how many probes and
/// which `tools/list` requests (by whether they carried `_meta`) it saw.
struct EraStub {
    mode: Arc<std::sync::atomic::AtomicU8>,
    release: Arc<tokio::sync::Notify>,
    discovers: Arc<AtomicUsize>,
    lists: Arc<std::sync::Mutex<Vec<bool>>>,
}

/// An MCP server on loopback whose era probe answers as [`EraStub::mode`] says.
async fn era_stub() -> (String, EraStub) {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let stub = EraStub {
        mode: Arc::new(std::sync::atomic::AtomicU8::new(DISCOVER_MODERN)),
        release: Arc::new(tokio::sync::Notify::new()),
        discovers: Arc::new(AtomicUsize::new(0)),
        lists: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let (mode, release, discovers, lists) = (
        Arc::clone(&stub.mode),
        Arc::clone(&stub.release),
        Arc::clone(&stub.discovers),
        Arc::clone(&stub.lists),
    );
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let (mode, release, discovers, lists) = (
            Arc::clone(&mode),
            Arc::clone(&release),
            Arc::clone(&discovers),
            Arc::clone(&lists),
        );
        async move {
            let Some(id) = message.get("id").cloned() else {
                return StatusCode::ACCEPTED.into_response();
            };
            let modern_answer = json!({ "jsonrpc": "2.0", "id": id, "result": {
                "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                "capabilities": {}
            }});
            let body = match message["method"].as_str().unwrap_or_default() {
                "server/discover" => {
                    discovers.fetch_add(1, Ordering::SeqCst);
                    match mode.load(Ordering::SeqCst) {
                        DISCOVER_HELD => {
                            release.notified().await;
                            modern_answer
                        }
                        DISCOVER_LEGACY => json!({ "jsonrpc": "2.0", "id": id,
                            "error": { "code": -32601, "message": "method not found" } }),
                        _ => modern_answer,
                    }
                }
                "initialize" => json!({ "jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                    "capabilities": {},
                    "serverInfo": { "name": "era-stub", "version": "0" }
                }}),
                "tools/list" => {
                    lists
                        .lock()
                        .unwrap()
                        .push(message["params"].get("_meta").is_some());
                    json!({ "jsonrpc": "2.0", "id": id, "result": { "tools": [] } })
                }
                _ => json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32601, "message": "method not found" } }),
            };
            axum::Json(body).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, stub)
}

/// A plain HTTP backend (no OAuth) at `url`.
fn http_backend(url: String) -> Arc<Backend> {
    Arc::new(Backend::new(
        "build-first-era",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn non_interactive_restart(
    backend: &Arc<Backend>,
) -> tokio::task::JoinHandle<Result<RestartOutcome>> {
    let backend = Arc::clone(backend);
    tokio::spawn(
        async move { crate::oauth::login_gate::non_interactive(backend.force_restart()).await },
    )
}

/// ERA.1 + ERA.2 (upgrade kept): while the candidate's era probe is held, the
/// old transport keeps its Modern verdict and keeps shaping calls Modern;
/// once the candidate is published its own probe's verdict is installed.
#[tokio::test]
async fn the_old_transport_keeps_its_era_while_the_candidate_probes() {
    use crate::protocol::era::Era;
    let (url, stub) = era_stub().await;
    let backend = http_backend(url);
    backend.start().await.expect("premise: the backend starts");
    let entry = backend.shared_entry();
    assert_eq!(
        entry.era.cached().await,
        Some(Era::Modern),
        "premise: modern"
    );
    let old = pooled(&backend).expect("premise: pooled");

    stub.mode.store(DISCOVER_HELD, Ordering::SeqCst);
    let restart = non_interactive_restart(&backend);
    within("the candidate's probe reaching the peer", async {
        while stub.discovers.load(Ordering::SeqCst) < 2 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    assert_eq!(
        entry.era.cached_now(),
        Some(Era::Modern),
        "the serving transport lost its verdict while the candidate probed"
    );
    old.request("tools/list", None)
        .await
        .expect("the old transport still serves");
    assert_eq!(
        stub.lists.lock().unwrap().last(),
        Some(&true),
        "a call on the old transport during the probe was not shaped Modern"
    );

    stub.mode.store(DISCOVER_MODERN, Ordering::SeqCst);
    stub.release.notify_waiters();
    let outcome = within("the restart", restart)
        .await
        .expect("restart task")
        .expect("the candidate starts");
    assert!(matches!(outcome, RestartOutcome::Rebuilt), "{outcome:?}");
    assert!(!Arc::ptr_eq(&old, &pooled(&backend).unwrap()), "swapped");
    assert_eq!(entry.era.cached().await, Some(Era::Modern));
}

/// ERA.2 (downgrade): a candidate whose peer now answers legacy installs
/// Legacy at the swap; the old verdict is not kept past it.
#[tokio::test]
async fn a_successful_swap_installs_the_candidates_era() {
    use crate::protocol::era::Era;
    let (url, stub) = era_stub().await;
    let backend = http_backend(url);
    backend.start().await.expect("premise: the backend starts");
    let entry = backend.shared_entry();
    assert_eq!(
        entry.era.cached().await,
        Some(Era::Modern),
        "premise: modern"
    );

    stub.mode.store(DISCOVER_LEGACY, Ordering::SeqCst);
    let outcome = within("the restart", non_interactive_restart(&backend))
        .await
        .expect("restart task")
        .expect("the candidate starts");
    assert!(matches!(outcome, RestartOutcome::Rebuilt), "{outcome:?}");
    assert_eq!(
        entry.era.cached().await,
        Some(Era::Legacy),
        "the candidate's verdict was not installed at the swap"
    );
}

/// PROBETO.1 / PROBETO.2 (MIK-8016): the probe's request hangs (as a ping
/// whose token refresh stalls does) until the probe times out and rebuilds.
/// The replacement cannot start (here: no usable target), so the working
/// transport must still be pooled after the probe returns.
#[tokio::test]
async fn a_probe_timeout_whose_replacement_cannot_start_keeps_the_transport() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let mock = Arc::new(ProbeMock::legacy_then(vec![]).gated(Arc::clone(&gate)));
    let backend = super::probe_backend(Arc::clone(&mock), false).await;

    let probed = backend.health_probe(Duration::from_millis(200)).await;
    assert!(probed.is_err(), "premise: the hung request fails the probe");
    assert!(
        backend.rebuilds_attempted.load(Ordering::SeqCst) > 0,
        "premise: the probe's timeout rebuilt"
    );
    let now = pooled(&backend).expect("the transport must stay pooled");
    assert!(
        std::ptr::addr_eq(Arc::as_ptr(&now), Arc::as_ptr(&mock)),
        "a rebuild whose replacement failed replaced the working transport"
    );
    gate.notify_waiters();
}
