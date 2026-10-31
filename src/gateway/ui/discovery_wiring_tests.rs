// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared discovery cache as the production router and the decision set
//! use it: read from `MetaMcp` at request time (R14), one client-file scan
//! for the radar and the discovery route (R1b), and every rescan published
//! to the decision set (R15).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use futures::future::BoxFuture;
use serde_json::Value;
use tower::ServiceExt as _;

use crate::config::TransportConfig;
use crate::discovery::config_scanner::ConfigScanner;
use crate::discovery::config_scanner::client_scan::{Candidate, ClientScan, Fingerprint, Format};
use crate::discovery::listing::{DiscoveryCache, ScanSource};
use crate::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use crate::gateway::router::AppState;

/// Client files the test scripts: its finds, a watched file whose writes
/// change the fingerprint, and a scan counter.
pub(super) struct Scripted {
    scans: AtomicUsize,
    finds: Mutex<Vec<DiscoveredServer>>,
    watched: Vec<Candidate>,
    now: Mutex<Instant>,
    /// A scan that never ends, to hit the timeout.
    hang: std::sync::atomic::AtomicBool,
}

impl Scripted {
    pub(super) fn new(dir: &Path, names: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            scans: AtomicUsize::new(0),
            finds: Mutex::new(names.iter().map(|name| find(name)).collect()),
            watched: vec![Candidate {
                path: dir.join("watched.json"),
                source: DiscoverySource::ClaudeDesktop,
                format: Format::Claude,
            }],
            now: Mutex::new(Instant::now()),
            hang: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Replace the finds and change the fingerprint, as an edited file would.
    pub(super) fn edit(&self, names: &[&str]) {
        *self.finds.lock().expect("finds") = names.iter().map(|name| find(name)).collect();
        let path: &PathBuf = &self.watched[0].path;
        let previous = std::fs::read(path).unwrap_or_default();
        std::fs::write(path, [previous, b"x".to_vec()].concat()).expect("edit");
    }

    /// Move the cache's clock on by `by`.
    pub(super) fn advance(&self, by: std::time::Duration) {
        *self.now.lock().expect("clock") += by;
    }

    /// Make every scan from now on hang, or stop hanging.
    pub(super) fn hang(&self, on: bool) {
        self.hang.store(on, Ordering::SeqCst);
    }

    pub(super) fn scans(&self) -> usize {
        self.scans.load(Ordering::SeqCst)
    }
}

impl ScanSource for Scripted {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&self.watched)
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        self.scans.fetch_add(1, Ordering::SeqCst);
        let scan = ClientScan {
            finds: self.finds.lock().expect("finds").clone(),
            fingerprint: self.fingerprint(),
            unreadable: Vec::new(),
        };
        let hang = self.hang.load(Ordering::SeqCst);
        Box::pin(async move {
            if hang {
                std::future::pending::<()>().await;
            }
            scan
        })
    }
    fn now(&self) -> Instant {
        *self.now.lock().expect("clock")
    }
}

pub(super) fn find(name: &str) -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        name.to_string(),
        String::new(),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Http {
            http_url: format!("https://{name}.example.internal/mcp"),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ServerMetadata {
            config_path: Some(PathBuf::from("/tmp/claude_desktop_config.json")),
            ..ServerMetadata::default()
        },
    );
    server.entry_digest = format!("digest-{name}");
    server
}

/// An admin GET of `uri` through the production UI router.
pub(super) async fn admin_get(state: &Arc<AppState>, uri: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .uri(uri)
        .extension(state.live_config.generation())
        .extension(crate::gateway::auth::AuthenticatedClient {
            admin: true,
            authenticated: true,
            principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
            ..crate::gateway::auth::anonymous_client()
        })
        .body(Body::empty())
        .expect("request builds");
    let response = super::api_router()
        .with_state(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

pub(super) async fn state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    crate::gateway::router::tests::audience_state(
        &crate::config::AuthConfig::default(),
        (None, None),
        |meta| meta,
    )
    .await
}

/// R14: with no cache on `MetaMcp`, discovery answers 503 and the radar is
/// unavailable; with one set, the same router serves from it and builds no
/// second cache.
#[tokio::test]
async fn the_production_router_reads_the_cache_from_meta_mcp() {
    let (state, _dir) = state().await;
    let (status, body) = admin_get(&state, "/ui/api/discovery").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let (status, body) = admin_get(&state, "/ui/api/control-plane").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["shadow_radar"]["scan_status"], "unavailable", "{body}");

    let files = tempfile::tempdir().expect("tempdir");
    let source = Scripted::new(files.path(), &["r14-find"]);
    let cache = Arc::new(DiscoveryCache::new(
        Arc::clone(&source) as Arc<dyn ScanSource>
    ));
    state.meta_mcp.set_discovery_cache(cache);
    let (status, body) = admin_get(&state, "/ui/api/discovery").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .filter_map(|server| server["name"].as_str())
        .collect();
    assert_eq!(names, ["r14-find"], "{body}");
    assert_eq!(source.scans(), 1, "one cache, scanned once");
}

fn names_of(servers: &Value, field: &str) -> Vec<String> {
    servers
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|server| server[field].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// R1b: the radar and the discovery route share one client-file scan, and
/// the radar's client-config assets are exactly the cache's finds.
#[tokio::test]
async fn one_client_scan_serves_the_radar_and_the_discovery_route() {
    let (state, _dir) = state().await;
    let files = tempfile::tempdir().expect("tempdir");
    let source = Scripted::new(files.path(), &["r1b-find"]);
    let cache = Arc::new(DiscoveryCache::new(
        Arc::clone(&source) as Arc<dyn ScanSource>
    ));
    state.meta_mcp.set_discovery_cache(Arc::clone(&cache));

    let (status, body) = admin_get(&state, "/ui/api/control-plane").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let assets = &body["shadow_radar"]["control_plane_assets"];
    let client: Vec<String> = assets
        .as_array()
        .expect("assets")
        .iter()
        .filter(|asset| asset["ownership"] == "client_config")
        .filter_map(|asset| asset["display_name"].as_str().map(str::to_string))
        .collect();
    assert_eq!(client, ["r1b-find"], "{assets}");

    let (status, discovery) = admin_get(&state, "/ui/api/discovery").await;
    assert_eq!(status, StatusCode::OK, "{discovery}");
    let (listing, _) = cache.listing().await.expect("listing");
    let cached: Vec<String> = listing.finds.iter().map(|f| f.find_id.clone()).collect();
    assert_eq!(names_of(&discovery["servers"], "find_id"), cached);
    assert_eq!(source.scans(), 1, "the radar and the route read one scan");
}

/// R15: a discovery GET that rescans has published the new listing before
/// it returns, with no refresh loop running.
#[tokio::test]
async fn a_get_that_rescans_publishes_before_it_returns() {
    let (state, _dir) = state().await;
    let files = tempfile::tempdir().expect("tempdir");
    let source = Scripted::new(files.path(), &["r15-a"]);
    let cache = Arc::new(DiscoveryCache::new(
        Arc::clone(&source) as Arc<dyn ScanSource>
    ));
    let published: Arc<Mutex<Vec<Vec<String>>>> = Arc::default();
    let seen = Arc::clone(&published);
    cache.set_publisher(Arc::new(move |listing| {
        let names = listing.finds.iter().map(|f| f.name.clone()).collect();
        seen.lock().expect("published").push(names);
    }));
    state.meta_mcp.set_discovery_cache(cache);

    let (status, _) = admin_get(&state, "/ui/api/discovery").await;
    assert_eq!(status, StatusCode::OK);
    source.edit(&["r15-b"]);
    let (status, _) = admin_get(&state, "/ui/api/discovery").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        published.lock().expect("published").last().cloned(),
        Some(vec!["r15-b".to_string()]),
        "the rescan was not published before the GET returned"
    );
}

/// A gateway with an empty gateway.yaml, so every scripted find is an adopt
/// decision, and its decision set started over `source`.
async fn started(
    dir: &Path,
    source: &Arc<Scripted>,
) -> (
    Arc<AppState>,
    crate::gateway::router::tests::FixtureDir,
    tokio::sync::broadcast::Sender<()>,
) {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "backends: {}\n").expect("write");
    let (mut state, store) = state().await;
    Arc::get_mut(&mut state).expect("unique").config_path = Some(path);
    let (stop, shutdown) = tokio::sync::broadcast::channel(1);
    let _set = super::decisions::start_with_source(
        &state.meta_mcp,
        state.config_path.clone(),
        shutdown,
        Arc::clone(source) as Arc<dyn ScanSource>,
    );
    (state, store, stop)
}

fn adopt_open(state: &AppState, name: &str) -> bool {
    state
        .meta_mcp
        .decisions()
        .and_then(|set| set.view().ok())
        .is_some_and(|view| {
            view.decisions
                .iter()
                .any(|item| item["kind"] == "adopt" && item["server"]["name"] == name)
        })
}

/// Wait until `done` holds. The guard is wall-clock time: these rows pause
/// Tokio's clock, which skips every sleep.
async fn until(what: &str, done: impl Fn() -> bool) {
    let guard = std::time::Instant::now();
    while !done() {
        assert!(
            guard.elapsed() < std::time::Duration::from_secs(30),
            "never: {what}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// R4: an edited client file reaches the decision set on the cache's own
/// refresh, with no GET.
#[tokio::test(start_paused = true)]
async fn an_edit_reaches_the_set_without_a_get() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = Scripted::new(dir.path(), &["r4-a"]);
    let (state, _store, _stop) = started(dir.path(), &source).await;
    until("the first find opens", || adopt_open(&state, "r4-a")).await;
    source.edit(&["r4-b"]);
    source.advance(crate::discovery::listing::CACHE_WINDOW);
    tokio::time::advance(crate::discovery::listing::CACHE_WINDOW).await;
    until("the edited find opens", || adopt_open(&state, "r4-b")).await;
    assert!(!adopt_open(&state, "r4-a"), "the removed find closed");
}

/// R3 (warm): a scan that times out with a listing cached keeps the set's
/// items and its count; a later good scan replaces them.
#[tokio::test(start_paused = true)]
async fn a_timed_out_scan_keeps_the_cached_decisions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = Scripted::new(dir.path(), &["r3-a"]);
    let (state, _store, _stop) = started(dir.path(), &source).await;
    until("the first find opens", || adopt_open(&state, "r3-a")).await;
    let scans = source.scans();
    source.hang(true);
    source.edit(&["r3-b"]);
    source.advance(crate::discovery::listing::CACHE_WINDOW);
    tokio::time::advance(crate::discovery::listing::CACHE_WINDOW).await;
    until("a scan starts and hangs", || source.scans() > scans).await;
    tokio::time::advance(crate::discovery::listing::SCAN_TIMEOUT).await;
    let set = state.meta_mcp.decisions().expect("a set");
    assert!(set.view().is_ok(), "the count stays a number");
    assert!(adopt_open(&state, "r3-a"), "the cached item is kept");

    source.hang(false);
    source.advance(crate::discovery::listing::CACHE_WINDOW);
    tokio::time::advance(crate::discovery::listing::CACHE_WINDOW).await;
    until("a good scan replaces the listing", || {
        adopt_open(&state, "r3-b")
    })
    .await;
}
