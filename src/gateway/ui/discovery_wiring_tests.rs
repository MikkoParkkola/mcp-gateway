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
        })
    }

    /// Replace the finds and change the fingerprint, as an edited file would.
    pub(super) fn edit(&self, names: &[&str]) {
        *self.finds.lock().expect("finds") = names.iter().map(|name| find(name)).collect();
        let path: &PathBuf = &self.watched[0].path;
        let previous = std::fs::read(path).unwrap_or_default();
        std::fs::write(path, [previous, b"x".to_vec()].concat()).expect("edit");
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
        Box::pin(async move { scan })
    }
    fn now(&self) -> Instant {
        Instant::now()
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
        .extension(state.live_config.get())
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
