// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `adopt_discovery` driven in process: a real gateway.yaml, a real reload
//! context and the files store, with a scan source the test controls. Each
//! row kills one way the route could go wrong without the end-to-end test
//! noticing: a write that ignores the revision, a missing admin check, a
//! refused find written anyway, a name the gateway owns, a splice that
//! cannot be made, a store entry left behind by a refused write.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::to_bytes;
use axum::http::StatusCode;
use futures::future::BoxFuture;
use serde_json::Value;

use super::*;
use crate::config::{AuthConfig, Config, FailsafeConfig, TransportConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::discovery::config_scanner::ConfigScanner;
use crate::discovery::config_scanner::client_scan::{ClientScan, Fingerprint};
use crate::discovery::listing::ScanSource;
use crate::discovery::{DiscoverySource, ServerMetadata};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::test_helpers::write_owner_only;

const CANARY: &str = "zq-adopt-route-canary";

/// A scan returning `finds`, running `during` (once) inside the scan: the
/// moment between the route's revision check and its write.
struct Clients {
    finds: Vec<DiscoveredServer>,
    during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl ScanSource for Clients {
    fn fingerprint(&self) -> Fingerprint {
        ConfigScanner::fingerprint(&[])
    }
    fn scan(&self) -> BoxFuture<'_, ClientScan> {
        if let Some(during) = self.during.lock().expect("hook").take() {
            during();
        }
        let scan = ClientScan {
            finds: self.finds.clone(),
            fingerprint: self.fingerprint(),
            unreadable: Vec::new(),
        };
        Box::pin(async move { scan })
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
}

fn stdio(name: &str, command: &str, env: &[(&str, &str)]) -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        name.to_owned(),
        String::new(),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: command.to_owned(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    );
    server.env = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    server.entry_digest = format!("digest-{name}");
    server
}

/// A gateway over `text` in a temp dir, adopting from `finds`.
struct Route {
    dir: tempfile::TempDir,
    _store: crate::gateway::router::tests::FixtureDir,
    state: Arc<AppState>,
    cache: Arc<DiscoveryCache>,
    clients: Arc<Clients>,
}

impl Route {
    async fn new(text: &str, finds: Vec<DiscoveredServer>) -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write config");
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        )
        .await;
        Arc::get_mut(&mut state)
            .expect("state is unique")
            .config_path = Some(path.clone());
        let context = ReloadContext::new(
            path,
            Arc::new(LiveConfig::new(Config::default())),
            Arc::clone(&state.backends),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config");
        state.meta_mcp.set_reload_context(Arc::new(context));
        let clients = Arc::new(Clients {
            finds,
            during: Mutex::new(None),
        });
        let source: Arc<dyn ScanSource> = clients.clone();
        Self {
            dir,
            _store: store,
            state,
            cache: Arc::new(DiscoveryCache::new(source)),
            clients,
        }
    }

    fn config(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.config()).expect("config reads")
    }

    /// The files store's entries beside the config.
    fn entries(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("secrets")).map_or(0, Iterator::count)
    }

    /// The listed find id of `name`, and the current file revision.
    async fn listed(&self, name: &str) -> (String, String) {
        let (listing, _) = self.cache.listing().await.expect("listing");
        let id = listing
            .finds
            .iter()
            .find(|find| find.name == name)
            .unwrap_or_else(|| panic!("{name} not listed"))
            .find_id
            .clone();
        (id, FileRevision::of(&self.bytes()).as_str().to_owned())
    }

    async fn adopt(&self, admin: bool, find_id: &str, revision: &str) -> (StatusCode, Value) {
        let body = AdoptBody {
            find_id: find_id.to_owned(),
            revision: revision.to_owned(),
        };
        let response = adopt_discovery(
            axum::extract::State(Arc::clone(&self.state)),
            Extension(Arc::clone(&self.cache)),
            Guard::for_route(
                crate::gateway::routes::UI_DISCOVERY_ADOPT,
                &axum::http::Method::POST,
                Some(client(admin)),
            ),
            Ok(Json(body)),
        )
        .await;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "adopt-route".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        principal: crate::gateway::auth::principal_of("adopt-route-secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

/// The files store, pinned: `auto` would probe the host keychain.
const EMPTY: &str = "# keep me\nsecrets:\n  store: files\nbackends: {}\n";

/// The race: gateway.yaml changes after the route checked its revision and
/// before the writer runs. The writer's own revision check refuses it
/// (kills `Expected::Revision` turned into `Expected::Any`): nothing is
/// written over the other change, and no store entry is left behind.
#[tokio::test]
async fn a_config_change_during_the_adopt_is_refused_as_stale() {
    let route = Route::new(
        EMPTY,
        vec![stdio("tool", "npx tool", &[("API_KEY", CANARY)])],
    )
    .await;
    let (id, revision) = route.listed("tool").await;
    let path = route.config();
    let changed = "# changed by someone else\nsecrets:\n  store: files\nbackends: {}\n";
    *route.clients.during.lock().expect("hook") = Some(Box::new(move || {
        write_owner_only(&path, changed).expect("concurrent write");
    }));

    let (status, body) = route.adopt(true, &id, &revision).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "stale", "{body}");
    assert_eq!(
        body["current"],
        FileRevision::of(changed.as_bytes()).as_str(),
        "the stale answer names the file as it now is"
    );
    assert_eq!(
        route.bytes(),
        changed.as_bytes(),
        "the other change was overwritten"
    );
    assert_eq!(route.entries(), 0, "a refused write left a store entry");
}

/// Only an admin adopts; a caller who is not is refused before anything is
/// read, and nothing is written.
#[tokio::test]
async fn a_caller_who_is_not_an_admin_is_refused() {
    let route = Route::new(EMPTY, vec![stdio("tool", "npx tool", &[])]).await;
    let (id, revision) = route.listed("tool").await;
    let (status, body) = route.adopt(false, &id, &revision).await;
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "{status} {body}"
    );
    assert_eq!(route.bytes(), EMPTY.as_bytes());
}

/// A find the adopt rule refuses is never written, its reasons name fields
/// only, and no answer or warning repeats its value, argument or URL.
// Multi-thread: the answer is awaited inside the synchronous log capture.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_find_is_named_by_field_and_never_echoed() {
    // A literal on the refused find: a refusal must not echo or log it, and
    // must create no store entry for it.
    let mut url = stdio("remote", "npx", &[("API_KEY", CANARY)]);
    url.transport = TransportConfig::Http {
        http_url: format!("https://tool.example.test/mcp?token={CANARY}-url"),
        streamable_http: None,
        protocol_version: None,
    };
    let mut cwd = stdio(
        "local",
        &format!("npx {CANARY}-arg"),
        &[("KEY", "zq-${SUFFIX}")],
    );
    if let TransportConfig::Stdio { cwd: dir, .. } = &mut cwd.transport {
        *dir = Some(format!("{CANARY}-relative"));
    }
    let route = Route::new(EMPTY, vec![url, cwd]).await;
    for (name, reason) in [
        ("remote", "credential_in_url"),
        ("local", "literal_in_template"),
    ] {
        let (id, revision) = route.listed(name).await;
        let ((status, body), logs) = {
            let mut answer = None;
            let ((), logs) = crate::test_log_capture::capture_warnings(|| {
                answer = Some(futures::executor::block_on(
                    route.adopt(true, &id, &revision),
                ));
            });
            (answer.expect("answered"), logs)
        };
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {body}");
        assert_eq!(body["error"], "not_adoptable", "{body}");
        assert!(body.to_string().contains(reason), "{name}: {body}");
        assert!(!body.to_string().contains("zq-"), "{name} echoed: {body}");
        assert!(!logs.contains("zq-"), "{name} logged: {logs}");
    }
    assert_eq!(route.bytes(), EMPTY.as_bytes());
    assert_eq!(route.entries(), 0);
}

/// A find named like `capabilities.name` is the gateway's own (409); a name
/// that is not a valid backend name is the find's (422).
#[tokio::test]
async fn names_the_gateway_owns_or_refuses_are_not_adopted() {
    let own = Config::default().capabilities.name;
    let route = Route::new(
        EMPTY,
        vec![stdio(&own, "npx", &[]), stdio("x/y", "npx", &[])],
    )
    .await;
    for (name, status, reason) in [
        (own.as_str(), StatusCode::CONFLICT, "capabilities_name"),
        ("x/y", StatusCode::UNPROCESSABLE_ENTITY, "invalid_name"),
    ] {
        let (id, revision) = route.listed(name).await;
        let (got, body) = route.adopt(true, &id, &revision).await;
        assert_eq!(got, status, "{name}: {body}");
        assert!(body.to_string().contains(reason), "{name}: {body}");
    }
    assert_eq!(route.bytes(), EMPTY.as_bytes());
}

/// A config whose backends cannot take a splice is refused as not in place:
/// the file is byte for byte as it was, and the literal saved for the write
/// is removed again.
#[tokio::test]
async fn a_change_that_cannot_be_spliced_leaves_file_and_store_as_they_were() {
    let text = "secrets:\n  store: files\nbackends: {other: {command: other}}\n";
    let route = Route::new(
        text,
        vec![stdio("tool", "npx tool", &[("API_KEY", CANARY)])],
    )
    .await;
    let (id, revision) = route.listed("tool").await;
    let (status, body) = route.adopt(true, &id, &revision).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "not_in_place", "{body}");
    assert_eq!(route.bytes(), text.as_bytes());
    assert_eq!(route.entries(), 0, "the refused write's entry stayed");
}

/// An adopt whose client leaves after its writer started still lands, and
/// the admin audit layer records it once, naming the caller: the write is
/// paused between writing gateway.yaml and publishing its reload, the request
/// is dropped there, then the reload goes on. The adopt route's row of the
/// UI's cancel rows (`router::ui_audit_cancel_tests`), through the real layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_adopt_still_lands_and_records_its_caller() {
    use tower::ServiceExt as _;
    let mut route = Route::new(EMPTY, vec![stdio("tool", "npx tool", &[])]).await;
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: route
                    .dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "adopt-cancel".to_string(),
                ..Default::default()
            },
        ))
        .expect("open log"),
    );
    Arc::get_mut(&mut route.state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    let (id, revision) = route.listed("tool").await;
    let router = crate::gateway::ui::admin_audit::behind_admin_layer_for_test(
        super::super::discovery_router_with(Arc::clone(&route.cache)),
        &route.state,
    )
    .with_state(Arc::clone(&route.state));
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(crate::gateway::routes::UI_DISCOVERY_ADOPT)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"find_id": id, "revision": revision}).to_string(),
        ))
        .expect("a request");
    request.extensions_mut().insert(client(true));
    let admin_actions = || -> Vec<Value> {
        std::fs::read_to_string(log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == "admin_action")
            .collect()
    };

    let pause = crate::config_reload::arm_reload_pause(&route.config());
    let metrics = tokio::runtime::Handle::current().metrics();
    let baseline = metrics.num_alive_tasks();
    let sent = tokio::spawn(async move { router.oneshot(request).await });
    tokio::time::timeout(crate::test_wait::HANG_BOUND, pause.reached.notified())
        .await
        .expect("the adopt reached its reload");
    sent.abort();
    assert!(
        sent.await
            .expect_err("the request was dropped")
            .is_cancelled(),
        "the client's request was cancelled before the reload went on"
    );
    pause.release.notify_one();

    let deadline = tokio::time::Instant::now() + crate::test_wait::HANG_BOUND;
    while admin_actions().is_empty() || metrics.num_alive_tasks() > baseline {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the adopt never settled; the log holds {:#?}",
            admin_actions()
        );
        tokio::task::yield_now().await;
    }
    let file = String::from_utf8(route.bytes()).expect("utf-8 config");
    assert!(file.contains("tool"), "the adopt did not land: {file}");
    let context = route
        .state
        .meta_mcp
        .reload_context()
        .expect("a reload context");
    assert!(
        context.live_config.get().backends.contains_key("tool"),
        "the reload after the cancel did not publish the adopted backend"
    );
    let records = admin_actions();
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    let record = &records[0];
    assert_eq!(
        record["route"],
        crate::gateway::routes::UI_DISCOVERY_ADOPT,
        "{record}"
    );
    assert_eq!(
        record["who"]["account"], "adopt-route",
        "the caller is named: {record}"
    );
    assert!(
        record["http_status"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status)),
        "the handler's own answer: {record}"
    );
}

/// No gateway.yaml: nothing can be adopted into it (409).
#[tokio::test]
async fn without_a_config_file_nothing_is_adopted() {
    let route = Route::new(EMPTY, vec![stdio("tool", "npx tool", &[])]).await;
    let (id, revision) = route.listed("tool").await;
    std::fs::remove_file(route.config()).expect("remove");
    let (status, body) = route.adopt(true, &id, &revision).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "no_config_file", "{body}");
}
