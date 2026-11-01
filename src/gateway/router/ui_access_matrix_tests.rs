// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The web UI API's access answers, pinned: every UI path × method × request
//! shape × caller kind, through `create_router`, so the real `auth_middleware`,
//! the admin-audit layer and every handler's own check run.
//!
//! The expected cells live in `ui_access_matrix.tsv` beside this file. Each
//! cell is the status code, plus a digest of the body where the body is what
//! must not change: every 401/403 refusal, and every answer of a route that
//! returns a caller-scoped view (Activity, the control plane), so a widened
//! scope fails as surely as a loosened guard. On a mismatch the test prints
//! the whole computed table between markers.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::control_plane::ControlPlaneRole;
use crate::control_plane::role_mapping::{ControlPlaneRoleMappingConfig, ControlPlaneRoleRule};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
use crate::gateway::routes;
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::transparency_log::recompute_entry_hash;

const BEARER: &str = "matrix-static-bearer";
const ADMIN_KEY: &str = "matrix-admin-key";
const STANDARD_KEY: &str = "matrix-standard-key";
const ISSUER: &str = "https://issuer-matrix";
/// The Developer the seeded log's first record names; the second names another.
const DEV: &str = "dev-1";
const OTHER_DEV: &str = "dev-2";

/// Every caller kind a UI guard branches on.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// Auth on, no credential, on a non-public path.
    NoKey,
    /// Auth on, no credential, with the status route public.
    NoKeyPublicStatus,
    /// Auth off: the anonymous, non-admin identity.
    AuthOff,
    StandardKey,
    AdminKey,
    Bearer,
    /// A dashboard session cookie (admin by the cookie).
    Session,
    OidcAdmin,
    OidcAuditor,
    OidcReviewer,
    OidcDeveloper,
    OidcDeveloperNoSubject,
    OidcDeveloperNoIssuer,
    OidcUnmapped,
    /// An admin key that also carries an unmapped OIDC identity.
    AdminKeyUnmapped,
}

const CALLERS: &[Caller] = &[
    Caller::NoKey,
    Caller::NoKeyPublicStatus,
    Caller::AuthOff,
    Caller::StandardKey,
    Caller::AdminKey,
    Caller::Bearer,
    Caller::Session,
    Caller::OidcAdmin,
    Caller::OidcAuditor,
    Caller::OidcReviewer,
    Caller::OidcDeveloper,
    Caller::OidcDeveloperNoSubject,
    Caller::OidcDeveloperNoIssuer,
    Caller::OidcUnmapped,
    Caller::AdminKeyUnmapped,
];

/// Which gateway a caller is sent to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Gateway {
    On,
    OnPublicStatus,
    Off,
}

impl Caller {
    fn gateway(self) -> Gateway {
        match self {
            Self::NoKeyPublicStatus => Gateway::OnPublicStatus,
            Self::AuthOff => Gateway::Off,
            _ => Gateway::On,
        }
    }

    fn bearer(self) -> Option<&'static str> {
        match self {
            Self::StandardKey
            | Self::OidcAdmin
            | Self::OidcAuditor
            | Self::OidcReviewer
            | Self::OidcDeveloper
            | Self::OidcDeveloperNoSubject
            | Self::OidcDeveloperNoIssuer
            | Self::OidcUnmapped => Some(STANDARD_KEY),
            Self::AdminKey | Self::AdminKeyUnmapped => Some(ADMIN_KEY),
            Self::Bearer => Some(BEARER),
            Self::NoKey | Self::NoKeyPublicStatus | Self::AuthOff | Self::Session => None,
        }
    }

    /// The verified identity attached outside the router, as the listener does.
    fn identity(self) -> Option<VerifiedIdentity> {
        let (issuer, subject, group) = match self {
            Self::OidcAdmin => (ISSUER, "admin-1", "admins"),
            Self::OidcAuditor => (ISSUER, "auditor-1", "auditors"),
            Self::OidcReviewer => (ISSUER, "reviewer-1", "reviewers"),
            Self::OidcDeveloper => (ISSUER, DEV, "devs"),
            Self::OidcDeveloperNoSubject => (ISSUER, "", "devs"),
            Self::OidcDeveloperNoIssuer => ("", DEV, "devs"),
            Self::OidcUnmapped | Self::AdminKeyUnmapped => (ISSUER, "nobody-1", "nobody"),
            _ => return None,
        };
        Some(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!(
                "{}@example.test",
                if subject.is_empty() { "x" } else { subject }
            ),
            name: None,
            groups: vec![group.to_string()],
            issuer: issuer.to_string(),
        })
    }
}

fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn rule(group: &str, role: ControlPlaneRole) -> ControlPlaneRoleRule {
    ControlPlaneRoleRule {
        issuer: ISSUER.to_string(),
        group: Some(group.to_string()),
        email: None,
        domain: None,
        role,
    }
}

/// One fresh gateway of `kind`, with role rules, a seeded invocation log and,
/// with `store`, an in-memory control-plane store. Fresh per path, so no
/// cell's write reaches another path's cells.
struct Fixture {
    state: Arc<AppState>,
    /// The receipt id of the record naming [`OTHER_DEV`].
    other_receipt: String,
    _dirs: (crate::gateway::router::tests::FixtureDir, tempfile::TempDir),
}

async fn fixture(kind: Gateway, store: bool) -> Fixture {
    let auth = match kind {
        Gateway::Off => AuthConfig::default(),
        Gateway::On | Gateway::OnPublicStatus => AuthConfig {
            enabled: true,
            bearer_token: Some(BEARER.to_string()),
            api_keys: vec![api_key(ADMIN_KEY, true), api_key(STANDARD_KEY, false)],
            public_paths: if kind == Gateway::OnPublicStatus {
                vec!["/health".to_string(), routes::UI_STATUS.to_string()]
            } else {
                vec!["/health".to_string()]
            },
            ..AuthConfig::default()
        },
    };
    let (mut state, dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    let mut config = (*state.live_config.get()).clone();
    config.control_plane.role_mapping = ControlPlaneRoleMappingConfig {
        rules: vec![
            rule("admins", ControlPlaneRole::Admin),
            rule("auditors", ControlPlaneRole::Auditor),
            rule("reviewers", ControlPlaneRole::SecurityReviewer),
            rule("devs", ControlPlaneRole::Developer),
        ],
    };
    state.live_config.set(config);
    let (log_dir, other_receipt) = seed_log(&mut state);
    if store {
        Arc::get_mut(&mut state)
            .expect("state is unique")
            .control_plane_store = Some(Arc::new(
            crate::control_plane::InMemoryControlPlaneStore::new(),
        ));
    }
    Fixture {
        state,
        other_receipt,
        _dirs: (dir, log_dir),
    }
}

/// An invocation log holding one call by [`DEV`], one by [`OTHER_DEV`] and one
/// by a key, chained and hashed like the logger's, opened as the server would.
fn seed_log(state: &mut Arc<AppState>) -> (tempfile::TempDir, String) {
    use crate::security::transparency_log::TransparencyLogConfig;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let calls = [Some(DEV), Some(OTHER_DEV), None];
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    let mut other = String::new();
    for (i, subject) in calls.iter().enumerate() {
        let mut who = json!({"account": STANDARD_KEY, "principal": STANDARD_KEY});
        if let Some(subject) = subject {
            who["authority"] = ISSUER.into();
            who["subject"] = (*subject).into();
        }
        let mut entry = json!({
            "counter": i + 1, "prev_entry_hash": prev,
            "timestamp": format!("2026-10-26T10:00:{i:02}+00:00"),
            "outcome": "ok", "server": "srv", "tool": format!("tool_{i}"),
            "route": "meta_invoke", "request_hash": "sha256:aa", "who": who,
        });
        let hash = recompute_entry_hash(&entry).expect("hashes");
        entry["entry_hash"] = hash.clone().into();
        body.push_str(&(entry.to_string() + "\n"));
        if *subject == Some(OTHER_DEV) {
            let hex = hash.rsplit(':').next().unwrap_or(&hash);
            other = format!("{}-{}", i + 1, &hex[..16]);
        }
        prev = hash;
    }
    std::fs::write(&path, body).expect("seed log");
    let log = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "matrix".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    Arc::get_mut(state)
        .expect("state is unique")
        .transparency_log = Some(Arc::new(log));
    (dir, other)
}

/// A session issued now, as a redeemed link would issue it.
fn session(state: &AppState) -> String {
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits)
}

/// Every path the UI API router mounts, plus the dashboard page.
fn paths() -> Vec<&'static str> {
    let mut paths = vec![
        routes::DASHBOARD,
        routes::UI_STATUS,
        routes::UI_OVERVIEW,
        routes::UI_TOOLS,
        routes::UI_TOOLS_CALL,
        routes::UI_REFUSALS,
        routes::UI_DECISIONS,
        routes::UI_GATEWAY,
        routes::UI_KEYS,
        routes::UI_CONFIG,
        routes::UI_RELOAD,
        routes::UI_DASHBOARD_LINK,
        routes::UI_PREVIEWS,
        routes::UI_CAPABILITIES,
        routes::UI_CAPABILITY,
        routes::UI_CAPABILITY_VALIDATE,
        routes::UI_CONTROL_PLANE,
        routes::UI_CONTROL_PLANE_GRANTS,
        routes::UI_CONTROL_PLANE_POLICIES,
        routes::UI_CONTROL_PLANE_DECISIONS,
        routes::UI_CONTROL_PLANE_EXPORT_STATUS,
        routes::UI_ACTIVITY,
        routes::UI_ACTIVITY_EXPORT,
        routes::UI_ACTIVITY_RECEIPT,
        routes::UI_BACKENDS,
        routes::UI_BACKEND,
        routes::UI_BACKEND_REVIVE,
        routes::UI_REGISTRY,
        routes::UI_DISCOVERY,
        routes::UI_DISCOVERY_ADOPT,
        routes::UI_REGISTRY_SEARCH,
        routes::UI_DEAD_LETTERS,
        routes::UI_DEAD_LETTERS_REPLAY,
        routes::UI_DEAD_LETTER_REPLAY,
        routes::UI_EVENTS_HELD,
        routes::UI_EVENTS_LEASES,
        routes::UI_IMPORT_PREVIEW,
        routes::UI_IMPORT,
        routes::UI_METRICS_SERIES,
        routes::UI_MARKERS,
    ];
    if cfg!(feature = "cost-governance") {
        paths.push(routes::UI_COSTS);
    }
    paths
}

/// Routes the matrix cannot probe: a server-sent event stream's body never
/// ends. The stream's own refusals and caps are pinned in `ui_stream_tests`.
const STREAMED: &[&str] = &[routes::UI_STREAM];

/// Routes whose successful answer is scoped to the caller: their body is
/// pinned too, so a widened scope moves a cell.
const SCOPED: &[&str] = &[
    routes::UI_STATUS,
    routes::UI_ACTIVITY,
    routes::UI_ACTIVITY_EXPORT,
    routes::UI_ACTIVITY_RECEIPT,
    routes::UI_CONTROL_PLANE,
    routes::UI_CONTROL_PLANE_EXPORT_STATUS,
];

/// Control-plane writes, probed with and without a store: the store check
/// answers before the role check today.
const STORE_WRITES: &[&str] = &[
    routes::UI_CONTROL_PLANE_GRANTS,
    routes::UI_CONTROL_PLANE_POLICIES,
    routes::UI_CONTROL_PLANE_DECISIONS,
];

/// Control-plane reads of the store, probed with and without one. The
/// snapshot reads only the store's audit log (its grant and policy rows are
/// never shown), so the store holds audit events by two different actors and
/// a widened view moves a cell. Export status reads no store.
const STORE_READS: &[&str] = &[routes::UI_CONTROL_PLANE];

/// The audit events [`seed_store`] writes, one per actor.
const SEEDED_EVENTS: [(&str, &str); 2] =
    [("matrix-event-dev", DEV), ("matrix-event-other", OTHER_DEV)];

/// Audit events for [`STORE_READS`]: one by [`DEV`], one by [`OTHER_DEV`].
fn seed_store(state: &AppState) {
    use crate::control_plane::{
        ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan,
    };
    let store = state.control_plane_store.as_ref().expect("a store");
    for (event_id, actor) in SEEDED_EVENTS {
        store
            .append_audit(&ControlPlaneAuditEvent {
                grant_change: None,
                event_id: event_id.to_string(),
                actor_id: actor.to_string(),
                action: ControlPlaneAction::MutateGrant,
                target_id: "matrix-target".to_string(),
                reason: "matrix seed".to_string(),
                rollback: ControlPlaneRollbackPlan {
                    summary: "revert".to_string(),
                    step: "none".to_string(),
                },
            })
            .expect("the event is stored");
    }
}

const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// The request shapes sent with `method`: well-formed, and malformed where
/// a body or query is parsed.
fn shapes(method: &str, path: &str) -> Vec<&'static str> {
    match method {
        "POST" if valid_body(path).is_some() => vec!["json", "valid", "bad-type", "bad-json"],
        "POST" | "PUT" | "PATCH" => vec!["json", "bad-type", "bad-json"],
        "GET" if path == routes::UI_ACTIVITY_RECEIPT => vec!["plain", "bad-query", "other-receipt"],
        // CSV is the unsigned export, so it answers without a signing key.
        "GET" if path == routes::UI_ACTIVITY_EXPORT => vec!["plain", "bad-query", "csv"],
        "GET" => vec!["plain", "bad-query"],
        _ => vec!["plain"],
    }
}

fn request(
    caller: Caller,
    (method, path, shape): (&str, &str, &str),
    fx: &Fixture,
    cookie: Option<&str>,
) -> Request<Body> {
    let object = if shape == "other-receipt" {
        fx.other_receipt.as_str()
    } else {
        "missing-object"
    };
    let mut uri = path.replace("{name}", object).replace("{id}", object);
    if shape == "bad-query" {
        uri.push_str("?limit=1&limit=2");
    } else if shape == "csv" {
        uri.push_str("?format=csv&server=srv");
    } else if path == routes::UI_ACTIVITY {
        // Only the seeded calls: the audit layer's own records for earlier
        // cells would otherwise page them out, newest first.
        uri.push_str("?server=srv");
    }
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))));
    if let Some(credential) = caller.bearer() {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    if let (Caller::Session, Some(handle)) = (caller, cookie) {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    if let Some(identity) = caller.identity() {
        builder = builder.extension(identity);
    }
    let body = match shape {
        "json" => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from("{}")
        }
        "valid" => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(valid_body(path).expect("a valid body").to_string())
        }
        "bad-type" => {
            builder = builder.header(header::CONTENT_TYPE, "text/plain");
            Body::from("x")
        }
        "bad-json" => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from("{not json")
        }
        _ => Body::empty(),
    };
    builder.body(body).expect("request builds")
}

/// A body that parses for routes whose handler parses before its guard, so
/// the guard itself is reached: `{}` is refused by the parser first there.
/// Each still changes nothing: an empty name fails validation, and this
/// build refuses control-plane writes after their role check.
fn valid_body(path: &str) -> Option<Value> {
    let rollback = json!({"summary": "none", "step": "none"});
    Some(match path {
        p if p == routes::UI_BACKENDS || p == routes::UI_PREVIEWS => json!({"name": ""}),
        p if p == routes::UI_CONTROL_PLANE_GRANTS => json!({
            "grant": {"grant_id": "g-matrix", "subject_id": "s", "server_id": "srv",
                      "tool_id": null, "status": "requested"},
            "reason": "matrix", "rollback": rollback,
        }),
        p if p == routes::UI_CONTROL_PLANE_POLICIES => json!({
            "policy": {"policy_id": "p-matrix", "name": "matrix", "enforced": false},
            "reason": "matrix", "rollback": rollback,
        }),
        p if p == routes::UI_CONTROL_PLANE_DECISIONS => json!({
            "target_kind": "grant", "target_id": "g-matrix", "decision": "approve",
            "reason": "matrix", "rollback": rollback,
        }),
        _ => return None,
    })
}

/// What a write would change: the published config, the backends and the
/// control-plane store's rows.
fn fingerprint(state: &AppState) -> String {
    let config = serde_json::to_string(&*state.live_config.get()).expect("config serialises");
    let mut backends: Vec<String> = state.backends.statuses().into_keys().collect();
    backends.sort_unstable();
    // Whole rows, so an in-place update shows, and the audit log's length,
    // so an audit-only append shows.
    let store = state.control_plane_store.as_ref().map(|store| {
        (
            store.list_grants().ok(),
            store.list_policies().ok(),
            store
                .read_audit(&crate::control_plane::AuditFilter::new(200))
                .map(|page| page.events.len())
                .ok(),
        )
    });
    format!("{}|{backends:?}|{store:?}", hash12(config.as_bytes()))
}

/// Keys whose values differ between two identical requests (clocks, ids).
const VOLATILE: &[&str] = &[
    "generated_at",
    "timestamp",
    "now",
    "as_of",
    "uptime_secs",
    "request_id",
    "checked_at",
];

/// Keys whose values come from the machine running the test, not from the
/// fixture: the control-plane shadow radar scans the host's MCP client
/// configs. No caller scoping touches them, so they are left out of the hash.
const HOST_DEPENDENT: &[&str] = &[
    "shadow_radar",
    "shadow_assets",
    "shadow_high_or_critical_assets",
];

fn strip(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|k, _| {
                !VOLATILE.contains(&k.as_str()) && !HOST_DEPENDENT.contains(&k.as_str())
            });
            map.values_mut().for_each(strip);
        }
        Value::Array(items) => items.iter_mut().for_each(strip),
        _ => {}
    }
}

fn hash12(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().take(6).fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    })
}

/// What a cell records for one answer.
fn cell(path: &str, status: StatusCode, body: &[u8]) -> String {
    let code = status.as_u16();
    let refused = matches!(code, 401 | 403);
    if refused && !body.is_empty() {
        return format!("{code}:{}", hash12(body));
    }
    if status.is_success() && path == routes::UI_ACTIVITY {
        // The list's scope is which seeded calls it shows. The audit layer
        // appends this run's own records too, with clocks and hashes of their
        // own, so only the seeded rows are pinned.
        let list: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let mut seen: Vec<&str> = list["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|row| row["tool"].as_str())
            .filter(|tool| tool.starts_with("tool_"))
            .collect();
        seen.sort_unstable();
        return format!("{code}:{}", seen.join(","));
    }
    if status.is_success() && path == routes::UI_ACTIVITY_EXPORT {
        // The export's scope is which seeded calls it carries; like the list,
        // only those are pinned.
        let text = String::from_utf8_lossy(body);
        let mut seen: Vec<&str> = text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|token| token.starts_with("tool_"))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        return format!("{code}:{}", seen.join(","));
    }
    if status.is_success() && SCOPED.contains(&path) && !body.is_empty() {
        let canonical = if let Ok(mut v) = serde_json::from_slice::<Value>(body) {
            strip(&mut v);
            if path == routes::UI_STATUS
                && let Some(answer) = v.as_object_mut()
            {
                // The `access` report is new in this change and has its own
                // test against the matrix; every other member is pinned.
                answer.remove("access");
            }
            v.to_string()
        } else {
            let mut lines: Vec<&str> = std::str::from_utf8(body)
                .unwrap_or_default()
                .lines()
                .collect();
            lines.sort_unstable();
            lines.join("\n")
        };
        return format!("{code}:{}", hash12(canonical.as_bytes()));
    }
    code.to_string()
}

async fn send(router: &axum::Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = tokio::time::timeout(Duration::from_secs(30), router.clone().oneshot(request))
        .await
        .expect("the request finished")
        .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (status, body.to_vec())
}

type Matrix = BTreeMap<String, String>;

/// Every cell, computed against today's code.
async fn compute() -> Matrix {
    let mut matrix = Matrix::new();
    for path in paths() {
        let stores: &[bool] = if STORE_WRITES.contains(&path) || STORE_READS.contains(&path) {
            &[false, true]
        } else {
            &[false]
        };
        for &store in stores {
            for gateway in [Gateway::On, Gateway::OnPublicStatus, Gateway::Off] {
                let fx = fixture(gateway, store).await;
                if store && STORE_READS.contains(&path) {
                    seed_store(&fx.state);
                }
                let router = create_router(Arc::clone(&fx.state));
                let cookie = session(&fx.state);
                for &caller in CALLERS.iter().filter(|c| c.gateway() == gateway) {
                    for &method in METHODS {
                        for shape in shapes(method, path) {
                            let req = (method, path, shape);
                            let before = (shape == "valid").then(|| fingerprint(&fx.state));
                            let (status, body) =
                                send(&router, request(caller, req, &fx, Some(&cookie))).await;
                            // A body that parses reaches the guard; whatever
                            // answers, it must not have written anything.
                            if let Some(before) = before {
                                assert_eq!(
                                    before,
                                    fingerprint(&fx.state),
                                    "{path} {method} {shape} {caller:?} answered {status} and \
                                     changed the gateway's state"
                                );
                            }
                            let value = cell(path, status, &body);
                            if SCOPED.contains(&path) && status.is_success() {
                                let (again, body2) =
                                    send(&router, request(caller, req, &fx, Some(&cookie))).await;
                                assert_eq!(
                                    value,
                                    cell(path, again, &body2),
                                    "{path} {method} {shape} {caller:?}: the scoped answer is not \
                                     stable across two identical requests; add the moving key to \
                                     VOLATILE.\nfirst: {}\nsecond: {}",
                                    String::from_utf8_lossy(&body),
                                    String::from_utf8_lossy(&body2),
                                );
                            }
                            let variant = if store {
                                format!("{shape}+store")
                            } else {
                                shape.to_string()
                            };
                            matrix
                                .insert(format!("{path}\t{method}\t{variant}\t{caller:?}"), value);
                        }
                    }
                }
            }
        }
    }
    matrix
}

/// The checked-in expectation, without the cost rows when that feature is off.
fn expected() -> Matrix {
    include_str!("ui_access_matrix.tsv")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.rsplit_once('\t')
                .unwrap_or_else(|| panic!("a matrix line has a key and an answer: {l:?}"))
        })
        .filter(|(key, _)| {
            cfg!(feature = "cost-governance")
                || !key.starts_with(&format!("{}\t", routes::UI_COSTS))
        })
        .fold(Matrix::new(), |mut matrix, (key, value)| {
            let earlier = matrix.insert(key.to_string(), value.to_string());
            assert!(earlier.is_none(), "a matrix cell is listed twice: {key}");
            matrix
        })
}

/// Every UI API answer a caller sees today, pinned before the
/// guards move into one table. The refactor must leave this test unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_api_access_matrix_is_preserved() {
    let computed = compute().await;
    let expected = expected();
    if computed == expected {
        return;
    }
    let moved: Vec<String> = computed
        .iter()
        .filter(|(k, v)| expected.get(*k) != Some(*v))
        .map(|(k, v)| format!("{k}: expected {:?}, got {v}", expected.get(k)))
        .chain(
            expected
                .keys()
                .filter(|k| !computed.contains_key(*k))
                .map(|k| format!("{k}: expected, not computed")),
        )
        .collect();
    let table = computed.iter().fold(String::new(), |mut table, (k, v)| {
        let _ = writeln!(table, "{k}\t{v}");
        table
    });
    panic!(
        "{} cells moved; first 40:\n{}\n---- BEGIN MATRIX ----\n{table}---- END MATRIX ----",
        moved.len(),
        moved
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

/// The streamed exemption is the live stream alone: a second route left out
/// of the matrix and the report needs a deliberate edit here.
#[test]
fn the_streamed_exemption_is_the_stream_alone() {
    assert_eq!(STREAMED, [routes::UI_STREAM]);
}

/// The matrix covers every UI API path the listener owns: a new route fails
/// here until it has cells.
#[test]
fn every_ui_api_path_is_in_the_matrix() {
    let mut owned: Vec<&str> = routes::OWNED
        .iter()
        .copied()
        .filter(|p| p.starts_with("/ui/api/") || *p == routes::DASHBOARD)
        .filter(|p| cfg!(feature = "cost-governance") || *p != routes::UI_COSTS)
        .filter(|p| !STREAMED.contains(p))
        .collect();
    let mut probed = paths();
    owned.sort_unstable();
    probed.sort_unstable();
    assert_eq!(owned, probed);
}

/// The hand-written facts about the expectation.
#[path = "ui_access_matrix_known_tests.rs"]
mod known;

/// The status report against the guards, through the same fixture.
#[path = "ui_access_report_tests.rs"]
mod report;
