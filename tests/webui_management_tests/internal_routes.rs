// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! INTERNAL routes stay mounted with today's answers (MIK-8044 SURF.4b).
//!
//! Every row of docs/design/surface-4.0.md "## Surface: routes" whose class is
//! INTERNAL has rows here keyed by (path, method). The expected codes were
//! copied from a run against the unchanged handlers, never written from
//! reading; each row names the handler that produces them.

use std::collections::BTreeSet;

use mcp_gateway::control_plane::{ExportStatus, InMemoryControlPlaneStore};

use super::*;

const SURFACE_DOC: &str = include_str!("../../docs/design/surface-4.0.md");

/// Who sends the request, and to which gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Caller {
    /// No credential, authentication ON: the auth middleware answers first.
    AnonOn,
    /// No credential, authentication OFF (`Config::default()`): the middleware
    /// inserts the anonymous client, so the handler's own refusal is reached.
    AnonOff,
    /// A non-admin API key, which the control plane projects as Auditor.
    Auditor,
    /// The static admin bearer.
    Admin,
}

/// Column order of [`Row::base`].
const BASE_CALLERS: [Caller; 4] = [
    Caller::AnonOn,
    Caller::AnonOff,
    Caller::Auditor,
    Caller::Admin,
];
/// Column order of [`Row::configured`] (an auth-on gateway only).
const CONFIGURED_CALLERS: [Caller; 3] = [Caller::AnonOn, Caller::Auditor, Caller::Admin];

/// Which gateway a request goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fixture {
    /// Auth on, no control-plane store, no SIEM export.
    AuthOn,
    /// `Config::default()` auth: disabled.
    AuthOff,
    /// Auth on, with an in-memory control-plane store and an export status.
    Configured,
}

/// A body that passes the route's extractors, so the answer is the handler's.
#[derive(Clone, Copy, Debug)]
enum Payload {
    None,
    Json(&'static str),
    Yaml,
    Import,
}

/// One registered (path, method), with today's answer per caller.
struct Row {
    /// The doc's path, as the route builder registers it.
    path: &'static str,
    method: Method,
    /// A concrete URI for the path.
    uri: &'static str,
    payload: Payload,
    /// Status for [`BASE_CALLERS`] on the auth-on / auth-off gateways.
    base: [u16; 4],
    /// Status for [`CONFIGURED_CALLERS`] on [`Fixture::Configured`], for a
    /// route whose answer depends on the store or export being configured.
    configured: Option<[u16; 3]>,
}

const AUDITOR_KEY: &str = "auditor-key";

/// The auth-on posture: the admin bearer plus the Auditor API key from
/// registry.rs (`test_control_plane_endpoint_projects_non_admin_api_key_as_auditor`).
fn auth_on() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        api_keys: vec![
            serde_json::from_value(json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(AUDITOR_KEY.as_bytes()),
                "name": "auditor-client", "backends": ["docs"], "admin": false
            }))
            .expect("api key fixture"),
        ],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

/// A gateway with one named backend (`docs`) and a private capability dir, so
/// an admin write lands in a tempdir and never in the repo.
struct Gateway {
    router: Router,
    caps: TempDir,
    _store: TempDir,
}

async fn gateway(fixture: Fixture) -> Gateway {
    let caps = TempDir::new().expect("capability dir");
    let cap_dir = caps.path().to_str().expect("utf-8 tempdir").to_string();
    let (mut state, store) = make_app_state(Some(&cap_dir), None).await;
    {
        let s = Arc::get_mut(&mut state).expect("test AppState should be uniquely owned");
        let auth = match fixture {
            Fixture::AuthOff => Config::default().auth,
            Fixture::AuthOn | Fixture::Configured => auth_on(),
        };
        s.auth_config = Arc::new(ResolvedAuthConfig::from_config(&auth));
        if fixture == Fixture::Configured {
            s.control_plane_store = Some(Arc::new(InMemoryControlPlaneStore::new()));
            s.export_status = Some(Arc::new(ExportStatus::default()));
        }
    }
    register_http_backend(&state, "docs");
    Gateway {
        router: create_router(state),
        caps,
        _store: store,
    }
}

/// A minimal `OpenAPI` document, as in `openapi_import.rs`.
const OPENAPI_SPEC: &str = r#"
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /users/{id}:
    get:
      operationId: getUser
      summary: Get a user by ID
      responses:
        "200":
          description: User found
"#;

fn request(method: &Method, uri: &str, caller: Caller, payload: Payload) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    let token = match caller {
        Caller::Admin => Some(ADMIN_TOKEN),
        Caller::Auditor => Some(AUDITOR_KEY),
        Caller::AnonOn | Caller::AnonOff => None,
    };
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let (content_type, body) = match payload {
        Payload::None => return builder.body(Body::empty()).unwrap(),
        Payload::Json(text) => ("application/json", text.to_string()),
        Payload::Yaml => ("text/yaml", VALID_YAML.to_string()),
        // `selected_tools: []` imports nothing, so an admin import writes no file.
        Payload::Import => (
            "application/json",
            json!({ "spec": OPENAPI_SPEC, "selected_tools": [] }).to_string(),
        ),
    };
    builder
        .header("content-type", content_type)
        .body(Body::from(body))
        .unwrap()
}

/// Send one request; return the status, the content type and the body.
async fn send(gw: &Gateway, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    let response = gw.router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, content_type, bytes)
}

/// The doc's INTERNAL route paths, read from its routes table.
fn doc_internal_paths(md: &str) -> BTreeSet<String> {
    let mut inside = false;
    let mut paths = BTreeSet::new();
    for line in md.lines() {
        if line.starts_with("## ") {
            inside = line.trim() == "## Surface: routes";
            continue;
        }
        if !inside {
            continue;
        }
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cells.get(1) == Some(&"INTERNAL")
            && let Some(path) = cells[0].strip_prefix('`').and_then(|s| s.strip_suffix('`'))
        {
            paths.insert(path.to_owned());
        }
    }
    paths
}

/// `/ui/api/costs` is mounted only with `cost-governance`.
fn mounted(path: &str) -> bool {
    path != "/ui/api/costs" || cfg!(feature = "cost-governance")
}

/// Bodies from `src/gateway/ui/control_plane_mutation_tests.rs` (grant-1, pol-1).
const GRANT: &str = r#"{"grant":{"grant_id":"grant-1","subject_id":"user-1","server_id":"srv-1","status":"approved"},"reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;
const POLICY: &str = r#"{"policy":{"policy_id":"pol-1","name":"p","enforced":false},"reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;
const DECISION: &str = r#"{"target_kind":"grant","target_id":"grant-1","decision":"approve","reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;
/// `AddBackendRequest` / `UpdateBackendRequest` (src/gateway/ui/backends.rs:48, :67).
const ADD_BACKEND: &str = r#"{"name":"probe","url":"http://127.0.0.1:9/probe"}"#;
const UPDATE_BACKEND: &str = r#"{"description":"probe"}"#;

const fn row(
    path: &'static str,
    method: Method,
    uri: &'static str,
    payload: Payload,
    base: [u16; 4],
) -> Row {
    Row {
        path,
        method,
        uri,
        payload,
        base,
        configured: None,
    }
}

const fn row_cfg(
    path: &'static str,
    method: Method,
    uri: &'static str,
    payload: Payload,
    base: [u16; 4],
    configured: [u16; 3],
) -> Row {
    Row {
        path,
        method,
        uri,
        payload,
        base,
        configured: Some(configured),
    }
}

// Columns: [anonymous auth on, anonymous auth off, Auditor, admin]. Every 401 in
// the first column is the auth middleware's missing-credential answer
// (src/gateway/auth.rs:683-686), which answers before any handler.
const ROWS: &[Row] = &[
    // src/gateway/router/handlers/session_end.rs:74 (sse_deprecated_handler)
    row(
        "/sse",
        Method::GET,
        "/sse",
        Payload::None,
        [401, 410, 410, 410],
    ),
    row(
        "/sse",
        Method::POST,
        "/sse",
        Payload::Json("{}"),
        [401, 410, 410, 410],
    ),
    // src/gateway/ui/mod.rs:388 (status)
    row(
        "/ui/api/status",
        Method::GET,
        "/ui/api/status",
        Payload::None,
        [401, 200, 200, 200],
    ),
    // src/gateway/ui/mod.rs:464 (tools)
    row(
        "/ui/api/tools",
        Method::GET,
        "/ui/api/tools",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/mod.rs:520 (config)
    row(
        "/ui/api/config",
        Method::GET,
        "/ui/api/config",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/mod.rs:556 (reload; no reload context in the fixture)
    row(
        "/ui/api/reload",
        Method::POST,
        "/ui/api/reload",
        Payload::None,
        [401, 403, 403, 503],
    ),
    // src/gateway/ui/session.rs:123 (dashboard_link)
    row(
        "/ui/api/dashboard-link",
        Method::POST,
        "/ui/api/dashboard-link",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/mod.rs:605 (costs)
    row(
        "/ui/api/costs",
        Method::GET,
        "/ui/api/costs",
        Payload::None,
        [401, 401, 401, 200],
    ),
    // src/gateway/ui/capabilities.rs:217 (list_capabilities)
    row(
        "/ui/api/capabilities",
        Method::GET,
        "/ui/api/capabilities",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:397 (create_capability; `{}` returns the template)
    row(
        "/ui/api/capabilities",
        Method::POST,
        "/ui/api/capabilities",
        Payload::Json("{}"),
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:319 (put_capability)
    row(
        "/ui/api/capabilities/{name}",
        Method::PUT,
        "/ui/api/capabilities/test_cap",
        Payload::Yaml,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:278 (get_capability)
    row(
        "/ui/api/capabilities/{name}",
        Method::GET,
        "/ui/api/capabilities/test_cap",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:486 (delete_capability)
    row(
        "/ui/api/capabilities/{name}",
        Method::DELETE,
        "/ui/api/capabilities/test_cap",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/control_plane.rs:72 (require_authenticated layer), :116 (snapshot)
    row(
        "/ui/api/control-plane",
        Method::GET,
        "/ui/api/control-plane",
        Payload::None,
        [401, 403, 200, 200],
    ),
    // control_plane.rs:72, mutations.rs:53 (mutate_grant), :310 (store), :330 (RBAC), :342 (409)
    row_cfg(
        "/ui/api/control-plane/grants",
        Method::POST,
        "/ui/api/control-plane/grants",
        Payload::Json(GRANT),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, mutations.rs:79 (mutate_policy), :310, :330, :342
    row_cfg(
        "/ui/api/control-plane/policies",
        Method::POST,
        "/ui/api/control-plane/policies",
        Payload::Json(POLICY),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, mutations.rs:131 (resolve_decision), :194 (store), :245 (RBAC), :258 (409)
    row_cfg(
        "/ui/api/control-plane/decisions",
        Method::POST,
        "/ui/api/control-plane/decisions",
        Payload::Json(DECISION),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, :89 (export_status_handler: 404 `configured: false` when unset)
    row_cfg(
        "/ui/api/control-plane/export-status",
        Method::GET,
        "/ui/api/control-plane/export-status",
        Payload::None,
        [401, 403, 404, 404],
        [401, 200, 200],
    ),
    // src/gateway/ui/backends.rs:184 (add_backend; no config path in the fixture)
    row(
        "/ui/api/backends",
        Method::POST,
        "/ui/api/backends",
        Payload::Json(ADD_BACKEND),
        [401, 403, 403, 503],
    ),
    // backends.rs:388 (update_backend)
    row(
        "/ui/api/backends/{name}",
        Method::PATCH,
        "/ui/api/backends/docs",
        Payload::Json(UPDATE_BACKEND),
        [401, 403, 403, 503],
    ),
    // backends.rs:273 (remove_backend)
    row(
        "/ui/api/backends/{name}",
        Method::DELETE,
        "/ui/api/backends/docs",
        Payload::None,
        [401, 403, 403, 503],
    ),
    // backends.rs:337 (revive_backend)
    row(
        "/ui/api/backends/{name}/revive",
        Method::POST,
        "/ui/api/backends/docs/revive",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // backends.rs:510 (list_registry)
    row(
        "/ui/api/registry",
        Method::GET,
        "/ui/api/registry",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // backends.rs:527 (search_registry)
    row(
        "/ui/api/registry/search",
        Method::GET,
        "/ui/api/registry/search?q=tavily",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/events.rs:106 (list), :59 (admin), :71 (404: events not enabled)
    row(
        "/ui/api/events/dead-letters",
        Method::GET,
        "/ui/api/events/dead-letters",
        Payload::None,
        [401, 403, 403, 404],
    ),
    // events.rs:139 (replay_all), :59, :71
    row(
        "/ui/api/events/dead-letters/replay",
        Method::POST,
        "/ui/api/events/dead-letters/replay?all=1&subscription=s",
        Payload::None,
        [401, 403, 403, 404],
    ),
    // events.rs:123 (replay_one), :59, :71
    row(
        "/ui/api/events/dead-letters/{id}/replay",
        Method::POST,
        "/ui/api/events/dead-letters/evt-1/replay",
        Payload::None,
        [401, 403, 403, 404],
    ),
    // events.rs:94 (held), :59, :71
    row(
        "/ui/api/events/held",
        Method::GET,
        "/ui/api/events/held",
        Payload::None,
        [401, 403, 403, 404],
    ),
    // src/gateway/ui/import.rs:95 (preview_handler)
    row(
        "/ui/api/import/openapi/preview",
        Method::POST,
        "/ui/api/import/openapi/preview",
        Payload::Import,
        [401, 403, 403, 200],
    ),
    // import.rs:129 (import_handler)
    row(
        "/ui/api/import/openapi",
        Method::POST,
        "/ui/api/import/openapi",
        Payload::Import,
        [401, 403, 403, 200],
    ),
];

/// Send one row as one caller and record any answer that is not today's.
async fn check(
    gw: &Gateway,
    row: &Row,
    caller: Caller,
    fixture: Fixture,
    want: u16,
    wrong: &mut Vec<String>,
) {
    // Each `{name}` row finds the capability whatever ran before it, so a
    // reorder of ROWS cannot turn an admin 200 into a 404 (a DELETE removes it).
    if row.path == "/ui/api/capabilities/{name}" {
        std::fs::write(gw.caps.path().join("test_cap.yaml"), VALID_YAML)
            .expect("seed test_cap");
    }
    let (status, content_type, body) =
        send(gw, request(&row.method, row.uri, caller, row.payload)).await;
    let label = format!("{} {} as {caller:?} on {fixture:?}", row.method, row.path);
    let text = String::from_utf8_lossy(&body);
    // `/sse` is a pointer, not a transport: a 410 must still say where to go.
    if row.path == "/sse" && status == StatusCode::GONE && !text.contains("POST /mcp") {
        wrong.push(format!("{label}: 410 without the `POST /mcp` pointer: {text}"));
    }
    // A row whose method is not registered answers 405, and the probe below
    // skips methods a row claims: pin that and the route is unguarded.
    if status == StatusCode::METHOD_NOT_ALLOWED {
        wrong.push(format!(
            "{label}: 405, the row names an unregistered method"
        ));
    }
    // axum's extractor rejections are plain text; the answer must be the handler's.
    if content_type.starts_with("text/plain") {
        wrong.push(format!("{label}: extractor rejection {status}: {text}"));
    }
    if status.as_u16() != want {
        wrong.push(format!("{label}: expected {want}, got {status}: {text}"));
    }
}

#[tokio::test]
async fn internal_routes_answer_as_today() {
    let on = gateway(Fixture::AuthOn).await;
    let off = gateway(Fixture::AuthOff).await;
    let configured = gateway(Fixture::Configured).await;
    let mut wrong = Vec::new();
    for row in ROWS.iter().filter(|r| mounted(r.path)) {
        for (caller, want) in BASE_CALLERS.into_iter().zip(row.base) {
            let (gw, fixture) = if caller == Caller::AnonOff {
                (&off, Fixture::AuthOff)
            } else {
                (&on, Fixture::AuthOn)
            };
            check(gw, row, caller, fixture, want, &mut wrong).await;
        }
        for (caller, want) in row
            .configured
            .iter()
            .flat_map(|c| CONFIGURED_CALLERS.into_iter().zip(*c))
        {
            check(
                &configured,
                row,
                caller,
                Fixture::Configured,
                want,
                &mut wrong,
            )
            .await;
        }
    }
    assert!(
        wrong.is_empty(),
        "INTERNAL route answers moved:\n{}",
        wrong.join("\n")
    );
}

/// A doc INTERNAL path with no row, or a row for a path that is not one, fails.
#[test]
fn every_doc_internal_route_has_rows_and_no_other() {
    let doc: BTreeSet<String> = doc_internal_paths(SURFACE_DOC)
        .into_iter()
        .filter(|p| mounted(p))
        .collect();
    assert!(
        doc.contains("/sse"),
        "the routes table was not read: {doc:?}"
    );
    let rows: BTreeSet<String> = ROWS
        .iter()
        .filter(|r| mounted(r.path))
        .map(|r| r.path.to_owned())
        .collect();
    assert_eq!(
        doc.difference(&rows).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "doc INTERNAL routes with no row"
    );
    assert_eq!(
        rows.difference(&doc).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "rows for paths that are not doc INTERNAL routes"
    );
}

const PROBE_METHODS: [Method; 7] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];

/// A method outside a route's rows answers 405. HEAD on a GET route is served
/// by the GET handler (axum 0.8), so it answers like GET with an empty body.
#[tokio::test]
async fn internal_routes_refuse_every_other_method() {
    let gw = gateway(Fixture::AuthOn).await;
    let mut wrong = Vec::new();
    for path in doc_internal_paths(SURFACE_DOC)
        .iter()
        .filter(|p| mounted(p))
    {
        let rows: Vec<&Row> = ROWS.iter().filter(|r| r.path == path).collect();
        let Some(first) = rows.first() else { continue };
        let has = |m: &Method| rows.iter().any(|r| r.method == *m);
        for method in PROBE_METHODS.iter().filter(|m| !has(m)) {
            if *method == Method::HEAD && has(&Method::GET) {
                // Back to back, so no row's write sits between the two.
                let (get, _, _) = send(
                    &gw,
                    request(&Method::GET, first.uri, Caller::Admin, Payload::None),
                )
                .await;
                let (head, _, body) = send(
                    &gw,
                    request(method, first.uri, Caller::Admin, Payload::None),
                )
                .await;
                if head != get || !body.is_empty() {
                    wrong.push(format!(
                        "HEAD {path}: {head} with {} body bytes, GET answered {get}",
                        body.len()
                    ));
                }
                continue;
            }
            let (status, _, _) = send(
                &gw,
                request(method, first.uri, Caller::Admin, Payload::None),
            )
            .await;
            if status != StatusCode::METHOD_NOT_ALLOWED {
                wrong.push(format!("{method} {path}: expected 405, got {status}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "INTERNAL routes answer methods they have no row for:\n{}",
        wrong.join("\n")
    );
}

/// A non-admin gets counts only: no backend name and no other field.
#[tokio::test]
async fn ui_status_redacts_for_a_non_admin() {
    for (fixture, caller) in [
        (Fixture::AuthOn, Caller::Auditor),
        (Fixture::AuthOff, Caller::AnonOff),
    ] {
        let gw = gateway(fixture).await;
        let (status, _, body) = send(
            &gw,
            request(&Method::GET, "/ui/api/status", caller, Payload::None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{caller:?}");
        let text = String::from_utf8_lossy(&body);
        let json: Value = serde_json::from_slice(&body).expect("status is JSON");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "degraded_count",
                "healthy_count",
                "server_count",
                "uptime_secs",
                "version"
            ],
            "{caller:?} got a field beyond the counts: {text}"
        );
        assert_eq!(
            json["server_count"], 1,
            "the fixture's backend is counted: {text}"
        );
        assert!(
            !text.contains("docs"),
            "{caller:?} got the backend name: {text}"
        );
    }
    // Positive control: the same fixture names the backend to an admin.
    let gw = gateway(Fixture::AuthOn).await;
    let (status, _, body) = send(
        &gw,
        request(&Method::GET, "/ui/api/status", Caller::Admin, Payload::None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).expect("status is JSON");
    assert_eq!(json["servers"][0]["name"], "docs", "{json}");
}
