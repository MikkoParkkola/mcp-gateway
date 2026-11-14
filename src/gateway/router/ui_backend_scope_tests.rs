// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential's backend scope bounds every UI read, whatever role it holds:
//! each scoped read surface × caller kind, against two registered backends.
//! A role sets how much of the scope a caller reads, never past it.
//!
//! The main matrix's callers all hold `*`, so its table is unchanged; these
//! cells are the scoped ones.

use super::*;
use crate::gateway::router::tests::http_backend_at;

const SCOPED_KEY: &str = "scope-alpha-key";
const SCOPED_ADMIN_KEY: &str = "scope-alpha-admin-key";
const EMPTY_KEY: &str = "scope-empty-key";
const UI_ADMIN_KEY: &str = "scope-ui-admin-key";

/// Every caller kind, by its key and the identity it carries.
#[derive(Clone, Copy, Debug)]
enum Who {
    AdminKey,
    Auditor,
    Developer,
    ScopedKey,
    ScopedAuditor,
    ScopedDeveloper,
    /// A non-admin key scoped to `alpha` whose identity maps to Admin.
    ScopedRoleAdmin,
    /// An admin key scoped to `alpha`: what the UI sees of a key-server
    /// token whose identity maps to Admin (`admin` from the role mapping,
    /// `backends` from the token's scopes).
    ScopedAdminKey,
    EmptyAuditor,
    /// A non-admin key with an empty list whose identity maps to Admin: the
    /// role adds no scope, so it reads nothing.
    EmptyRoleAdmin,
    /// An admin key with an empty list: a UI-wide admin that calls no
    /// backend.
    UiAdminKey,
}

impl Who {
    fn key(self) -> &'static str {
        match self {
            Self::AdminKey => ADMIN_KEY,
            Self::Auditor | Self::Developer => STANDARD_KEY,
            Self::ScopedKey
            | Self::ScopedAuditor
            | Self::ScopedDeveloper
            | Self::ScopedRoleAdmin => SCOPED_KEY,
            Self::ScopedAdminKey => SCOPED_ADMIN_KEY,
            Self::EmptyAuditor | Self::EmptyRoleAdmin => EMPTY_KEY,
            Self::UiAdminKey => UI_ADMIN_KEY,
        }
    }

    fn identity(self) -> Option<VerifiedIdentity> {
        match self {
            Self::Auditor | Self::ScopedAuditor | Self::EmptyAuditor => Caller::OidcAuditor,
            Self::Developer | Self::ScopedDeveloper => Caller::OidcDeveloper,
            Self::ScopedRoleAdmin | Self::EmptyRoleAdmin => Caller::OidcAdmin,
            Self::AdminKey | Self::ScopedKey | Self::ScopedAdminKey | Self::UiAdminKey => {
                return None;
            }
        }
        .identity()
    }
}

fn key_on(key: &str, admin: bool, backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        ..api_key(key, admin)
    }
}

/// One fresh gateway, the receipt id of `beta`'s Developer call, and the
/// directories it reads.
struct Scoped {
    state: Arc<AppState>,
    beta_receipt: String,
    _dirs: (
        crate::gateway::router::tests::FixtureDir,
        std::sync::Arc<tempfile::TempDir>,
    ),
}

/// A gateway with backends `alpha` and `beta`, the matrix's role rules and a
/// seeded log.
async fn scoped_fixture() -> Scoped {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![
            api_key(ADMIN_KEY, true),
            api_key(STANDARD_KEY, false),
            key_on(SCOPED_KEY, false, &["alpha"]),
            key_on(SCOPED_ADMIN_KEY, true, &["alpha"]),
            key_on(EMPTY_KEY, false, &[]),
            key_on(UI_ADMIN_KEY, true, &[]),
        ],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (mut state, dir) = test_router_app_state_with_auth_and_key_server(&auth, None).await;
    let mut config = (*state.live_config.get()).clone();
    config.control_plane.role_mapping = ControlPlaneRoleMappingConfig {
        rules: vec![
            rule("admins", ControlPlaneRole::Admin),
            rule("auditors", ControlPlaneRole::Auditor),
            rule("devs", ControlPlaneRole::Developer),
        ],
    };
    state.live_config.set(config);
    for name in ["alpha", "beta"] {
        // A port nothing listens on: registered, never started.
        let _ = state
            .backends
            .register(http_backend_at(name, "http://127.0.0.1:9/mcp"));
    }
    let (log_dir, beta_receipt) = seed_scoped_log(&mut state);
    Scoped {
        state,
        beta_receipt,
        _dirs: (dir, log_dir),
    }
}

/// The seeded calls: (server, Developer subject or none, tool).
const CALLS: [(&str, Option<&str>, &str); 4] = [
    ("alpha", Some(DEV), "tool_alpha_dev"),
    ("alpha", None, "tool_alpha_key"),
    ("beta", Some(DEV), "tool_beta_dev"),
    ("beta", Some(OTHER_DEV), "tool_beta_other"),
];

/// An invocation log of [`CALLS`] and one admin action, chained and hashed
/// like the logger's; returns the receipt id of `beta`'s [`DEV`] call.
fn seed_scoped_log(state: &mut Arc<AppState>) -> (std::sync::Arc<tempfile::TempDir>, String) {
    use crate::security::transparency_log::TransparencyLogConfig;
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("audit.jsonl");
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    let mut beta_receipt = String::new();
    let entries = CALLS
        .iter()
        .map(|(server, subject, tool)| {
            let mut who = json!({"account": STANDARD_KEY, "principal": STANDARD_KEY});
            if let Some(subject) = subject {
                who["authority"] = ISSUER.into();
                who["subject"] = (*subject).into();
            }
            json!({
                "outcome": "ok", "server": server, "tool": tool,
                "route": "meta_invoke", "request_hash": "sha256:aa", "who": who,
            })
        })
        .chain(std::iter::once(json!({
            "event": "admin_action", "surface": "ui", "route": "/ui/api/config",
            "method": "PUT", "http_status": 200,
        })));
    for (i, mut entry) in entries.enumerate() {
        entry["counter"] = (i + 1).into();
        entry["prev_entry_hash"] = prev.clone().into();
        entry["timestamp"] = format!("2026-10-26T10:00:{i:02}+00:00").into();
        let hash = recompute_entry_hash(&entry).expect("hashes");
        entry["entry_hash"] = hash.clone().into();
        body.push_str(&(entry.to_string() + "\n"));
        if entry["tool"] == "tool_beta_dev" {
            let hex = hash.rsplit(':').next().unwrap_or(&hash);
            beta_receipt = format!("{}-{}", i + 1, &hex[..16]);
        }
        prev = hash;
    }
    std::fs::write(&path, body).expect("seed log");
    let log = crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "scope".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    Arc::get_mut(state)
        .expect("state is unique")
        .transparency_log = Some(Arc::new(log));
    (dir, beta_receipt)
}

fn get(who: Who, uri: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .header(header::AUTHORIZATION, format!("Bearer {}", who.key()));
    if let Some(identity) = who.identity() {
        builder = builder.extension(identity);
    }
    builder.body(Body::empty()).expect("request builds")
}

/// The seeded tool names in `body`, sorted, comma-joined.
fn seeded_tools(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut seen: Vec<&str> = CALLS
        .iter()
        .map(|(_, _, tool)| *tool)
        .filter(|tool| text.contains(tool))
        .collect();
    seen.sort_unstable();
    seen.join(",")
}

/// Every backend name the body names as `backend:<name>`, sorted.
fn named_backends(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut seen: Vec<&str> = ["alpha", "beta"]
        .into_iter()
        .filter(|name| text.contains(&format!("\"backend:{name}\"")))
        .collect();
    seen.sort_unstable();
    seen.join(",")
}

/// One caller's answers on every scoped read surface, as a row of cells:
/// status, list, export, receipt of beta's Developer call, snapshot, link.
async fn row_for(who: Who) -> [String; 6] {
    let fx = scoped_fixture().await;
    let router = create_router(Arc::clone(&fx.state));
    let ask = |uri: String| send(&router, get(who, &uri));

    let (code, body) = ask(routes::UI_STATUS.to_string()).await;
    let status: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let code = code.as_u16();
    let status = match status.get("servers") {
        Some(servers) => format!("{code}:full:{}", servers.as_array().map_or(0, Vec::len)),
        None => format!(
            "{code}:counts:{}/{}",
            status["server_count"], status["healthy_count"]
        ),
    };

    let (code, body) = ask(format!("{}?limit=200", routes::UI_ACTIVITY)).await;
    let list: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let admin_rows = list["rows"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["kind"] != "call"));
    let list = format!(
        "{}:{}{}",
        code.as_u16(),
        seeded_tools(&body),
        if admin_rows { "+non-call" } else { "" }
    );

    let (code, body) = ask(format!("{}?format=csv", routes::UI_ACTIVITY_EXPORT)).await;
    // The CSV's second column is the row kind: any row but a call is
    // gateway-wide.
    let non_call = String::from_utf8_lossy(&body)
        .lines()
        .skip(1)
        .any(|line| matches!(line.split(',').nth(1), Some("config" | "admin_action")));
    let export = format!(
        "{}:{}{}",
        code.as_u16(),
        seeded_tools(&body),
        if non_call { "+non-call" } else { "" }
    );

    let receipt_uri = |id: &str| routes::UI_ACTIVITY_RECEIPT.replace("{id}", id);
    let (code, body) = ask(receipt_uri(&fx.beta_receipt)).await;
    let receipt = if code == StatusCode::NOT_FOUND {
        let (_, missing) = ask(receipt_uri("9999-0000000000000000")).await;
        if body == missing {
            "404=missing".to_string()
        } else {
            "404!=missing".to_string()
        }
    } else {
        code.as_u16().to_string()
    };

    let (code, body) = ask(routes::UI_CONTROL_PLANE.to_string()).await;
    let snapshot = format!("{}:{}", code.as_u16(), named_backends(&body));

    let mut link = get(who, routes::UI_DASHBOARD_LINK);
    *link.method_mut() = axum::http::Method::POST;
    let (code, _) = send(&router, link).await;
    let link = code.as_u16().to_string();

    [status, list, export, receipt, snapshot, link]
}

const ALL: &str = "tool_alpha_dev,tool_alpha_key,tool_beta_dev,tool_beta_other";
const ALPHA: &str = "tool_alpha_dev,tool_alpha_key";

/// The answers each caller gets: status, list, export, receipt, snapshot,
/// dashboard link. Unscoped rows are today's; every scoped row reads alpha
/// only, nothing gateway-wide, and a receipt it may not read answers as a
/// missing one.
fn expected(who: Who) -> [String; 6] {
    let scoped_reader = |status: &str, tools: &str| {
        [
            status.to_string(),
            format!("200:{tools}"),
            format!("200:{tools}"),
            "404=missing".to_string(),
            "200:alpha".to_string(),
            "403".to_string(),
        ]
    };
    match who {
        Who::AdminKey | Who::UiAdminKey => [
            "200:full:2".to_string(),
            format!("200:{ALL}+non-call"),
            format!("200:{ALL}+non-call"),
            "200".to_string(),
            "200:alpha,beta".to_string(),
            "200".to_string(),
        ],
        Who::Auditor => [
            "200:counts:2/2".to_string(),
            format!("200:{ALL}+non-call"),
            format!("200:{ALL}+non-call"),
            "200".to_string(),
            "200:alpha,beta".to_string(),
            "403".to_string(),
        ],
        Who::Developer => [
            "200:counts:2/2".to_string(),
            "200:tool_alpha_dev,tool_beta_dev".to_string(),
            "200:tool_alpha_dev,tool_beta_dev".to_string(),
            "200".to_string(),
            "200:alpha,beta".to_string(),
            "403".to_string(),
        ],
        Who::ScopedKey => [
            "200:counts:1/1".to_string(),
            "403:".to_string(),
            "403:".to_string(),
            "403".to_string(),
            "200:alpha".to_string(),
            "403".to_string(),
        ],
        Who::ScopedAuditor | Who::ScopedRoleAdmin | Who::ScopedAdminKey => {
            scoped_reader("200:counts:1/1", ALPHA)
        }
        Who::ScopedDeveloper => scoped_reader("200:counts:1/1", "tool_alpha_dev"),
        Who::EmptyAuditor | Who::EmptyRoleAdmin => {
            let mut row = scoped_reader("200:counts:0/0", "");
            row[4] = "200:".to_string();
            row
        }
    }
}

const WHO: [Who; 11] = [
    Who::AdminKey,
    Who::Auditor,
    Who::Developer,
    Who::ScopedKey,
    Who::ScopedAuditor,
    Who::ScopedDeveloper,
    Who::ScopedRoleAdmin,
    Who::ScopedAdminKey,
    Who::EmptyAuditor,
    Who::EmptyRoleAdmin,
    Who::UiAdminKey,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_scope_bounds_every_role_on_every_read() {
    let mut wrong = Vec::new();
    for who in WHO {
        let (got, want) = (row_for(who).await, expected(who));
        if got != want {
            wrong.push(format!("{who:?}:\n  got  {got:?}\n  want {want:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} callers moved:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// S1: the status route's restart member. Before any accept the full view
/// answers `restart: null`, after one the record; every counts-only and
/// scoped caller never carries the member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_only_the_full_status_view_carries_restart() {
    let fx = scoped_fixture().await;
    let router = create_router(Arc::clone(&fx.state));
    let board = fx.state.meta_mcp.restart_board();
    let mut wrong = Vec::new();
    for accepted in [false, true] {
        if accepted {
            board.accept(1_000);
        }
        for who in WHO {
            let (code, body) = send(&router, get(who, routes::UI_STATUS)).await;
            assert_eq!(code, StatusCode::OK, "{who:?}");
            let body: Value = serde_json::from_slice(&body).expect("status JSON");
            let want = match (body.get("servers").is_some(), accepted) {
                (false, _) => None,
                (true, false) => Some(Value::Null),
                (true, true) => Some(board.status().expect("a record").wire()),
            };
            let got = body.get("restart");
            let phase_ok = !(want.is_some() && accepted) || body["restart"]["phase"] == "accepted";
            if got != want.as_ref() || !phase_ok {
                wrong.push(format!("{who:?} accepted={accepted}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[path = "ui_backend_scope_snapshot_tests.rs"]
mod snapshot;
