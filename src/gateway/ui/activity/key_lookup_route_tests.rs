// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin email lookup through the real UI router, behind the admin audit
//! layer, over a real transparency log whose issuance rows are written the
//! way the key server writes them.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{AuthConfig, Config, KeyServerConfig};
use crate::config_reload::LiveConfig;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client};
use crate::gateway::router::AppState;
use crate::gateway::routes;
use crate::key_server::KeyServer;
use crate::key_server::audit::AuditEvent;
use crate::key_server::email_hash::EmailHashKey;
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::store::{TemporaryToken, TokenScopes};
use crate::security::audit::{AuditEnvelope, CredentialKind};
use crate::security::transparency_log::RotationConfig;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const ISS: &str = "https://issuer.invalid";
const EMAIL: &str = "Planted.Person@corp.invalid";
const OTHER: &str = "someone.else@corp.invalid";

fn client(admin: bool, backends: &[&str], kind: CredentialKind) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        quota_principal: None,
        name: "c".to_string(),
        rate_limit: 0,
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        allowed_tools: None,
        denied_tools: None,
        admin,
        authenticated: true,
        credential_kind: kind,
    }
}

fn admin(name: &str) -> AuthenticatedClient {
    let mut c = client(true, &["*"], CredentialKind::StaticBearer);
    c.name = name.to_owned();
    c
}

struct Fx {
    rt: tokio::runtime::Runtime,
    state: Arc<AppState>,
    live: Arc<LiveConfig>,
    log: Arc<TransparencyLogger>,
    ks: Arc<KeyServer>,
    dir: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
}

impl Fx {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let dir = crate::test_dir_keep::kept_tempdir();
        let (mut state, store) = rt.block_on(crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        ));
        let config = TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "test".into(),
            shared_secret: String::new(),
            // Small segments: the rows spread across several.
            rotation: RotationConfig {
                max_segment_bytes: 700,
                ..RotationConfig::default()
            },
        };
        let log = Arc::new(TransparencyLogger::open(Arc::new(config)).expect("opens"));
        log.keep_test_dir(Arc::clone(&dir));
        let ks = Arc::new(KeyServer::new(
            KeyServerConfig::default(),
            EmailHashKey::for_test(),
        ));
        let unique = Arc::get_mut(&mut state).expect("state is unique");
        unique.transparency_log = Some(Arc::clone(&log));
        unique.key_server = Some(Arc::clone(&ks));
        let live = Arc::new(LiveConfig::new(Config::default()));
        unique.live_config = Arc::clone(&live);
        Self {
            rt,
            state,
            live,
            log,
            ks,
            dir,
            _store: store,
        }
    }

    /// Write one issuance row for `email` under `subject`, as the mint does.
    fn plant(&self, subject: &str, email: &str, key: &EmailHashKey) {
        let identity = VerifiedIdentity::for_test(subject, email, None, Vec::new(), ISS);
        let token = TemporaryToken {
            jti: format!("jti-{subject}"),
            token: format!("mcpgw_{subject}"),
            identity,
            scopes: TokenScopes::default(),
            iat: 1,
            exp: 2,
            client_ip: None,
        };
        let serde_json::Value::Object(fields) =
            serde_json::to_value(AuditEvent::issued(&token, key)).expect("event")
        else {
            panic!("an event is an object");
        };
        let log = Arc::clone(&self.log);
        let out = self
            .rt
            .block_on(log.append_issuance_row(fields, AuditEnvelope::gateway()));
        assert_eq!(out.label(), "confirmed", "{out:?}");
    }

    fn post(&self, who: AuthenticatedClient, body: &str) -> (StatusCode, Option<String>, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .extension(self.live.generation())
            .extension(who)
            .body(Body::from(body.to_owned()))
            .expect("request");
        self.rt.block_on(async {
            let response = crate::gateway::ui::admin_audit::audited_api_router(&self.state)
                .with_state(self.state.clone())
                .oneshot(request)
                .await
                .expect("infallible");
            let status = response.status();
            let cache = response
                .headers()
                .get("cache-control")
                .map(|v| v.to_str().unwrap().to_owned());
            let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
            let value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            (status, cache, value)
        })
    }

    fn lookup(&self, email: &str, extra: Value) -> Value {
        let mut body = json!({"email": email});
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        let (status, cache, value) = self.post(admin("a"), &body.to_string());
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(cache.as_deref(), Some("no-store"));
        value
    }

    fn all_files(&self) -> Vec<(String, String)> {
        std::fs::read_dir(self.dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    String::from_utf8_lossy(&std::fs::read(e.path()).unwrap()).into_owned(),
                )
            })
            .collect()
    }
}

fn subjects(page: &Value) -> Vec<String> {
    page["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r["subject"].as_str().expect("subject").to_owned())
        .collect()
}

/// MIK-9455.LOOKUP.1: only gateway-wide admin standing is admitted; a scoped
/// admin, a non-admin key and an anonymous caller are refused, and a refusal
/// reads nothing and spends none of the shared budget.
/// Mutant: admit any authenticated caller, or charge before admission.
#[test]
fn only_a_gateway_wide_admin_is_admitted_and_refusals_spend_nothing() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    let refused = [
        ("anonymous", anonymous_client()),
        ("user key", client(false, &["*"], CredentialKind::ApiKey)),
        (
            "scoped admin",
            client(true, &["alpha"], CredentialKind::ApiKey),
        ),
    ];
    for (who, c) in refused {
        for _ in 0..4 {
            // A body that is not even JSON: still the refusal, never a 400.
            let (status, _, body) = fx.post(c.clone(), "not json");
            assert!(
                status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
                "{who}: {status} {body}"
            );
            assert!(!body.to_string().contains("rows"), "{who} saw rows");
        }
    }
    // Twelve refusals later the budget is untouched: two lookups still pass.
    for key in [admin("k1"), client(true, &["*"], CredentialKind::ApiKey)] {
        let (status, _, body) = fx.post(key, &json!({"email": EMAIL}).to_string());
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// MIK-9455.LOOKUP.3: one budget for every session and credential, charged
/// for every admitted attempt including a malformed one; the refusal carries
/// Retry-After.
/// Mutant: a budget per client, or free malformed attempts.
#[test]
fn the_budget_is_shared_and_charges_malformed_attempts() {
    let fx = Fx::new();
    let (s1, _, _) = fx.post(admin("one"), "{ not json");
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    let (s2, _, _) = fx.post(admin("two"), &json!({"email": ""}).to_string());
    assert_eq!(s2, StatusCode::BAD_REQUEST);
    let (s3, cache, body) = fx.post(admin("three"), &json!({"email": EMAIL}).to_string());
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
}

/// MIK-9455.LOOKUP.2: hash match across segments, case-insensitive per the
/// hash's normalization, the same email on two subjects returns both, another
/// email, another key id and a bare subject never match.
/// Mutant: match on the subject, ignore the key id, or read one segment.
#[test]
fn matching_rows_come_from_every_segment_and_only_for_the_same_hash() {
    let fx = Fx::new();
    let other_key = EmailHashKey::for_test_other();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    fx.plant("s3", OTHER, &fx.ks.email_key);
    fx.plant("s4", EMAIL, &other_key);
    let sealed = fx
        .all_files()
        .iter()
        .filter(|(n, _)| {
            n.starts_with("audit.jsonl.") && n.chars().last().is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    assert!(sealed >= 2, "the rows span several segments");
    let page = fx.lookup(&EMAIL.to_lowercase(), json!({}));
    let mut got = subjects(&page);
    got.sort();
    assert_eq!(got, vec!["s1", "s2"], "{page}");
    assert_eq!(page["scope"], "retained");
    assert_eq!(page["scan_exhausted"], false);
    assert_eq!(subjects(&fx.lookup(OTHER, json!({}))), vec!["s3"]);
}

/// MIK-9455.LOOKUP.2: pages follow the cursor, which is bound to the safe
/// filter: another email's cursor restarts at the newest row and says so.
/// Mutant: ignore the bind, or never return a cursor.
#[test]
fn pages_follow_a_cursor_that_is_bound_to_its_filter() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    fx.plant("s3", OTHER, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, json!({"limit": 1}));
    assert_eq!(subjects(&first), vec!["s2"], "newest first: {first}");
    let token = first["next_cursor"]
        .as_str()
        .expect("a next cursor")
        .to_owned();
    let second = fx.lookup(EMAIL, json!({"limit": 1, "cursor": token}));
    assert_eq!(subjects(&second), vec!["s1"], "{second}");
    assert_eq!(second["cursor_reset"], false);
    let foreign = fx.lookup(OTHER, json!({"limit": 1, "cursor": token}));
    assert_eq!(foreign["cursor_reset"], true, "{foreign}");
    assert_eq!(subjects(&foreign), vec!["s3"]);
}

/// MIK-9455.LOOKUP.2: a log line that is not a JSON entry is reported, not
/// silently skipped: an empty-looking page can carry `unreadable`.
/// Mutant: drop the unreadable count.
#[test]
fn a_malformed_line_is_reported_not_hidden() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    let active = fx.dir.path().join("audit.jsonl");
    let mut text = std::fs::read_to_string(&active).unwrap();
    text.push_str("this is not an entry\n");
    std::fs::write(&active, text).unwrap();
    let page = fx.lookup(EMAIL, json!({}));
    assert_eq!(page["unreadable"], 1, "{page}");
}

/// MIK-9455.LOOKUP.4: the planted email is in no file the key server and its
/// log wrote, a refusal never echoes the submitted text, the request's own
/// audit record is there with no body, and every admitted answer is no-store.
/// Mutant: log the request body, echo the email in a 400, drop the header.
#[test]
fn the_email_is_in_no_file_and_no_answer_and_the_request_is_audited_without_it() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    let (status, cache, body) = fx.post(
        admin("a"),
        &json!({"email": EMAIL, "limit": 0, "cursor": "tok"}).to_string(),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert!(
        !body.to_string().to_lowercase().contains("planted"),
        "{body}"
    );
    let _ = fx.lookup(EMAIL, json!({}));
    let mut audit_records = 0;
    for (name, text) in fx.all_files() {
        let lower = text.to_lowercase();
        assert!(!lower.contains("planted.person"), "{name} holds the email");
        assert!(
            !lower.contains("corp.invalid\"") || !lower.contains("planted"),
            "{name}"
        );
        audit_records += text
            .lines()
            .filter(|l| l.contains("admin_action") && l.contains("lookup_email"))
            .count();
    }
    assert_eq!(audit_records, 2, "each admitted lookup left its own record");
}
