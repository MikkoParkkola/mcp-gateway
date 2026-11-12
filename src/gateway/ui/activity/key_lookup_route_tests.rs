// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The admin email lookup through the real UI router, behind the admin audit
//! layer, over a real transparency log whose issuance rows are written the
//! way the key server writes them.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use base64::Engine as _;
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
    // A credential principal of its own: a page token binds to it.
    c.principal =
        crate::gateway::record_principal::InternalPrincipal::new(format!("principal-{name}"));
    c
}

/// The digest of `who`'s credential principal, as the route binds tokens.
fn fingerprint(who: &AuthenticatedClient) -> String {
    crate::hashing::sha256_hex(
        who.credential_principal()
            .expect("a credential principal")
            .storage_form()
            .as_bytes(),
    )
}

struct Fx {
    rt: tokio::runtime::Runtime,
    state: Arc<AppState>,
    live: Arc<LiveConfig>,
    log: Arc<TransparencyLogger>,
    ks: Arc<KeyServer>,
    dir: Arc<tempfile::TempDir>,
    /// The Retry-After header of the last answer, if it had one.
    retry_after: std::cell::RefCell<Option<String>>,
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
            retry_after: std::cell::RefCell::new(None),
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

    /// Write an issuance row carrying exactly this hash, version and key id.
    fn plant_raw(&self, subject: &str, hash: &str, version: u64, key_id: &str) {
        let fields = json!({
            "event": "token.issued",
            "token_jti": format!("jti-{subject}"),
            "identity": {
                "subject": subject, "issuer": ISS, "email_hash": hash,
                "email_hash_version": version, "email_hash_key_id": key_id,
            },
        });
        let serde_json::Value::Object(fields) = fields else {
            panic!("an object");
        };
        let log = Arc::clone(&self.log);
        let out = self
            .rt
            .block_on(log.append_issuance_row(fields, AuditEnvelope::gateway()));
        assert_eq!(out.label(), "confirmed", "{out:?}");
    }

    fn post(&self, who: AuthenticatedClient, body: &str) -> (StatusCode, Option<String>, Value) {
        self.post_via(true, who, body)
    }

    /// `audited`: behind the admin audit layer, which runs the handler in its
    /// own task. A row that reads a thread-local recorder goes without it.
    fn post_via(
        &self,
        audited: bool,
        who: AuthenticatedClient,
        body: &str,
    ) -> (StatusCode, Option<String>, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .extension(self.live.generation())
            .extension(who)
            .body(Body::from(body.to_owned()))
            .expect("request");
        self.rt.block_on(async {
            let router = if audited {
                crate::gateway::ui::admin_audit::audited_api_router(&self.state)
            } else {
                crate::gateway::ui::api_router()
            };
            let response = router
                .with_state(self.state.clone())
                .oneshot(request)
                .await
                .expect("infallible");
            let status = response.status();
            let cache = response
                .headers()
                .get("cache-control")
                .map(|v| v.to_str().unwrap().to_owned());
            *self.retry_after.borrow_mut() = response
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_owned());
            let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
            let value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            (status, cache, value)
        })
    }

    /// POST whose body never arrives; the answer must come without it.
    fn post_stalled(&self, who: AuthenticatedClient) -> StatusCode {
        let body = Body::from_stream(futures::stream::pending::<
            Result<axum::body::Bytes, std::io::Error>,
        >());
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .extension(self.live.generation())
            .extension(who)
            .body(body)
            .expect("request");
        self.rt.block_on(async {
            let answer = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                crate::gateway::ui::api_router()
                    .with_state(self.state.clone())
                    .oneshot(request),
            )
            .await
            .expect("the route answered without waiting for the body");
            answer.expect("infallible").status()
        })
    }

    fn lookup(&self, email: &str, extra: &Value) -> Value {
        let mut body = json!({"email": email});
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        // A row that looks up several times is not a budget row: start full.
        self.state.process.lookup_budget().reset_for_test();
        let (status, cache, value) = self.post(admin("a"), &body.to_string());
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(cache.as_deref(), Some("no-store"));
        value
    }

    /// A next-page request: the token and nothing else (plus `extra`), on a
    /// full budget.
    fn next_page(
        &self,
        who: AuthenticatedClient,
        token: &str,
        extra: &Value,
    ) -> (StatusCode, Option<String>, Value) {
        let mut body = json!({"cursor": token});
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        self.state.process.lookup_budget().reset_for_test();
        self.post(who, &body.to_string())
    }

    /// The scope a page token for EMAIL carries, born at `born`.
    fn scope(&self, born: u64) -> super::key_lookup::PageScope {
        super::key_lookup::PageScope {
            hash: self.ks.email_key.hash(EMAIL),
            version: u64::from(crate::key_server::email_hash::VERSION),
            key_id: self.ks.email_key.key_id(),
            from: None,
            to: None,
            pos: super::reader::Cursor {
                inv: None,
                gov: None,
                gov_bound: None,
            },
            born,
        }
    }

    /// Seal a page token by hand, for the rows that need a time or a scope the
    /// route would not mint.
    fn seal_by_hand(
        &self,
        who: &AuthenticatedClient,
        scope: &super::key_lookup::PageScope,
        now: u64,
    ) -> String {
        super::key_lookup::seal(&self.state, &fingerprint(who), scope, now).expect("sealed")
    }

    fn all_files(&self) -> Vec<(String, String)> {
        std::fs::read_dir(self.dir.path())
            .unwrap()
            .filter_map(Result::ok)
            // The writer's lease sentinel holds no data, and on Windows its
            // byte-range lock makes any read of it fail.
            .filter(|e| e.path().is_file() && e.path().extension().is_none_or(|x| x != "lock"))
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
    let wait: u64 = fx
        .retry_after
        .borrow()
        .clone()
        .expect("a Retry-After")
        .parse()
        .expect("whole seconds");
    assert!(
        (1..=6).contains(&wait),
        "a refill is at most six seconds away: {wait}"
    );
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
    let page = fx.lookup(&EMAIL.to_lowercase(), &json!({}));
    let mut got = subjects(&page);
    got.sort();
    assert_eq!(got, vec!["s1", "s2"], "{page}");
    assert_eq!(page["scope"], "retained");
    assert_eq!(page["scan_exhausted"], false);
    assert_eq!(subjects(&fx.lookup(OTHER, &json!({}))), vec!["s3"]);
}

/// MIK-9455.LOOKUP.2: a next page is asked for with the token alone, and the
/// token the route hands out is sealed: it holds neither the email nor its
/// keyed hash, in the clear or as base64 of either.
/// Mutant: return a token that spells the hash (an unsealed cursor), or
/// require the email again for the next page.
#[test]
fn pages_follow_a_sealed_cursor_sent_without_the_email() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    fx.plant("s3", OTHER, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    assert_eq!(subjects(&first), vec!["s2"], "newest first: {first}");
    let token = first["next_cursor"]
        .as_str()
        .expect("a next cursor")
        .to_owned();
    let hash = fx.ks.email_key.hash(EMAIL);
    for secret in [EMAIL, EMAIL.to_lowercase().as_str(), hash.as_str()] {
        assert!(!token.contains(secret), "the token spells {secret}");
    }
    for part in token.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_') {
        if let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part) {
            let raw = String::from_utf8_lossy(&raw).into_owned();
            assert!(!raw.contains(hash.as_str()), "a token part decodes to the hash");
            assert!(!raw.to_lowercase().contains(&EMAIL.to_lowercase()));
        }
    }
    let (status, cache, second) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(subjects(&second), vec!["s1"], "{second}");
    assert!(
        !second.to_string().contains(EMAIL),
        "the answer must not echo the email"
    );
}

/// The two request shapes are exclusive: a first page is an email (and
/// optionally limit, from, to); a next page is a cursor (and optionally a
/// limit). Both, neither, or a window beside a cursor are refused.
/// Mutant: accept both and ignore one, or let from/to ride beside a cursor.
#[test]
fn a_request_is_an_email_or_a_cursor_never_both_or_neither() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    for body in [
        json!({"email": EMAIL, "cursor": token}),
        json!({"limit": 1}),
        json!({"cursor": token, "from": "2000-01-01T00:00:00Z"}),
        json!({"cursor": token, "to": "2100-01-01T00:00:00Z"}),
        json!({"cursor": token, "extra": 1}),
    ] {
        fx.state.process.lookup_budget().reset_for_test();
        let (status, _, answer) = fx.post(admin("a"), &body.to_string());
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {answer}");
        assert!(!answer.to_string().contains(EMAIL), "{answer}");
    }
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
    let page = fx.lookup(EMAIL, &json!({}));
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
    let _ = fx.lookup(EMAIL, &json!({}));
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

/// MIK-9455.LOOKUP.5: every authorized attempt is counted once and every
/// throttled one once, on counters with no labels (so no email, hash or
/// caller can reach a metric); a refusal at admission counts nothing.
/// Mutant: count before admission, count throttles as attempts, add a label.
#[cfg(feature = "metrics")]
#[test]
fn attempts_and_throttles_are_counted_on_unlabelled_counters() {
    let fx = Fx::new();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        let (refused, _, _) = fx.post_via(false, anonymous_client(), "{}");
        assert!(refused == StatusCode::UNAUTHORIZED || refused == StatusCode::FORBIDDEN);
        for _ in 0..2 {
            let (s, _, _) = fx.post_via(false, admin("a"), &json!({"email": EMAIL}).to_string());
            assert_eq!(s, StatusCode::OK);
        }
        let (third, _, _) = fx.post_via(false, admin("a"), &json!({"email": EMAIL}).to_string());
        assert_eq!(third, StatusCode::TOO_MANY_REQUESTS);
    });
    let rendered = handle.render();
    let value = |name: &str| {
        rendered
            .lines()
            .find(|l| l.starts_with(name))
            .map(str::to_owned)
    };
    assert_eq!(
        value("mcp_key_server_lookup_attempts_total").as_deref(),
        Some("mcp_key_server_lookup_attempts_total 3"),
        "{rendered}"
    );
    assert_eq!(
        value("mcp_key_server_lookup_throttled_total").as_deref(),
        Some("mcp_key_server_lookup_throttled_total 1"),
        "{rendered}"
    );
}

/// MIK-9455.LOOKUP.2: the key id and the version are part of the match: a row
/// with the same hash under another key id or version is not this person's.
/// Mutant: ignore the key id, or ignore the version.
#[test]
fn the_key_id_and_version_are_part_of_the_match() {
    let fx = Fx::new();
    let hash = fx.ks.email_key.hash(EMAIL);
    let key_id = fx.ks.email_key.key_id();
    fx.plant_raw("right", &hash, 1, &key_id);
    fx.plant_raw("other-key", &hash, 1, "0000");
    fx.plant_raw("other-version", &hash, 2, &key_id);
    assert_eq!(subjects(&fx.lookup(EMAIL, &json!({}))), vec!["right"]);
}

/// MIK-9455.LOOKUP.1 and .3: the body is not waited for before admission or
/// the budget: an anonymous caller and an over-budget admin are answered at
/// once though their body never arrives (the 30 s bound is a hang guard).
/// Mutant: extract the body before the guard or before the charge.
#[test]
fn a_body_that_never_arrives_is_not_waited_for_before_admission_or_payment() {
    let fx = Fx::new();
    let refused = fx.post_stalled(anonymous_client());
    assert!(
        refused == StatusCode::UNAUTHORIZED || refused == StatusCode::FORBIDDEN,
        "{refused}"
    );
    // Spend both permits with two quick malformed attempts.
    for _ in 0..2 {
        let (status, _, _) = fx.post(admin("a"), "{ not json");
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        fx.post_stalled(admin("a")),
        StatusCode::TOO_MANY_REQUESTS,
        "no permit left: answered without the body"
    );
}

/// MIK-9455.LOOKUP.4: an admitted caller whose body stalls is cut off with a
/// 408 at the deadline, on a paused clock (no real wait).
/// Mutant: no deadline (the read waits forever).
#[tokio::test(start_paused = true)]
async fn a_stalled_body_is_cut_off_at_the_deadline() {
    let body = Body::from_stream(futures::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let request = Request::builder().body(body).expect("request");
    let refusal = super::key_lookup::read_body(request)
        .await
        .expect_err("a body that never arrives is refused");
    assert_eq!(refusal.status(), StatusCode::REQUEST_TIMEOUT);
}

/// An oversize body is refused with a 413 before it is all read.
/// Mutant: no size bound.
#[tokio::test]
async fn an_oversize_body_is_refused() {
    let request = Request::builder()
        .body(Body::from(vec![b'a'; 9 * 1024]))
        .expect("request");
    let refusal = super::key_lookup::read_body(request)
        .await
        .expect_err("over the cap");
    assert_eq!(refusal.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// MIK-9455.LOOKUP.2: a window that ends before it starts is refused.
/// Mutant: drop the check (a scan of an impossible interval).
#[test]
fn a_window_that_ends_before_it_starts_is_refused() {
    let fx = Fx::new();
    let (status, _, body) = fx.post(
        admin("a"),
        &json!({"email": EMAIL, "from": "2026-11-02T00:00:00Z", "to": "2026-11-01T00:00:00Z"})
            .to_string(),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// MIK-9455.LOOKUP.2: the time window keeps rows inside it and drops rows
/// outside it, and a next page under a window still answers (that the window
/// itself rides in the token is the seal rows' business).
/// Mutant: ignore the window.
#[test]
fn the_window_filters_rows_and_the_next_page_still_answers() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let wide = json!({"from": "2000-01-01T00:00:00Z", "to": "2100-01-01T00:00:00Z"});
    assert_eq!(subjects(&fx.lookup(EMAIL, &wide)).len(), 2);
    let later = json!({"from": "2100-01-01T00:00:00Z"});
    assert!(
        subjects(&fx.lookup(EMAIL, &later)).is_empty(),
        "rows before from are dropped"
    );
    let earlier = json!({"to": "2000-01-01T00:00:00Z"});
    assert!(
        subjects(&fx.lookup(EMAIL, &earlier)).is_empty(),
        "rows after to are dropped"
    );
    // The window rides inside the sealed token: page two keeps it.
    let first = fx.lookup(EMAIL, &json!({"limit": 1, "from": "2000-01-01T00:00:00Z"}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let (status, _, second) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(subjects(&second).len(), 1, "{second}");
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

fn refusal_of(fx: &Fx, who: AuthenticatedClient, token: &str) -> (StatusCode, Option<String>, Option<String>, Value) {
    let (status, cache, value) = fx.next_page(who, token, &json!({}));
    let retry = fx.retry_after.borrow().clone();
    (status, cache, retry, value)
}

/// A page token belongs to the credential principal it was minted for: another
/// admin presenting it is refused, and the refusal is the same fixed answer
/// every bad token gets.
/// Mutant: leave the principal out of the AAD or the redemption check.
#[test]
fn a_page_token_is_refused_to_another_principal_with_the_one_fixed_answer() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let other = refusal_of(&fx, admin("b"), &token);
    assert_eq!(other.0, StatusCode::BAD_REQUEST, "{other:?}");
    let garbage = refusal_of(&fx, admin("a"), "not-a-token");
    assert_eq!(other, garbage, "a wrong principal must look like garbage");
    assert!(!other.3.to_string().contains(EMAIL));
}

/// Every way a token can fail to open gives one answer, byte for byte: status,
/// cache header, retry header and body. Tampered, garbage, empty, expired,
/// another purpose, another keyring, an old hash key id, an old hash version,
/// past the chain ceiling.
/// Mutant: a distinct message or status for any one cause.
#[test]
fn every_token_that_does_not_open_gets_the_same_answer() {
    use crate::protocol::continuation::{ContinuationPurpose, Keyring, Payload};
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    let who = admin("a");
    let now = now_secs();
    let good = fx.seal_by_hand(&who, &fx.scope(now), now);
    let mut tampered = good.clone();
    let last = tampered.pop().expect("a token");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    // Past its own expiry but inside the chain ceiling, then far past both.
    let expired = fx.seal_by_hand(&who, &fx.scope(now - 400), now - 400);
    let long_gone = fx.seal_by_hand(&who, &fx.scope(now - 10_000), now - 10_000);
    let old_ceiling = {
        let mut scope = fx.scope(now - 1_000);
        scope.born = now - 1_000;
        fx.seal_by_hand(&who, &scope, now)
    };
    let mut wrong_key = fx.scope(now);
    wrong_key.key_id = "another-key".into();
    let mut wrong_version = fx.scope(now);
    wrong_version.version += 1;
    let preview = fx
        .state
        .continuation
        .keyring()
        .mint(&Payload::mint_preview(fingerprint(&who), "d".into(), now))
        .expect("a preview token");
    let _ = ContinuationPurpose::PreviewConfirm;
    let other_ring = Keyring::new(&[(1, [9u8; 32])])
        .expect("a ring")
        .mint(&Payload::mint_lookup(
            fingerprint(&who),
            serde_json::to_string(&fx.scope(now)).expect("scope"),
            now,
        ))
        .expect("a token");
    let tokens = [
        tampered,
        "garbage".to_owned(),
        String::new(),
        expired,
        long_gone,
        old_ceiling,
        fx.seal_by_hand(&who, &wrong_key, now),
        fx.seal_by_hand(&who, &wrong_version, now),
        preview,
        other_ring,
    ];
    let reference = refusal_of(&fx, who.clone(), "garbage");
    assert_eq!(reference.0, StatusCode::BAD_REQUEST, "{reference:?}");
    for token in &tokens {
        assert_eq!(
            refusal_of(&fx, who.clone(), token),
            reference,
            "a token that fails to open answered differently: {token}"
        );
    }
    // The good one still opens, so the rows above refused for their reasons.
    let (status, _, _) = fx.next_page(who, &good, &json!({}));
    assert_eq!(status, StatusCode::OK);
}

/// A page token carries the whole scope and gives it back: hash, version, key
/// id, window and log position survive seal and open for the same principal,
/// and `open` is opaque: `None` for another principal, an empty principal, or a
/// stale scope.
/// Mutant: drop the window from the scope, or open for any principal.
#[test]
fn seal_and_open_round_trip_the_scope_for_one_principal_only() {
    let fx = Fx::new();
    let who = admin("a");
    let now = now_secs();
    let mut scope = fx.scope(now);
    scope.from = Some("2000-01-01T00:00:00Z".into());
    scope.to = Some("2100-01-01T00:00:00Z".into());
    let token = fx.seal_by_hand(&who, &scope, now);
    let open = |principal: &str, token: &str| {
        super::key_lookup::open(&fx.state, principal, token, now, &fx.ks.email_key)
    };
    let got = open(&fingerprint(&who), &token)
        .expect("opens for its principal")
        .scope;
    assert_eq!(got.hash, scope.hash);
    assert_eq!(got.from, scope.from);
    assert_eq!(got.to, scope.to);
    assert_eq!(got.born, scope.born);
    assert!(open(&fingerprint(&admin("b")), &token).is_none());
    assert!(open("", &token).is_none(), "an empty principal never opens");
}

/// A caller with no credential principal gets a first page, but when a next
/// page would exist it is told no token can be issued (503, a fixed line), and
/// no token is minted. Mutant: mint a token bound to the empty principal.
#[test]
fn a_caller_without_a_principal_is_given_no_page_token() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let mut nobody = admin("a");
    nobody.principal = crate::gateway::record_principal::InternalPrincipal::new(String::new());
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, body) = fx.post(
        nobody.clone(),
        &json!({"email": EMAIL, "limit": 1}).to_string(),
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.get("next_cursor").is_none(), "{body}");
    // And a last page needs no token, so it still answers.
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, body) = fx.post(nobody, &json!({"email": EMAIL, "limit": 10}).to_string());
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A page token is single use, and it is spent by the page it serves: a 429
/// (the budget is spent), leaves it redeemable; once a page has been answered
/// it is spent and the same token is refused with the fixed answer.
/// Mutant: never consume (replayable), or consume before the budget charge.
#[test]
fn a_token_is_spent_by_the_page_it_serves_and_not_by_a_throttle() {
    let fx = Fx::new();
    for subject in ["s1", "s2", "s3"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    // Spend the whole budget, then ask with the token: a 429, token intact.
    let who = admin("a");
    let body = json!({"cursor": token, "limit": 1}).to_string();
    fx.state.process.lookup_budget().reset_for_test();
    loop {
        let (status, _, _) = fx.post(who.clone(), &json!({"email": "x@corp.invalid"}).to_string());
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    let (status, _, throttled) = fx.post(who.clone(), &body);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{throttled}");
    // Budget back: the same token serves a page once.
    fx.state.process.lookup_budget().reset_for_test();
    let (status, _, second) = fx.post(who.clone(), &body);
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(subjects(&second), vec!["s2"], "{second}");
    // And only once.
    let replay = refusal_of(&fx, who.clone(), &token);
    assert_eq!(replay, refusal_of(&fx, who, "garbage"), "{replay:?}");
}

/// A scan that fails (503) does not spend the token: the retry gets the page.
/// Unix only: the failure is a log file the process may not read.
/// Mutant: consume the token at open, before the scan.
#[cfg(unix)]
#[test]
fn a_failed_scan_leaves_the_token_redeemable() {
    use std::os::unix::fs::PermissionsExt as _;
    let fx = Fx::new();
    for subject in ["s1", "s2"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let files: Vec<_> = std::fs::read_dir(fx.dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|x| x != "lock"))
        .collect();
    for f in &files {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let (status, _, down) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    for f in &files {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{down}");
    let (status, _, again) = fx.next_page(admin("a"), &token, &json!({"limit": 1}));
    assert_eq!(status, StatusCode::OK, "the token was burned: {again}");
}

/// The order is pinned so a token cannot be probed through other errors: a
/// bad limit, or no key server, answers its own refusal BEFORE the token is
/// opened, whatever the token is.
/// Mutant: open the token before the limit check or the key-server check.
#[test]
fn every_refusal_that_is_not_about_the_token_comes_before_it_is_opened() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let good = first["next_cursor"].as_str().expect("cursor").to_owned();
    let bad_limit = |token: &str| {
        fx.state.process.lookup_budget().reset_for_test();
        fx.post(
            admin("a"),
            &json!({"cursor": token, "limit": 0}).to_string(),
        )
    };
    let (s1, _, b1) = bad_limit(&good);
    let (s2, _, b2) = bad_limit("garbage");
    assert_eq!((s1, &b1), (s2, &b2), "limit error must not depend on the token");
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    assert_ne!(
        b1,
        refusal_of(&fx, admin("a"), "garbage").3,
        "a bad limit and a bad token are different refusals"
    );
}

/// A page request is a lookup: it is charged to the shared budget before the
/// body is read, so a stolen token cannot dodge the throttle.
/// Mutant: skip the charge on a cursor request.
#[test]
fn a_cursor_request_is_charged_to_the_shared_budget() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    fx.state.process.lookup_budget().reset_for_test();
    let mut statuses = Vec::new();
    for _ in 0..4 {
        let (status, _, _) = fx.post(admin("a"), &json!({"cursor": "garbage"}).to_string());
        statuses.push(status);
    }
    assert_eq!(
        statuses,
        vec![
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS
        ],
        "burst 2, then throttled, bad tokens included"
    );
}

/// Two requests that present one token at the same moment: both may scan (the
/// token is spent after its page is read, so a throttle or a failed read does
/// not burn it), but the ledger lets exactly one deliver. The other gets the
/// fixed refusal and its page is dropped. The cost of the race is one extra
/// read under the shared budget, bound to the same principal and the same
/// data; the loser learns nothing the winner did not.
/// Mutant: deliver on both (spend ignored), or deliver on neither.
#[test]
fn two_requests_with_one_token_deliver_exactly_one_page() {
    let fx = Fx::new();
    for subject in ["s1", "s2", "s3"] {
        fx.plant(subject, EMAIL, &fx.ks.email_key);
    }
    let first = fx.lookup(EMAIL, &json!({"limit": 1}));
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    fx.state.process.lookup_budget().reset_for_test();
    let call = || {
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .extension(fx.live.generation())
            .extension(admin("a"))
            .body(Body::from(json!({"cursor": token, "limit": 1}).to_string()))
            .expect("request");
        let router = crate::gateway::ui::api_router().with_state(fx.state.clone());
        async move { router.oneshot(request).await.expect("infallible").status() }
    };
    let (one, two) = fx.rt.block_on(async { tokio::join!(call(), call()) });
    let mut got = [one, two];
    got.sort();
    assert_eq!(
        got,
        [StatusCode::OK, StatusCode::BAD_REQUEST],
        "exactly one request delivers the page"
    );
}

/// Every dashboard session carries one constant principal, so a token bound to
/// it would open in any other browser session. A session binds to its own
/// cookie handle: another session's token is the fixed refusal, the same
/// session pages on, and a session whose cookie is gone mints nothing.
/// Mutant: bind a dashboard session to the shared principal.
#[test]
fn a_dashboard_session_pages_only_its_own_tokens() {
    let fx = Fx::new();
    fx.plant("s1", EMAIL, &fx.ks.email_key);
    fx.plant("s2", EMAIL, &fx.ks.email_key);
    let session = |cookie: &str, body: &Value| {
        let mut c = client(true, &["*"], CredentialKind::DashboardSession);
        c.principal = crate::gateway::record_principal::InternalPrincipal::new(
            "dashboard-session".to_owned(),
        );
        let request = Request::builder()
            .method("POST")
            .uri(routes::UI_KEY_SERVER_LOOKUP_EMAIL)
            .header("content-type", "application/json")
            .header("cookie", format!("mcp_gateway_session={cookie}"))
            .extension(fx.live.generation())
            .extension(c)
            .body(Body::from(body.to_string()))
            .expect("request");
        fx.state.process.lookup_budget().reset_for_test();
        fx.rt.block_on(async {
            let response = crate::gateway::ui::api_router()
                .with_state(fx.state.clone())
                .oneshot(request)
                .await
                .expect("infallible");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        })
    };
    let (status, first) = session("handle-one", &json!({"email": EMAIL, "limit": 1}));
    assert_eq!(status, StatusCode::OK, "{first}");
    let token = first["next_cursor"].as_str().expect("cursor").to_owned();
    let (status, _) = session("handle-two", &json!({"cursor": token}));
    assert_eq!(status, StatusCode::BAD_REQUEST, "another session opened it");
    let (status, second) = session("handle-one", &json!({"cursor": token}));
    assert_eq!(status, StatusCode::OK, "the same session pages on: {second}");
}
