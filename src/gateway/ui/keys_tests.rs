// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/keys` (slice B, test plan r2 rows T7-T10): the configured
//! keys, from the request's pinned table, with no secret, digest, store key,
//! limit key or principal anywhere, and `last_used` exact, in memory, keyed
//! by principal.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, Config};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::auth::runtime::AuthRuntime;
use crate::gateway::router::AppState;

const URI: &str = "/ui/api/keys";
const ZETA: &str = "keys-route-secret-zeta";
const ZETA_OLD: &str = "keys-route-secret-zeta-old";
const ALPHA: &str = "keys-route-secret-alpha";
const MU: &str = "keys-route-secret-mu";
const P1: &str = "a1b2c3d4e5f6";

fn spec(secret: &str) -> String {
    crate::config::api_key_digest_spec(secret.as_bytes())
}

fn at(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("fixed instant")
        .with_timezone(&Utc)
}

fn expiry() -> DateTime<Utc> {
    at("2999-01-01T00:00:00Z")
}

/// `zeta`, `alpha`, `mu`: a deliberately non-alphabetical table order.
fn keys(mu_file: &std::path::Path) -> Vec<ApiKeyConfig> {
    vec![
        ApiKeyConfig {
            key_sha256: Some(spec(ZETA)),
            name: "zeta".into(),
            rate_limit: 30,
            admin: true,
            principal: Some(P1.into()),
            previous_key_sha256: Some(spec(ZETA_OLD)),
            previous_expires_at: Some(expiry()),
            expires_at: Some(expiry()),
            backends: vec!["fs".into()],
            allowed_tools: Some(vec!["read_file".into()]),
            ..Default::default()
        },
        ApiKeyConfig {
            key_sha256: Some(spec(ALPHA)),
            name: "alpha".into(),
            backends: vec!["*".into()],
            denied_tools: Some(vec!["write_file".into()]),
            ..Default::default()
        },
        ApiKeyConfig {
            key_sha256: Some(format!("file:{}", mu_file.display())),
            name: "mu".into(),
            backends: vec!["*".into()],
            ..Default::default()
        },
    ]
}

struct Fixture {
    state: Arc<AppState>,
    runtime: Arc<AuthRuntime>,
    dir: tempfile::TempDir,
    _router_dir: crate::gateway::router::tests::FixtureDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("mu.digest"), spec(MU)).expect("write");
        let (state, router_dir) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |meta| meta,
        )
        .await;
        Self {
            state,
            runtime: Arc::new(AuthRuntime::default()),
            dir,
            _router_dir: router_dir,
        }
    }

    fn mu_file(&self) -> std::path::PathBuf {
        self.dir.path().join("mu.digest")
    }

    /// The key table over the fixture's one runtime, as a reload builds it.
    fn auth(&self, keys: Vec<ApiKeyConfig>) -> Arc<ResolvedAuthConfig> {
        let config = AuthConfig {
            enabled: true,
            api_keys: keys,
            ..AuthConfig::default()
        };
        let resolved = ResolvedAuthConfig::try_from_config(
            &config,
            &crate::config::EnvOverlay::none(),
            crate::gateway::record_principal::TEST_RECORD_KEY,
        )
        .expect("the key table resolves")
        .with_runtime(Arc::clone(&self.runtime));
        Arc::new(resolved)
    }

    fn table(&self) -> Arc<ResolvedAuthConfig> {
        self.auth(keys(&self.mu_file()))
    }

    /// `GET /ui/api/keys` on the UI routes with `auth` pinned, as `client`.
    async fn get(
        &self,
        auth: Arc<ResolvedAuthConfig>,
        client: crate::gateway::auth::AuthenticatedClient,
    ) -> (StatusCode, String) {
        let generation = Arc::new(crate::config_reload::Generation::prepare_startup(
            Config::default(),
            auth,
        ));
        let request = Request::builder()
            .uri(URI)
            .extension(generation)
            .extension(client)
            .body(Body::empty())
            .expect("request builds");
        let response = crate::gateway::ui::api_router()
            .with_state(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("the router is infallible");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// The route as the static bearer, which never writes `last_used`.
    async fn as_bearer(&self, auth: Arc<ResolvedAuthConfig>) -> Value {
        let (status, body) = self.get(auth, bearer()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_str(&body).expect("json")
    }
}

fn bearer() -> crate::gateway::auth::AuthenticatedClient {
    crate::gateway::auth::AuthenticatedClient {
        name: "bearer".into(),
        admin: true,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::StaticBearer,
        principal: crate::gateway::record_principal::InternalPrincipal::new("bearer".into()),
        ..crate::gateway::auth::anonymous_client()
    }
}

/// The answer's object for `name`.
fn entry<'a>(answer: &'a Value, name: &str) -> &'a Value {
    answer
        .as_array()
        .and_then(|keys| keys.iter().find(|k| k["name"] == name))
        .unwrap_or_else(|| panic!("no {name} in {answer}"))
}

/// T7: one object per key, in table order, each exactly the listed fields
/// with their configured values.
#[tokio::test]
async fn t7_the_answer_is_the_configured_keys_in_table_order() {
    let fx = Fixture::new().await;
    let answer = fx.as_bearer(fx.table()).await;
    let expected = json!([
        {
            "name": "zeta", "backends": ["fs"], "allowed_tools": ["read_file"],
            "denied_tools": null, "admin": true, "expires_at": "2999-01-01T00:00:00Z",
            "rate_limit": 30, "last_used": null
        },
        {
            "name": "alpha", "backends": ["*"], "allowed_tools": null,
            "denied_tools": ["write_file"], "admin": false, "expires_at": null,
            "rate_limit": 0, "last_used": null
        },
        {
            "name": "mu", "backends": ["*"], "allowed_tools": null,
            "denied_tools": null, "admin": false, "expires_at": null,
            "rate_limit": 0, "last_used": null
        }
    ]);
    assert_eq!(answer, expected);
}

/// T7b: the answer lists the request's pinned table, not the published one.
#[tokio::test]
async fn t7b_the_answer_reads_the_pinned_table() {
    let fx = Fixture::new().await;
    let pinned = fx.table();
    let published = fx.auth(vec![ApiKeyConfig {
        key_sha256: Some(spec("keys-route-published-only")),
        name: "published-only".into(),
        backends: vec!["*".into()],
        ..Default::default()
    }]);
    let first = fx.as_bearer(Arc::clone(&pinned)).await;
    let names = |v: &Value| {
        v.as_array()
            .map(|a| a.iter().map(|k| k["name"].clone()).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    assert_eq!(
        names(&first),
        vec![json!("zeta"), json!("alpha"), json!("mu")]
    );
    let next = fx.as_bearer(published).await;
    assert_eq!(names(&next), vec![json!("published-only")]);
}

fn digest(secret: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into()
}

/// Every spelling of `bytes` the leak checks refuse: hex in both cases,
/// unpadded standard and URL-safe base64 (covering the padded forms), a JSON
/// byte array and the spaced Debug list.
fn spellings(bytes: &[u8]) -> Vec<String> {
    use base64::Engine as _;
    let list: Vec<String> = bytes.iter().map(u8::to_string).collect();
    vec![
        hex::encode(bytes),
        hex::encode_upper(bytes),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        format!("[{}]", list.join(",")),
        format!("[{}]", list.join(", ")),
    ]
}

/// T8: a populated answer, and nothing that identifies a credential in the
/// body or in any log record written during the call.
#[test]
fn t8_no_credential_identifier_leaves_the_route() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fx = rt.block_on(Fixture::new());
    let table = fx.table();
    let mut forbidden: Vec<String> = vec![
        ZETA.into(),
        ZETA_OLD.into(),
        ALPHA.into(),
        MU.into(),
        P1.into(),
        format!("file:{}", fx.mu_file().display()),
    ];
    for secret in [ZETA, ZETA_OLD, ALPHA, MU] {
        forbidden.extend(spellings(&digest(secret)));
        let derived = crate::gateway::auth::configured_key_principal(None, &digest(secret));
        forbidden.push(derived.storage_form().to_owned());
    }
    for secret in [ZETA, ZETA_OLD, ALPHA, MU] {
        let quota = table
            .validate_token(secret)
            .and_then(|client| client.quota_principal)
            .expect("each secret authenticates with a quota principal");
        forbidden.push(quota.as_store_key().to_owned());
        forbidden.push(quota.limit_store_key().to_owned());
    }
    let mut answer = (StatusCode::IM_A_TEAPOT, String::new());
    let logs = crate::test_log_capture::records(|| {
        answer = rt.block_on(fx.get(Arc::clone(&table), bearer()));
    });
    let (status, body) = answer;
    assert_eq!(status, StatusCode::OK, "{body}");
    let parsed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(parsed.as_array().map(Vec::len), Some(3), "{body}");
    let logged = serde_json::to_string(&logs).expect("logs serialise");
    for needle in &forbidden {
        assert!(!body.contains(needle.as_str()), "the body carries {needle}");
        assert!(
            !logged.contains(needle.as_str()),
            "a log record carries {needle}"
        );
    }
}

fn t(seconds: i64) -> DateTime<Utc> {
    at("2026-11-01T10:00:00Z") + chrono::Duration::seconds(seconds)
}

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// T9a: after a restart (a fresh runtime) every key reads null.
#[tokio::test]
async fn t9a_after_a_restart_every_key_reads_null() {
    let fx = Fixture::new().await;
    let answer = fx.as_bearer(fx.table()).await;
    for name in ["zeta", "alpha", "mu"] {
        assert_eq!(entry(&answer, name)["last_used"], Value::Null, "{name}");
    }
}

/// T9b: a match sets that key's time exactly, a later match moves it, and
/// other keys stay null.
#[tokio::test]
async fn t9b_a_match_sets_its_own_keys_time() {
    let fx = Fixture::new().await;
    let table = fx.table();
    assert!(table.validate_token_at(ZETA, t(0)).is_some(), "premise");
    let answer = fx.as_bearer(Arc::clone(&table)).await;
    assert_eq!(entry(&answer, "zeta")["last_used"], json!(rfc3339(t(0))));
    assert_eq!(entry(&answer, "alpha")["last_used"], Value::Null);
    assert!(table.validate_token_at(ZETA, t(60)).is_some(), "premise");
    let answer = fx.as_bearer(table).await;
    assert_eq!(entry(&answer, "zeta")["last_used"], json!(rfc3339(t(60))));
}

/// T9c: a derived-principal key rotated to a new digest reads null until its
/// first match under it.
#[tokio::test]
async fn t9c_a_derived_rotation_reads_null_until_used() {
    let fx = Fixture::new().await;
    let one = |secret: &str| {
        fx.auth(vec![ApiKeyConfig {
            key_sha256: Some(spec(secret)),
            name: "d".into(),
            backends: vec!["*".into()],
            ..Default::default()
        }])
    };
    let before = one("keys-route-derived-a");
    assert!(
        before
            .validate_token_at("keys-route-derived-a", t(0))
            .is_some()
    );
    let after = one("keys-route-derived-b");
    let answer = fx.as_bearer(Arc::clone(&after)).await;
    assert_eq!(entry(&answer, "d")["last_used"], Value::Null);
    assert!(
        after
            .validate_token_at("keys-route-derived-b", t(5))
            .is_some()
    );
    let answer = fx.as_bearer(after).await;
    assert_eq!(entry(&answer, "d")["last_used"], json!(rfc3339(t(5))));
}

/// T9c2: a rotation under one explicit principal, and a rebuild with no
/// change, both keep the time.
#[tokio::test]
async fn t9c2_an_explicit_rotation_keeps_the_time() {
    let fx = Fixture::new().await;
    let table = fx.table();
    assert!(table.validate_token_at(ZETA, t(0)).is_some(), "premise");
    let rebuilt = fx.as_bearer(fx.table()).await;
    assert_eq!(entry(&rebuilt, "zeta")["last_used"], json!(rfc3339(t(0))));
    let mut rotated = keys(&fx.mu_file());
    rotated[0].key_sha256 = Some(spec("keys-route-secret-zeta-new"));
    let answer = fx.as_bearer(fx.auth(rotated)).await;
    assert_eq!(entry(&answer, "zeta")["last_used"], json!(rfc3339(t(0))));
}

/// T9e: a match refused for expiry, of the key or of its previous secret's
/// grace, writes nothing; a previous secret within its grace does.
#[tokio::test]
async fn t9e_a_refused_match_writes_nothing() {
    let fx = Fixture::new().await;
    let table = fx.table();
    let past = expiry() + chrono::Duration::days(1);
    assert!(
        table.validate_token_at(ZETA, past).is_none(),
        "premise: expired"
    );
    assert!(
        table.validate_token_at(ZETA_OLD, past).is_none(),
        "premise: grace over"
    );
    let answer = fx.as_bearer(Arc::clone(&table)).await;
    assert_eq!(entry(&answer, "zeta")["last_used"], Value::Null);
    assert!(
        table.validate_token_at(ZETA_OLD, t(9)).is_some(),
        "premise: in grace"
    );
    let answer = fx.as_bearer(table).await;
    assert_eq!(entry(&answer, "zeta")["last_used"], json!(rfc3339(t(9))));
}

/// T10: only an API-key match writes: the static bearer, a dashboard session
/// and an OIDC identity leave every key null.
#[tokio::test]
async fn t10_only_an_api_key_match_writes() {
    let fx = Fixture::new().await;
    let config = AuthConfig {
        enabled: true,
        bearer_token: Some("keys-route-bearer".into()),
        api_keys: keys(&fx.mu_file()),
        ..AuthConfig::default()
    };
    let table = Arc::new(
        ResolvedAuthConfig::try_from_config(
            &config,
            &crate::config::EnvOverlay::none(),
            crate::gateway::record_principal::TEST_RECORD_KEY,
        )
        .expect("resolves")
        .with_runtime(Arc::clone(&fx.runtime)),
    );
    assert!(
        table.validate_token_at("keys-route-bearer", t(0)).is_some(),
        "premise"
    );
    let answer = fx.as_bearer(table).await;
    for name in ["zeta", "alpha", "mu"] {
        assert_eq!(entry(&answer, name)["last_used"], Value::Null, "{name}");
    }
}
