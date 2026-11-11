// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A mint's `token.issued` row: written and synced before the bearer is
//! valid, under the audit log's failure policy (design round 5 table).

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;

use super::handler::issue;
use crate::config::KeyServerConfig;
use crate::key_server::email_hash::EmailHashKey;
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::store::{
    ActivateError, InMemoryTokenStore, ReservationId, ReservationRequest, ReserveError,
    TemporaryToken, TokenScopes, TokenStore,
};
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::RotationConfig;
use crate::security::transparency_log::{Malformed, log_contains_entry};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const ISS: &str = "https://issuer.invalid";
const EMAIL: &str = "planted.person@corp.invalid";

pub(crate) fn open_log(
    dir: &tempfile::TempDir,
    policy: AuditFailurePolicy,
) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        rotation: RotationConfig::default(),
    };
    Arc::new(
        TransparencyLogger::open(Arc::new(config))
            .expect("opens")
            .with_failure_policy(policy),
    )
}

fn server(log: &Arc<TransparencyLogger>) -> crate::key_server::KeyServer {
    crate::key_server::KeyServer::new(KeyServerConfig::default(), EmailHashKey::for_test())
        .with_issuance_log(Arc::clone(log))
}

pub(crate) async fn mint(ks: &crate::key_server::KeyServer) -> axum::response::Response {
    let identity = VerifiedIdentity::for_test(
        "sub",
        EMAIL,
        Some("Planted Person".to_owned()),
        vec!["g".into()],
        ISS,
    );
    issue(ks, identity, TokenScopes::default(), None).await
}

fn has_row(dir: &tempfile::TempDir, jti: Option<&str>) -> bool {
    log_contains_entry(
        &dir.path().join("audit.jsonl"),
        "issuance row check",
        Malformed::Refuse,
        |e| {
            e.get("event").and_then(|v| v.as_str()) == Some("token.issued")
                && jti.is_none_or(|j| e.get("token_jti").and_then(|v| v.as_str()) == Some(j))
        },
    )
    .expect("the log reads")
}

pub(crate) async fn bearer_of(response: axum::response::Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let v: serde_json::Value = serde_json::from_slice(&body).expect("json");
    v["access_token"].as_str().expect("a bearer").to_owned()
}

/// A refused mint holds no slot and no bearer.
async fn nothing_issued(ks: &crate::key_server::KeyServer) {
    assert_eq!(
        ks.store.count_for_subject(ISS, "sub").await,
        0,
        "no slot or token held"
    );
}

/// NEW.W.1: the confirmed row exists when the store activates, and after an
/// abrupt restart on the same storage.
/// Mutant: append after activation, or skip the append.
#[tokio::test]
async fn failclosed_confirmed_row_precedes_the_bearer_and_survives_restart() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::FailClosed);
    let mut ks = server(&log);
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    ks.store = Arc::new(RowFirst {
        inner: Arc::new(InMemoryTokenStore::new(5, 3600)),
        path: dir.path().join("audit.jsonl"),
        seen: Arc::clone(&seen),
    });
    let response = mint(&ks).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        "the row was on disk at activation"
    );
    let bearer = bearer_of(response).await;
    let jti = ks.store.get(&bearer).await.expect("valid bearer").jti;
    drop(ks);
    drop(log);
    assert!(has_row(&dir, Some(&jti)), "the row survives a restart");
}

/// NEW.W.2: append failure, admission error, no task started and an
/// unconfirmed write each refuse with a 503 and issue nothing.
/// Mutant: any one cell proceeds to activation.
#[tokio::test]
async fn failclosed_every_non_confirmed_outcome_refuses_with_503() {
    for cell in Cell::ALL {
        let dir = crate::test_dir_keep::kept_tempdir();
        let log = open_log(&dir, AuditFailurePolicy::FailClosed);
        let mut ks = server(&log);
        let store = Arc::new(InMemoryTokenStore::new(1, 3600));
        ks.store = store.clone();
        let hold = cell.arm(&log);
        let response = mint(&ks).await;
        // The cap is one: a slot left pending by the refusal would refuse this.
        let probe = store.reserve(
            ReservationRequest {
                issuer: ISS.to_owned(),
                subject: "sub".to_owned(),
                jti: "probe".to_owned(),
            },
            1_800_000_000,
        );
        assert!(
            probe.is_ok(),
            "{cell:?}: the refused mint released its slot"
        );
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{cell:?}"
        );
        assert_eq!(
            response.headers().get(axum::http::header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("1")),
            "{cell:?}"
        );
        nothing_issued(&ks).await;
        if let Some(gate) = hold {
            log.release_and_drain(gate).await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Cell {
    AppendFails,
    AdmissionRefused,
    NotStarted,
    Unconfirmed,
}

impl Cell {
    const ALL: [Self; 4] = [
        Self::AppendFails,
        Self::AdmissionRefused,
        Self::NotStarted,
        Self::Unconfirmed,
    ];

    /// Put the log into this cell's state; a held write is returned.
    fn arm(
        self,
        log: &Arc<TransparencyLogger>,
    ) -> Option<crate::security::transparency_log::rotation::StallRelease> {
        match self {
            Self::AppendFails => log.fail_next_append_for_test(),
            Self::AdmissionRefused => {
                // One failed append degrades a FailClosed log; every probe
                // then fails too.
                log.set_append_failure_for_test(true);
                let _ = log.append_event(
                    serde_json::Map::from_iter([("event".to_owned(), "x".into())]),
                    &crate::security::audit::AuditEnvelope::gateway(),
                );
                assert!(log.is_degraded());
            }
            Self::NotStarted => log.close_append_permit_for_test(),
            Self::Unconfirmed => {
                return Some(log.stall_next_write_for_test(Duration::from_millis(200)));
            }
        }
        None
    }
}

/// Wraps the store: checks the row is on disk at activation, and can answer
/// the commit as revoked.
struct RowFirst {
    inner: Arc<InMemoryTokenStore>,
    path: std::path::PathBuf,
    seen: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl TokenStore for RowFirst {
    fn reserve(
        &self,
        request: ReservationRequest,
        now: u64,
    ) -> Result<ReservationId, ReserveError> {
        self.inner.reserve(request, now)
    }
    fn activate(
        &self,
        id: &ReservationId,
        token: TemporaryToken,
        now: u64,
    ) -> Result<(), ActivateError> {
        let row = log_contains_entry(&self.path, "row-first", Malformed::Refuse, |e| {
            e.get("token_jti").and_then(|v| v.as_str()) == Some(token.jti.as_str())
        })
        .expect("reads");
        self.seen.store(row, std::sync::atomic::Ordering::SeqCst);
        self.inner.activate(id, token, now)
    }
    fn abort(&self, id: &ReservationId) {
        self.inner.abort(id);
    }
    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        self.inner.get(bearer).await
    }
    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        self.inner.live_jti(jti, now).await
    }
    async fn revoke_by_jti(&self, jti: &str) -> bool {
        self.inner.revoke_by_jti(jti).await
    }
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.revoke_by_subject(issuer, subject).await
    }
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        self.inner.count_for_subject(issuer, subject).await
    }
    async fn reap_expired(&self) -> usize {
        self.inner.reap_expired().await
    }
}

/// NEW.W.3: under `BestEffort` every cell still mints, the row is simply
/// missing, and the bearer is valid.
/// Mutant: `BestEffort` refuses like `FailClosed`.
#[tokio::test]
async fn besteffort_every_cell_mints_without_the_row() {
    // An admission error cannot arise on a healthy BestEffort log (it never
    // degrades), so that cell is covered by the helper rows instead.
    for cell in [Cell::AppendFails, Cell::NotStarted, Cell::Unconfirmed] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let log = open_log(&dir, AuditFailurePolicy::BestEffort);
        let ks = server(&log);
        let hold = cell.arm(&log);
        let response = mint(&ks).await;
        assert_eq!(response.status(), StatusCode::OK, "{cell:?}");
        let bearer = bearer_of(response).await;
        assert!(
            ks.store.get(&bearer).await.is_some(),
            "{cell:?}: bearer valid"
        );
        if !matches!(cell, Cell::Unconfirmed) {
            assert!(!has_row(&dir, None), "{cell:?}: no row was written");
        }
        if let Some(gate) = hold {
            log.release_and_drain(gate).await;
        }
    }
}

/// NEW.W.2: a commit refused as revoked activates nothing even though the
/// row landed.
/// Mutant: activate on any landed row.
#[tokio::test]
async fn a_revoked_commit_issues_nothing_even_with_a_row() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::FailClosed);
    let mut ks = server(&log);
    ks.store = Arc::new(Revoking(Arc::new(InMemoryTokenStore::new(5, 3600))));
    let response = mint(&ks).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(has_row(&dir, None), "the row landed");
    nothing_issued(&ks).await;
}

/// The store, answering every commit as revoked.
struct Revoking(Arc<InMemoryTokenStore>);

#[async_trait::async_trait]
impl TokenStore for Revoking {
    fn reserve(
        &self,
        request: ReservationRequest,
        now: u64,
    ) -> Result<ReservationId, ReserveError> {
        self.0.reserve(request, now)
    }
    fn activate(
        &self,
        id: &ReservationId,
        _token: TemporaryToken,
        _now: u64,
    ) -> Result<(), ActivateError> {
        self.0.abort(id);
        Err(ActivateError::Revoked)
    }
    fn abort(&self, id: &ReservationId) {
        self.0.abort(id);
    }
    async fn get(&self, bearer: &str) -> Option<TemporaryToken> {
        self.0.get(bearer).await
    }
    async fn live_jti(&self, jti: &str, now: u64) -> bool {
        self.0.live_jti(jti, now).await
    }
    async fn revoke_by_jti(&self, jti: &str) -> bool {
        self.0.revoke_by_jti(jti).await
    }
    async fn revoke_by_subject(&self, issuer: &str, subject: &str) -> usize {
        self.0.revoke_by_subject(issuer, subject).await
    }
    async fn count_for_subject(&self, issuer: &str, subject: &str) -> usize {
        self.0.count_for_subject(issuer, subject).await
    }
    async fn reap_expired(&self) -> usize {
        self.0.reap_expired().await
    }
}

/// NEW.W.4: the row carries the safe envelope only.
/// Mutant: serialize the verified identity, or add name/groups.
#[tokio::test]
async fn the_row_holds_the_safe_envelope_and_no_email() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = open_log(&dir, AuditFailurePolicy::FailClosed);
    let ks = server(&log);
    let response = mint(&ks).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bearer = bearer_of(response).await;
    let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
    assert!(!text.contains(&bearer), "the bearer must not be on disk");
    let row: serde_json::Value = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .find(|v: &serde_json::Value| v["event"] == "token.issued")
        .expect("a row");
    let id = &row["identity"];
    for key in [
        "subject",
        "issuer",
        "email_hash",
        "email_hash_version",
        "email_hash_key_id",
    ] {
        assert!(id.get(key).is_some(), "{key}");
    }
    for word in [EMAIL, "Planted Person", "\"groups\"", "\"email\":"] {
        assert!(!text.contains(word), "{word} must not be on disk");
    }
}

/// NEW.W.4: the key server reaches the audit log through the one helper;
/// the startup key record is the only other writer.
/// Mutant: a second append path in the key server.
#[test]
fn only_the_issuance_helper_appends_from_the_key_server() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/key_server");
    let banned = [
        "append_event(",
        "append_event_synced(",
        "append_bounded(",
        "append_bounded_within(",
        "dispatch_bounded(",
        "append_admin_action(",
        "log_invocation(",
    ];
    let mut users = Vec::new();
    let mut callers: Vec<(String, usize)> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.extension().is_none_or(|e| e != "rs") || name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let production = crate::test_source_text::production_text(&text);
        if banned.iter().any(|b| production.contains(b)) {
            users.push(name.clone());
        }
        let calls = production.matches("append_issuance_row(").count();
        if calls > 0 {
            callers.push((name, calls));
        }
    }
    assert_eq!(
        users,
        vec!["email_hmac_store.rs".to_owned()],
        "appenders: {users:?}"
    );
    assert_eq!(
        callers,
        vec![("issuance.rs".to_owned(), 1)],
        "exactly one call of the issuance helper, in issuance.rs"
    );
    let record = std::fs::read_to_string(dir.join("issuance.rs")).unwrap();
    assert!(
        record.contains("append_issuance_row("),
        "the mint uses the helper"
    );
}
