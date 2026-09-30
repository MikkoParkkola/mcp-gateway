// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D3-a fixture: one personal capability served by a loopback endpoint, its
//! grants, a transparency log, and readers for what the log holds.
//!
//! The capability answers through a swapped HTTP client and a `localhost`
//! base URL, the `account_rest_fixture` pattern, so a granted call succeeds
//! and a chain can take a second step. The endpoint can hold a request until
//! released, which is the barrier the cancellation and stall cells use.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::identity_grants::{IdentityGrant, LocalIdentityGrantStore};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

/// The capability backend name every grant check is keyed on.
pub(crate) const CAPS: &str = "personal_caps";
/// The personal capability, which is also its tool name.
pub(crate) const PERSONAL: &str = "calendar_read_day";
/// The record kind a grant decision is written as.
pub(crate) const DECISION_KIND: &str = "identity_grant_decision";

/// A loopback endpoint that counts arrivals and, when armed, holds each
/// request until released.
pub(crate) struct Endpoint {
    pub(crate) port: u16,
    arrivals: Arc<AtomicUsize>,
    arrived: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
struct EndpointState {
    arrivals: Arc<AtomicUsize>,
    arrived: Arc<tokio::sync::Notify>,
    release: Option<Arc<tokio::sync::Semaphore>>,
}

async fn answer(
    axum::extract::State(state): axum::extract::State<EndpointState>,
) -> axum::Json<Value> {
    state.arrivals.fetch_add(1, Ordering::SeqCst);
    state.arrived.notify_waiters();
    if let Some(release) = &state.release
        && let Ok(permit) = release.acquire().await
    {
        permit.forget();
    }
    axum::Json(json!({ "day": "2026-09-27", "events": [] }))
}

impl Endpoint {
    /// An endpoint that answers at once (`hold == false`) or holds every
    /// request until [`Self::release`].
    pub(crate) async fn start(hold: bool) -> Self {
        let arrivals = Arc::new(AtomicUsize::new(0));
        let arrived = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let state = EndpointState {
            arrivals: Arc::clone(&arrivals),
            arrived: Arc::clone(&arrived),
            release: hold.then(|| Arc::clone(&release)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the endpoint binds a loopback port");
        let port = listener.local_addr().expect("bound address").port();
        let router = axum::Router::new()
            .route("/read", axum::routing::get(answer))
            .with_state(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self {
            port,
            arrivals,
            arrived,
            release,
        }
    }

    pub(crate) fn arrivals(&self) -> usize {
        self.arrivals.load(Ordering::SeqCst)
    }

    /// Wait, bounded, until `count` requests have arrived.
    pub(crate) async fn wait_for_arrivals(&self, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while self.arrivals() < count {
                let notified = self.arrived.notified();
                if self.arrivals() >= count {
                    break;
                }
                let _ = tokio::time::timeout(std::time::Duration::from_millis(50), notified).await;
            }
        })
        .await
        .expect("the capability endpoint must be reached within the bound");
    }

    /// Let one held request answer.
    pub(crate) fn release_one(&self) {
        self.release.add_permits(1);
    }

    /// Let every held and future request answer.
    pub(crate) fn release(&self) {
        self.release.add_permits(1_000);
    }
}

/// The personal capability, owned by `(authority, subject)`, served at `port`.
pub(crate) fn capability_backend(port: u16, owner: (&str, &str)) -> Arc<CapabilityBackend> {
    capability_backend_exposed(port, owner, "personal")
}

/// [`capability_backend`] with `exposure` (`personal`, `shared`, `public`).
pub(crate) fn capability_backend_exposed(
    port: u16,
    owner: (&str, &str),
    exposure: &str,
) -> Arc<CapabilityBackend> {
    let definition = crate::capability::parse_capability(&format!(
        "name: {PERSONAL}\n\
         description: Read one calendar day\n\
         metadata:\n\
         \x20 exposure: {exposure}\n\
         \x20 read_only: true\n\
         \x20 identity_owner:\n\
         \x20   authority: {}\n\
         \x20   subject: {}\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://localhost:{port}\n\
         \x20     path: /read\n\
         \x20     method: GET\n",
        owner.0, owner.1
    ))
    .expect("the fixture capability parses");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("the fixture HTTP client builds");
    let executor = Arc::new(CapabilityExecutor::new().with_test_http_client(client));
    let backend = Arc::new(CapabilityBackend::new(CAPS, executor));
    backend
        .register_capability(definition)
        .expect("the fixture capability registers");
    backend
}

/// A read grant `grant_id` for `subject` on the personal capability.
pub(crate) fn grant(grant_id: &str, subject: (&str, &str), owner: (&str, &str)) -> IdentityGrant {
    serde_json::from_value(json!({
        "grant_id": grant_id,
        "subject": { "authority": subject.0, "subject": subject.1 },
        "agent": "any",
        "capability": PERSONAL,
        "scope": "read",
        "owner": { "authority": owner.0, "subject": owner.1 },
        "provenance": "local-operator",
        "reason": "D3-a fixture grant"
    }))
    .expect("the fixture grant deserialises")
}

pub(crate) fn grants(rows: Vec<IdentityGrant>) -> LocalIdentityGrantStore {
    LocalIdentityGrantStore::from_grants(rows)
}

/// A log at `<dir>/audit.jsonl` under `policy`.
pub(crate) fn logger(
    dir: &tempfile::TempDir,
    policy: AuditFailurePolicy,
) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: log_path(dir).to_string_lossy().into_owned(),
        key_id: "d3a".to_string(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(
        TransparencyLogger::open(Arc::new(config))
            .expect("the fixture log opens")
            .with_failure_policy(policy),
    )
}

pub(crate) fn log_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("audit.jsonl")
}

/// Every entry in the log, in order.
pub(crate) fn entries(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(log_path(dir))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

/// Whether `entry` is a grant decision record. The one place the record's
/// kind is read.
pub(crate) fn is_decision(entry: &Value) -> bool {
    entry.get("kind").and_then(Value::as_str) == Some(DECISION_KIND)
}

/// The grant decision records.
pub(crate) fn decisions(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir).into_iter().filter(is_decision).collect()
}

/// D1's invocation records: a `route`, and not a decision.
pub(crate) fn invocations(dir: &tempfile::TempDir) -> Vec<Value> {
    entries(dir)
        .into_iter()
        .filter(|entry| !is_decision(entry) && entry.get("route").is_some())
        .collect()
}

/// The grant subject a decision record names. The one place its path is read.
pub(crate) fn decision_subject(record: &Value) -> (Option<&str>, Option<&str>) {
    let subject = &record["subject"];
    (
        subject.get("authority").and_then(Value::as_str),
        subject.get("subject").and_then(Value::as_str),
    )
}

pub(crate) fn trace_of(record: &Value) -> Option<&str> {
    record.get("trace_id").and_then(Value::as_str)
}

/// Put `log` in the stalled state: arm a stuck write and let one bounded
/// append time out on it. Returns the release for the end of the cell.
pub(crate) async fn stall_log(log: &Arc<TransparencyLogger>) -> Box<dyn FnOnce() + Send> {
    let gate = log.stall_next_write_for_test(std::time::Duration::from_millis(100));
    let fields: serde_json::Map<String, Value> =
        [("kind".to_string(), Value::from("d3a_stall_probe"))]
            .into_iter()
            .collect();
    let envelope = crate::security::audit::AuditEnvelope::gateway();
    let timed_out = log
        .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
        .await;
    assert!(
        timed_out.is_err() && log.is_stalled(),
        "the probe append must stall the log"
    );
    Box::new(move || gate.release())
}
