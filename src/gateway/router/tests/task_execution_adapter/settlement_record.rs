// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1 gap 1: the settlement record of a recovered upstream task
//! (design `2026-10-01-min1-recovery-record.md`, rows R1-R10).
//!
//! Both recovery paths are driven through the real route: the worker that
//! follows its own handle, and the owner's `tasks/get` of a retained row.
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::firewall::tenant_guard::TenantGuardConfig;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::transparency_log::TransparencyLogConfig;

mod races;

const UPSTREAM_HANDLE: &str = "upstream-job-settlement-record";
const ARRIVAL_BOUND: Duration = Duration::from_secs(10);

/// AWS's documented example key id, which response inspection rates HIGH.
/// Assembled at runtime so secret scanners do not flag the source.
fn example_access_key() -> String {
    ["AKIA", "IOSFODNN7", "EXAMPLE"].concat()
}

fn h(id: &str) -> String {
    crate::security::hash_argument(&json!(id))
}

fn sha256_of(value: &Value) -> String {
    format!(
        "sha256:{}",
        crate::hashing::sha256_hex(crate::hashing::canonical_json(value).as_bytes())
    )
}

/// JSON text naming `cust-9`, plus `extra` text beside it.
fn rows_naming_cust9(extra: &str) -> String {
    json!({"rows": [{"customer_id": "cust-9"}], "note": extra}).to_string()
}

fn result_naming_cust9(extra: &str) -> Value {
    json!({"content": [{"type": "text", "text": rows_naming_cust9(extra)}]})
}

/// The owner every row submits as: `key-a`'s verified identity (`support.rs`).
fn admission_principal() -> String {
    crate::key_server::oidc::VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

// =====================================================================
// The peer
// =====================================================================

/// Answers the task-augmented leg with a genuine `CreateTask` envelope, and the
/// ordinary leg with a plain result.
struct Peer {
    /// Extra members merged into the envelope (R9's refused handle).
    envelope_extra: Value,
}

#[async_trait::async_trait]
impl Transport for Peer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
            }),
            "tools/list" => json!({
                "tools": [{ "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }]
            }),
            "tools/call" => json!({ "content": [{ "type": "text", "text": "{\"plain\":true}" }] }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method != "tools/call" {
            return self.request(method, params).await;
        }
        let mut envelope = json!({
            "resultType": "task",
            "taskId": UPSTREAM_HANDLE,
            "status": "working"
        });
        if let (Some(envelope), Some(extra)) =
            (envelope.as_object_mut(), self.envelope_extra.as_object())
        {
            envelope.extend(extra.clone());
        }
        Ok(JsonRpcResponse::success(RequestId::Number(1), envelope))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

// =====================================================================
// The recovery adapter
// =====================================================================

/// The upstream job's terminal answer.
#[derive(Clone)]
enum Terminal {
    Completed(Value),
    Failed(i32, String),
}

/// Holds every terminal query until the row releases it. With `retain_first`
/// the first query answers `Unavailable` at once, which ends the worker's
/// follow and leaves the row to the owner's read.
struct Recovery {
    retain_first: bool,
    answer: Terminal,
    queries: AtomicUsize,
    release: Arc<tokio::sync::Semaphore>,
}

impl Recovery {
    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    fn release_all(&self) {
        self.release.add_permits(1_000);
    }

    async fn wait_for_queries(&self, count: usize) {
        let deadline = Instant::now() + ARRIVAL_BOUND;
        while self.queries() < count {
            std::assert!(
                Instant::now() < deadline,
                "only {} upstream queries in {ARRIVAL_BOUND:?}; {count} expected",
                self.queries()
            );
            tokio::task::yield_now().await;
        }
    }
}

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        let seen = self.queries.fetch_add(1, Ordering::SeqCst);
        if self.retain_first && seen == 0 {
            return UpstreamAnswer::Unavailable;
        }
        self.release
            .clone()
            .acquire_owned()
            .await
            .expect("the release semaphore outlives every query")
            .forget();
        match self.answer.clone() {
            Terminal::Completed(result) => UpstreamAnswer::Completed(result),
            Terminal::Failed(code, message) => {
                UpstreamAnswer::Failed(crate::protocol::JsonRpcError {
                    code,
                    message,
                    data: None,
                })
            }
        }
    }
}

// =====================================================================
// The fixture
// =====================================================================

/// Which recovery path settles the row.
#[derive(Clone, Copy, Debug)]
enum Path {
    /// The worker follows its own handle to the terminal answer.
    Worker,
    /// The worker retains the row; the owner's `tasks/get` recovers it.
    OwnerRead,
}

const BOTH: [Path; 2] = [Path::Worker, Path::OwnerRead];

struct Setup {
    answer: Terminal,
    policy: AuditFailurePolicy,
    /// Response inspection in action mode: a HIGH finding refuses.
    refusing: bool,
    envelope_extra: Value,
}

impl Setup {
    fn answering(answer: Terminal) -> Self {
        Self {
            answer,
            policy: AuditFailurePolicy::BestEffort,
            refusing: false,
            envelope_extra: json!({}),
        }
    }
}

struct Fixture {
    state: Arc<AppState>,
    recovery: Arc<Recovery>,
    log: Arc<TransparencyLogger>,
    log_dir: tempfile::TempDir,
    _store: tempfile::TempDir,
}

/// The suite's real state with an attributing firewall, a transparency log,
/// the peer under [`BACKEND`] and the recovery adapter installed.
async fn fixture(setup: Setup, path: Path) -> Fixture {
    let (state, store) = fixture_state(&two_principal_auth()).await;
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Peer {
        envelope_extra: setup.envelope_extra,
    }) as Arc<dyn Transport>);
    std::assert!(state.backends.register(backend), "the peer must register");
    let recovery = Arc::new(Recovery {
        retain_first: matches!(path, Path::OwnerRead),
        answer: setup.answer,
        queries: AtomicUsize::new(0),
        release: Arc::new(tokio::sync::Semaphore::new(0)),
    });
    std::assert!(
        state
            .task_executor
            .install_recovery(Arc::clone(&recovery) as Arc<dyn UpstreamRecovery>),
        "the recovery adapter must install"
    );

    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log_dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "min1".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(setup.policy),
    );
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let mut meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    meta.enable_transparency_log(Arc::clone(&log));
    meta.set_firewall(Some(Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["customer_id".to_string()],
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ))));
    if setup.refusing {
        meta.enable_response_inspection_action_mode();
    }
    app.meta_mcp = Arc::new(meta);
    Fixture {
        state: Arc::new(app),
        recovery,
        log,
        log_dir,
        _store: store,
    }
}

async fn join_workers(state: &Arc<AppState>) {
    let bound = Duration::from_secs(5);
    let joined = tokio::time::timeout(bound, state.task_executor.drain(bound))
        .await
        .expect("the worker settles within the fixture bound");
    std::assert!(joined.is_clean(), "the worker must finish: {joined:?}");
}

impl Fixture {
    /// Submit one task-augmented call and return its task id.
    async fn submit(&self, key: &str) -> String {
        let created = post(&self.state, "key-a", task_invoke(1, key, json!({ "n": 1 }))).await;
        task_id(&created)
    }

    /// Submit, then settle on `path`, with `before` run once the submission
    /// is recorded and before the terminal answer is released. Returns the
    /// task id and the owner's read of the settled row.
    async fn settle(&self, path: Path, before: impl FnOnce(&Self)) -> (String, Value) {
        let id = self.submit(&format!("min1-settlement-{path:?}")).await;
        self.recovery.wait_for_queries(1).await;
        if matches!(path, Path::OwnerRead) {
            // The worker's one query answered `Unavailable`: the row is retained.
            join_workers(&self.state).await;
        }
        before(self);
        self.recovery.release_all();
        if matches!(path, Path::Worker) {
            join_workers(&self.state).await;
        }
        let fetched = get_task(&self.state, "key-a", &id).await;
        (id, fetched)
    }

    /// Every entry in the log, in order.
    fn entries(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log_dir.path().join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }

    /// Invocation records only: entries naming a `route`. A `tasks/get`
    /// also writes a `response_delivery_attempt` event, which is not one.
    fn records(&self) -> Vec<Value> {
        self.entries()
            .into_iter()
            .filter(|entry| entry.get("route").is_some())
            .collect()
    }

    /// How many `response_delivery_attempt` events the log holds.
    fn deliveries(&self) -> usize {
        self.entries()
            .iter()
            .filter(|entry| entry["event"] == "response_delivery_attempt")
            .count()
    }

    fn settlement_records(&self) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|record| record["route"] == "task_recovery")
            .collect()
    }

    /// The one settlement record, or a failure naming every record written.
    fn only_settlement(&self, path: Path) -> Value {
        let found = self.settlement_records();
        std::assert_eq!(
            found.len(),
            1,
            "{path:?}: exactly one `task_recovery` record per recovered task; log: {:?}",
            self.records()
        );
        found.into_iter().next().expect("one record")
    }
}

fn tenants_of(record: &Value) -> Vec<Value> {
    record["tenants"].as_array().cloned().unwrap_or_default()
}

// =====================================================================
// Rows
// =====================================================================

/// R1, both paths, and the kill criterion: a recovered result naming `cust-9`
/// writes one settlement record, joined by the task id, attributed to the
/// admission principal and nothing more.
#[tokio::test]
async fn r1_a_recovered_result_writes_one_settlement_record() {
    for path in BOTH {
        let fx = fixture(
            Setup::answering(Terminal::Completed(result_naming_cust9(""))),
            path,
        )
        .await;
        let (id, fetched) = fx.settle(path, |_| {}).await;
        std::assert_eq!(status_of(&fetched), "completed", "{path:?}: {fetched}");

        let record = fx.only_settlement(path);
        std::assert_eq!(record["task_id"], json!(id), "{path:?}: {record}");
        std::assert_eq!(record["server"], json!(BACKEND), "{path:?}: {record}");
        std::assert_eq!(record["tool"], json!(TOOL), "{path:?}: {record}");
        std::assert_eq!(record["outcome"], json!("ok"), "{path:?}: {record}");
        std::assert_eq!(
            record["tenants"],
            json!([h("cust-9")]),
            "{path:?}: {record}"
        );
        std::assert!(
            record["data_classes"]
                .as_array()
                .is_some_and(|classes| !classes.is_empty()),
            "{path:?}: the kernel's data classes travel with the transition: {record}"
        );
        let delivered = fetched
            .pointer("/result/result")
            .unwrap_or_else(|| panic!("{path:?}: a completed task serves its result: {fetched}"));
        std::assert_eq!(
            record["response_hash"],
            json!(sha256_of(delivered)),
            "{path:?}: the hash covers the processed result: {record}"
        );
        std::assert_eq!(
            record["request_hash"],
            json!(sha256_of(&json!({ "task_id": id }))),
            "{path:?}: the request hash is of the join key the recovering path holds: {record}"
        );
        std::assert_eq!(
            record["correlation_source"],
            json!("task_id"),
            "{path:?}: {record}"
        );
        std::assert_eq!(record["session_id"], json!(id), "{path:?}: {record}");
        std::assert_eq!(
            record["who"]["account"],
            json!(admission_principal()),
            "{path:?}: {record}"
        );
        std::assert!(
            record["who"].get("credential_kind").is_none(),
            "{path:?}: the recovering path claims no credential: {record}"
        );
        let text = std::fs::read_to_string(fx.log_dir.path().join("audit.jsonl")).unwrap();
        std::assert!(
            !text.contains("cust-9"),
            "{path:?}: a raw tenant id was written"
        );
    }
}

/// R2: an owner read is attributed to the principal the task was admitted
/// under, never to the reading request's key.
///
/// The reader can differ only by credential here: an owner read is scoped to
/// the admitting identity, so a second identity cannot recover the row at all.
/// The key-name check is the guard against the reader's caller being written.
#[tokio::test]
async fn r2_an_owner_read_names_the_admission_principal_not_the_reader() {
    let path = Path::OwnerRead;
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        path,
    )
    .await;
    let _ = fx.settle(path, |_| {}).await;
    let record = fx.only_settlement(path);
    std::assert_eq!(
        record["who"]["account"],
        json!(admission_principal()),
        "{record}"
    );
    std::assert_ne!(
        record["caller"],
        json!("principal-a"),
        "the reader's key name is not the admission principal: {record}"
    );
}

/// R3, both paths: a recovered result an output policy refuses settles failed,
/// and its record keeps the raw response's tenants, the refusal's code and no
/// response hash. The firewall's refusal is the -32600 a native task reads
/// (MIK-7667); anomaly screening, which runs first when armed, stays -32603.
#[tokio::test]
async fn r3_a_refused_recovered_result_is_recorded_with_its_tenants() {
    let note = format!("AWS_ACCESS_KEY_ID={}", example_access_key());
    for (path, screening) in BOTH.into_iter().flat_map(|p| [(p, false), (p, true)]) {
        let mut setup = Setup::answering(Terminal::Completed(result_naming_cust9(&note)));
        setup.refusing = screening;
        let fx = fixture(setup, path).await;
        let (_, fetched) = fx.settle(path, |_| {}).await;
        let code = json!(if screening { -32603 } else { -32600 });
        std::assert_eq!(status_of(&fetched), "failed", "{path:?}: {fetched}");
        let error = &fetched["result"]["error"];
        std::assert_eq!(error["code"], code, "{path:?} {screening}: {fetched}");
        std::assert!(
            screening || error["message"] == "Response blocked by security firewall",
            "{path:?}: {fetched}"
        );
        std::assert!(!fetched.to_string().contains(&example_access_key()));

        let record = fx.only_settlement(path);
        std::assert!(
            tenants_of(&record).contains(&json!(h("cust-9"))),
            "{path:?}: {record}"
        );
        std::assert_ne!(record["outcome"], json!("ok"), "{path:?}: {record}");
        std::assert_eq!(record["error_code"], code, "{path:?}: {record}");
        std::assert!(record.get("response_hash").is_none(), "{path:?}: {record}");
    }
}

/// R4, both paths: a recovered peer failure naming a tenant writes a failure
/// record with the peer's code and the tenants its message named.
#[tokio::test]
async fn r4_a_screened_peer_failure_is_recorded_with_its_code() {
    for path in BOTH {
        let fx = fixture(
            Setup::answering(Terminal::Failed(-32050, rows_naming_cust9(""))),
            path,
        )
        .await;
        let (_, fetched) = fx.settle(path, |_| {}).await;
        std::assert_eq!(status_of(&fetched), "failed", "{path:?}: {fetched}");

        let record = fx.only_settlement(path);
        std::assert_eq!(record["error_code"], json!(-32050), "{path:?}: {record}");
        std::assert!(
            tenants_of(&record).contains(&json!(h("cust-9"))),
            "{path:?}: {record}"
        );
        std::assert!(record.get("response_hash").is_none(), "{path:?}: {record}");
    }
}

/// R5, both paths: a result over the task record size limit is recorded with
/// its tenants and processed hash, and the task delivers only the bounded
/// failure.
#[tokio::test]
async fn r5_an_oversize_result_is_recorded_and_delivered_bounded() {
    // Over the 512 KiB record limit, under the 1 MiB attribution parse bound.
    let pad = "x".repeat(600 * 1024);
    for path in BOTH {
        let fx = fixture(
            Setup::answering(Terminal::Completed(result_naming_cust9(&pad))),
            path,
        )
        .await;
        let (_, fetched) = fx.settle(path, |_| {}).await;
        std::assert_eq!(status_of(&fetched), "failed", "{path:?}: {fetched}");
        let body = fetched.to_string();
        std::assert!(
            body.contains("exceeds the record size limit"),
            "{path:?}: the store's bounded failure is delivered: {body}"
        );
        std::assert!(
            !body.contains("cust-9"),
            "{path:?}: no backend content is delivered"
        );

        let record = fx.only_settlement(path);
        std::assert!(
            tenants_of(&record).contains(&json!(h("cust-9"))),
            "{path:?}: {record}"
        );
        std::assert!(
            record["response_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:")),
            "{path:?}: the processed result's hash is kept: {record}"
        );
    }
}

/// R6, both paths: under `FailClosed` a failed settlement write commits `-32005`,
/// and none of the recovered content is stored or delivered.
#[tokio::test]
async fn r6_a_failed_write_under_fail_closed_withholds_the_result() {
    for path in BOTH {
        let mut setup = Setup::answering(Terminal::Completed(result_naming_cust9("")));
        setup.policy = AuditFailurePolicy::FailClosed;
        let fx = fixture(setup, path).await;
        let (id, _) = fx
            .settle(path, |fx| fx.log.set_append_failure_for_test(true))
            .await;
        // The read above wrote a delivery event too, and was withheld for it.
        // With the log healthy again, read what the settlement committed.
        // Wait out a first probe that overruns its bound (MIK-8171).
        fx.log.heal_for_test().await;
        let fetched = get_task(&fx.state, "key-a", &id).await;
        std::assert_eq!(status_of(&fetched), "failed", "{path:?}: {fetched}");
        let body = fetched.to_string();
        std::assert!(body.contains("-32005"), "{path:?}: {body}");
        std::assert!(
            !body.contains("cust-9"),
            "{path:?}: recovered content was committed: {body}"
        );
    }
}

/// R7, both paths: under `BestEffort` an unwritable log still commits the
/// recovered result, and the failed write is counted.
#[tokio::test]
async fn r7_a_failed_write_under_best_effort_commits_the_result() {
    for path in BOTH {
        let fx = fixture(
            Setup::answering(Terminal::Completed(result_naming_cust9(""))),
            path,
        )
        .await;
        // Counted when the fault is armed, past the submission's own writes.
        let armed = std::cell::Cell::new((0, 0));
        // One append fails: the first one after the terminal answer, which is
        // the settlement record. The read's delivery event after it is written.
        let (_, fetched) = fx
            .settle(path, |fx| {
                armed.set((fx.log.append_failures(), fx.deliveries()));
                fx.log.fail_next_append_for_test();
            })
            .await;
        let (failures, deliveries) = armed.get();
        std::assert_eq!(status_of(&fetched), "completed", "{path:?}: {fetched}");
        std::assert_eq!(
            fx.log.append_failures(),
            failures + 1,
            "{path:?}: one failed append"
        );
        std::assert!(
            fx.deliveries() > deliveries,
            "{path:?}: the failed append was the read's delivery event, not a \
             settlement record written before the commit"
        );
        std::assert!(fx.settlement_records().is_empty(), "{:?}", fx.records());
    }
}

/// R9: the submission record carries the gateway task id whenever the raw
/// handle was captured, including when a response gate refused the handle.
#[tokio::test]
async fn r9_the_submission_record_carries_the_task_id() {
    for refused in [false, true] {
        let path = Path::Worker;
        let mut setup = Setup::answering(Terminal::Completed(result_naming_cust9("")));
        if refused {
            setup.refusing = true;
            let text = format!("AWS_ACCESS_KEY_ID={}", example_access_key());
            setup.envelope_extra = json!({ "content": [{ "type": "text", "text": text }] });
        }
        let fx = fixture(setup, path).await;
        let (id, _) = fx.settle(path, |_| {}).await;
        let submissions: Vec<Value> = fx
            .records()
            .into_iter()
            .filter(|record| record["route"] == "meta")
            .collect();
        std::assert_eq!(submissions.len(), 1, "refused={refused}: {submissions:?}");
        let submission = &submissions[0];
        std::assert_eq!(
            submission["task_id"],
            json!(id),
            "refused={refused}: {submission}"
        );
        if refused {
            std::assert_ne!(submission["outcome"], json!("ok"), "{submission}");
        }
    }
}

/// R10: a call that recovers no task writes exactly one record with no
/// `task_id`, and a log holding a `task_recovery` record verifies.
#[tokio::test]
async fn r10_a_plain_call_is_unchanged_and_the_log_verifies() {
    let path = Path::Worker;
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        path,
    )
    .await;
    let _ = fx.settle(path, |_| {}).await;
    let before = fx.records().len();
    let answered = post(&fx.state, "key-a", sync_invoke(7, json!({ "n": 2 }))).await;
    std::assert!(answered.get("error").is_none(), "{answered}");

    let records = fx.records();
    std::assert_eq!(
        records.len(),
        before + 1,
        "one record for the plain call: {records:?}"
    );
    let plain = records.last().expect("the plain call's record");
    std::assert_eq!(plain["route"], json!("meta"), "{plain}");
    std::assert!(plain.get("task_id").is_none(), "{plain}");

    std::assert_eq!(fx.settlement_records().len(), 1, "{records:?}");
    let verified =
        crate::security::transparency_log::verify_log(&fx.log_dir.path().join("audit.jsonl"))
            .expect("the log reads");
    std::assert!(verified.ok, "{verified:?}");
}
