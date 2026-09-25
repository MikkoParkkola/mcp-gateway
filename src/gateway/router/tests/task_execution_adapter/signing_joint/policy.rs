// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Joint D — attestation authorization recheck on the signed task worker.
//!
//! Valid tokens attach through `MetaMcp::with_attestation` in Enforce mode
//! before the router shares the fixture. Rotation uses the same shared
//! `AttestationValidator` with zero grace. Existing `signed_state/cases` stay
//! untouched; this module only reinstalls the exclusive `MetaMcp`.

use super::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::attestation::{
    AttestationMode, AttestationValidator, BnautAttestationSigner, TokenRequest,
};
use crate::gateway::task_service::{CommitObserver, CommitStage};

const ATTESTATION_KEY: &[u8] = b"joint-d-attestation-key-at-least-32b";
const AUDIT_CAPACITY: usize = 8;
const TTL: TimeDelta = TimeDelta::minutes(5);

fn attested(mut body: Value, token: &str) -> Value {
    body["params"]["arguments"]["attestation"] = json!(token);
    body
}

fn issue(signer: &BnautAttestationSigner, identity: &str) -> crate::attestation::AttestationToken {
    signer.issue(
        &TokenRequest {
            agent_identity: identity.to_owned(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec![TOOL.to_string()],
        },
        Utc::now(),
        TTL,
    )
}

/// Exclusive signed fixture plus shared Enforce validator. Preserves the
/// fixture `MetaMcp` (admission, subscriptions, executor) — no replacement.
async fn attested_state(
    mock: &Arc<MockBackend>,
) -> (
    Arc<AppState>,
    tempfile::TempDir,
    Arc<AttestationValidator>,
    BnautAttestationSigner,
) {
    let signer = BnautAttestationSigner::new(ATTESTATION_KEY.to_vec(), "joint-d");
    let validator = Arc::new(AttestationValidator::with_settings(
        BnautAttestationSigner::new(ATTESTATION_KEY.to_vec(), "joint-d"),
        AUDIT_CAPACITY,
        TimeDelta::zero(),
    ));
    let (state, store) = signed_state(mock).await;
    let mut app = Arc::try_unwrap(state)
        .unwrap_or_else(|_| panic!("signed fixture still exclusive before attestation"));
    let meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture MetaMcp still exclusive"));
    app.meta_mcp =
        Arc::new(meta.with_attestation(Arc::clone(&validator), AttestationMode::Enforce));
    (Arc::new(app), store, validator, signer)
}

struct HoldObserver {
    hold: AtomicBool,
    arrived: tokio::sync::mpsc::UnboundedSender<()>,
    release: Arc<Semaphore>,
}

struct Hold {
    arrived: tokio::sync::mpsc::UnboundedReceiver<()>,
    release: Arc<Semaphore>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release.add_permits(1);
    }
}

impl Hold {
    fn disarm_and_release(&self, observer: &HoldObserver) {
        observer.hold.store(false, Ordering::SeqCst);
        self.release.add_permits(1);
    }
}

#[async_trait]
impl CommitObserver for HoldObserver {
    async fn reached(&self, stage: CommitStage, _task_id: &str) {
        if stage == CommitStage::Dispatched && self.hold.load(Ordering::SeqCst) {
            let _ = self.arrived.send(());
            self.release
                .acquire()
                .await
                .expect("hold semaphore stays open")
                .forget();
        }
    }
}

fn observe_dispatched(state: &Arc<AppState>) -> (Arc<HoldObserver>, Hold) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let observer = Arc::new(HoldObserver {
        hold: AtomicBool::new(true),
        arrived: tx,
        release: Arc::clone(&release),
    });
    state
        .task_executor
        .observe_commits(Arc::clone(&observer) as Arc<dyn CommitObserver>);
    (
        observer,
        Hold {
            arrived: rx,
            release,
        },
    )
}

/// D1 — unchanged valid attestation still signs a real modern task.
#[tokio::test]
async fn joint_d_valid_attestation_dispatches_once_and_validates_the_production_signature() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store, _validator, signer) = attested_state(&mock).await;
    let token = issue(&signer, "alice");
    let nonce = "joint-d1-nonce-fresh";

    let created = bounded(
        "attested signed create",
        post(
            &state,
            "key-a",
            attested(
                with_nonce(
                    task_invoke(410, "joint-d1-key", json!({ "q": "ok" })),
                    json!(nonce),
                ),
                token.encoded(),
            ),
        ),
    )
    .await;
    let id = task_id(&created);
    let _ = assert_signed_for_nonce(&created, nonce);
    let settled = bounded(
        "attested signed settle",
        poll_until_terminal(&state, "key-a", &id),
    )
    .await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "one valid token, one dispatch: {:?}",
        mock.seen()
    );
    std::assert_eq!(
        durable_records(&store).len(),
        1,
        "one accepted task, one record"
    );
}

/// D2 — predecessor admitted, durable Dispatched mark, then rotate (zero grace)
/// before current policy recheck. Predecessor must not reach the backend.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end joint-rotation scenario read as a single sequence"
)]
async fn joint_d_rotated_predecessor_refused_after_dispatched_mark_successor_dispatches() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, store, validator, signer) = attested_state(&mock).await;
    let predecessor = issue(&signer, "alice");
    let nonce = "joint-d2-nonce-pred";
    let (observer, mut hold) = observe_dispatched(&state);

    let created = bounded(
        "predecessor create",
        post(
            &state,
            "key-a",
            attested(
                with_nonce(
                    task_invoke(420, "joint-d2-pred", json!({ "q": "pred" })),
                    json!(nonce),
                ),
                predecessor.encoded(),
            ),
        ),
    )
    .await;
    let pred_id = task_id(&created);
    let _ = assert_signed_for_nonce(&created, nonce);

    bounded("durable dispatched mark", hold.arrived.recv())
        .await
        .expect("worker must reach Dispatched before policy recheck");
    std::assert_eq!(
        mock.calls(),
        0,
        "Dispatched mark is before backend; a call here is the wrong seam"
    );

    validator
        .validate_boundary_call(
            Some(predecessor.encoded()),
            "gateway_invoke",
            Some(TOOL),
            Utc::now(),
        )
        .unwrap_or_else(|rejection| {
            panic!(
                "predecessor must still validate at Dispatched hold before rotation: {rejection}"
            )
        });

    let successor = validator.rotate(predecessor.claims(), Utc::now(), TTL);
    hold.disarm_and_release(&observer);

    let settled = bounded(
        "predecessor terminal after rotation",
        poll_until_terminal(&state, "key-a", &pred_id),
    )
    .await;
    std::assert_eq!(
        status_of(&settled),
        "failed",
        "rotated predecessor must settle failed, not complete: {settled}"
    );
    let refusal = settled
        .pointer("/result/error/code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| {
            panic!("durable failed task must carry /result/error/code -32002: {settled}")
        });
    std::assert_eq!(
        refusal,
        -32002,
        "attestation Enforce refusal, not HTTP shape: {settled}"
    );
    let message = settled
        .pointer("/result/error/message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!("durable failed task must carry /result/error/message: {settled}")
        });
    std::assert!(
        !message.is_empty() && message.contains("Attestation rejected at gateway_invoke"),
        "failed task message must attribute attestation Enforce refusal: {settled}"
    );
    std::assert_eq!(
        mock.calls(),
        0,
        "predecessor must not reach the backend after rotation: {:?}",
        mock.seen()
    );

    validator
        .validate_boundary_call(
            Some(successor.encoded()),
            "gateway_invoke",
            Some(TOOL),
            Utc::now(),
        )
        .unwrap_or_else(|rejection| panic!("successor must validate after rotation: {rejection}"));
    validator
        .validate_boundary_call(
            Some(predecessor.encoded()),
            "gateway_invoke",
            Some(TOOL),
            Utc::now(),
        )
        .expect_err("rotated predecessor must not still validate as the successor");

    let succ_nonce = "joint-d2-nonce-succ";
    let successor_created = bounded(
        "successor create",
        post(
            &state,
            "key-a",
            attested(
                with_nonce(
                    task_invoke(421, "joint-d2-succ", json!({ "q": "succ" })),
                    json!(succ_nonce),
                ),
                successor.encoded(),
            ),
        ),
    )
    .await;
    let succ_id = task_id(&successor_created);
    let _ = assert_signed_for_nonce(&successor_created, succ_nonce);
    let succ_settled = bounded(
        "successor settle",
        poll_until_terminal(&state, "key-a", &succ_id),
    )
    .await;
    assert_carries_the_backend_result(&succ_settled);
    std::assert_eq!(
        mock.calls(),
        1,
        "successor dispatches once: {:?}",
        mock.seen()
    );
    std::assert_eq!(
        durable_records(&store).len(),
        2,
        "failed predecessor record plus successor record"
    );
}

// ── MIK-7570.ATTEST.1 part 3 (c): Enforce read from configuration ─────────

/// The signed fixture with Enforce built the way a deployment builds it: an
/// env file with `enforce` and the key, read through the overlay.
async fn state_enforced_from_config(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = signed_state(mock).await;
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture MetaMcp still exclusive"));
    let key = std::str::from_utf8(ATTESTATION_KEY).expect("utf-8 key");
    let (validator, mode) = crate::attestation::wiring::enforce_from_env_file(key, "joint-d");
    app.meta_mcp = Arc::new(meta.with_attestation(validator, mode));
    (Arc::new(app), store)
}

fn config_signer() -> BnautAttestationSigner {
    BnautAttestationSigner::new(ATTESTATION_KEY.to_vec(), "joint-d")
}

/// Signing on, Enforce from config: an unattested signed call is refused
/// before it is admitted, and an attested one dispatches exactly once.
#[tokio::test]
async fn signed_invoke_enforce_from_config_checks_token() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_enforced_from_config(&mock).await;

    let refused = bounded(
        "unattested signed create",
        post(
            &state,
            "key-a",
            with_nonce(
                task_invoke(430, "cfg-no-token", json!({ "q": "none" })),
                json!("cfg-nonce-none"),
            ),
        ),
    )
    .await;
    std::assert_eq!(error_code(&refused), -32002, "{refused}");
    std::assert_eq!(
        mock.calls(),
        0,
        "an unattested signed call must not dispatch"
    );

    let token = issue(&config_signer(), "alice");
    let created = bounded(
        "attested signed create",
        post(
            &state,
            "key-a",
            attested(
                with_nonce(
                    task_invoke(431, "cfg-token", json!({ "q": "ok" })),
                    json!("cfg-nonce-token"),
                ),
                token.encoded(),
            ),
        ),
    )
    .await;
    let id = task_id(&created);
    let settled = bounded("attested settle", poll_until_terminal(&state, "key-a", &id)).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(mock.calls(), 1, "one valid token, one dispatch");
}

/// Enforce from config: the task worker re-validates the creating request's
/// token at dispatch, so a token that expires while the task is held before
/// dispatch fails the task with -32002 and never reaches the backend.
#[tokio::test]
async fn task_dispatch_enforce_from_config_carries_token() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store) = state_enforced_from_config(&mock).await;
    let (observer, mut hold) = observe_dispatched(&state);
    let short = config_signer().issue(
        &TokenRequest {
            agent_identity: "alice".to_owned(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec![TOOL.to_string()],
        },
        Utc::now(),
        TimeDelta::seconds(2),
    );

    let created = bounded(
        "short-lived token create",
        post(
            &state,
            "key-a",
            attested(
                with_nonce(
                    task_invoke(432, "cfg-expiring", json!({ "q": "late" })),
                    json!("cfg-nonce-expiring"),
                ),
                short.encoded(),
            ),
        ),
    )
    .await;
    let id = task_id(&created);
    bounded("dispatched mark", hold.arrived.recv())
        .await
        .expect("the worker reaches Dispatched");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    hold.disarm_and_release(&observer);

    let settled = bounded("expired settle", poll_until_terminal(&state, "key-a", &id)).await;
    std::assert_eq!(status_of(&settled), "failed", "{settled}");
    std::assert_eq!(
        settled
            .pointer("/result/error/code")
            .and_then(Value::as_i64),
        Some(-32002),
        "{settled}"
    );
    std::assert_eq!(mock.calls(), 0, "an expired token must not dispatch");
}
