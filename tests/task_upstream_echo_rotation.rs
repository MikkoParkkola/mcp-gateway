// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A deferred upstream task whose result echoes the secret its dispatch
//! injected must never deliver it once the gateway can no longer redact it:
//! after a restart (the new process's redaction set holds only the rules'
//! current values) or after a rotation. Such a task settles withheld, with a
//! fixed reason, and its result is never stored.
//!
//! Real gateway processes over one root (task store and config dir), a
//! loopback peer that runs the call as an upstream task, and the real route.

// Unix-only, as the recovery helper's process control is.
#![cfg(unix)]

#[path = "common/yaml.rs"]
mod yaml;

#[allow(
    dead_code,
    reason = "the recovery targets' shared helper; this target uses the restart, peer and store parts"
)]
#[path = "task_upstream_recovery/helper.rs"]
mod helper;

use serde_json::{Value, json};

use helper::{
    BACKEND, Fixture, Gateway, PeerGuard, Upstream, durable_record, serve_peer, status_of,
    task_id_of, task_invoke, tasks_get, write_config_with,
};
use mcp_gateway::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// The value the task's dispatch injected.
const OLD: &str = "rotation-old-secret-5e1b7c9a";
/// The value after the rotation.
const NEW: &str = "rotation-new-secret-a04d22f8";
/// What a withheld settlement says, and nothing of the result.
const WITHHELD: &str = "the backend's injected credential changed since this task was dispatched";

fn rule(value: &str) -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: value.to_string(),
        inject_as: InjectTarget::Argument,
        inject_key: "api_key".to_string(),
        tools: vec!["*".to_string()],
    }
}

/// The gateway config for `peer`, its backend carrying `secret` when set.
fn config(
    root: &std::path::Path,
    name: &str,
    peer: &PeerGuard,
    secret: Option<&str>,
) -> std::path::PathBuf {
    write_config_with(
        root,
        &Fixture {
            name,
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
        |config| {
            if let (Some(value), Some(backend)) = (secret, config.backends.get_mut(BACKEND)) {
                backend.secrets = vec![rule(value)];
            }
        },
    )
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client")
}

/// The peer's completed answer: the value the call carried, echoed.
fn echoing(value: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": format!("finished with key {value}") }],
        "isError": false,
    })
}

/// Read the task until the peer's terminal answer is settled, bounded.
async fn settled(gateway: &Gateway, client: &reqwest::Client, task_id: &str) -> Value {
    let deadline = std::time::Instant::now() + helper::OBSERVE_BOUND;
    for read in 0_i64.. {
        let got = gateway.post(client, &tasks_get(500 + read, task_id)).await;
        if !matches!(status_of(&got), Some("working")) {
            return got;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the task never settled within {:?}: {got}",
            helper::OBSERVE_BOUND
        );
        tokio::time::sleep(helper::POLL_GAP).await;
    }
    unreachable!("the read loop returns or panics")
}

/// Wait, bounded, until the task's upstream handle is durable: a restart
/// before that leaves nothing to recover, and would test nothing.
async fn captured(root: &std::path::Path, task_id: &str) {
    let deadline = std::time::Instant::now() + helper::OBSERVE_BOUND;
    loop {
        let row = helper::durable_records(root)
            .into_iter()
            .find(|row| row.to_string().contains(task_id));
        if row.is_some_and(|row| row.to_string().contains(helper::HANDLE)) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the task's upstream handle was never captured within {:?}",
            helper::OBSERVE_BOUND
        );
        tokio::time::sleep(helper::POLL_GAP).await;
    }
}

/// The settled read and the durable row hold neither value, and the task is
/// withheld with its fixed reason.
fn assert_withheld(answer: &Value, row: &Value) {
    for (what, text) in [
        ("answer", answer.to_string()),
        ("stored row", row.to_string()),
    ] {
        assert!(
            !text.contains(OLD),
            "the {what} holds the old secret: {text}"
        );
        assert!(
            !text.contains(NEW),
            "the {what} holds the new secret: {text}"
        );
    }
    assert!(
        answer.to_string().contains(WITHHELD),
        "the task was not withheld: {answer}"
    );
}

/// Restart then settle: the task was dispatched with OLD under the first
/// process; the second runs with NEW, so its redaction set does not hold OLD.
/// The peer's answer echoes OLD: it must be withheld, never delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_result_echoing_a_secret_rotated_across_a_restart_is_withheld() {
    let root = tempfile::Builder::new()
        .prefix("echo-rotation-restart")
        .tempdir()
        .expect("an owned temporary root");
    let peer = serve_peer(Upstream::Working).await;
    let client = client();
    let first = config(root.path(), "first.yaml", &peer, Some(OLD));
    let mut gateway = Gateway::start(root.path(), &first, "first.log");
    gateway.wait_until_ready(&client).await;
    let task_id = task_id_of(
        &gateway
            .post(&client, &task_invoke(1, "echo-rotation-1"))
            .await,
    );
    captured(root.path(), &task_id).await;
    assert_eq!(
        peer.peer.submissions(),
        1,
        "premise: the call reached the peer"
    );
    gateway.terminate_confirmed().await;

    let second = config(root.path(), "second.yaml", &peer, Some(NEW));
    let mut restarted = Gateway::start(root.path(), &second, "second.log");
    restarted.wait_until_ready(&client).await;
    peer.peer.set_payload(echoing(OLD));
    peer.peer.set(Upstream::Completed);
    let answer = settled(&restarted, &client, &task_id).await;
    let row = durable_record(root.path(), &task_id);
    restarted.terminate().await;
    assert_withheld(&answer, &row);
}

/// A task stored with no fingerprint member at all, as a 4.0 pre-release
/// build wrote it, is withheld at its recovery read: nothing says what its
/// dispatch injected. The backend has no rule before or after, so a stored
/// `"none"` would have been delivered; only the absent member withholds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_task_stored_without_a_fingerprint_is_withheld() {
    let root = tempfile::Builder::new()
        .prefix("echo-rotation-absent")
        .tempdir()
        .expect("an owned temporary root");
    let peer = serve_peer(Upstream::Working).await;
    let client = client();
    let first = config(root.path(), "first.yaml", &peer, None);
    let mut gateway = Gateway::start(root.path(), &first, "first.log");
    gateway.wait_until_ready(&client).await;
    let task_id = task_id_of(
        &gateway
            .post(&client, &task_invoke(1, "echo-rotation-2"))
            .await,
    );
    captured(root.path(), &task_id).await;
    gateway.terminate_confirmed().await;
    let mut legacy = durable_record(root.path(), &task_id);
    assert_eq!(
        legacy["upstream"]["secretFingerprint"],
        json!("none"),
        "premise: this build wrote the member"
    );
    legacy["upstream"]
        .as_object_mut()
        .expect("an upstream descriptor")
        .remove("secretFingerprint");
    std::fs::write(
        helper::store_dir(root.path()).join(format!("{task_id}.json")),
        serde_json::to_vec(&legacy).expect("the record serializes"),
    )
    .expect("the record is rewritten in place");

    let second = config(root.path(), "second.yaml", &peer, None);
    let mut restarted = Gateway::start(root.path(), &second, "second.log");
    restarted.wait_until_ready(&client).await;
    peer.peer.set_payload(echoing(OLD));
    peer.peer.set(Upstream::Completed);
    let answer = settled(&restarted, &client, &task_id).await;
    let row = durable_record(root.path(), &task_id);
    restarted.terminate().await;
    assert_withheld(&answer, &row);
}

/// Control: dispatched and settled in one process with the value unchanged,
/// the task is delivered, its echo redacted. A check that withheld this would
/// break every deferred task on a secret-bearing backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unchanged_secret_settles_delivered_and_redacted() {
    let root = tempfile::Builder::new()
        .prefix("echo-rotation-control")
        .tempdir()
        .expect("an owned temporary root");
    let peer = serve_peer(Upstream::Working).await;
    let client = client();
    let only = config(root.path(), "gateway.yaml", &peer, Some(OLD));
    let mut gateway = Gateway::start(root.path(), &only, "gateway.log");
    gateway.wait_until_ready(&client).await;
    let task_id = task_id_of(
        &gateway
            .post(&client, &task_invoke(1, "echo-rotation-3"))
            .await,
    );
    peer.peer.set_payload(echoing(OLD));
    peer.peer.set(Upstream::Completed);
    let answer = settled(&gateway, &client, &task_id).await;
    let row = durable_record(root.path(), &task_id);
    gateway.terminate().await;
    assert_eq!(
        status_of(&answer),
        Some("completed"),
        "the control was not delivered: {answer}"
    );
    for text in [answer.to_string(), row.to_string()] {
        assert!(!text.contains(OLD), "the secret was not redacted: {text}");
        assert!(
            text.contains("[redacted]"),
            "the result was emptied, not redacted: {text}"
        );
    }
}

/// The log line a config reload ends with.
const RELOADED: &str = "Config reload: complete";

/// Wait for one more completed reload than `before`, bounded.
async fn reloaded(gateway: &Gateway, before: usize) {
    let deadline = std::time::Instant::now() + helper::OBSERVE_BOUND;
    while gateway.logs().matches(RELOADED).count() <= before {
        assert!(
            std::time::Instant::now() < deadline,
            "no config reload completed within {:?}\n{}",
            helper::OBSERVE_BOUND,
            gateway.logs()
        );
        tokio::time::sleep(helper::POLL_GAP).await;
    }
}

/// Control: rotated in the same process by a config reload, then settled
/// within the grace. The process's redaction set still holds OLD (a value
/// retires only a grace after its last send), so the echo is redacted.
/// It is withheld after the fix, as any rotation is; on the line it is
/// delivered redacted. Either way no value is in the answer or the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secret_rotated_in_one_process_never_reaches_the_answer_or_the_store() {
    let root = tempfile::Builder::new()
        .prefix("echo-rotation-reload")
        .tempdir()
        .expect("an owned temporary root");
    let peer = serve_peer(Upstream::Working).await;
    let client = client();
    let path = config(root.path(), "gateway.yaml", &peer, Some(OLD));
    let mut gateway = Gateway::start(root.path(), &path, "gateway.log");
    gateway.wait_until_ready(&client).await;
    let task_id = task_id_of(
        &gateway
            .post(&client, &task_invoke(1, "echo-rotation-4"))
            .await,
    );
    let before = gateway.logs().matches(RELOADED).count();
    config(root.path(), "gateway.yaml", &peer, Some(NEW));
    reloaded(&gateway, before).await;
    peer.peer.set_payload(echoing(OLD));
    peer.peer.set(Upstream::Completed);
    let answer = settled(&gateway, &client, &task_id).await;
    let row = durable_record(root.path(), &task_id);
    gateway.terminate().await;
    // Withheld, not merely redacted: inside its grace the old value is still
    // scrubbed from the answer, so only the settlement shows the check ran.
    assert_withheld(&answer, &row);
}
