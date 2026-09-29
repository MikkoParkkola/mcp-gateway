// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.3: SIGKILL the real gateway binary at the create and
//! settlement boundaries, restart it over the same store, and check that
//! retained handles and outcomes stay readable by their owner and by no one
//! else.
//!
//! Scope of the create-boundary rows: the gateway sends the ack right after the
//! durable create, and nothing outside the process can pause it between the
//! two. These rows kill the process once the record is on disk, and the client
//! never uses the ack. That proves a client that lost its ack can recover the
//! same handle. It does not prove the kill landed between commit and ack.
//!
//! Unix only, like the harness it reuses: `Gateway::kill` is a unix `SIGKILL`.

#![cfg(unix)]

#[path = "task_upstream_recovery/helper.rs"]
#[allow(
    dead_code,
    reason = "shared fixture; this target drives only part of it"
)]
mod helper;

use std::path::{Path, PathBuf};

use mcp_gateway::config::{ApiKeyConfig, AuthConfig, DashboardSessionConfig};
use serde_json::{Value, json};

use helper::{
    BACKEND, Fixture, Gateway, MARKER, OBSERVE_BOUND, POLL_GAP, PeerGuard, Upstream,
    durable_record, free_port, modern, record_status, serve_peer, status_of, store_dir, task_id_of,
    task_invoke, tasks_get, write_config,
};

const KEY_A: &str = "crash-boundary-key-a";
const KEY_B: &str = "crash-boundary-key-b";
const IDEMPOTENCY_KEY: &str = "crash-boundary-create";
/// Well formed, and minted by nobody.
const NEVER_MINTED: &str = "task-00000000-0000-4000-8000-0000000000fe";

fn temp_root(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(name)
        .tempdir()
        .expect("an owned temporary root")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client")
}

fn api_key(name: &str, secret: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(mcp_gateway::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![BACKEND.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// The shared fixture config with authentication ON and two principals. With
/// it off every caller is one principal and no owner check can fail.
fn config_with_two_principals(root: &Path, port: u16, peer: &PeerGuard) -> PathBuf {
    let path = write_config(
        root,
        &Fixture {
            name: "gateway.yaml",
            port,
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let yaml = std::fs::read_to_string(&path).expect("the fixture config reads back");
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(&yaml).expect("the fixture config is YAML");
    let auth = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![api_key("principal-a", KEY_A), api_key("principal-b", KEY_B)],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: DashboardSessionConfig::default(),
    };
    doc["auth"] = serde_yaml::to_value(&auth).expect("the auth config serializes");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&doc).expect("the patched config serializes"),
    )
    .expect("the patched config is written inside the test's own temp root");
    path
}

/// The id of the first committed record in the store, waiting for it. Temp
/// files end in `.tmp.<pid>.<n>` and never match.
async fn first_record(root: &Path) -> String {
    let dir = store_dir(root);
    let found = async {
        loop {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(id) = name.strip_suffix(".json")
                        && id.starts_with("task-")
                    {
                        return id.to_string();
                    }
                }
            }
            tokio::time::sleep(POLL_GAP).await;
        }
    };
    tokio::time::timeout(OBSERVE_BOUND, found)
        .await
        .expect("the create is committed to the store within the bound")
}

/// Send the create as principal A, wait until its record is on disk, then
/// SIGKILL. The create future is dropped, so the client never uses an ack even
/// if one arrived first.
async fn create_then_kill_discarding_the_ack(
    root: &Path,
    config: &Path,
    port: u16,
    client: &reqwest::Client,
) -> String {
    let mut gateway = Gateway::start(root, config, port, "first.log");
    gateway.wait_until_ready(client).await;
    let body = task_invoke(1, IDEMPOTENCY_KEY);
    let task_id = {
        let create = gateway.post_as(client, &body, Some(KEY_A));
        tokio::pin!(create);
        tokio::select! {
            biased;
            id = first_record(root) => id,
            // The answer raced the store poll; it is discarded all the same.
            _ = &mut create => first_record(root).await,
        }
    };
    gateway.kill().await;
    task_id
}

/// `method` on `task_id` as principal B must be refused as absent, exactly as
/// an id nobody minted is, and must not reach the upstream peer.
async fn refused_like_a_never_minted_id(
    gateway: &Gateway,
    client: &reqwest::Client,
    peer: &PeerGuard,
    method: &str,
    task_id: &str,
) {
    let before = peer.peer.queries();
    let real = gateway
        .post_as(
            client,
            &modern(90, method, json!({ "taskId": task_id })),
            Some(KEY_B),
        )
        .await;
    let fabricated = gateway
        .post_as(
            client,
            &modern(90, method, json!({ "taskId": NEVER_MINTED })),
            Some(KEY_B),
        )
        .await;
    assert_eq!(
        real.pointer("/error/code"),
        Some(&json!(-32602)),
        "{method} on another principal's task is refused as absent: {real}"
    );
    assert_eq!(
        (real.get("error"), real.get("_httpStatus")),
        (fabricated.get("error"), fabricated.get("_httpStatus")),
        "{method} on another principal's task must read exactly like a never-minted id"
    );
    assert_eq!(
        peer.peer.queries(),
        before,
        "a refused {method} must cause zero upstream queries"
    );
}

/// Create boundary: the process dies with the record on disk and the ack
/// discarded. After a restart, principal A's byte-identical retry recovers the
/// same handle, A can read it, B cannot, and nothing is submitted twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_killed_before_its_ack_is_recovered_by_its_owner_only() {
    let root = temp_root("crash-create-ack");
    let peer = serve_peer(Upstream::Working).await;
    let port = free_port();
    let config = config_with_two_principals(root.path(), port, &peer);
    let client = client();
    let task_id = create_then_kill_discarding_the_ack(root.path(), &config, port, &client).await;
    let on_disk = durable_record(root.path(), &task_id);

    let mut restarted = Gateway::start(root.path(), &config, port, "second.log");
    restarted.wait_until_ready(&client).await;

    refused_like_a_never_minted_id(&restarted, &client, &peer, "tasks/get", &task_id).await;

    let read = restarted
        .post_as(&client, &tasks_get(10, &task_id), Some(KEY_A))
        .await;
    assert_eq!(
        read.pointer("/result/taskId").and_then(Value::as_str),
        Some(task_id.as_str()),
        "the owner reads the retained handle after the crash: {read}\nrecord: {on_disk}"
    );
    assert!(
        matches!(status_of(&read), Some("working" | "completed")),
        "a recovered row is live or settled, never lost: {read}\nrecord: {on_disk}"
    );

    let retried = restarted
        .post_as(&client, &task_invoke(1, IDEMPOTENCY_KEY), Some(KEY_A))
        .await;
    assert_eq!(
        retried.pointer("/result/taskId").and_then(Value::as_str),
        Some(task_id.as_str()),
        "the owner who never saw the ack gets the SAME handle back from its retry: \
         {retried}\nrecord: {on_disk}"
    );
    restarted.terminate().await;

    assert!(
        peer.peer.submissions() <= 1,
        "a crash, a restart and a retry must not submit the operation twice: {} \
         submissions\nrecord: {on_disk}",
        peer.peer.submissions()
    );
}

/// The falsifier for the row above: the same crash, then a restart over an
/// EMPTY store. The retry now mints a new handle and the owner is told the old
/// one does not exist. Without this row, a gateway that answered any retry
/// with any id, or any read with success, would pass the row above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_over_an_empty_store_does_not_recover_the_handle() {
    let root = temp_root("crash-create-ack-control");
    let empty = temp_root("crash-create-ack-empty");
    let peer = serve_peer(Upstream::Working).await;
    let port = free_port();
    let config = config_with_two_principals(root.path(), port, &peer);
    let client = client();
    let task_id = create_then_kill_discarding_the_ack(root.path(), &config, port, &client).await;

    let empty_config = config_with_two_principals(empty.path(), port, &peer);
    let mut restarted = Gateway::start(empty.path(), &empty_config, port, "second.log");
    restarted.wait_until_ready(&client).await;

    let read = restarted
        .post_as(&client, &tasks_get(10, &task_id), Some(KEY_A))
        .await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32602)),
        "an empty store holds no such task, even for its creator: {read}"
    );
    let retried = restarted
        .post_as(&client, &task_invoke(1, IDEMPOTENCY_KEY), Some(KEY_A))
        .await;
    let minted = task_id_of(&retried);
    restarted.terminate().await;
    assert_ne!(
        minted, task_id,
        "with no retained record the retry must mint a new handle"
    );
}

/// Kill before settlement: the upstream job is still working. After the
/// restart A reads it working and B cannot see it.
async fn kill_before_settlement(
    root: &Path,
    config: &Path,
    port: u16,
    client: &reqwest::Client,
    peer: &PeerGuard,
) -> String {
    let mut gateway = Gateway::start(root, config, port, "first.log");
    gateway.wait_until_ready(client).await;
    let created = gateway
        .post_as(client, &task_invoke(1, IDEMPOTENCY_KEY), Some(KEY_A))
        .await;
    let task_id = task_id_of(&created);
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = Gateway::start(root, config, port, "second.log");
    restarted.wait_until_ready(client).await;
    refused_like_a_never_minted_id(&restarted, client, peer, "tasks/get", &task_id).await;
    let live = restarted
        .post_as(client, &tasks_get(20, &task_id), Some(KEY_A))
        .await;
    assert_eq!(
        status_of(&live),
        Some("working"),
        "a job killed before settlement is retained as working for its owner: {live}"
    );
    restarted.kill().await;
    task_id
}

/// Kill after settlement: A's read commits the upstream result, then the
/// process dies. Returns the settled payload A was shown.
async fn kill_after_settlement(
    root: &Path,
    config: &Path,
    port: u16,
    client: &reqwest::Client,
    peer: &PeerGuard,
    task_id: &str,
) -> Value {
    let mut gateway = Gateway::start(root, config, port, "third.log");
    gateway.wait_until_ready(client).await;
    peer.peer.set(Upstream::Completed);
    let settled = gateway
        .post_as(client, &tasks_get(30, task_id), Some(KEY_A))
        .await;
    assert_eq!(
        status_of(&settled),
        Some("completed"),
        "the owner's read commits the upstream result: {settled}"
    );
    let record = durable_record(root, task_id);
    assert_eq!(
        record_status(&record),
        Some("completed"),
        "the settlement is durable before the kill: {record}"
    );
    gateway.kill().await;
    settled
        .pointer("/result/result")
        .cloned()
        .unwrap_or_else(|| panic!("a completed task carries its payload: {settled}"))
}

/// Settlement boundary, both sides: SIGKILL while the job is working, restart,
/// settle, SIGKILL right after the settlement commit, restart again. The owner
/// reads the same outcome with no new upstream query; B can neither read nor
/// cancel it; the operation was submitted once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_outcome_survives_kills_on_both_sides_of_settlement() {
    let root = temp_root("crash-settlement");
    let peer = serve_peer(Upstream::Working).await;
    let port = free_port();
    let config = config_with_two_principals(root.path(), port, &peer);
    let client = client();

    let task_id = kill_before_settlement(root.path(), &config, port, &client, &peer).await;
    let settled = kill_after_settlement(root.path(), &config, port, &client, &peer, &task_id).await;
    assert!(
        settled.to_string().contains(MARKER),
        "the settled payload is the peer's own: {settled}"
    );

    // Counted from before the restart, and the peer can no longer answer: a
    // gateway that re-fetched the outcome at startup or on the read would be
    // seen, and could not rebuild the payload from upstream.
    let queries = peer.peer.queries();
    peer.peer.set(Upstream::Unavailable);
    let mut restarted = Gateway::start(root.path(), &config, port, "fourth.log");
    restarted.wait_until_ready(&client).await;
    let read = restarted
        .post_as(&client, &tasks_get(40, &task_id), Some(KEY_A))
        .await;
    assert_eq!(
        status_of(&read),
        Some("completed"),
        "the settled outcome is retained across the kill: {read}"
    );
    assert_eq!(
        read.pointer("/result/result"),
        Some(&settled),
        "the owner reads the same payload it was shown before the kill: {read}"
    );
    assert_eq!(
        peer.peer.queries(),
        queries,
        "a settled row is answered from the store, not by asking upstream again"
    );
    refused_like_a_never_minted_id(&restarted, &client, &peer, "tasks/get", &task_id).await;
    refused_like_a_never_minted_id(&restarted, &client, &peer, "tasks/cancel", &task_id).await;
    restarted.terminate().await;

    assert_eq!(
        peer.peer.submissions(),
        1,
        "three restarts submitted the operation exactly once"
    );
}
