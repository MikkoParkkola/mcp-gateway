// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! I5 upstream recovery — SYNTHETIC controls, over real gateway processes, a
//! real durable store and the real route.
//!
//! Named synthetic because the peer is a loopback fixture rather than the
//! pinned SDK. It speaks the vocabulary the SDK was observed to speak, but it
//! is NOT offered as evidence about the SDK: that proof is
//! `task_upstream_recovery_sdk.rs`, which runs the actual pinned `FastMCP`
//! `TasksExtension` over Docket. Everything asserted here is about this
//! gateway's own store, route, authorization and counting.

// Unix-only: the crash is a SIGKILL whose death by signal the helper asserts (helper.rs:523-542).
#![cfg(unix)]

#[path = "task_upstream_recovery/helper.rs"]
mod helper;

use serde_json::{Value, json};

use helper::{
    BACKEND, Fixture, Gateway, HANDLE, MARKER, Upstream, durable_record, modern, serve_peer,
    status_of, task_id_of, task_invoke, tasks_get, write_config,
};

fn temp_root(name: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(name)
        .tempdir()
        .expect("an owned temporary root")
}

/// Start a task against the peer and leave it running upstream.
async fn start_live_task(
    root: &std::path::Path,
    config: &std::path::Path,
    log: &str,
    client: &reqwest::Client,
) -> (Gateway, String) {
    let mut gateway = Gateway::start(root, config, log);
    gateway.wait_until_ready(client).await;
    let created = gateway
        .post(client, &task_invoke(1, "upstream-recovery-key"))
        .await;
    let task_id = task_id_of(&created);
    (gateway, task_id)
}

/// The whole durable table in one place: a row that never reached the wire, a
/// row that did, and a row that captured a handle are three different states,
/// and only the third is recoverable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_captured_handle_is_recorded_at_version_three_with_its_descriptor() {
    let root = temp_root("upstream-handle-table");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) =
        start_live_task(root.path(), &config, "gateway.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let record = durable_record(root.path(), &task_id);
    assert_eq!(
        record["version"],
        json!(5),
        "a direct task records its target at creation (#2450), which raises the row to version 5; \
         the handle's own descriptor is asserted below: {record}"
    );
    assert_eq!(
        record["dispatched"],
        json!(true),
        "the marker is durable before the call goes out: {record}"
    );
    assert_eq!(
        record.pointer("/upstream/handle").and_then(Value::as_str),
        Some(HANDLE),
        "the peer's own opaque handle is what was persisted: {record}"
    );
    assert_eq!(
        record.pointer("/upstream/backend").and_then(Value::as_str),
        Some(BACKEND),
        "and the backend the query may be sent to: {record}"
    );
    assert_eq!(
        record.pointer("/upstream/tool").and_then(Value::as_str),
        Some(helper::TOOL),
        "and the original backend tool: {record}"
    );
    assert!(
        record.pointer("/upstream/arguments").is_some(),
        "the complete original arguments must be persisted, because the reader \
         re-authorizes with them: {record}"
    );
    assert_eq!(
        record.pointer("/upstream/operationDigest"),
        record.pointer("/admission/operationDigest"),
        "the descriptor is bound to the operation this record was admitted for: {record}"
    );
    assert!(
        record.pointer("/upstream/handle").is_some()
            && record["admission"]["metadataBytes"].is_number(),
        "the handle is gateway state and must not have perturbed the admitted \
         metadata accounting: {record}"
    );
}

/// Exactly one submission, ever. Not one per read, not one per restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_original_operation_is_submitted_once_and_never_resubmitted() {
    let root = temp_root("upstream-one-submission");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &config, "first.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = Gateway::start(root.path(), &config, "second.log");
    restarted.wait_until_ready(&client).await;
    let before = peer.peer.queries();
    for id in 10..13 {
        restarted.post(&client, &tasks_get(id, &task_id)).await;
    }
    restarted.terminate().await;

    assert_eq!(
        peer.peer.submissions(),
        1,
        "the backend must see exactly one tools/call across the whole lifetime: \
         a restart and three reads may not re-run the operation"
    );
    assert!(
        peer.peer.queries() > before,
        "an authorized read of a still-live job issues its bounded query"
    );
    assert!(
        peer.peer
            .handles_asked()
            .iter()
            .all(|asked| asked == HANDLE),
        "every query names the ONE persisted handle: {:?}",
        peer.peer.handles_asked()
    );
}

/// The managed row survives a crash, stays `working` without any startup query,
/// and its owner — and only its owner — can move it forward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_durable_handle_survives_reopen_and_only_its_owner_reads_it() {
    let root = temp_root("upstream-survives-reopen");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &config, "first.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = Gateway::start(root.path(), &config, "second.log");
    let queries_at_start = peer.peer.queries();
    restarted.wait_until_ready(&client).await;
    assert_eq!(
        peer.peer.queries(),
        queries_at_start,
        "startup imports and classifies but must not query upstream: a managed \
         working row is valid state, not an unclassified store"
    );

    // Someone else's id: the existing absence answer, and zero queries.
    let foreign = "task-00000000-0000-4000-8000-0000000000ff";
    let before_foreign = peer.peer.queries();
    let refused = restarted.post(&client, &tasks_get(20, foreign)).await;
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32602)),
        "a task nobody owns is absent, in the existing wording: {refused}"
    );
    assert_eq!(
        peer.peer.queries(),
        before_foreign,
        "a read that resolves to absence must cause zero upstream calls"
    );

    let owned = restarted.post(&client, &tasks_get(21, &task_id)).await;
    assert_eq!(
        status_of(&owned),
        Some("working"),
        "a still-live upstream job stays working; it is never faked terminal: {owned}"
    );
    restarted.terminate().await;
}

/// Unavailable, then working, then complete — the same handle throughout, and
/// no resubmission at any point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_then_live_then_complete_reuses_the_one_handle() {
    let root = temp_root("upstream-pending-then-complete");
    let peer = serve_peer(Upstream::Unavailable).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &config, "first.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = Gateway::start(root.path(), &config, "second.log");
    restarted.wait_until_ready(&client).await;

    let unavailable = restarted.post(&client, &tasks_get(30, &task_id)).await;
    assert_eq!(
        status_of(&unavailable),
        Some("working"),
        "an unreachable peer retains the handle rather than settling unknown: {unavailable}"
    );

    peer.peer.set(Upstream::Working);
    let live = restarted.post(&client, &tasks_get(31, &task_id)).await;
    assert_eq!(
        status_of(&live),
        Some("working"),
        "a live job retains the handle for a later read: {live}"
    );

    peer.peer.set(Upstream::Completed);
    let done = restarted.post(&client, &tasks_get(32, &task_id)).await;
    assert_eq!(
        status_of(&done),
        Some("completed"),
        "the eventual upstream result is committed on the owner's read: {done}"
    );
    let text = serde_json::to_string(&done).expect("the answer serializes");
    assert!(
        text.contains(MARKER),
        "the exact upstream payload reaches its owner: {done}"
    );
    restarted.terminate().await;

    assert_eq!(
        peer.peer.submissions(),
        1,
        "three reads and one restart submitted the operation exactly once"
    );
    assert!(
        peer.peer.handles_asked().iter().all(|a| a == HANDLE),
        "the same handle was read every time: {:?}",
        peer.peer.handles_asked()
    );
    let record = durable_record(root.path(), &task_id);
    assert_eq!(
        helper::record_status(&record),
        Some("completed"),
        "and the durable record carries the committed terminal outcome: {record}"
    );
}

/// The recovered payload faces the SAME configured output policy a live
/// dispatch faces. A blocked payload becomes the task's failure, not a silent
/// pass-through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_configured_output_policy_applies_to_a_recovered_result() {
    let root = temp_root("upstream-output-policy");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: true,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &config, "first.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = Gateway::start(root.path(), &config, "second.log");
    restarted.wait_until_ready(&client).await;
    peer.peer.set(Upstream::Completed);
    let answered = restarted.post(&client, &tasks_get(40, &task_id)).await;
    restarted.terminate().await;

    let text = serde_json::to_string(&answered).expect("the answer serializes");
    assert!(
        !text.contains(MARKER),
        "a payload the configured contract forbids must not reach the owner \
         through the recovery path: {answered}"
    );
    assert_eq!(
        status_of(&answered),
        Some("failed"),
        "an action-mode contract violation is the task's outcome, not a silent \
         pass-through and not a row left mid-flight: {answered}"
    );
}

/// The no-adapter control. Nothing about the conservative branch may change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_no_configured_adapter_the_conservative_branch_is_unchanged() {
    let root = temp_root("upstream-no-adapter");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: Vec::new(),
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &config, "first.log", &client).await;
    gateway.kill().await;

    let queries_before = peer.peer.queries();
    let mut restarted = Gateway::start(root.path(), &config, "second.log");
    restarted.wait_until_ready(&client).await;
    let answered = restarted.post(&client, &tasks_get(50, &task_id)).await;
    restarted.terminate().await;

    assert_eq!(
        peer.peer.queries(),
        queries_before,
        "no adapter is configured, so the read issues zero upstream queries"
    );
    assert_eq!(
        status_of(&answered),
        Some("completed"),
        "the interrupted row is settled by I3's own table: {answered}"
    );
    let text = serde_json::to_string(&answered).expect("the answer serializes");
    assert!(
        text.contains("executionOutcome"),
        "and it carries the conservative outcome the table names: {answered}"
    );

    let record = durable_record(root.path(), &task_id);
    assert!(
        record.get("upstream").is_none(),
        "no handle is captured at all when no adapter is configured: {record}"
    );
}

/// An adapter dropped from configuration between the submission and the read
/// refuses the query. Not query-then-discard: zero calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_adapter_untrusted_at_restart_causes_zero_queries() {
    let root = temp_root("upstream-trust-lost");
    let peer = serve_peer(Upstream::Working).await;
    let trusted = write_config(
        root.path(),
        &Fixture {
            name: "trusted.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, task_id) = start_live_task(root.path(), &trusted, "first.log", &client).await;
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    // Trust withdrawn. The durable handle is untouched; the vocabulary is gone.
    let untrusted = write_config(
        root.path(),
        &Fixture {
            name: "untrusted.yaml",
            backend_url: &peer.url,
            adapters: Vec::new(),
            forbid_marker: false,
        },
    );
    let queries_before = peer.peer.queries();
    let mut restarted = Gateway::start(root.path(), &untrusted, "second.log");
    restarted.wait_until_ready(&client).await;
    let answered = restarted.post(&client, &tasks_get(60, &task_id)).await;
    restarted.terminate().await;

    assert_eq!(
        peer.peer.queries(),
        queries_before,
        "a backend nobody trusts now is never asked: the refusal is before the wire"
    );
    assert_eq!(
        peer.peer.submissions(),
        1,
        "and losing trust certainly does not resubmit anything"
    );
    let _ = answered;
}

/// The opt-in this gateway must put on the wire for a peer to run the call as a
/// task at all.
///
/// Asserted against the outbound request the peer actually received, because
/// the modern envelope writer is the last writer on that path and a value it
/// replaces is a value the peer never sees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_task_extension_optin_reaches_the_backend() {
    let root = temp_root("upstream-optin");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let (mut gateway, _task_id) =
        start_live_task(root.path(), &config, "gateway.log", &client).await;
    gateway.terminate().await;

    assert_eq!(
        peer.peer.submissions(),
        1,
        "one submission reached the peer"
    );
    assert_eq!(
        peer.peer.optin_seen(),
        1,
        "the submission must carry \
         _meta[io.modelcontextprotocol/clientCapabilities].extensions\
         [io.modelcontextprotocol/tasks]; without it the pinned SDK runs the call \
         synchronously and answers tasks/* with -32021"
    );
}

/// A gateway-shaped task envelope is not an upstream handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_envelope_is_never_mistaken_for_an_upstream_job() {
    let root = temp_root("upstream-envelope");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let mut gateway = Gateway::start(root.path(), &config, "gateway.log");
    gateway.wait_until_ready(&client).await;
    // The gateway's OWN answer to a task-augmented call also carries
    // `resultType: "task"` and a `taskId`; it names a gateway record, not an
    // upstream job, and the recogniser only ever runs on the raw peer reply.
    let created = gateway
        .post(&client, &task_invoke(70, "envelope-key"))
        .await;
    assert_eq!(
        created
            .pointer("/result/resultType")
            .and_then(Value::as_str),
        Some("task"),
        "the gateway's own envelope: {created}"
    );
    let task_id = task_id_of(&created);
    assert!(
        task_id.starts_with("task-"),
        "the gateway's handle is its own validated id, never the peer's opaque \
         string: {task_id}"
    );
    assert_ne!(task_id, HANDLE, "and it is not the peer's handle");
    gateway.terminate().await;
}

/// The read arm still answers a malformed request the way it always did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_without_a_task_id_is_refused_before_anything_else() {
    let root = temp_root("upstream-no-task-id");
    let peer = serve_peer(Upstream::Working).await;
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let mut gateway = Gateway::start(root.path(), &config, "gateway.log");
    gateway.wait_until_ready(&client).await;
    let before = peer.peer.queries();
    let refused = gateway
        .post(&client, &modern(80, "tasks/get", json!({})))
        .await;
    gateway.terminate().await;
    assert!(
        refused.get("error").is_some(),
        "a read naming no task is refused: {refused}"
    );
    assert_eq!(
        peer.peer.queries(),
        before,
        "and causes no upstream call whatsoever"
    );
}

/// Long enough for several relay fingerprints, with nothing any other
/// scanner reacts to.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// COLLUDE.1 M15: an upstream-followed task's recovered result is a delivery
/// to its owner, recorded at settlement. Alice's task completes upstream with
/// [`PROSE`]; Bob, who never received it, sending it is refused. A `working`
/// stub recorded in its place would hold none of the text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn meta_upstream_task_result_recorded() {
    let root = temp_root("upstream-relay-receipt");
    let peer = serve_peer(Upstream::Working).await;
    peer.peer.set_payload(json!({
        "content": [{ "type": "text", "text": PROSE }],
        "isError": false,
    }));
    let config = write_config(
        root.path(),
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    with_relay_block(&config);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("bounded fixture HTTP client");
    let mut gateway = Gateway::start(root.path(), &config, "gateway.log");
    gateway.wait_until_ready(&client).await;
    let created = gateway
        .post_as(
            &client,
            &task_invoke(1, "relay-upstream-key"),
            Some("alice"),
        )
        .await;
    let _ = task_id_of(&created);
    peer.peer.wait_for_queries(1).await;
    peer.peer.set(Upstream::Completed);

    // Bob's relay rides `_meta.progressToken`, which reaches the backend: no
    // argument key the peer's empty schema would refuse first. Never a task
    // read, which would renew a receipt of its own.
    let mut relay = modern(
        2,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": BACKEND, "tool": helper::TOOL, "arguments": {} },
            "_meta": { "progressToken": PROSE },
        }),
    );
    relay["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let deadline = tokio::time::Instant::now() + helper::OBSERVE_BOUND;
    let answer = loop {
        let answer = gateway.post_as(&client, &relay, Some("bob")).await;
        if answer["error"]["code"] == -32002 || tokio::time::Instant::now() >= deadline {
            break answer;
        }
        tokio::time::sleep(helper::POLL_GAP).await;
    };
    gateway.terminate().await;
    assert_eq!(
        answer["error"]["code"], -32002,
        "the recovered result was not recorded for its owner: {answer}"
    );
}

/// Turn on authentication for `alice` and `bob` and relay detection in
/// `block`, every result of the fixture backend sensitive.
fn with_relay_block(path: &std::path::Path) {
    let text = std::fs::read_to_string(path).expect("the fixture config reads");
    let mut yaml: serde_yaml::Value = serde_yaml::from_str(&text).expect("the config parses");
    let key = |secret: &str| {
        json!({ "key_sha256": mcp_gateway::config::api_key_digest_spec(secret.as_bytes()),
                "name": secret, "backends": [BACKEND] })
    };
    let to_yaml = |value: Value| serde_yaml::to_value(value).expect("JSON maps to YAML");
    yaml["auth"]["enabled"] = serde_yaml::Value::Bool(true);
    yaml["auth"]["api_keys"] = to_yaml(json!([key("alice"), key("bob")]));
    // Auth on requires a writable audit log (UPGRADING-4.0 section 43).
    let audit = path.with_file_name("audit.jsonl");
    yaml["security"]["transparency_log"] = to_yaml(json!({
        "enabled": true, "path": audit.to_string_lossy()
    }));
    yaml["security"]["firewall"]["collusion"] = to_yaml(json!({
        "action": "block", "window_secs": 600, "sources": [format!("{BACKEND}:*")]
    }));
    let yaml = serde_yaml::to_string(&yaml).expect("the config serializes");
    mcp_gateway::gateway::test_helpers::write_owner_only(path, yaml)
        .expect("the config is rewritten inside the test's own temp root");
}
