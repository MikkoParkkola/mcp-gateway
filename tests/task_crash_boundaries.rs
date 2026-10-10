// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.3: SIGKILL the real gateway binary at the create and
//! settlement boundaries, restart it over the same store, and check that
//! retained handles and outcomes stay readable by their owner and by no one
//! else.
//!
//! Scope of the create-boundary rows: the gateway sends the ack right after the
//! durable create. One row kills the process once the record is on disk and
//! never uses the ack, which proves a client that lost its ack recovers the
//! same handle. The paused row pins the window itself: a debug build holds the
//! create at `Published`, after the commit and before the ack
//! (`MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED`, compiled out of release builds), and
//! the kill lands there (#2298).
//!
//! The two principals are delegated OIDC bearers from a temporary HTTPS
//! issuer, so each task owner is a verified identity. Static API keys own
//! tasks too (by credential, MIK-7967); this file exercises the OIDC owner.
//!
//! Unix only: `Gateway::kill` is a unix `SIGKILL`. The child trusts the
//! temporary issuer's CA through `SSL_CERT_FILE` (Linux) and the debug-only
//! `MCP_GATEWAY_TEST_TRUST_CA` (every platform; MIK-8188).
#![cfg(unix)]

#[path = "task_upstream_recovery/helper.rs"]
#[allow(
    dead_code,
    reason = "shared fixture; this target drives only part of it"
)]
mod helper;
#[path = "task_upstream_recovery_sdk/issuer.rs"]
mod issuer;
#[path = "task_upstream_recovery_sdk/pins.rs"]
#[allow(dead_code, reason = "the issuer reads only its bounds")]
mod pins;

use std::path::{Path, PathBuf};

use mcp_gateway::config::{
    Config, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig, PolicyScopesConfig,
};
use serde_json::{Value, json};

use helper::{
    BACKEND, Fixture, Gateway, MARKER, OBSERVE_BOUND, POLL_GAP, PeerGuard, Upstream,
    durable_record, modern, record_status, serve_peer, status_of, store_dir, task_id_of,
    task_invoke, tasks_get, write_config,
};

const EMAIL_A: &str = "principal-a@crash.test";
const EMAIL_B: &str = "principal-b@crash.test";
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

/// Two principals proven by delegated OIDC bearers, so each task is owned by a
/// verified identity through the key-server path. API-key owners are covered
/// by `e2e_task_api_key_owner`.
struct Principals {
    issuer: issuer::Issuer,
    ca: String,
    a: String,
    b: String,
}

impl Principals {
    async fn start(root: &Path) -> Self {
        let issuer = issuer::Issuer::start(root).await;
        Self {
            ca: issuer.ca_file.display().to_string(),
            a: issuer.mint("principal-a-subject", EMAIL_A),
            b: issuer.mint("principal-b-subject", EMAIL_B),
            issuer,
        }
    }

    /// The gateway child, trusting only this run's issuer CA.
    fn gateway(&self, root: &Path, config: &Path, log_name: &str) -> Gateway {
        self.gateway_with(root, config, log_name, &[])
    }

    /// [`Self::gateway`] with extra environment for the child.
    fn gateway_with(
        &self,
        root: &Path,
        config: &Path,
        log_name: &str,
        extra: &[(&str, &str)],
    ) -> Gateway {
        // SSL_CERT_FILE for Linux's verifier; the debug-only test root for
        // every platform (macOS reads its keychain; MIK-8188).
        let mut env = vec![
            ("SSL_CERT_FILE", self.ca.as_str()),
            ("MCP_GATEWAY_TEST_TRUST_CA", self.ca.as_str()),
        ];
        env.extend_from_slice(extra);
        Gateway::start_with_env(root, config, log_name, &env)
    }
}

/// The shared fixture config with authentication ON and two principals. With
/// it off every caller is one principal and no owner check can fail.
fn config_with_two_principals(root: &Path, peer: &PeerGuard, principals: &Principals) -> PathBuf {
    let path = write_config(
        root,
        &Fixture {
            name: "gateway.yaml",
            backend_url: &peer.url,
            adapters: vec![BACKEND.into()],
            forbid_marker: false,
        },
    );
    let yaml = std::fs::read_to_string(&path).expect("the fixture config reads back");
    let mut config: Config =
        serde_yaml::from_str(&yaml).expect("the gateway's own config type reloads its own YAML");
    config.auth.enabled = true;
    // `/health` only, so `/mcp` demands a credential.
    config.auth.public_paths = vec!["/health".to_string()];
    // Auth on requires an audit log (UPGRADING-4.0 item 43).
    config.security.transparency_log.enabled = Some(true);
    config.security.transparency_log.path = root
        .join("audit")
        .join("log.jsonl")
        .to_string_lossy()
        .into_owned();
    config.key_server.enabled = true;
    config.key_server.delegated_bearer = true;
    // The tokens are minted once and span every restart of a row.
    config.key_server.max_oidc_token_age_secs = 3_600;
    config.key_server.oidc = vec![KeyServerProviderConfig {
        issuer: principals.issuer.url.clone(),
        jwks_uri: None,
        discovery_url: None,
        auto_discover: true,
        audiences: vec![issuer::AUDIENCE.to_string()],
        allowed_domains: Vec::new(),
    }];
    config.key_server.policies = [EMAIL_A, EMAIL_B]
        .into_iter()
        .map(|email| KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                email: Some(email.to_string()),
                issuer: principals.issuer.url.clone(),
                ..PolicyMatchConfig::default()
            },
            // Both hold the same grant, so a refusal can only be ownership.
            scopes: PolicyScopesConfig {
                backends: vec![BACKEND.to_string()],
                tools: vec!["*".to_string()],
                rate_limit: 0,
            },
        })
        .collect();
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&config).expect("the patched config serializes"),
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
    client: &reqwest::Client,
    principals: &Principals,
) -> String {
    let mut gateway = principals.gateway(root, config, "first.log");
    gateway.wait_until_ready(client).await;
    let body = task_invoke(1, IDEMPOTENCY_KEY);
    let task_id = {
        let create = gateway.post_as(client, &body, Some(principals.a.as_str()));
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
    principals: &Principals,
) {
    let before = peer.peer.queries();
    let real = gateway
        .post_as(
            client,
            &modern(90, method, json!({ "taskId": task_id })),
            Some(principals.b.as_str()),
        )
        .await;
    let fabricated = gateway
        .post_as(
            client,
            &modern(90, method, json!({ "taskId": NEVER_MINTED })),
            Some(principals.b.as_str()),
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
async fn a_create_with_a_discarded_ack_is_recovered_by_its_owner_only() {
    let root = temp_root("crash-create-ack");
    let peer = serve_peer(Upstream::Working).await;
    let principals = Principals::start(root.path()).await;
    let config = config_with_two_principals(root.path(), &peer, &principals);
    let client = client();
    let task_id =
        create_then_kill_discarding_the_ack(root.path(), &config, &client, &principals).await;
    recovered_by_its_owner_only(root.path(), &config, &client, &peer, &principals, &task_id).await;
}

/// Create boundary, pinned (#2298): the child is held at `Published`, after
/// the durable create and before the ack, and killed there. So the kill lands
/// between commit and ack by construction, and the recovery must still hold.
///
/// Debug only, as the pause hook is (`execution.rs` gates `pause_hook` on
/// `debug_assertions`): this test and the binary it spawns share one profile,
/// so a release-profile run compiles the row out instead of failing on a hook
/// that is not there (MIK-7655).
#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_killed_between_commit_and_ack_is_recovered_by_its_owner_only() {
    let root = temp_root("crash-create-published");
    let peer = serve_peer(Upstream::Working).await;
    let principals = Principals::start(root.path()).await;
    let config = config_with_two_principals(root.path(), &peer, &principals);
    let client = client();
    let marker = root.path().join("paused-at-published");
    let marker_env = marker.display().to_string();
    let mut gateway = principals.gateway_with(
        root.path(),
        &config,
        "paused.log",
        &[("MCP_GATEWAY_TEST_PAUSE_AT_PUBLISHED", marker_env.as_str())],
    );
    gateway.wait_until_ready(&client).await;
    let body = task_invoke(1, IDEMPOTENCY_KEY);
    let create = gateway.post_as(&client, &body, Some(principals.a.as_str()));
    let paused = async {
        loop {
            if let Ok(id) = std::fs::read_to_string(&marker)
                && !id.is_empty()
            {
                return id;
            }
            tokio::time::sleep(POLL_GAP).await;
        }
    };
    let task_id = tokio::select! {
        id = tokio::time::timeout(OBSERVE_BOUND, paused) => {
            id.expect("the child pauses at Published within the bound")
        }
        answer = create => panic!(
            "the create was answered while paused at Published: {answer}\n{}",
            gateway.logs()
        ),
    };
    gateway.kill().await;
    recovered_by_its_owner_only(root.path(), &config, &client, &peer, &principals, &task_id).await;
}

/// After a create was killed before its ack: a restart over the same store,
/// then principal B is refused as for a never-minted id, principal A reads the
/// retained handle and its byte-identical retry gets the same handle back, and
/// nothing is submitted twice.
async fn recovered_by_its_owner_only(
    root: &Path,
    config: &Path,
    client: &reqwest::Client,
    peer: &PeerGuard,
    principals: &Principals,
    task_id: &str,
) {
    let on_disk = durable_record(root, task_id);

    let mut restarted = principals.gateway(root, config, "second.log");
    restarted.wait_until_ready(client).await;

    refused_like_a_never_minted_id(&restarted, client, peer, "tasks/get", task_id, principals)
        .await;
    refused_like_a_never_minted_id(
        &restarted,
        client,
        peer,
        "tasks/cancel",
        task_id,
        principals,
    )
    .await;

    let read = restarted
        .post_as(client, &tasks_get(10, task_id), Some(principals.a.as_str()))
        .await;
    assert_eq!(
        read.pointer("/result/taskId").and_then(Value::as_str),
        Some(task_id),
        "the owner reads the retained handle after the crash: {read}\nrecord: {on_disk}"
    );
    assert!(
        matches!(status_of(&read), Some("working" | "completed")),
        "a recovered row is live or settled, never lost: {read}\nrecord: {on_disk}"
    );

    let retried = restarted
        .post_as(
            client,
            &task_invoke(1, IDEMPOTENCY_KEY),
            Some(principals.a.as_str()),
        )
        .await;
    assert_eq!(
        retried.pointer("/result/taskId").and_then(Value::as_str),
        Some(task_id),
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
    let principals = Principals::start(root.path()).await;
    let config = config_with_two_principals(root.path(), &peer, &principals);
    let client = client();
    let task_id =
        create_then_kill_discarding_the_ack(root.path(), &config, &client, &principals).await;

    let empty_config = config_with_two_principals(empty.path(), &peer, &principals);
    let mut restarted = principals.gateway(empty.path(), &empty_config, "second.log");
    restarted.wait_until_ready(&client).await;

    let read = restarted
        .post_as(
            &client,
            &tasks_get(10, &task_id),
            Some(principals.a.as_str()),
        )
        .await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32602)),
        "an empty store holds no such task, even for its creator: {read}"
    );
    let retried = restarted
        .post_as(
            &client,
            &task_invoke(1, IDEMPOTENCY_KEY),
            Some(principals.a.as_str()),
        )
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
    client: &reqwest::Client,
    peer: &PeerGuard,
    principals: &Principals,
) -> String {
    let mut gateway = principals.gateway(root, config, "first.log");
    gateway.wait_until_ready(client).await;
    let created = gateway
        .post_as(
            client,
            &task_invoke(1, IDEMPOTENCY_KEY),
            Some(principals.a.as_str()),
        )
        .await;
    let task_id = task_id_of(&created);
    peer.peer.wait_for_queries(1).await;
    gateway.kill().await;

    let mut restarted = principals.gateway(root, config, "second.log");
    restarted.wait_until_ready(client).await;
    refused_like_a_never_minted_id(&restarted, client, peer, "tasks/get", &task_id, principals)
        .await;
    let live = restarted
        .post_as(
            client,
            &tasks_get(20, &task_id),
            Some(principals.a.as_str()),
        )
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
    client: &reqwest::Client,
    peer: &PeerGuard,
    task_id: &str,
    principals: &Principals,
) -> Value {
    let mut gateway = principals.gateway(root, config, "third.log");
    gateway.wait_until_ready(client).await;
    peer.peer.set(Upstream::Completed);
    let settled = gateway
        .post_as(client, &tasks_get(30, task_id), Some(principals.a.as_str()))
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
    let principals = Principals::start(root.path()).await;
    let config = config_with_two_principals(root.path(), &peer, &principals);
    let client = client();

    let task_id = kill_before_settlement(root.path(), &config, &client, &peer, &principals).await;
    let settled =
        kill_after_settlement(root.path(), &config, &client, &peer, &task_id, &principals).await;
    assert!(
        settled.to_string().contains(MARKER),
        "the settled payload is the peer's own: {settled}"
    );

    // Counted from before the restart, and the peer can no longer answer: a
    // gateway that re-fetched the outcome at startup or on the read would be
    // seen, and could not rebuild the payload from upstream.
    let queries = peer.peer.queries();
    peer.peer.set(Upstream::Unavailable);
    let mut restarted = principals.gateway(root.path(), &config, "fourth.log");
    restarted.wait_until_ready(&client).await;
    let read = restarted
        .post_as(
            &client,
            &tasks_get(40, &task_id),
            Some(principals.a.as_str()),
        )
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
    refused_like_a_never_minted_id(
        &restarted,
        &client,
        &peer,
        "tasks/get",
        &task_id,
        &principals,
    )
    .await;
    refused_like_a_never_minted_id(
        &restarted,
        &client,
        &peer,
        "tasks/cancel",
        &task_id,
        &principals,
    )
    .await;
    restarted.terminate().await;

    assert_eq!(
        peer.peer.submissions(),
        1,
        "three restarts submitted the operation exactly once"
    );
}
