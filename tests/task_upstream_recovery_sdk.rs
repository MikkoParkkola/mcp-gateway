// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The REAL pinned-SDK upstream-recovery vertical.
//!
//! Everything below is actual: the peer is fastmcp 4.0.3 + fastmcp-tasks 4.0.3 +
//! pydocket 0.25.0 under the pinned interpreter, its Docket backend is a
//! dedicated Redis service, the gateway is the production binary with
//! authentication ON, and the owners are verified OIDC subjects whose bearers
//! are checked by `key_server::OidcVerifier` against a temporary HTTPS issuer.
//! Nothing is injected, disabled or waived.
//!
//! Preconditions are requirements, not switches: a missing pin fails loudly
//! (`pins`), because a test that skipped itself would pass while proving
//! nothing.

#![cfg(unix)]

#[path = "task_upstream_recovery_sdk/authority.rs"]
mod authority;
#[path = "task_upstream_recovery_sdk/helper.rs"]
mod helper;
#[path = "task_upstream_recovery_sdk/issuer.rs"]
mod issuer;
#[path = "task_upstream_recovery_sdk/peer.rs"]
mod peer;
#[path = "task_upstream_recovery_sdk/pins.rs"]
mod pins;

use serde_json::{Value, json};

use authority::{Grant, Owner};
use helper::{Fixture, Gateway, durable_record, record_status, status_of, task_id_of};
use peer::{SDK_MARKER, SDK_TEXT, SDK_TOOL, SdkPeer};
use pins::{PEER_BOUND, POLL_GAP, REQUEST_BOUND};

/// One idempotency key for the whole journey: every retry below is a retry of
/// the SAME logical request.
const KEY: &str = "sdk-vertical";

fn sdk_task_invoke(id: i64) -> Value {
    let mut body = helper::modern(
        id,
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": {
                "server": helper::BACKEND,
                "tool": SDK_TOOL,
                "arguments": { "text": SDK_TEXT },
            },
            "task": {}
        }),
    );
    body["params"]["_meta"][helper::IDEMPOTENCY_KEY_META] = json!(KEY);
    body
}

/// The durable v3 descriptor, asserted as a precondition of everything the
/// recovery table claims. Returns the peer's own handle.
///
/// `mark_upstream` is a write of its own, distinct from the submission the peer
/// has already counted, so its arrival is waited for under a deadline rather
/// than assumed to have landed in the same instant.
async fn durable_handle(root: &std::path::Path, task_id: &str) -> String {
    let path = helper::store_dir(root).join(format!("{task_id}.json"));
    let deadline = tokio::time::Instant::now() + PEER_BOUND;
    loop {
        let landed = std::fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(&body).ok())
            .is_some_and(|record| record.pointer("/upstream/handle").is_some());
        if landed {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the durable handle never reached {} within {PEER_BOUND:?}",
            path.display()
        );
        tokio::time::sleep(POLL_GAP).await;
    }

    let record = durable_record(root, task_id);
    assert_eq!(
        record["version"],
        json!(3),
        "a recoverable row is a v3 row: {record}"
    );
    assert_eq!(
        record["dispatched"],
        json!(true),
        "the operation was dispatched: {record}"
    );
    assert_eq!(
        record_status(&record),
        Some("working"),
        "and it is still working: {record}"
    );
    let upstream = record
        .get("upstream")
        .unwrap_or_else(|| panic!("a recoverable row carries its handle: {record}"));
    assert_eq!(upstream["backend"], json!(helper::BACKEND), "{record}");
    assert_eq!(upstream["tool"], json!(SDK_TOOL), "{record}");
    assert_eq!(
        upstream["arguments"],
        json!({ "text": SDK_TEXT }),
        "the descriptor keeps the COMPLETE original arguments: {record}"
    );
    let handle = upstream["handle"]
        .as_str()
        .unwrap_or_else(|| panic!("the handle is a string: {record}"))
        .to_string();
    assert!(!handle.is_empty(), "the handle is non-empty: {record}");
    handle
}

/// The vertical: one real SDK job held open by an explicit gate, a gateway that
/// is killed while it runs, owner separation and current-policy refusal on real
/// credentials, and the original owner reading back the exact eventual result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result() {
    pins::require_supported_trust_override();

    let owned_root = tempfile::Builder::new()
        .prefix("upstream-sdk-vertical")
        .tempdir()
        .expect("an owned temporary root");
    let root = owned_root.path();
    // Every send and body read is bounded at the client, so no step of this
    // journey can hang without a deadline.
    let client = reqwest::Client::builder()
        .timeout(REQUEST_BOUND)
        .build()
        .expect("a bounded HTTP client");

    // ── The peer, the issuer and two real owners ──────────────────────────
    let mut sdk = SdkPeer::start(root, &client);
    sdk.wait_until_ready().await;
    let issuer = issuer::Issuer::start(root).await;
    let alice = Owner::new(&issuer, "alice-subject", "alice@vertical.test");
    let bob = Owner::new(&issuer, "bob-subject", "bob@vertical.test");
    let ca = issuer.ca_file.display().to_string();
    let trust = [("SSL_CERT_FILE", ca.as_str())];

    let port = helper::free_port();
    let base = helper::write_config(
        root,
        &Fixture {
            name: "gateway-base.yaml",
            port,
            backend_url: &sdk.url(),
            adapters: vec![helper::BACKEND.to_string()],
        },
    );
    let granted = authority::write_authenticated_config(
        root,
        &base,
        "gateway-granted.yaml",
        &issuer,
        &[
            Grant {
                owner: &alice,
                backends: vec![helper::BACKEND.to_string()],
            },
            Grant {
                owner: &bob,
                backends: vec![helper::BACKEND.to_string()],
            },
        ],
    );
    // The same subjects, authenticated identically; Alice's CURRENT grant no
    // longer covers the backend the original call named.
    let revoked = authority::write_authenticated_config(
        root,
        &base,
        "gateway-revoked.yaml",
        &issuer,
        &[
            Grant {
                owner: &alice,
                backends: vec!["some-other-backend".to_string()],
            },
            Grant {
                owner: &bob,
                backends: vec![helper::BACKEND.to_string()],
            },
        ],
    );

    // ── 1. Submit one real SDK job ────────────────────────────────────────
    let mut first = Gateway::start_with_env(root, &granted, port, "first.log", &trust);
    first.wait_until_ready(&client).await;

    let anonymous = first
        .post_as(&client, &helper::tasks_get(1, "task-does-not-exist"), None)
        .await;
    assert_eq!(
        anonymous["_httpStatus"],
        json!(401),
        "authentication is ON: an uncredentialed read is refused, so every \
         owner below is a verified subject rather than a shared anonymous \
         identity: {anonymous}\n{}",
        first.logs()
    );

    let created = first
        .post_as(&client, &sdk_task_invoke(2), Some(alice.token.as_str()))
        .await;
    assert_eq!(
        created["_httpStatus"],
        json!(200),
        "Alice's real OIDC bearer authenticates through the key server: \
         {created}\n{}",
        first.logs()
    );
    let task_id = task_id_of(&created);

    // The SDK tool body has ENTERED the gate and is holding there. This is the
    // fixture's own state; no interval is being trusted to mean "still running".
    sdk.wait_until_entered().await;
    let submitted = sdk.counters().await;
    assert_eq!(
        submitted["submissions"],
        json!(1),
        "the SDK saw exactly one tools/call: {submitted}"
    );
    assert_eq!(
        submitted["optin"],
        json!(1),
        "and it carried the tasks-extension opt-in, without which the SDK runs \
         the call synchronously and refuses tasks/* with -32021: {submitted}"
    );

    // A retry of the SAME key is not a second operation.
    let retried = first
        .post_as(&client, &sdk_task_invoke(3), Some(alice.token.as_str()))
        .await;
    assert_eq!(
        task_id_of(&retried),
        task_id,
        "the retry returns the original local handle"
    );
    assert_eq!(
        sdk.counters().await["submissions"],
        json!(1),
        "a same-key retry must not submit a second upstream job: {retried}"
    );

    // ── 2. The durable descriptor, then the crash ─────────────────────────
    let handle = durable_handle(root, &task_id).await;
    first.kill().await;
    sdk.assert_still_held("across the gateway kill").await;

    // ── 3. Restart: managed working, zero startup queries ─────────────────
    let before_restart = sdk.queries().await;
    let mut second = Gateway::start_with_env(root, &granted, port, "second.log", &trust);
    second.wait_until_ready(&client).await;
    assert_eq!(
        sdk.queries().await,
        before_restart,
        "startup must not query upstream; the row is retained as managed \
         working\n{}",
        second.logs()
    );

    // ── 4. A valid owner read queries THAT handle, while the job still runs ─
    let alice_read = second
        .post_as(
            &client,
            &helper::tasks_get(4, &task_id),
            Some(alice.token.as_str()),
        )
        .await;
    assert_eq!(
        status_of(&alice_read),
        Some("working"),
        "the job is still held, so the record stays working: {alice_read}\n{}",
        second.logs()
    );
    let after_alice = sdk.counters().await;
    assert!(
        after_alice["queries"].as_u64().unwrap_or(0) > before_restart,
        "an authorized owner read queries the upstream: {after_alice}"
    );
    assert!(
        after_alice["handles"]
            .as_array()
            .is_some_and(|asked| asked.iter().any(|id| id == &json!(handle))),
        "and it asks for the DURABLE handle {handle}: {after_alice}"
    );
    sdk.assert_still_held("while its owner reads it").await;

    // ── 5. A different verified owner asking for Alice's EXACT id ─────────
    let bob_sees = second
        .post_as(
            &client,
            &helper::modern(5, "tools/list", json!({})),
            Some(bob.token.as_str()),
        )
        .await;
    assert!(
        bob_sees.get("result").is_some(),
        "Bob's own credential is accepted, so the refusal below is ownership \
         and not authentication: {bob_sees}\n{}",
        second.logs()
    );
    let before_foreign = sdk.queries().await;
    let foreign = second
        .post_as(
            &client,
            &helper::tasks_get(6, &task_id),
            Some(bob.token.as_str()),
        )
        .await;
    assert_eq!(
        foreign["_httpStatus"],
        json!(200),
        "Bob is authenticated; his read is refused by ownership: {foreign}"
    );
    assert_eq!(foreign.pointer("/error/code"), Some(&json!(-32602)));
    assert!(
        foreign.pointer("/error/data").is_none(),
        "NotFound carries no data: {foreign}"
    );
    assert!(
        foreign.get("error").is_some() && foreign.get("result").is_none(),
        "Alice's real task is absent for Bob: {foreign}"
    );
    assert!(
        !serde_json::to_string(&foreign)
            .expect("the answer serializes")
            .contains(&handle),
        "and the absence leaks nothing about the upstream handle: {foreign}"
    );
    assert_eq!(
        sdk.queries().await,
        before_foreign,
        "a foreign read costs the upstream nothing"
    );

    // A same-key retry across the restart is still the same operation: the
    // in-memory reservation died with the first process, and startup's
    // `import_task` restores the binding whose identity folds in this key.
    let retried_after_restart = second
        .post_as(&client, &sdk_task_invoke(7), Some(alice.token.as_str()))
        .await;
    assert_eq!(
        task_id_of(&retried_after_restart),
        task_id,
        "the restored binding returns the original local handle"
    );
    assert_eq!(
        sdk.counters().await["submissions"],
        json!(1),
        "a same-key retry after a restart must not submit a second upstream \
         job: {retried_after_restart}"
    );

    // ── 6. The same subject, a changed CURRENT grant ──────────────────────
    second.terminate().await;
    let mut denied = Gateway::start_with_env(root, &revoked, port, "revoked.log", &trust);
    denied.wait_until_ready(&client).await;
    let before_denied = sdk.queries().await;
    let row_before_denied = durable_record(root, &task_id);
    let refused = denied
        .post_as(
            &client,
            &helper::tasks_get(8, &task_id),
            Some(alice.token.as_str()),
        )
        .await;
    // Checked BEFORE the query count: an authentication failure would also
    // produce zero queries, and reading that as a policy refusal is exactly the
    // misleading oracle this test must not have.
    assert_eq!(
        refused["_httpStatus"],
        json!(200),
        "Alice is still authenticated under the narrowed grant — what changed \
         is what she may invoke, not whether she is known: {refused}\n{}",
        denied.logs()
    );
    assert_eq!(
        sdk.queries().await,
        before_denied,
        "a caller whose CURRENT grant no longer covers the original backend \
         issues ZERO upstream queries: {refused}\n{}",
        denied.logs()
    );
    assert_eq!(
        status_of(&refused),
        Some("working"),
        "the owner may still see working metadata; what is refused is the \
         recovery query: {refused}"
    );
    let refused_text = serde_json::to_string(&refused).expect("the answer serializes");
    assert!(
        !refused_text.contains(SDK_MARKER)
            && refused.pointer("/result/result").is_none()
            && refused.pointer("/result/error").is_none(),
        "and no result or error payload is delivered: {refused}"
    );
    assert_eq!(
        durable_record(root, &task_id),
        row_before_denied,
        "no durable field changes while the grant is withdrawn"
    );
    sdk.assert_still_held("while the owner's grant is withdrawn")
        .await;

    // ── 7. The grant restored, the gate released, the exact result ────────
    denied.terminate().await;
    let mut last = Gateway::start_with_env(root, &granted, port, "final.log", &trust);
    last.wait_until_ready(&client).await;
    sdk.release().await;

    let deadline = tokio::time::Instant::now() + PEER_BOUND;
    let mut id = 100;
    let answer = loop {
        let body = last
            .post_as(
                &client,
                &helper::tasks_get(id, &task_id),
                Some(alice.token.as_str()),
            )
            .await;
        id += 1;
        if status_of(&body) == Some("completed") {
            break body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the owner's authenticated read never committed the SDK's result \
             within {PEER_BOUND:?}: {body}\n{}\n{}",
            last.logs(),
            sdk.logs()
        );
        tokio::time::sleep(POLL_GAP).await;
    };
    assert!(
        serde_json::to_string(&answer)
            .expect("the answer serializes")
            .contains(SDK_MARKER),
        "and it is the EXACT string only the SDK tool body produces: {answer}"
    );

    let final_counters = sdk.counters().await;
    assert_eq!(
        final_counters["submissions"],
        json!(1),
        "across two restarts, two same-key retries and every read, the \
         operation was submitted exactly once: {final_counters}"
    );
    assert_eq!(
        record_status(&durable_record(root, &task_id)),
        Some("completed"),
        "and the recovered result settled through the ordinary durable path"
    );
    last.terminate().await;
}
