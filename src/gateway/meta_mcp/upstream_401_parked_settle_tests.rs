// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A bridged round parked at its cold-slot list (a managed account's 401) after
//! an earlier round reached the backend keeps its key as may-have-run.
//!
//! The same script as `a_bridged_cold_list_401_refreshes_and_releases_the_key`,
//! with each call inside a delivery of its own. That row runs outside any
//! delivery, where no send is counted and the key is released; here round one's
//! `tools/call` is counted, so the refused round cannot release.

use super::super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Answer, Bind, Descriptors, ProviderStep, ROTATED_TOKEN, WORK, account_key,
    custody_with_steps, execute_bridged_keyed, gateway, grant, identity, slots,
};

const FRESH: u64 = u64::MAX;

/// R19(b), integration: round one was sent and asked, round two's list gets the
/// 401 and is parked. The earlier send is counted, so the key is committed (one
/// entry stays in the cache) instead of released (none).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parked_round_after_an_earlier_send_keeps_the_idempotency_key() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::InvalidGrant],
    );
    let installed = custody.installed();
    let (_log, mut meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    let keys = std::sync::Arc::new(crate::idempotency::IdempotencyCache::new());
    meta.enable_idempotency(
        std::sync::Arc::clone(&keys),
        std::time::Duration::from_secs(300),
    );
    let backend = meta
        .backends
        .for_test()
        .get("mail")
        .expect("the fixture registers mail");
    dispatches.on_next_call(move || backend.empty_tool_catalogues_for_test());
    dispatches.script_lists();
    dispatches.script(&[
        Answer::Result(serde_json::json!({
            "tools": [{"name": "read", "inputSchema": {"type": "object"}}]
        })),
        Answer::Result(serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "k1": {
                    "method": "elicitation/create",
                    "params": {"message": "Which folder?", "requestedSchema": {"type": "object"}}
                }
            },
            "requestState": "backend-state-parked"
        })),
        Answer::Status(401),
    ]);
    let alice = identity("alice");

    let first = crate::gateway::delivery_facts::scope(Box::pin(execute_bridged_keyed(
        &meta,
        "mail",
        Some(&alice),
        Some("k-parked"),
    )))
    .await
    .expect_err("a revoked grant on the continuation's list must refuse");

    assert_eq!(
        dispatches.calls().len(),
        1,
        "premise: round one was the only tools/call sent"
    );
    assert_eq!(
        custody.refreshes(),
        1,
        "premise: the round-two list got the 401 and forced its one refresh"
    );
    assert_eq!(
        first.to_rpc_code(),
        -32603,
        "premise: the round was parked as the reconnect refusal: {first}"
    );
    assert_eq!(
        keys.len(),
        1,
        "the parked round released a key whose earlier round reached the backend"
    );
}
