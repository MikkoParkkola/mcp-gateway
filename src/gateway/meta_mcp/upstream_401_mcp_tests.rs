// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11 on the MCP route (T7-meta, T12): the lease the dispatch was minted
//! under reaches the post-dispatch Err arm, and only a vault-minted credential
//! can trigger a forced refresh.
//!
//! The backend answers through the fixture's capturing transport with the
//! typed `Error::Http` the HTTP transport produces for a non-2xx status
//! (A11-b), so these cells exercise the meta route's Err arm without a socket.
//! The HTTP transport's own typing is pinned by T8.

use crate::personal_accounts::refusal::marked;

use super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Answer, Bind, Descriptors, ProviderStep, ROTATED_TOKEN, WORK, account_key,
    custody_with_steps, execute, execute_bridged, external_cfg, gateway, grant, identity, slots,
};

const FRESH: u64 = u64::MAX;

/// T7-meta: a 401 on a revoked grant, dispatched over the MCP route, forces one
/// refresh and comes back as the reconnect refusal. With no offers installed,
/// `with_connect_offer` returns it unmarked (`offer.rs:129-139`), so an `Err`
/// that is NOT marked proves the refusal went through that path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_route_401_uses_propagated_lease() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::InvalidGrant],
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    dispatches.answer_with(&[401]);

    let error = Box::pin(execute(&meta, "mail", Some(&identity("alice"))))
        .await
        .expect_err("a 401 on a revoked grant must refuse, not return a tool result");
    assert!(
        marked(&error).is_none(),
        "the refusal must pass through with_connect_offer: {error}"
    );
    assert_eq!(custody.refreshes(), 1, "exactly one forced refresh");
    assert_eq!(dispatches.count(), 1, "the 401 is not retried");

    Box::pin(execute(&meta, "mail", Some(&identity("alice"))))
        .await
        .expect_err("the fenced account refuses before dispatch");
    assert_eq!(dispatches.count(), 1, "a fenced account never reaches the backend");
}

/// T12 (positive control for the carrier): a credential minted by a
/// non-vault strategy carries no `ManagedLease`, so a 401 forces nothing and
/// keeps today's backend-error tool result. It is not retried either (A11-g).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_vault_401_forces_no_refresh() {
    let custody = custody_with_steps(&[], ROTATED_TOKEN, &[]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("partner", Bind::Propagation(external_cfg()))],
        &Descriptors::same(&[]),
        &installed,
        &[],
    );
    dispatches.answer_with(&[401]);

    let result = Box::pin(execute(&meta, "partner", Some(&identity("alice"))))
        .await
        .expect("a non-managed 401 stays a tool result");
    assert_eq!(
        result.get("isError").and_then(serde_json::Value::as_bool),
        Some(true),
        "today's backend error: {result}"
    );
    assert_eq!(custody.refreshes(), 0);
    assert_eq!(dispatches.count(), 1, "a 401 is a deterministic refusal, never retried");
}

/// T7-meta-b (grok): on the meta Err arm, a rotation becomes a tool result
/// telling the caller to retry, with the code the single mapping chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_route_401_with_live_grant_says_retry() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::Rotate(ROTATED_TOKEN)],
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    dispatches.answer_with(&[401]);

    let result = Box::pin(execute(&meta, "mail", Some(&identity("alice"))))
        .await
        .expect("a rotation is reported as a tool result");
    assert_eq!(result.get("isError").and_then(serde_json::Value::as_bool), Some(true), "{result}");
    assert_eq!(result["recovery"]["error_code"], "UPSTREAM_AUTH_REJECTED", "{result}");
    assert_eq!(result["recovery"]["retry"], true, "{result}");
    assert_eq!(custody.refreshes(), 1);
    assert_eq!(dispatches.count(), 1, "the call itself is not retried");
}

/// T16 (grok, positive control): the 401/403 exclusion must not stop 429
/// backoff, which rides the same `Error::Http` (`error.rs:332`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limited_429_is_still_retried() {
    let custody = custody_with_steps(&[], ROTATED_TOKEN, &[]);
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("partner", Bind::Propagation(external_cfg()))],
        &Descriptors::same(&[]),
        &installed,
        &[],
    );
    dispatches.answer_with(&[429]);

    Box::pin(execute(&meta, "partner", Some(&identity("alice"))))
        .await
        .expect("the retry after a 429 succeeds");
    assert_eq!(dispatches.count(), 2, "a 429 is retried once, then succeeds");
}

/// T17: a 401 on an elicitation continuation. The first dispatch asks a
/// question, the bridge answers it for this legacy client, and the re-dispatch
/// is refused with 401: the continuation forces the one refresh too and
/// answers with the reconnect refusal, not the generic bridged-exchange -32003
/// (RECONNECT.1 names no route).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridged_continuation_401_forces_the_refresh() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::InvalidGrant],
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    dispatches.script(&[
        Answer::Result(serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "k1": {
                    "method": "elicitation/create",
                    "params": {"message": "Which folder?", "requestedSchema": {"type": "object"}}
                }
            },
            "requestState": "backend-state-a11"
        })),
        Answer::Status(401),
    ]);

    let error = Box::pin(execute_bridged(&meta, "mail", Some(&identity("alice"))))
        .await
        .expect_err("a revoked grant on the continuation must refuse");
    assert_eq!(
        error.to_rpc_code(),
        -32603,
        "the unmarked reconnect refusal (Error::Config), not the generic bridged -32003: {error}"
    );
    assert!(marked(&error).is_none(), "passed through with_connect_offer: {error}");
    assert_eq!(custody.refreshes(), 1, "exactly one forced refresh");
    assert_eq!(dispatches.count(), 2, "the first call and the one continuation");
}

/// T17b: a rotation on the continuation answers as the first dispatch would:
/// a tool result whose hint says a retry presents the new token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridged_continuation_401_with_live_grant_says_retry() {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        &[ProviderStep::Rotate(ROTATED_TOKEN)],
    );
    let installed = custody.installed();
    let (meta, dispatches) = gateway(
        &[("mail", Bind::Account(WORK))],
        &Descriptors::same(&[WORK]),
        &installed,
        &slots(&[("alice", WORK)]),
    );
    dispatches.script(&[
        Answer::Result(serde_json::json!({
            "resultType": "input_required",
            "inputRequests": {
                "k1": {
                    "method": "elicitation/create",
                    "params": {"message": "Which folder?", "requestedSchema": {"type": "object"}}
                }
            },
            "requestState": "backend-state-a11b"
        })),
        Answer::Status(401),
    ]);

    let result = Box::pin(execute_bridged(&meta, "mail", Some(&identity("alice"))))
        .await
        .expect("a rotation on the continuation is reported as a tool result");
    assert_eq!(result.get("isError").and_then(serde_json::Value::as_bool), Some(true), "{result}");
    assert_eq!(result["recovery"]["error_code"], "UPSTREAM_AUTH_REJECTED", "{result}");
    assert_eq!(result["recovery"]["retry"], true, "{result}");
    assert_eq!(custody.refreshes(), 1);
    assert_eq!(dispatches.count(), 2);
}
