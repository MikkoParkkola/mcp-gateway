// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9216.EFFECT.1: a completed-execution replay served at the HTTP route
//! stage records the declared effect of the backend tool on the slot its first
//! execution ran under, read now. A result that stored no slot, or whose slot
//! or backend is gone, records none, never a fallback slot's.

use std::sync::Arc;

use serde_json::{Value, json};

use super::effect_records::listing;
use super::{api_key_caller, context, ok_result, records};
use crate::backend::PoolKey;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::admission::SyncAdmission;
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The presented name every row calls; the backend tool is `read`.
const INVOKE: &str = "gateway_invoke";

/// How the first execution ran under its lease.
enum First {
    /// Through the real dispatch, which notes the slot it ran under.
    Dispatched,
    /// Marked dispatched with no slot noted: a result that stores none.
    Unnoted,
}

fn args() -> Value {
    json!({"server": "alpha", "tool": "read", "arguments": {}})
}

/// Relist `read` on alpha's shared slot with `hint`, as an accepted fill
/// would store it.
fn relist(meta: &MetaMcp, hint: Option<bool>) {
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    let mut tool = json!({"name": "read", "inputSchema": {"type": "object"}});
    if let Some(hint) = hint {
        tool["annotations"] = json!({"readOnlyHint": hint});
    }
    alpha.prefill_tools_for_test(vec![serde_json::from_value(tool).expect("tool")]);
    let read_only: &[&str] = if hint == Some(true) { &["read"] } else { &[] };
    alpha.set_read_only_declared_for_test(read_only);
}

/// Run the first execution of `args()` under an owned lease, settle it, run
/// `between`, then replay it through the route stage as
/// `dispatch_tools_call` does. The slot the repeat's admission read back, and
/// the replay record's decision.
async fn replayed(
    meta: &MetaMcp,
    dir: &tempfile::TempDir,
    key: &str,
    first: First,
    between: impl FnOnce(),
) -> (Option<PoolKey>, Value) {
    let who = api_key_caller();
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(key.to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let ctx = MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let owner = || AdmissionOwner::for_test(ctx.owner_principal());
    let admitted =
        meta.admit_meta_sync_for_test(owner(), &ctx, INVOKE, &args(), None, &RequestId::Number(1));
    let Ok(SyncAdmission::Owned(lease)) = admitted else {
        panic!("premise: the first call owns its admission");
    };
    match first {
        First::Dispatched => {
            let inner = MetaMcpCallerContext {
                execution: Some(&lease),
                ..context(&AllowAll, &who)
            };
            let _ = meta.invoke_tool(&args(), None, &inner).await;
        }
        First::Unnoted => lease.mark_dispatched(),
    }
    lease.complete_secured(&JsonRpcResponse::success(RequestId::Number(1), ok_result()));
    between();
    let again =
        meta.admit_meta_sync_for_test(owner(), &ctx, INVOKE, &args(), None, &RequestId::Number(2));
    let Ok(SyncAdmission::Replay(response, audit, target, dispatched, bindings, slot)) = again else {
        panic!("premise: the repeat is admitted as a replay");
    };
    let stored = slot.clone();
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            INVOKE,
            &args(),
            &ctx,
            target,
            (dispatched, bindings, slot),
            (response, audit),
        )
        .await
    else {
        panic!("premise: the replay is served, not deferred");
    };
    let answer = meta
        .audit_replay(INVOKE, &args(), None, &ctx, response, audit)
        .await;
    assert!(answer.error.is_none(), "premise: delivered: {answer:?}");
    let all = records(dir);
    let last = all.last().expect("the replay's record");
    (stored, last["decision"].clone())
}

fn assert_no_effect(decision: &Value) {
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert!(decision.get("declared_effect").is_none(), "{decision}");
    assert!(decision.get("declared_effect_source").is_none(), "{decision}");
}

/// The first execution ran on the shared slot, declared may-write; the
/// declaration then flips to read-only. The replay records the backend tool's
/// effect on the stored slot now (`read`, not the presented
/// `gateway_invoke`), and says it was replayed, not decided again.
#[tokio::test]
async fn an_http_route_stage_replay_records_the_stored_slot_effect() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, calls) = listing(Some(false), &dir);
    let (stored, decision) = replayed(&meta, &dir, "e1-flip", First::Dispatched, || {
        relist(&meta, Some(true));
    })
    .await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: the first execution reached the backend once"
    );
    assert_eq!(stored, Some(PoolKey::Shared), "premise: the dispatch noted its slot");
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(decision["declared_effect_source"], "tool_annotation", "{decision}");
}

/// The hint removed (the tool still listed) reads undeclared on the replay.
#[tokio::test]
async fn an_http_route_stage_replay_of_a_removed_hint_records_undeclared() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(&meta, &dir, "e1-hint", First::Dispatched, || {
        relist(&meta, None);
    })
    .await;
    assert_eq!(stored, Some(PoolKey::Shared), "premise: the dispatch noted its slot");
    assert_eq!(decision["declared_effect"], "undeclared", "{decision}");
    assert_eq!(decision["declared_effect_source"], "tool_annotation", "{decision}");
}

/// A result that stored no slot records no effect, though the shared slot is
/// warm and declares `read` read-only: no fallback to it.
#[tokio::test]
async fn a_result_stored_with_no_slot_records_none() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, _) = listing(Some(true), &dir);
    relist(&meta, Some(true));
    let (stored, decision) = replayed(&meta, &dir, "e1-none", First::Unnoted, || {}).await;
    assert_eq!(stored, None, "premise: nothing noted, nothing stored");
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    assert_eq!(
        alpha.declared_effect_for(None, "read"),
        Some(crate::security::decision_record::Effect::ReadOnly),
        "premise: the shared slot is a tempting fallback"
    );
    assert_no_effect(&decision);
}

/// The backend removed between settle and replay: no effect.
#[tokio::test]
async fn a_replay_of_a_removed_backend_records_none() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(&meta, &dir, "e1-gone", First::Dispatched, || {
        assert!(meta.backends.for_test().remove("alpha"), "premise: removed");
    })
    .await;
    assert_eq!(stored, Some(PoolKey::Shared), "premise: the dispatch noted its slot");
    assert_no_effect(&decision);
}

/// The tool no longer listed on the stored slot: no effect.
#[tokio::test]
async fn a_replay_of_a_tool_no_longer_listed_records_none() {
    let dir = tempfile::tempdir().unwrap();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(&meta, &dir, "e1-unlisted", First::Dispatched, || {
        let alpha = meta.backends.for_test().get("alpha").expect("alpha");
        alpha.prefill_tools_for_test(Vec::new());
        alpha.set_read_only_declared_for_test(&[]);
    })
    .await;
    assert_eq!(stored, Some(PoolKey::Shared), "premise: the dispatch noted its slot");
    assert_no_effect(&decision);
}
