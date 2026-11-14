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

/// Which route's owner admits the call.
#[derive(Clone, Copy)]
enum Route {
    /// The HTTP route stage: the caller's own principal owns the lease.
    Http,
    /// The stdio route: the local operator owns it.
    Stdio,
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

/// Run the first execution of `args` under an owned lease, settle it, run
/// `between`, then replay it through the route stage as
/// `dispatch_tools_call` does. The slot the repeat's admission read back, and
/// the replay record's decision.
async fn replayed(
    meta: &MetaMcp,
    dir: &tempfile::TempDir,
    (key, args): (&str, &Value),
    (route, first): (Route, First),
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
    let owner = || match route {
        Route::Http => AdmissionOwner::for_test(ctx.owner_principal()),
        Route::Stdio => AdmissionOwner::local_operator(),
    };
    let admitted =
        meta.admit_meta_sync_for_test(owner(), &ctx, INVOKE, args, None, &RequestId::Number(1));
    let Ok(SyncAdmission::Owned(lease)) = admitted else {
        panic!("premise: the first call owns its admission");
    };
    match first {
        First::Dispatched => {
            let inner = MetaMcpCallerContext {
                execution: Some(&lease),
                ..context(&AllowAll, &who)
            };
            let _ = meta.invoke_tool(args, None, &inner).await;
        }
        First::Unnoted => lease.mark_dispatched(),
    }
    lease.complete_secured(&JsonRpcResponse::success(RequestId::Number(1), ok_result()));
    between();
    let again =
        meta.admit_meta_sync_for_test(owner(), &ctx, INVOKE, args, None, &RequestId::Number(2));
    let Ok(SyncAdmission::Replay(response, audit, target, dispatched, bindings, slot)) = again
    else {
        panic!("premise: the repeat is admitted as a replay");
    };
    let stored = slot.clone();
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            INVOKE,
            args,
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
        .audit_replay(INVOKE, args, None, &ctx, response, audit)
        .await;
    assert!(answer.error.is_none(), "premise: delivered: {answer:?}");
    let all = records(dir);
    let last = all.last().expect("the replay's record");
    (stored, last["decision"].clone())
}

fn assert_no_effect(decision: &Value) {
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert!(decision.get("declared_effect").is_none(), "{decision}");
    assert!(
        decision.get("declared_effect_source").is_none(),
        "{decision}"
    );
}

/// The first execution ran on the shared slot, declared may-write; the
/// declaration then flips to read-only. The replay records the backend tool's
/// effect on the stored slot now (`read`, not the presented
/// `gateway_invoke`), and says it was replayed, not decided again.
#[tokio::test]
async fn an_http_route_stage_replay_records_the_stored_slot_effect() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, calls) = listing(Some(false), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-flip", &args()),
        (Route::Http, First::Dispatched),
        || {
            relist(&meta, Some(true));
        },
    )
    .await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "premise: the first execution reached the backend once"
    );
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// The hint removed (the tool still listed) reads undeclared on the replay.
#[tokio::test]
async fn an_http_route_stage_replay_of_a_removed_hint_records_undeclared() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-hint", &args()),
        (Route::Http, First::Dispatched),
        || {
            relist(&meta, None);
        },
    )
    .await;
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    assert_eq!(decision["declared_effect"], "undeclared", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// A result that stored no slot records no effect, though the shared slot is
/// warm and declares `read` read-only: no fallback to it.
#[tokio::test]
async fn a_result_stored_with_no_slot_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    relist(&meta, Some(true));
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-none", &args()),
        (Route::Http, First::Unnoted),
        || {},
    )
    .await;
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
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-gone", &args()),
        (Route::Http, First::Dispatched),
        || {
            assert!(meta.backends.for_test().remove("alpha"), "premise: removed");
        },
    )
    .await;
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    assert_no_effect(&decision);
}

/// The tool no longer listed on the stored slot: no effect.
#[tokio::test]
async fn a_replay_of_a_tool_no_longer_listed_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-unlisted", &args()),
        (Route::Http, First::Dispatched),
        || {
            let alpha = meta.backends.for_test().get("alpha").expect("alpha");
            alpha.prefill_tools_for_test(Vec::new());
            alpha.set_read_only_declared_for_test(&[]);
        },
    )
    .await;
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    assert_no_effect(&decision);
}

/// A capability `lookup` on provider `caps` whose definition says `read_only`.
fn capability(read_only: bool) -> crate::capability::CapabilityDefinition {
    crate::capability::parse_capability(&format!(
        "name: lookup\n\
         description: Look one thing up\n\
         metadata:\n\
         \x20 exposure: public\n\
         \x20 read_only: {read_only}\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://127.0.0.1:9\n\
         \x20     path: /lookup\n\
         \x20     method: GET\n"
    ))
    .expect("the capability parses")
}

/// `meta` (alpha's shared slot declaring `read` read-only, a tempting
/// fallback) with the provider `caps` serving [`capability`]`(read_only)`.
fn with_caps(
    dir: &tempfile::TempDir,
    read_only: bool,
) -> (MetaMcp, Arc<crate::capability::CapabilityBackend>) {
    let (meta, _) = listing(Some(true), dir);
    let executor = Arc::new(crate::capability::CapabilityExecutor::new());
    let caps = Arc::new(crate::capability::CapabilityBackend::new("caps", executor));
    caps.register_capability(capability(read_only))
        .expect("registers");
    meta.set_capabilities(Arc::clone(&caps));
    (meta, caps)
}

fn caps_args() -> Value {
    json!({"server": "caps", "tool": "lookup", "arguments": {}})
}

/// A capability replay through the route stage records its live
/// definition's `read_only` (edited from may-write to read-only between
/// settle and replay), from the definition, with no slot needed.
#[tokio::test]
async fn a_capability_replay_records_its_live_definitions_effect() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, caps) = with_caps(&dir, false);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("c-edit", &caps_args()),
        (Route::Http, First::Unnoted),
        || {
            caps.register_capability(capability(true))
                .expect("replaces");
        },
    )
    .await;
    assert_eq!(stored, None, "premise: a capability needs no stored slot");
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "capability_definition",
        "{decision}"
    );
}

/// A capability whose definition was removed records no effect. The route
/// stage admits no replay of a removed definition (its repeat is not
/// admitted as one), so this calls `audit_replay` with the facts a stored
/// capability replay carries, after the unload.
#[tokio::test]
async fn a_capability_replay_of_a_removed_definition_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, caps) = with_caps(&dir, true);
    assert!(caps.unload_capability("lookup"), "premise: unloaded");
    replay_caps(&meta).await;
    let all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_no_effect(&all[0]["decision"]);
}

/// Hides the provider `caps` from the caller.
struct HidesCaps;

impl crate::gateway::meta_mcp::hiding::CallerHiding for HidesCaps {
    fn hides(&self, server: &str) -> bool {
        server == "caps"
    }
}

/// Replay `caps`' `lookup` through `audit_replay` with the facts a
/// capability replay carries.
async fn replay_caps(meta: &MetaMcp) {
    let who = api_key_caller();
    let facts = crate::gateway::meta_mcp::admission::ReplayFacts {
        server: Some("caps".to_owned()),
        tool: Some("lookup".to_owned()),
        ..Default::default()
    };
    let response = JsonRpcResponse::success(RequestId::Number(7), ok_result());
    let _ = meta
        .audit_replay(
            INVOKE,
            &caps_args(),
            None,
            &context(&AllowAll, &who),
            response,
            facts,
        )
        .await;
}

/// The replay effect is computed under the replaying caller's view: a
/// caller the provider is hidden from records none, one it is not hidden
/// from records the definition's. Called on `audit_replay` directly, since
/// visibility refuses a hiding caller before any replay is admitted.
#[tokio::test]
async fn a_capability_replay_under_a_hiding_view_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _caps) = with_caps(&dir, true);
    crate::gateway::meta_mcp::hiding::with_caller(Arc::new(HidesCaps), replay_caps(&meta)).await;
    replay_caps(&meta).await;
    let all = records(&dir);
    assert_eq!(all.len(), 2, "{all:?}");
    assert_no_effect(&all[0]["decision"]);
    assert_eq!(
        all[1]["decision"]["declared_effect"], "read_only",
        "{all:?}"
    );
    assert_eq!(
        all[1]["decision"]["declared_effect_source"], "capability_definition",
        "{all:?}"
    );
}

/// The stdio route serves the same replay under the local operator's lease:
/// the stored slot's effect now, flipped from may-write to read-only.
#[tokio::test]
async fn a_stdio_replay_records_the_stored_slot_effect() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(false), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("s-flip", &args()),
        (Route::Stdio, First::Dispatched),
        || {
            relist(&meta, Some(true));
        },
    )
    .await;
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "read_only", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}

/// A stdio replay of a result that stored no slot records none, with the
/// shared slot warm and declaring `read` read-only.
#[tokio::test]
async fn a_stdio_replay_with_no_stored_slot_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    relist(&meta, Some(true));
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("s-none", &args()),
        (Route::Stdio, First::Unnoted),
        || {},
    )
    .await;
    assert_eq!(stored, None, "premise: nothing noted, nothing stored");
    assert_no_effect(&decision);
}

/// A result stored under a per-user slot, replayed after the backend stopped
/// propagating identity (so `alpha` has no per-user slots now, and resolving
/// that binding again would collapse it to the shared slot). The shared slot
/// declares `read` read-only. The replay looks up the stored slot itself,
/// which does not exist, and records no effect, never the shared slot's.
#[tokio::test]
async fn a_replay_after_propagation_is_turned_off_records_none() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    relist(&meta, Some(true));
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
    assert_eq!(
        alpha.declared_effect_for(Some("b-1"), "read"),
        Some(crate::security::decision_record::Effect::ReadOnly),
        "premise: re-resolving the binding reads the shared slot"
    );
    let who = api_key_caller();
    let facts = crate::gateway::meta_mcp::admission::ReplayFacts {
        server: Some("alpha".to_owned()),
        tool: Some("read".to_owned()),
        slot: Some(PoolKey::PerUser {
            binding: "b-1".to_owned(),
        }),
        ..Default::default()
    };
    let response = JsonRpcResponse::success(RequestId::Number(7), ok_result());
    let _ = meta
        .audit_replay(
            INVOKE,
            &args(),
            None,
            &context(&AllowAll, &who),
            response,
            facts,
        )
        .await;
    let all = records(&dir);
    assert_eq!(all.len(), 1, "{all:?}");
    assert_no_effect(&all[0]["decision"]);
}

/// The first execution ran while the slot declared `read` read-only; the
/// slot then declares it may-write. The replay records the slot's effect when
/// it is served (may-write), never the first run's: a stale read-only would
/// understate what the replayed call could have changed.
#[tokio::test]
async fn a_replay_after_read_only_turns_may_write_records_may_write() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let (meta, _) = listing(Some(true), &dir);
    let (stored, decision) = replayed(
        &meta,
        &dir,
        ("e1-widen", &args()),
        (Route::Http, First::Dispatched),
        || relist(&meta, Some(false)),
    )
    .await;
    assert_eq!(
        stored,
        Some(PoolKey::Shared),
        "premise: the dispatch noted its slot"
    );
    let all = records(&dir);
    assert_eq!(
        all.first()
            .map(|r| r["decision"]["declared_effect"].clone()),
        Some(json!("read_only")),
        "premise: the first run recorded read-only: {all:?}"
    );
    assert_eq!(decision["decided"], "replayed", "{decision}");
    assert_eq!(decision["declared_effect"], "may_write", "{decision}");
    assert_eq!(
        decision["declared_effect_source"], "tool_annotation",
        "{decision}"
    );
}
