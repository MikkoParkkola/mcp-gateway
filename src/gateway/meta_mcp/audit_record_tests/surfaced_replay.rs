// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8520 (MIK-7645 AC3 prerequisite): a replayed surfaced call is recorded
//! under the server it was admitted for, never under the live surfaced map
//! read again. Each row moves the map only after the target is resolved, as a
//! reload landing between admission and the record would.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{api_key_caller, context, meta, ok_result, only_record, records};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::admission::{ReplayTarget, SyncAdmission};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The surfaced name every row calls.
const NAME: &str = "read";

/// `meta` with `NAME` surfaced from `server` and an idempotency cache.
fn surfaced(meta: MetaMcp, server: &str) -> MetaMcp {
    let mut meta = meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: server.to_string(),
        tool: NAME.to_string(),
    }]);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(300),
    );
    meta
}

fn keyed(key: &str) -> crate::protocol::mrtr::RetryFields {
    crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(key.to_string()),
        ..crate::protocol::mrtr::RetryFields::default()
    }
}

fn server_of(record: &Value) -> &str {
    record["server"].as_str().unwrap_or_default()
}

/// A per-caller backend `idp` (identity propagation), so a replay to it
/// defers, as in `admission_replay_tests`.
fn idp_backend() -> Arc<crate::backend::Backend> {
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    Arc::new(crate::backend::Backend::new(
        "idp",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "idp".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// R1: the repeat is admitted while `NAME` is surfaced from `alpha`, the map
/// then moves to `beta`, and the replay is served and recorded. The record
/// names `alpha`, the server the call was admitted for (M1).
#[tokio::test]
async fn r1_a_surfaced_replay_records_the_admitted_server() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = surfaced(meta(Ok(ok_result()), &dir), "alpha");
    let who = api_key_caller();
    let retry = keyed("r1");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let owner = || crate::gateway::meta_mcp::AdmissionOwner::for_test(ctx.owner_principal());
    let args = json!({});
    let first =
        meta.admit_meta_sync_for_test(owner(), &ctx, NAME, &args, None, &RequestId::Number(1));
    let Ok(SyncAdmission::Owned(lease)) = first else {
        panic!("premise: the first surfaced call owns its admission");
    };
    lease.mark_dispatched();
    lease.complete_secured(&JsonRpcResponse::success(RequestId::Number(1), ok_result()));
    let again =
        meta.admit_meta_sync_for_test(owner(), &ctx, NAME, &args, None, &RequestId::Number(2));
    let Ok(SyncAdmission::Replay(response, audit, target, dispatched, bindings)) = again else {
        panic!("premise: the repeat is admitted as a replay");
    };
    assert_eq!(
        target.as_ref().map(|t| t.server.as_str()),
        Some("alpha"),
        "premise: admission resolved alpha"
    );
    meta.resurface_for_test(NAME, "beta");
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            NAME,
            &args,
            &ctx,
            target,
            (dispatched, bindings),
            (response, audit),
        )
        .await
    else {
        panic!("premise: the replay is served, not deferred");
    };
    let answer = meta
        .audit_replay(NAME, &args, None, &ctx, response, audit)
        .await;
    assert!(answer.error.is_none(), "premise: delivered: {answer:?}");
    let record = only_record(&dir);
    assert_eq!(
        server_of(&record),
        "alpha",
        "R1: the replay's record names the live map's server, not the admitted one: {record}"
    );
}

/// R7: a continuation retry's origin is a backend tool no operator surfaced,
/// so its replay writes no invocation record, as before (M6). The origin
/// target is built as `replay_origin_target` builds it.
#[tokio::test]
async fn r7_a_continuation_origin_replay_writes_no_record() {
    let dir = tempfile::tempdir().unwrap();
    let meta = surfaced(meta(Ok(ok_result()), &dir), "alpha");
    let who = api_key_caller();
    let retry = keyed("r7");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let origin = ReplayTarget {
        server: "alpha".to_string(),
        tool: "continued".to_string(),
        origin: crate::gateway::meta_mcp::admission::ReplayOrigin::ContinuationOrigin,
    };
    let stored = JsonRpcResponse::success(RequestId::Number(3), ok_result());
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            "continued",
            &json!({}),
            &ctx,
            Some(origin),
            (None, Vec::new()),
            (stored, None),
        )
        .await
    else {
        panic!("premise: the replay is served, not deferred");
    };
    let _ = meta
        .audit_replay("continued", &json!({}), None, &ctx, response, audit)
        .await;
    assert!(
        records(&dir).is_empty(),
        "R7: a continuation-origin replay wrote a record: {:?}",
        records(&dir)
    );
}

/// R5b: a replay that must defer but finds no request memo fails closed with
/// an error (`defer_or_serve_replay`'s defer-failure return). That answer is
/// still the surfaced call admitted for `idp`, so its record names `idp`
/// after the map moves (M5b).
#[tokio::test]
async fn r5b_a_failed_deferral_records_the_admitted_server() {
    let dir = tempfile::tempdir().unwrap();
    let base = meta(Ok(ok_result()), &dir);
    assert!(
        base.backends.for_test().register(idp_backend()),
        "premise: idp registers"
    );
    let mut meta = surfaced(base, "idp");
    let retry = keyed("r5b");
    let who = api_key_caller();
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    assert!(
        meta.stored_replay_defers(&meta.unscoped_for_test(), "idp", NAME),
        "premise: the target defers"
    );
    let target = ReplayTarget {
        server: "idp".to_string(),
        tool: NAME.to_string(),
        origin: crate::gateway::meta_mcp::admission::ReplayOrigin::Named,
    };
    meta.resurface_for_test(NAME, "beta");
    let stored = JsonRpcResponse::success(RequestId::Number(4), ok_result());
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            NAME,
            &json!({}),
            &ctx,
            Some(target),
            (None, Vec::new()),
            (stored, None),
        )
        .await
    else {
        panic!("premise: outside a memo the deferral fails closed with an answer");
    };
    assert!(
        response.error.is_some(),
        "premise: the answer is the defer-failure error"
    );
    let _ = meta
        .audit_replay(NAME, &json!({}), None, &ctx, response, audit)
        .await;
    let all = records(&dir);
    let names: Vec<&str> = all.iter().map(server_of).collect();
    assert_eq!(
        names,
        vec!["idp"],
        "R5b: the failed deferral's record names the live map's server: {all:?}"
    );
}

/// Long enough for several winnowed fingerprints, as in `relay_tests`.
#[cfg(feature = "firewall")]
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// R2: on a firewall that treats `alpha:*` as a relay source, the replay of
/// the surfaced call admitted for `alpha` stages its receipt for `alpha` after
/// the map moves to `beta`, so `bob` relaying the text through `alpha` is
/// refused (M2). Base stages it for `beta`, which is no source.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn r2_a_surfaced_replay_stages_its_receipt_for_the_admitted_server() {
    use crate::security::firewall::{
        CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
    };
    let dir = tempfile::tempdir().unwrap();
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources: vec!["alpha:*".to_string()],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    let mut base = meta(Ok(ok_result()), &dir);
    base.set_firewall(Some(Arc::clone(&firewall)));
    base.share_keyring_with_for_test(&firewall);
    let mut meta = surfaced(base, "alpha");
    let who = api_key_caller();
    let retry = keyed("r2");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        caller_key: Some("alice"),
        ..context(&AllowAll, &who)
    };
    let target = ReplayTarget {
        server: "alpha".to_string(),
        tool: NAME.to_string(),
        origin: crate::gateway::meta_mcp::admission::ReplayOrigin::Named,
    };
    meta.resurface_for_test(NAME, "beta");
    let stored = JsonRpcResponse::success(
        RequestId::Number(5),
        json!({"content": [{"type": "text", "text": PROSE}], "isError": false}),
    );
    let Some((response, audit)) = meta
        .defer_or_serve_replay(
            NAME,
            &json!({}),
            &ctx,
            Some(target),
            (None, Vec::new()),
            (stored, None),
        )
        .await
    else {
        panic!("premise: the replay is served, not deferred");
    };
    let (answer, staged) = meta
        .collecting_staged(meta.audit_replay(NAME, &json!({}), None, &ctx, response, audit))
        .await;
    assert!(answer.error.is_none(), "premise: delivered: {answer:?}");
    staged.commit(true);
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    let relayed = !firewall
        .check_relay(
            RelayCaller::Keyed("bob"),
            "alpha",
            "send",
            &params,
            ("s", "bob"),
        )
        .allowed;
    assert!(
        relayed,
        "R2: the replay's receipt was staged under the live map's server, not alpha"
    );
}

/// R8 (M8): an unkeyed replay of a `Named` target (`deferred_replay_key`
/// answers `None`) still carries the admitted server. Admission never yields
/// a replay without a key, so the route stage is called directly.
#[tokio::test]
async fn r8_an_unkeyed_named_replay_carries_the_admitted_server() {
    let dir = tempfile::tempdir().unwrap();
    let meta = surfaced(meta(Ok(ok_result()), &dir), "alpha");
    let who = api_key_caller();
    let ctx = context(&AllowAll, &who);
    let target = ReplayTarget {
        server: "alpha".to_string(),
        tool: NAME.to_string(),
        origin: crate::gateway::meta_mcp::admission::ReplayOrigin::Named,
    };
    let stored = JsonRpcResponse::success(RequestId::Number(8), ok_result());
    let Some((_, facts)) = meta
        .defer_or_serve_replay(
            NAME,
            &json!({}),
            &ctx,
            Some(target),
            (None, Vec::new()),
            (stored, None),
        )
        .await
    else {
        panic!("premise: an unkeyed replay is served");
    };
    assert_eq!(
        facts.server.as_deref(),
        Some("alpha"),
        "R8: the unkeyed return dropped the admitted server"
    );
}

/// R3 (M3): with no server carried, a surfaced name the live map still binds
/// (to `beta`) is never looked up again: no record is written and no receipt
/// is staged. On the relay fixture, so "nothing staged" can fail.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn r3_no_carried_server_records_and_stages_nothing() {
    use crate::security::firewall::{
        CollusionAction, CollusionConfig, Firewall, FirewallConfig, RelayCaller,
    };
    let dir = tempfile::tempdir().unwrap();
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    sources: vec!["beta:*".to_string()],
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    );
    let mut base = meta(Ok(ok_result()), &dir);
    base.set_firewall(Some(Arc::clone(&firewall)));
    base.share_keyring_with_for_test(&firewall);
    let mut meta = surfaced(base, "alpha");
    meta.resurface_for_test(NAME, "beta");
    let who = api_key_caller();
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        caller_key: Some("alice"),
        ..context(&AllowAll, &who)
    };
    let replay = JsonRpcResponse::success(
        RequestId::Number(6),
        json!({"content": [{"type": "text", "text": PROSE}], "isError": false}),
    );
    let facts = crate::gateway::meta_mcp::admission::ReplayFacts::default();
    let (_, staged) = meta
        .collecting_staged(meta.audit_replay(NAME, &json!({}), None, &ctx, replay, facts))
        .await;
    staged.commit(true);
    assert!(
        records(&dir).is_empty(),
        "R3: a replay with no carried server wrote a record: {:?}",
        records(&dir)
    );
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    assert!(
        firewall
            .check_relay(
                RelayCaller::Keyed("bob"),
                "beta",
                "send",
                &params,
                ("s", "bob")
            )
            .allowed,
        "R3: a receipt was staged from the live map's server"
    );
}

/// R5 (M5): a stored step recorded under a binding the target no longer has
/// is refused at the route stage (`judge_bindings`). The refusal is still the
/// surfaced call admitted for `alpha`, so its record names `alpha` after the
/// map moves, outcome and response hash included.
#[tokio::test]
async fn r5_a_refused_replay_records_the_admitted_server() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = surfaced(meta(Ok(ok_result()), &dir), "alpha");
    let who = api_key_caller();
    let retry = keyed("r5");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let target = ReplayTarget {
        server: "alpha".to_string(),
        tool: NAME.to_string(),
        origin: crate::gateway::meta_mcp::admission::ReplayOrigin::Named,
    };
    meta.resurface_for_test(NAME, "beta");
    let stored = JsonRpcResponse::success(RequestId::Number(7), ok_result());
    let bindings = vec![(
        "alpha".to_string(),
        NAME.to_string(),
        Some("a-binding-alpha-no-longer-has".to_string()),
    )];
    let Some((response, facts)) = meta
        .defer_or_serve_replay(
            NAME,
            &json!({}),
            &ctx,
            Some(target),
            (None, bindings),
            (stored, None),
        )
        .await
    else {
        panic!("premise: the refusal is answered, not deferred");
    };
    let refusal = response
        .error
        .clone()
        .expect("premise: the binding is refused");
    let _ = meta
        .audit_replay(NAME, &json!({}), None, &ctx, response, facts)
        .await;
    let record = only_record(&dir);
    assert_eq!(
        server_of(&record),
        "alpha",
        "R5: the refused replay's record names the live map's server: {record}"
    );
    assert!(
        record.get("outcome").is_some() && record.get("request_hash").is_some(),
        "R5: the refused replay's record is incomplete ({refusal:?}): {record}"
    );
}

/// MIK-8520 L8 (N10, pin): across requests. A keyed surfaced call completes
/// on `alpha`; the name then moves to `beta` (as a reload moves it); the
/// keyed repeat is refused at execution admission, because the operation
/// names the server. It never runs on `beta` and is never served `alpha`'s
/// answer as `beta`'s: one client key never produces two writes (lead
/// ruling 2026-10-25). This already holds on base, so the row pins it.
#[tokio::test]
async fn l8_a_keyed_repeat_after_the_name_moves_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = surfaced(meta(Ok(ok_result()), &dir), "alpha");
    let who = api_key_caller();
    let retry = keyed("l8");
    let ctx = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..context(&AllowAll, &who)
    };
    let owner = || crate::gateway::meta_mcp::AdmissionOwner::for_test(ctx.owner_principal());
    let args = json!({});
    let first =
        meta.admit_meta_sync_for_test(owner(), &ctx, NAME, &args, None, &RequestId::Number(1));
    let Ok(SyncAdmission::Owned(lease)) = first else {
        panic!("premise: the first surfaced call owns its admission");
    };
    lease.mark_dispatched();
    lease.complete_secured(&JsonRpcResponse::success(RequestId::Number(1), ok_result()));
    meta.resurface_for_test(NAME, "beta");
    let again =
        meta.admit_meta_sync_for_test(owner(), &ctx, NAME, &args, None, &RequestId::Number(2));
    assert!(
        !matches!(again, Ok(SyncAdmission::Replay(..))),
        "L8: the repeat after the move was served alpha's stored answer"
    );
    assert!(
        again.is_err(),
        "L8: the repeat after the move was admitted as a new operation"
    );
}
