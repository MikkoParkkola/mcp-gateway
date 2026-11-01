// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 A5 ruling A at keyed admission: a plan step the caller cannot see
//! is never answered by its reason, here when the key is already in flight.

use serde_json::json;

use crate::gateway::authz::{AllowAll, DenyOne, ToolAuthorizer};
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::protocol::mrtr::RetryFields;

/// A modern caller with an owner the admission can key on, `retry` its
/// retry fields, judged by `authorizer`.
fn owned<'a>(
    retry: &'a RetryFields,
    authorizer: &'a (dyn ToolAuthorizer + Sync),
) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        retry,
        is_modern: true,
        credential_principal: Some("verified-credential-owner"),
        record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
        ..ctx(authorizer)
    }
}

/// Two keyed `gateway_execute` calls of `[beta:other, beta:read]`: the first,
/// judged while `read` is allowed, holds the key; the second, judged by
/// `authorizer`, asks while it is in flight. The second call's answer.
fn second_while_in_flight(authorizer: &(dyn ToolAuthorizer + Sync)) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("in-flight".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let held = admit(&owned(&retry, &AllowAll), 1);
    assert!(
        matches!(held, Ok(super::SyncAdmission::Owned(_))),
        "premise: the first, allowed call owns the key"
    );
    let second = admit(&owned(&retry, authorizer), 2)
        .err()
        .map(|error| error.to_string());
    drop(held);
    second.expect("premise: a key in flight refuses the second call")
}

/// Ruling A, addition 2: with the key in flight, a call whose last step the
/// policy now withholds gets exactly the answer a call whose last step it
/// allows gets (a missing step passes admission the same way): the key's own
/// answer, never the withheld step's reason.
#[test]
fn a_key_in_flight_answers_a_withheld_step_as_a_missing_one() {
    let withheld = second_while_in_flight(&DenyOne { tool: "read" });
    let missing = second_while_in_flight(&AllowAll);
    assert!(
        !withheld.contains("denied by test authorizer"),
        "the withheld step's reason reached the caller: {withheld}"
    );
    assert_eq!(withheld, missing, "in flight: withheld vs missing");
}

/// Ruling A (lead correction): on a REGISTERED backend, a key admitted and
/// completed while `read` was allowed, then replayed after the policy
/// withholds it, gets the step's current refusal, -32003, as SUB.4 pins it
/// for unregistered backends: a replayed key's holder held access before, so
/// "forbidden" tells it nothing new, and no retained result is served.
#[test]
fn a_replay_past_revocation_on_a_registered_backend_keeps_its_refusal() {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("replayed".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let allowed = owned(&retry, &AllowAll);
    let Ok(super::SyncAdmission::Owned(owner)) = admit(&allowed, 1) else {
        panic!("premise: the first allowed call owns the key");
    };
    owner.mark_dispatched();
    // The first run dispatched both steps (#3872 FIX 1: only a dispatched
    // step's replay meets its refusal).
    owner.note_step(("beta", "other"));
    owner.note_step(("beta", "read"));
    owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"retained": "yes"}),
    ));
    let denied = DenyOne { tool: "read" };
    let revoked = owned(&retry, &denied);
    match admit(&revoked, 2) {
        Err(crate::Error::Forbidden { code, .. }) => assert_eq!(code, -32003),
        Err(other) => panic!("the replay past revocation lost SUB.4's answer: {other}"),
        Ok(_) => panic!("a retained result was served past the revocation"),
    }
}

/// A keyed `gateway_execute` of `[beta:other]` admitted and completed, then
/// the same key reused with `[beta:other, beta:{step}]` judged by `authorizer`,
/// with `blocked` (if any) withheld by its description before the reuse:
/// the reuse's answer (a key mismatch: other arguments under a used key).
fn reuse_with_another_step(
    authorizer: &(dyn ToolAuthorizer + Sync),
    blocked: Option<&str>,
    step: &str,
) -> String {
    let (registry, _calls) = counted_backend("beta");
    if let Some(tool) = blocked {
        registry
            .get("beta")
            .expect("the beta backend")
            .block_tool_for_test(tool);
    }
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("reused".into()),
        ..RetryFields::default()
    };
    let admit = |caller: &MetaMcpCallerContext<'_>, args: &serde_json::Value, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let first = json!({"chain": [{"tool": "beta:other", "arguments": {}}]});
    let Ok(super::SyncAdmission::Owned(owner)) = admit(&owned(&retry, &AllowAll), &first, 1) else {
        panic!("premise: the first call owns the key");
    };
    owner.mark_dispatched();
    owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"retained": "yes"}),
    ));
    let second = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": format!("beta:{step}"), "arguments": {}}
    ]});
    match admit(&owned(&retry, authorizer), &second, 2) {
        Err(error) => format!("{error:?}"),
        Ok(_) => panic!("premise: a used key with other arguments is refused"),
    }
}

/// #3872 product review (oracle 1): a used key reused with other arguments is
/// a mismatch, not a replay. Its holder never held the new step, so a step
/// the caller cannot see answers as a missing one does (the key mismatch),
/// never its own refusal; otherwise any caller could probe names with keys.
#[test]
fn a_key_reused_with_a_withheld_step_answers_as_with_a_missing_one() {
    let withheld = reuse_with_another_step(&DenyOne { tool: "read" }, None, "read");
    let missing = reuse_with_another_step(&AllowAll, None, "no_such");
    assert_eq!(withheld, missing, "key reuse: withheld vs missing step");
}

/// The same for a step withheld by its description, a catalogue reason, not
/// the policy (#3872 review, low): the reuse answers as with a missing step.
#[test]
fn a_key_reused_with_a_descriptor_withheld_step_answers_as_with_a_missing_one() {
    let withheld = reuse_with_another_step(&AllowAll, Some("read"), "read");
    let missing = reuse_with_another_step(&AllowAll, None, "no_such");
    assert_eq!(
        withheld, missing,
        "key reuse: descriptor-withheld vs missing"
    );
}

/// A keyed `gateway_execute` of `[alpha:other, beta:{step}]` with `beta`
/// killed, judged by `authorizer`: admission's answer (an owned key, or the
/// refusal), rendered.
fn keyed_chain_on_a_killed_backend(authorizer: &(dyn ToolAuthorizer + Sync), step: &str) -> String {
    let (registry, _calls) = counted_backend("beta");
    let (alpha, _) = counted_backend("alpha");
    assert!(
        registry.register(alpha.get("alpha").expect("the alpha backend")),
        "premise: alpha registers"
    );
    let meta = MetaMcp::new(registry).with_code_mode(true);
    meta.kill_switch().kill("beta");
    let retry = RetryFields {
        idempotency_key: Some("killed".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "alpha:other", "arguments": {}},
        {"tool": format!("beta:{step}"), "arguments": {}}
    ]});
    let caller = owned(&retry, authorizer);
    match meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        "gateway_execute",
        &args,
        Some("legacy:session"),
        &RequestId::Number(1),
    ) {
        Ok(super::SyncAdmission::Owned(_)) => "admitted".to_string(),
        Ok(_) => "another admission".to_string(),
        Err(error) => format!("{error:?}"),
    }
}

/// #3872 review (FIX 2): the kill switch speaks about the backend, not the
/// name. A keyed chain whose step names a killed backend is refused whole at
/// admission (0 sends) for a missing name; a step the caller may not see on
/// that backend is refused the same way, never deferred so that the earlier
/// step runs and the chain fails part-way.
#[test]
fn a_keyed_chain_on_a_killed_backend_answers_a_withheld_step_as_a_missing_one() {
    let withheld = keyed_chain_on_a_killed_backend(&DenyOne { tool: "read" }, "read");
    let missing = keyed_chain_on_a_killed_backend(&AllowAll, "no_such");
    assert!(
        missing.contains("kill switch"),
        "premise: the missing step's chain is refused by the kill switch: {missing}"
    );
    assert_eq!(
        withheld, missing,
        "killed backend: withheld vs missing step"
    );
}

/// #3872 review (FIX 1, condition 2): a sync result stored before the step
/// list existed still decodes, with no list, and its replay keeps today's
/// refusal of a now-hidden step (fail closed). A listed run meets the refusal
/// of the first hidden step it was served, never one it was not (review B).
#[test]
fn a_stored_result_without_a_step_list_keeps_the_refusal() {
    use super::stored::{dispatched_steps, refusal_to_meet};
    let step = |tool: &str| ("beta".to_string(), tool.to_string());
    let withheld = || {
        vec![
            (step("other"), crate::Error::json_rpc(-32003, "other")),
            (step("read"), crate::Error::json_rpc(-32003, "read")),
        ]
    };
    let older = serde_json::to_vec(&json!({
        "response": {"jsonrpc": "2.0", "id": null, "result": {"retained": "yes"}},
        "chain": "not_eligible"
    }))
    .expect("serializes");
    assert!(
        super::stored::stored_response(&older).is_some(),
        "an older record still decodes"
    );
    assert_eq!(
        dispatched_steps(&older),
        None,
        "an older record has no list"
    );
    let refused = |served: Option<&[(String, String)]>| {
        refusal_to_meet(served, withheld()).map(|error| error.to_string())
    };
    assert_eq!(
        refused(dispatched_steps(&older).as_deref()),
        Some(crate::Error::json_rpc(-32003, "other").to_string()),
        "an older record keeps the first refusal"
    );
    assert_eq!(
        refused(Some(&[step("write")])),
        None,
        "no hidden step ran: the stored answer"
    );
    assert_eq!(
        refused(Some(&[step("read")])),
        Some(crate::Error::json_rpc(-32003, "read").to_string()),
        "the refusal of the hidden step that ran"
    );
}

/// #3872 review (round 3, A), live, not seeded: a keyed chain `[read, write]`
/// runs under its lease (with `read` answered from the response cache when
/// `cached`), completes, and is replayed with `revoked` denied. The replay's
/// answer: SUB.4's refusal, as the step's retained data is in the stored
/// response whether it was sent or served from the cache.
async fn replay_after_revoking(cached: Option<&str>, revoked: &'static str) -> crate::Result<()> {
    let (registry, calls) = counted_backend("beta");
    let meta = MetaMcp::with_features(
        registry,
        Some(std::sync::Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        std::time::Duration::from_secs(60),
    )
    .with_code_mode(true);
    let session = Some("legacy:session");
    let unkeyed = RetryFields::default();
    if let Some(tool) = cached {
        let warm = json!({"server": "beta", "tool": tool, "arguments": {}});
        meta.invoke_tool(&warm, session, &owned(&unkeyed, &AllowAll))
            .await
            .expect("warms the cache");
    }
    let before = calls.load(std::sync::atomic::Ordering::SeqCst);
    let retry = RetryFields {
        idempotency_key: Some("live-replay".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:read", "arguments": {}},
        {"tool": "beta:write", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            session,
            &RequestId::Number(id),
        )
    };
    let mut allowed = owned(&retry, &AllowAll);
    let Ok(super::SyncAdmission::Owned(lease)) = admit(&allowed, 1) else {
        panic!("premise: the first allowed chain owns the key");
    };
    allowed.execution = Some(&lease);
    let ran = meta
        .code_mode_execute(&args, session, &allowed)
        .await
        .expect("the chain runs");
    let sent = calls.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert_eq!(
        sent,
        2 - usize::from(cached.is_some()),
        "premise: steps sent"
    );
    lease.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        ran,
    ));
    let denied = DenyOne { tool: revoked };
    match admit(&owned(&retry, &denied), 2) {
        Err(error) => Err(error),
        Ok(_) => Ok(()),
    }
}

fn assert_sub4_refusal(answer: crate::Result<()>, row: &str) {
    match answer {
        Err(crate::Error::Forbidden { code, .. }) => assert_eq!(code, -32003, "{row}"),
        Err(other) => panic!("{row}: the replay lost SUB.4's answer: {other}"),
        Ok(()) => panic!("{row}: a retained result was served past the revocation"),
    }
}

/// A step answered from the response cache, then revoked: its replay refuses.
#[tokio::test]
async fn a_replay_past_revocation_of_a_cached_step_keeps_its_refusal() {
    let answer = Box::pin(replay_after_revoking(Some("read"), "read")).await;
    assert_sub4_refusal(answer, "cached step");
}

/// A step the run sent, then revoked: its replay refuses (live, so the
/// dispatch path's own note is what proves it ran).
#[tokio::test]
async fn a_replay_past_revocation_of_a_sent_step_keeps_its_refusal() {
    let answer = Box::pin(replay_after_revoking(None, "write")).await;
    assert_sub4_refusal(answer, "sent step");
}

/// The replay refused by today's policy is the gateway refusing the call:
/// its delivery records refused, as the live call's refusal would.
#[tokio::test]
async fn a_replay_past_revocation_records_refused() {
    use crate::gateway::delivery_facts;
    let mut fields = serde_json::Map::new();
    let answer = delivery_facts::scope(async {
        let answer = Box::pin(replay_after_revoking(None, "write")).await;
        delivery_facts::record_fields(delivery_facts::snapshot().as_ref(), false, &mut fields);
        answer
    })
    .await;
    assert_sub4_refusal(answer, "premise");
    assert_eq!(
        fields.get("response_effect"),
        Some(&json!("refused")),
        "{fields:?}"
    );
}

/// Denies each of `0`, with `DenyOne`'s refusal.
struct DenyEach(&'static [&'static str]);

impl ToolAuthorizer for DenyEach {
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        None
    }
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> crate::gateway::authz::BackendGrant<'_> {
        crate::gateway::authz::BackendGrant::Unscoped
    }
    fn decide<'a>(
        &'a self,
        target: crate::gateway::authz::ToolTarget<'a>,
    ) -> crate::gateway::authz::Decision<'a> {
        if self.0.contains(&target.tool) {
            return crate::gateway::authz::Decision::of(Err(
                crate::gateway::authz::AuthorizationError::forbidden(
                    crate::security::decision_record::DecisionKind::ToolPolicy,
                    -32003,
                    format!("denied by test authorizer: '{}'", target.tool),
                ),
            ));
        }
        crate::gateway::authz::Decision::of(Ok(()))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
    }
    fn transport(&self) -> crate::gateway::authz::Transport {
        crate::gateway::authz::Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// A keyed chain `[first, beta:read]` admitted under `admitted`, whose run
/// was served `read` only (`first` hidden or missing, never run), then
/// replayed under `replayed`: the replay's refusal.
fn replay_naming(
    first: &str,
    admitted: &(dyn ToolAuthorizer + Sync),
    replayed: &(dyn ToolAuthorizer + Sync),
) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let retry = RetryFields {
        idempotency_key: Some("first-hidden".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": format!("beta:{first}"), "arguments": {}},
        {"tool": "beta:read", "arguments": {}}
    ]});
    let admit = |caller: &MetaMcpCallerContext<'_>, id| {
        meta.admit_meta_sync_for_test(
            AdmissionOwner::for_test(caller.owner_principal()),
            caller,
            "gateway_execute",
            &args,
            Some("legacy:session"),
            &RequestId::Number(id),
        )
    };
    let Ok(super::SyncAdmission::Owned(owner)) = admit(&owned(&retry, admitted), 1) else {
        panic!("premise: the first call owns the key");
    };
    owner.mark_dispatched();
    owner.note_step(("beta", "read"));
    owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"retained": "yes"}),
    ));
    match admit(&owned(&retry, replayed), 2) {
        Err(error) => format!("{error:?}"),
        Ok(_) => panic!("premise: the replay past the revocation is refused"),
    }
}

/// #3872 review (round 3, B): a chain whose first step was hidden from the
/// first call (never run) and whose second ran, replayed after the second is
/// revoked, names the second step's refusal, as when the first step is
/// missing; never the hidden step's. Seeded, not live: a fresh run cannot
/// reach this record, because a chain stops at its first failed step ("Chain
/// step N failed"), so a hidden first step ends the run before the second.
#[test]
fn a_replay_names_the_refusal_of_the_step_that_ran() {
    let withheld = replay_naming(
        "other",
        &DenyOne { tool: "other" },
        &DenyEach(&["other", "read"]),
    );
    let missing = replay_naming("nope", &AllowAll, &DenyOne { tool: "read" });
    assert!(
        missing.contains("'read'"),
        "premise: the missing twin names read: {missing}"
    );
    assert_eq!(withheld, missing, "the replay names the step that ran");
}

/// A keyed `gateway_execute` of `[beta:other, beta:{step}]`, `beta:read` in
/// error-rate cooldown, judged by `authorizer`: admission's answer, rendered.
fn keyed_chain_with_a_disabled_step(
    authorizer: &(dyn ToolAuthorizer + Sync),
    step: &str,
) -> String {
    let (registry, _calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry).with_code_mode(true);
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..(cfg.window_size * 2) {
        meta.kill_switch()
            .record_capability_failure("beta", "read", &cfg);
    }
    assert!(
        meta.kill_switch().is_capability_disabled("beta", "read"),
        "premise: read is in cooldown"
    );
    let retry = RetryFields {
        idempotency_key: Some("cooldown".into()),
        ..RetryFields::default()
    };
    let args = json!({"chain": [
        {"tool": "beta:other", "arguments": {}},
        {"tool": format!("beta:{step}"), "arguments": {}}
    ]});
    let caller = owned(&retry, authorizer);
    match meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        "gateway_execute",
        &args,
        Some("legacy:session"),
        &RequestId::Number(1),
    ) {
        Ok(super::SyncAdmission::Owned(_)) => "admitted".to_string(),
        Ok(_) => "another admission".to_string(),
        Err(error) => format!("{error:?}"),
    }
}

/// #3872 review (round 4, M2): keyed admission meets a hidden step in
/// error-rate cooldown as it meets a missing step, never with the cooldown's
/// refusal, which names the tool; only the server-wide kill switch refuses
/// both (the killed-chain row).
#[test]
fn a_keyed_chain_with_a_disabled_hidden_step_answers_as_a_missing_one() {
    let withheld = keyed_chain_with_a_disabled_step(&DenyOne { tool: "read" }, "read");
    let missing = keyed_chain_with_a_disabled_step(&AllowAll, "no_such");
    assert!(
        !withheld.contains("temporarily disabled"),
        "the cooldown named the hidden tool: {withheld}"
    );
    assert_eq!(withheld, missing, "cooldown: withheld vs missing step");
}
