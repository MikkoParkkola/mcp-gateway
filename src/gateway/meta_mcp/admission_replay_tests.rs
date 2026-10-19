// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 site 1: a deferral that cannot be recorded fails closed.

use std::sync::Arc;

use serde_json::json;

use super::super::ReplayTarget;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::{JsonRpcResponse, RequestId};

/// The per-caller `idp` backend: identity propagation, so a replay to it
/// defers. `account` names an account descriptor, as a re-bind would.
fn idp_backend(account: Option<&str>) -> Arc<crate::backend::Backend> {
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
            account: account.map(str::to_owned),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// A Meta-MCP over the per-caller [`idp_backend`], with its registry.
fn per_caller() -> (MetaMcp, Arc<crate::backend::BackendRegistry>) {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(
        registry.register(idp_backend(None)),
        "the backend registers"
    );
    (MetaMcp::new(Arc::clone(&registry)), registry)
}

/// A per-caller backend: identity propagation, so a replay to it defers.
fn per_caller_meta() -> MetaMcp {
    per_caller().0
}

/// R-closed (product seat finding 3; mutant M-closed): outside a request
/// memo the deferral cannot be recorded, so site 1 answers an error instead
/// of `None` (deferred), which would let the caller re-run a completed call
/// unprotected with no lift to serve it. Answering `None` regardless of the
/// record (M-closed) fails this row.
#[tokio::test]
async fn an_unrecorded_deferral_fails_closed() {
    let meta = per_caller_meta();
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("closed".to_string()),
        ..Default::default()
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..ctx(&AllowAll)
    };
    assert!(
        meta.stored_replay_defers(&meta.unscoped_for_test(), "idp", "read"),
        "premise: the target defers"
    );
    let stored = JsonRpcResponse::success(RequestId::Number(4), json!({"content": []}));
    let answer = meta
        .defer_or_serve_replay(
            "gateway_invoke",
            &json!({"server": "idp", "tool": "read"}),
            &caller,
            Some(ReplayTarget {
                server: "idp".to_string(),
                tool: "read".to_string(),
            }),
            (None, Vec::new()),
            (stored, None),
        )
        .await;
    let (response, audit) = answer.expect("R-closed: an unrecorded deferral answered None");
    assert!(
        audit.is_none(),
        "R-closed: no stored facts travel with the refusal"
    );
    let error = response.error.expect("R-closed: the answer is an error");
    assert_eq!(error.code, -32603, "R-closed: {error:?}");
    assert_eq!(
        response.id,
        Some(RequestId::Number(4)),
        "R-closed: the request's id"
    );
}

/// MIK-8387: a target outside the caller's grant defers to the live dispatch,
/// so a stored result for it is never served at admission. Dropping the
/// absence check serves it, and this row fails.
#[test]
fn an_out_of_scope_target_defers() {
    let meta = per_caller_meta();
    let granted = ["other".to_string()];
    let view = meta.scoped(crate::gateway::authz::BackendGrant::Scoped(&granted));
    assert!(
        meta.stored_replay_defers(&view, "idp", "read"),
        "out of scope: defers"
    );
    assert!(
        meta.stored_replay_defers(&view, "ghost", "read"),
        "unregistered: defers"
    );
}

/// A stored `gateway_execute` answer and the call that made it: one step
/// on the per-caller backend `idp`, whose account no caller here can prove.
fn plan_replay() -> (serde_json::Value, JsonRpcResponse) {
    let arguments = json!({"tool": "idp:read", "arguments": {}});
    let stored = JsonRpcResponse::success(
        RequestId::Number(5),
        json!({"content": [{"type": "text", "text": "stored-plan-output"}]}),
    );
    (arguments, stored)
}

/// P8-legacy (MIK-8406; mutant mNoneServe): a stored plan record with no
/// executed-step list (`dispatched: None`, a record from before the list)
/// judges the call's declared targets, fail closed: its declared step on
/// `idp`, whose account is not proven, refuses the replay. Serving a `None`
/// list (mNoneServe) fails this row.
#[tokio::test]
async fn p8_legacy_a_plan_record_with_no_step_list_judges_its_declared_targets() {
    let meta = per_caller_meta();
    let (arguments, stored) = plan_replay();
    let answer = crate::gateway::meta_mcp::visible::with_visibility_memo(async {
        meta.defer_or_serve_replay(
            "gateway_execute",
            &arguments,
            &ctx(&AllowAll),
            None,
            (None, Vec::new()),
            (stored.clone(), None),
        )
        .await
    })
    .await;
    let (response, audit) = answer.expect("P8-legacy: a plan replay is answered, never deferred");
    assert!(
        response.error.is_some() && response.result.is_none(),
        "P8-legacy: the stored plan was served on an unproven declared target: {response:?}"
    );
    assert!(
        audit.is_none(),
        "P8-legacy: stored facts travelled with the refusal"
    );
}

/// P8-empty (MIK-8406; mutant mEmptyDeclared): a stored plan record whose
/// run dispatched nothing (`dispatched: Some([])`) is served as stored, with
/// no account judged. Reading an empty list as a missing one (judging the
/// declared `idp` step, mEmptyDeclared) refuses it and fails this row. Only a
/// constructed record reaches this: a run that dispatched nothing is never
/// retained (admission.rs, `complete_delivery`).
#[tokio::test]
async fn p8_empty_a_plan_record_that_dispatched_nothing_is_served() {
    let meta = per_caller_meta();
    let (arguments, stored) = plan_replay();
    let answer = crate::gateway::meta_mcp::visible::with_visibility_memo(async {
        meta.defer_or_serve_replay(
            "gateway_execute",
            &arguments,
            &ctx(&AllowAll),
            None,
            (Some(Vec::new()), Vec::new()),
            (stored.clone(), None),
        )
        .await
    })
    .await;
    let (response, _) = answer.expect("P8-empty: a plan replay is answered, never deferred");
    assert_eq!(
        serde_json::to_value(&response).expect("serialises"),
        serde_json::to_value(&stored).expect("serialises"),
        "P8-empty: the stored plan was not served as stored"
    );
}

/// P8-noid (MIK-8406, fail closed): a stored plan replay with no request id
/// is not served. Admission always stamps the request's id, so only a
/// constructed record reaches this; the answer is -32603 with no id and no
/// stored facts. Its empty step list would otherwise serve it unproven, so
/// dropping the guard fails this row.
#[tokio::test]
async fn p8_noid_a_stored_plan_replay_with_no_request_id_fails_closed() {
    let meta = per_caller_meta();
    let (arguments, mut stored) = plan_replay();
    stored.id = None;
    let answer = crate::gateway::meta_mcp::visible::with_visibility_memo(async {
        meta.defer_or_serve_replay(
            "gateway_execute",
            &arguments,
            &ctx(&AllowAll),
            None,
            (Some(Vec::new()), Vec::new()),
            (stored, None),
        )
        .await
    })
    .await;
    let (response, audit) = answer.expect("P8-noid: a plan replay is answered, never deferred");
    let response = serde_json::to_value(&response).expect("serialises");
    assert_eq!(
        response.get("id"),
        Some(&serde_json::Value::Null),
        "{response}"
    );
    assert_eq!(
        response.pointer("/error/code"),
        Some(&json!(-32603)),
        "{response}"
    );
    assert_eq!(
        response.pointer("/error/message"),
        Some(&json!("stored plan replay has no request id")),
        "{response}"
    );
    assert!(
        response.get("result").is_none(),
        "P8-noid: served: {response}"
    );
    assert!(
        audit.is_none(),
        "P8-noid: stored facts travelled with the refusal"
    );
}

/// P8-rebind (MIK-8407; mutant: no judgement after the walk): a plan whose
/// recorded step ran under no account passes the judgement made before the
/// walk. Its backend is re-bound to an account while the walk runs, so the
/// judgement made again at the serving point refuses it: nothing stored is
/// served and no replay is audited. Serving on the first judgement alone
/// fails this row.
#[tokio::test]
async fn p8_rebind_a_step_rebound_while_the_plan_walk_runs_is_refused() {
    let (meta, registry) = per_caller();
    let (arguments, stored) = plan_replay();
    let rebind = Arc::clone(&registry);
    let _armed = super::walk_seam::after_plan_walk(move || {
        assert!(rebind.register(idp_backend(Some("rebound-account"))));
    });
    let answer = crate::gateway::meta_mcp::visible::with_visibility_memo(async {
        meta.defer_or_serve_replay(
            "gateway_execute",
            &arguments,
            &ctx(&AllowAll),
            None,
            (
                Some(Vec::new()),
                vec![("idp".to_owned(), "read".to_owned(), None)],
            ),
            (stored.clone(), None),
        )
        .await
    })
    .await;
    assert_eq!(
        registry
            .get("idp")
            .and_then(|backend| backend.account_descriptor_id().map(str::to_owned)),
        Some("rebound-account".to_owned()),
        "premise: the walk ended and the hook re-bound idp"
    );
    let (response, audit) = answer.expect("P8-rebind: a plan replay is answered, never deferred");
    assert!(audit.is_none(), "P8-rebind: a refused replay was audited");
    let text = serde_json::to_string(&response).expect("serialises");
    assert!(
        text.contains("produced under a different account"),
        "P8-rebind: not refused at the serving point: {text}"
    );
    assert!(
        !text.contains("stored-plan-output"),
        "P8-rebind: the stored plan was served: {text}"
    );
}
