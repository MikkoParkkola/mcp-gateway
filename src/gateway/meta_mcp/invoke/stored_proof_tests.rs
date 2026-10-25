// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 site 5 and E9 run directly on the managed-account
//! fixture, with this request's memo seeded as the route stage leaves it:
//! the carried failed fill (E4), the per-account dedupe, and E9's outcomes.

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::gateway::meta_mcp::sealed_hold::{CarriedHolds, Held};
use crate::gateway::meta_mcp::visible::{self, memo::AccountOutcome, memo::Carried};
use crate::gateway::task_service::CommittedTask;
use crate::gateway::task_service::Target;
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::protocol::RequestId;
use crate::protocol::tasks::Task;

const TOOL: &str = "read";

fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(b"sole-operator-key")),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

fn connected() -> (DirectAccountGateway, MetaMcp) {
    let mut gateway = DirectAccountGateway::new(sole_operator(), &Binding::Connected);
    let meta = gateway.take_meta();
    (gateway, meta)
}

/// Carry the operator's real resolution for `(BACKEND, TOOL)`, as the
/// route stage's caller verdict leaves it, with `fill_error`.
async fn carry(meta: &MetaMcp, fill_error: Option<crate::Error>) {
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let resolved = meta
        .resolve_dispatch(
            (BACKEND, TOOL),
            Some(&backend),
            CallerProof::new(None, CallerProvenance::Credential),
            None,
        )
        .await
        .expect("premise: the operator's live grant resolves");
    visible::memo::carry_dispatch(
        BACKEND,
        TOOL,
        Carried {
            backend,
            resolved,
            fill_error,
        },
    );
}

fn target() -> Target {
    Target {
        server: BACKEND.to_string(),
        tool: TOOL.to_string(),
    }
}

fn stored_on(task: &Task, targets: Vec<Target>) -> CommittedTask {
    CommittedTask {
        task: task.clone(),
        revision: 2,
        targets,
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
        bindings: Vec::new(),
        bindings_recorded: true,
    }
}

fn shared_tools(meta: &MetaMcp, name: &str) {
    let tool: crate::protocol::Tool = serde_json::from_value(serde_json::json!({
        "name": name, "inputSchema": {"type": "object"}
    }))
    .expect("a tool");
    meta.backends
        .for_test()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
}

fn finished() -> Task {
    let mut task = Task::create("gateway_invoke").expect("the test clock reads after 1970");
    task.complete(&serde_json::json!({"content": [{"type": "text", "text": "t5-stored"}]}))
        .expect("a live task takes its outcome");
    task
}

/// T6u (E4 at site 5; mutant M11): a carried failed fill answers as the
/// failed dispatch, never the stored task. Counting the carried
/// resolution as proof regardless of its fill error serves the task.
#[tokio::test]
async fn t6u_a_carried_failed_fill_answers_the_failed_dispatch() {
    let (_gateway, meta) = connected();
    let task = finished();
    let answer = visible::memo::with_visibility_memo(async {
        carry(
            &meta,
            Some(crate::Error::Transport("t6u fill refused".into())),
        )
        .await;
        meta.defer_or_serve_existing(
            RequestId::Number(6),
            "gateway_invoke",
            &[target()],
            Held::new(stored_on(&task, vec![target()]), CarriedHolds::none()),
            &ctx(&AllowAll),
        )
        .await
    })
    .await;
    let text = serde_json::to_value(&answer).expect("JSON").to_string();
    assert!(
        !text.contains("t5-stored"),
        "T6u: the stored task was served: {text}"
    );
    assert!(
        text.contains("t6u fill refused"),
        "T6u: not the failed fill's answer: {text}"
    );
}

/// D5 (site 5 dedupe; mutant M-dedupe): two recorded targets on one
/// account prove once. The first takes the clean carried resolution; the
/// second is the same account and is not resolved again (the anonymous
/// test caller could not resolve it), so the stored task is served.
#[tokio::test]
async fn d5_one_account_proves_once_per_repeat() {
    let (_gateway, meta) = connected();
    let task = finished();
    let answer = visible::memo::with_visibility_memo(async {
        carry(&meta, None).await;
        meta.defer_or_serve_existing(
            RequestId::Number(7),
            "gateway_invoke",
            &[target(), target()],
            Held::new(
                stored_on(&task, vec![target(), target()]),
                CarriedHolds::none(),
            ),
            &ctx(&AllowAll),
        )
        .await
    })
    .await;
    let text = serde_json::to_value(&answer).expect("JSON").to_string();
    assert!(
        text.contains("t5-stored"),
        "D5: the proven repeat was not served: {text}"
    );
}

/// E9u (E9's three outcomes on an Unavailable account): a view that is
/// not Lacked leaves the answer to the catalogue (None); a Lacked view
/// whose carried resolution is clean proves and passes (None); a Lacked
/// view whose carried fill failed answers that failure, shaped as live.
#[tokio::test]
async fn e9u_an_unavailable_repeat_answers_only_a_lacked_target() {
    let (_gateway, meta) = connected();
    let task = finished();
    let account = meta
        .target_account(&meta.unscoped_for_test(), BACKEND, TOOL)
        .expect("an account target");
    let stored = stored_on(&task, vec![target()]);
    let run = |lacked: bool, fill_error: Option<crate::Error>| {
        let (meta, account, stored) = (&meta, account.clone(), &stored);
        visible::memo::with_visibility_memo(async move {
            shared_tools(meta, if lacked { "other" } else { TOOL });
            visible::memo::record_account_outcome(BACKEND, &account, AccountOutcome::Unavailable);
            carry(meta, fill_error).await;
            meta.unavailable_repeat_answer(
                &RequestId::Number(8),
                stored,
                ("gateway_invoke", None),
                &ctx(&AllowAll),
            )
            .await
        })
    };
    assert!(
        run(false, None).await.is_none(),
        "E9u: a visible target was answered"
    );
    assert!(
        run(true, None).await.is_none(),
        "E9u: a proven Lacked target was answered"
    );
    let failed = run(
        true,
        Some(crate::Error::Transport("e9u fill refused".into())),
    )
    .await
    .expect("E9u: a Lacked target's failed fill went unanswered");
    let text = serde_json::to_value(&failed).expect("JSON").to_string();
    assert!(
        text.contains("e9u fill refused"),
        "E9u: not the fill's answer: {text}"
    );
}

/// MIK-8498 VISIBLE characterisation: a second carry for one target replaces
/// the first; a read leaves it in place; a take consumes it once. Two live
/// resolutions, told apart by their fill result.
#[tokio::test]
async fn a_second_carry_replaces_the_first_and_a_take_consumes_it() {
    let (_gateway, meta) = connected();
    visible::memo::with_visibility_memo(async {
        carry(&meta, None).await;
        carry(&meta, Some(crate::Error::Transport("second".into()))).await;
        let failed = |carried: &Carried| carried.fill_error.is_some();
        assert_eq!(
            visible::memo::with_carried(BACKEND, TOOL, failed),
            Some(true)
        );
        assert_eq!(
            visible::memo::with_carried(BACKEND, TOOL, failed),
            Some(true),
            "a read keeps it"
        );
        for (server, tool) in [("other", TOOL), (BACKEND, "other")] {
            assert_eq!(visible::memo::with_carried(server, tool, failed), None);
            assert!(visible::memo::take_carried(server, tool).is_none());
        }
        assert!(visible::memo::take_carried(BACKEND, TOOL).is_some_and(|c| c.fill_error.is_some()));
        assert!(
            visible::memo::take_carried(BACKEND, TOOL).is_none(),
            "taken once"
        );
    })
    .await;
    // Outside a memo a carry is dropped: nothing to read or take, here or in
    // a scope opened after it.
    carry(&meta, None).await;
    assert!(visible::memo::with_carried(BACKEND, TOOL, |_| ()).is_none());
    assert!(visible::memo::take_carried(BACKEND, TOOL).is_none());
    visible::memo::with_visibility_memo(async {
        assert!(visible::memo::take_carried(BACKEND, TOOL).is_none());
    })
    .await;
}

/// Lift `(BACKEND, TOOL)`'s deferred entry, recorded under `recorded` behind
/// a step on another backend recorded as unbound, for a resolution that
/// proved `proved` (`None`: the account it really proved). Returns the
/// answer (panicking if the lift neither served nor refused the entry), the
/// requests the backend received, the target's binding now, and the binding
/// recorded for it, so each row can pin which half of the judgement fails.
async fn lift_recorded(recorded: Option<String>, proved: Option<String>) -> Lifted {
    use crate::gateway::meta_mcp::MetaMcpCallerContext;
    use crate::gateway::meta_mcp::visible::deferred::{DeferredReplay, deferred_replay_key};
    use crate::gateway::meta_mcp::visible::memo::record_deferred_replay;
    use std::ops::ControlFlow;
    let (gateway, meta) = connected();
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let mut resolved = meta
        .resolve_dispatch(
            (BACKEND, TOOL),
            Some(&backend),
            CallerProof::new(None, CallerProvenance::Credential),
            None,
        )
        .await
        .expect("premise: the operator's live grant resolves");
    let current = resolved.account.clone();
    assert!(
        current.is_some(),
        "premise: the resolution names its account"
    );
    if proved.is_some() {
        resolved.account = proved;
    }
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("lift-key".to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..ctx(&AllowAll)
    };
    let now = meta.current_binding(
        &meta.scoped(caller.scope().authorizer.backend_grant()),
        BACKEND,
        TOOL,
    );
    let recorded = recorded.or(current);
    let key = deferred_replay_key(BACKEND, TOOL, &retry).expect("a keyed call");
    let deferred = DeferredReplay {
        response: crate::protocol::JsonRpcResponse::success(
            RequestId::Number(9),
            serde_json::json!({"content": [{"type": "text", "text": "lift-stored"}]}),
        ),
        audit: None,
        audit_server: None,
        tool_name: "gateway_invoke".to_owned(),
        arguments: serde_json::json!({}),
        bindings: vec![
            ("another-backend".to_owned(), TOOL.to_owned(), None),
            (BACKEND.to_owned(), TOOL.to_owned(), recorded.clone()),
        ],
    };
    let flow = visible::memo::with_visibility_memo(async {
        assert!(record_deferred_replay(key, deferred), "premise: deferred");
        let mut witness = super::super::nonce_settle::Witnessed::take(&caller);
        meta.lift_deferred((BACKEND, TOOL), &resolved, &mut witness, None, &caller)
            .await
    })
    .await;
    let ControlFlow::Break(answer) = flow else {
        panic!("the lift neither served nor refused the deferred entry");
    };
    Lifted {
        text: serde_json::to_string(&answer).expect("JSON"),
        dispatched: gateway.dispatched(),
        now,
        recorded,
    }
}

/// What [`lift_recorded`] observed.
struct Lifted {
    text: String,
    dispatched: usize,
    now: Option<String>,
    recorded: Option<String>,
}

/// The refusal both lift rows expect: the re-bind error, no stored output,
/// nothing sent.
fn assert_lift_refused(row: &str, lifted: &Lifted) {
    let (text, dispatched) = (&lifted.text, lifted.dispatched);
    assert!(
        text.contains("produced under a different account"),
        "{row}: the lift did not refuse the re-bound entry: {text}"
    );
    assert!(!text.contains("lift-stored"), "{row}: served: {text}");
    assert_eq!(dispatched, 0, "{row}: the lift sent the call");
}

/// MIK-8407 lift judgement, the resolution half (mutant: the lift ignores
/// the account its resolution proved). The entry was recorded under the
/// target's current binding, but this resolution proved another account, as
/// when a reload lands between deferral and dispatch. Only the comparison
/// against the proved account fails; the current-binding judgement passes.
/// The other backend's step is judged against its binding now, which still
/// matches.
#[tokio::test]
async fn a_deferred_replay_under_another_binding_is_refused_at_the_lift() {
    let lifted = lift_recorded(None, Some("not-this-account#0".to_owned())).await;
    assert_eq!(
        lifted.now, lifted.recorded,
        "premise: the binding now matches the record, so only the proved half refuses"
    );
    assert_lift_refused("lift, proved", &lifted);
}

/// MIK-8407 lift judgement, the current-binding half (mutant: the lift
/// skips the judgement against the target's binding now). The resolution
/// proved the recorded account, but the target is bound to another one now.
/// Only the current-binding judgement fails.
#[tokio::test]
async fn a_deferred_replay_whose_target_is_bound_elsewhere_now_is_refused_at_the_lift() {
    let recorded = Some("recorded-account#0".to_owned());
    let lifted = lift_recorded(recorded.clone(), recorded).await;
    assert_ne!(
        lifted.now, lifted.recorded,
        "premise: the binding now differs from the record the resolution proved"
    );
    assert_lift_refused("lift, current", &lifted);
}

/// MIK-8520 R4 (M4): a deferred replay of the surfaced name `TOOL`, admitted
/// for `BACKEND` and lifted after the surfaced map moves to `beta`, is
/// recorded under `BACKEND`, the server it was admitted for.
#[tokio::test]
async fn r4_a_lifted_surfaced_replay_records_the_admitted_server() {
    use crate::gateway::meta_mcp::MetaMcpCallerContext;
    use crate::gateway::meta_mcp::visible::deferred::{DeferredReplay, deferred_replay_key};
    use crate::gateway::meta_mcp::visible::memo::record_deferred_replay;
    use std::ops::ControlFlow;
    let dir = tempfile::tempdir().unwrap();
    let (_gateway, meta) = connected();
    let mut meta = meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: BACKEND.to_string(),
        tool: TOOL.to_string(),
    }]);
    let logger = crate::security::TransparencyLogger::open(std::sync::Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "r4".to_string(),
            ..Default::default()
        },
    ))
    .expect("open log");
    meta.enable_transparency_log(std::sync::Arc::new(logger));
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let resolved = meta
        .resolve_dispatch(
            (BACKEND, TOOL),
            Some(&backend),
            CallerProof::new(None, CallerProvenance::Credential),
            None,
        )
        .await
        .expect("premise: the operator's live grant resolves");
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("r4-key".to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..ctx(&AllowAll)
    };
    let recorded = meta.current_binding(
        &meta.scoped(caller.scope().authorizer.backend_grant()),
        BACKEND,
        TOOL,
    );
    let key = deferred_replay_key(BACKEND, TOOL, &retry).expect("a keyed call");
    let deferred = DeferredReplay {
        response: crate::protocol::JsonRpcResponse::success(
            RequestId::Number(11),
            serde_json::json!({"content": [{"type": "text", "text": "r4-stored"}]}),
        ),
        audit: None,
        audit_server: Some(BACKEND.to_owned()),
        tool_name: TOOL.to_owned(),
        arguments: serde_json::json!({}),
        bindings: vec![(BACKEND.to_owned(), TOOL.to_owned(), recorded)],
    };
    meta.resurface_for_test(TOOL, "beta");
    let flow = visible::memo::with_visibility_memo(async {
        assert!(record_deferred_replay(key, deferred), "premise: deferred");
        let mut witness = super::super::nonce_settle::Witnessed::take(&caller);
        meta.lift_deferred((BACKEND, TOOL), &resolved, &mut witness, None, &caller)
            .await
    })
    .await;
    let ControlFlow::Break(answer) = flow else {
        panic!("premise: the lift served the deferred entry");
    };
    assert!(answer.error.is_none(), "premise: served: {answer:?}");
    let servers: Vec<String> = std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .map(|entry| entry["server"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        servers,
        vec![BACKEND.to_owned()],
        "R4: the lifted replay's record names the live map's server, not the admitted one"
    );
}

/// MIK-8520 R7b (M7): a deferred continuation-origin replay carries no audit
/// server, so the lift records nothing for it, as before; taking the server
/// from the lift's dispatch pair would start recording it.
#[tokio::test]
async fn r7b_a_lifted_continuation_origin_replay_writes_no_record() {
    use crate::gateway::meta_mcp::MetaMcpCallerContext;
    use crate::gateway::meta_mcp::visible::deferred::{DeferredReplay, deferred_replay_key};
    use crate::gateway::meta_mcp::visible::memo::record_deferred_replay;
    use std::ops::ControlFlow;
    let dir = tempfile::tempdir().unwrap();
    let (_gateway, meta) = connected();
    let mut meta = meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: BACKEND.to_string(),
        tool: TOOL.to_string(),
    }]);
    let logger = crate::security::TransparencyLogger::open(std::sync::Arc::new(
        crate::security::transparency_log::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "r7b".to_string(),
            ..Default::default()
        },
    ))
    .expect("open log");
    meta.enable_transparency_log(std::sync::Arc::new(logger));
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let resolved = meta
        .resolve_dispatch(
            (BACKEND, TOOL),
            Some(&backend),
            CallerProof::new(None, CallerProvenance::Credential),
            None,
        )
        .await
        .expect("premise: the operator's live grant resolves");
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("r7b-key".to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..ctx(&AllowAll)
    };
    let recorded = meta.current_binding(
        &meta.scoped(caller.scope().authorizer.backend_grant()),
        BACKEND,
        TOOL,
    );
    let key = deferred_replay_key(BACKEND, TOOL, &retry).expect("a keyed call");
    let deferred = DeferredReplay {
        response: crate::protocol::JsonRpcResponse::success(
            RequestId::Number(11),
            serde_json::json!({"content": [{"type": "text", "text": "r4-stored"}]}),
        ),
        audit: None,
        audit_server: None,
        tool_name: "continued".to_owned(),
        arguments: serde_json::json!({}),
        bindings: vec![(BACKEND.to_owned(), TOOL.to_owned(), recorded)],
    };
    let flow = visible::memo::with_visibility_memo(async {
        assert!(record_deferred_replay(key, deferred), "premise: deferred");
        let mut witness = super::super::nonce_settle::Witnessed::take(&caller);
        meta.lift_deferred((BACKEND, TOOL), &resolved, &mut witness, None, &caller)
            .await
    })
    .await;
    let ControlFlow::Break(answer) = flow else {
        panic!("premise: the lift served the deferred entry");
    };
    assert!(answer.error.is_none(), "premise: served: {answer:?}");
    let servers: Vec<String> = std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| {
            entry.get("tool").is_some() && entry["event"] != "response_delivery_attempt"
        })
        .map(|entry| entry["server"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(
        servers.is_empty(),
        "R7b: a lifted continuation-origin replay wrote a record under {servers:?}"
    );
}
