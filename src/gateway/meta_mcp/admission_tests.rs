// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Component falsifiers of current-policy and operation-definition admission.
//! Explicit secured settlement is setup, not backend/transport acceptance.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use super::*;
use crate::backend::BackendRegistry;
use crate::gateway::authz::{AuthorizationError, ToolAuthorizer, ToolTarget, Transport};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::protocol::mrtr::RetryFields;

const SECRET: &str = "only-the-currently-authorized-caller-may-read-this";
const FIRST: (&str, &str) = ("alpha", "read_record");
const SECOND: (&str, &str) = ("beta", "read_private");

struct MutablePolicy {
    revoked: AtomicBool,
    denied_target: (&'static str, &'static str),
    seen: Mutex<Vec<(String, String)>>,
}

impl MutablePolicy {
    fn new(denied_target: (&'static str, &'static str)) -> Self {
        Self {
            revoked: AtomicBool::new(false),
            denied_target,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn assert_saw(&self, targets: &[(&str, &str)]) {
        let seen = self.seen.lock();
        for (server, tool) in targets {
            assert!(
                seen.iter()
                    .any(|target| target.0 == *server && target.1 == *tool),
                "current authorization did not observe {server}:{tool}: {seen:?}"
            );
        }
    }
}

impl ToolAuthorizer for MutablePolicy {
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }

    fn authorize(&self, target: ToolTarget<'_>) -> std::result::Result<(), AuthorizationError> {
        self.seen
            .lock()
            .push((target.server.into(), target.tool.into()));
        if self.revoked.load(Ordering::SeqCst) && (target.server, target.tool) == self.denied_target
        {
            Err(AuthorizationError::forbidden(-32003, "permission revoked"))
        } else {
            Ok(())
        }
    }
    fn transport(&self) -> Transport {
        Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        Some("same-display-label")
    }
}

fn context<'a>(policy: &'a MutablePolicy, retry: &'a RetryFields) -> MetaMcpCallerContext<'a> {
    MetaMcpCallerContext {
        task: None,
        execution: None,
        signing: None,
        is_modern: true,
        protocol_revision: None,
        credential_principal: Some("verified-credential-owner"),
        authorizer: policy,
        api_key_name: Some("same-display-label"),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        retry,
        era: crate::protocol::meta::Era::Modern,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

fn original_plan() -> crate::playbook::PlaybookDefinition {
    serde_json::from_value(json!({
        "name":"protected-plan", "description":"same semantic definition",
        "steps":[
            {"name":"first", "server":FIRST.0, "tool":FIRST.1, "arguments":{"record":"initial"}},
            {"name":"second", "server":SECOND.0, "tool":SECOND.1, "arguments":{"record":"public"}}
        ]
    }))
    .unwrap()
}

fn install_plan(meta: &MetaMcp, definition: crate::playbook::PlaybookDefinition) {
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
}

fn admit(
    meta: &MetaMcp,
    caller: &MetaMcpCallerContext<'_>,
    tool: &str,
    args: &Value,
    id: i64,
) -> Result<SyncAdmission> {
    meta.admit_meta_sync(
        caller,
        tool,
        args,
        Some("legacy:session"),
        &RequestId::Number(id),
    )
}

fn assert_replay(result: Result<SyncAdmission>, id: i64) {
    let Ok(SyncAdmission::Replay(response)) = result else {
        panic!("unchanged allowed operation must replay its retained secured result");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    assert_eq!(response.result.unwrap()["secret"], SECRET);
}

fn retained_operation(meta: &MetaMcp, caller: &MetaMcpCallerContext<'_>, tool: &str, args: &Value) {
    let Ok(SyncAdmission::Owned(owner)) = admit(meta, caller, tool, args, 1) else {
        panic!("initial allowed operation must own the real shared admission slot");
    };
    owner.mark_dispatched();
    owner.complete_secured(&JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"secret":SECRET}),
    ));
    assert_replay(admit(meta, caller, tool, args, 2), 2);
}

fn refusal(result: Result<SyncAdmission>) -> Error {
    let Err(error) = result else {
        panic!("request must refuse before exposing retained output")
    };
    assert!(
        !error.to_string().contains(SECRET),
        "refusal exposed secured content"
    );
    error
}

fn revoked_replay(
    is_modern: bool,
    tool: &str,
    args: Value,
    changed_args: Value,
    targets: &[(&'static str, &'static str)],
) {
    let meta =
        MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(tool == "gateway_execute");
    // No planted playbook can accidentally satisfy the code-mode oracle.
    if tool == "gateway_run_playbook" {
        install_plan(&meta, original_plan());
    }
    let policy = MutablePolicy::new(*targets.last().unwrap());
    let retry = RetryFields {
        idempotency_key: Some("same-key".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    // Seed in modern mode; the legacy case must reuse this same owner's key
    // across the protocol transition rather than merely replay legacy work.
    retained_operation(&meta, &caller, tool, &args);
    caller.is_modern = is_modern;
    policy.revoked.store(true, Ordering::SeqCst);
    for request in [&args, &changed_args] {
        policy.seen.lock().clear();
        let error = refusal(admit(&meta, &caller, tool, request, 3));
        assert!(
            matches!(
                error,
                Error::Forbidden {
                    code: -32003,
                    status: 403,
                    ..
                }
            ),
            "current policy must win over a deliberate fingerprint mismatch: {error}"
        );
        policy.assert_saw(targets);
    }
    // Denial cannot discard the original owner. Restored current permission
    // must find the same secured outcome, not a newly admitted operation.
    policy.revoked.store(false, Ordering::SeqCst);
    assert_replay(admit(&meta, &caller, tool, &args, 4), 4);
}

#[test]
fn sub4_replay_current_policy_single_target_control() {
    revoked_replay(
        true,
        "gateway_invoke",
        json!({"server":FIRST.0, "tool":FIRST.1, "arguments":{"record":"original"}}),
        json!({"server":FIRST.0, "tool":FIRST.1, "arguments":{"record":"changed"}}),
        &[FIRST],
    );
}

#[test]
fn sub4_replay_current_policy_code_mode_revocation() {
    let args = json!({"chain":[
        {"tool":"alpha:read_record", "arguments":{"record":"original"}},
        {"tool":"beta:read_private", "arguments":{"record":"second"}}
    ]});
    let mut changed = args.clone();
    changed["chain"][0]["arguments"]["record"] = json!("changed");
    revoked_replay(true, "gateway_execute", args, changed, &[FIRST, SECOND]);
}

#[test]
fn sub4_replay_current_policy_playbook_revocation() {
    revoked_replay(
        true,
        "gateway_run_playbook",
        json!({"name":"protected-plan", "arguments":{"record":"original"}}),
        json!({"name":"protected-plan", "arguments":{"record":"changed"}}),
        &[FIRST, SECOND],
    );
}

#[test]
fn sub4_replay_changed_playbook_definition_conflicts() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let original = original_plan();
    install_plan(&meta, original.clone());
    let policy = MutablePolicy::new(SECOND);
    let retry = RetryFields {
        idempotency_key: Some("same-key".into()),
        ..RetryFields::default()
    };
    let caller = context(&policy, &retry);
    let args = json!({"name":"protected-plan", "arguments":{}});
    retained_operation(&meta, &caller, "gateway_run_playbook", &args);
    // A generation-only fingerprint rejects this equivalent engine reload.
    install_plan(&meta, original.clone());
    assert_replay(admit(&meta, &caller, "gateway_run_playbook", &args, 3), 3);
    // Same count, target names, and encoded length: only a semantic argument
    // changes. Count-only, target-only and size-only fingerprints must fail.
    let mut changed = original.clone();
    changed.steps[1]
        .arguments
        .insert("record".into(), json!("secret"));
    assert_eq!(
        serde_json::to_vec(&original).unwrap().len(),
        serde_json::to_vec(&changed).unwrap().len()
    );
    install_plan(&meta, changed);
    let error = refusal(admit(&meta, &caller, "gateway_run_playbook", &args, 4));
    assert_eq!(
        error.to_rpc_code(),
        409,
        "changed semantic plan must be an exact mismatch"
    );
    let fresh_retry = RetryFields {
        idempotency_key: Some("deliberately-new-key".into()),
        ..RetryFields::default()
    };
    assert!(
        matches!(
            admit(
                &meta,
                &context(&policy, &fresh_retry),
                "gateway_run_playbook",
                &args,
                5
            ),
            Ok(SyncAdmission::Owned(_))
        ),
        "a new deliberate key admits the changed plan"
    );
    install_plan(&meta, original);
    assert_replay(admit(&meta, &caller, "gateway_run_playbook", &args, 6), 6);
}

#[test]
fn sub4_replay_current_policy_legacy_keyed_opt_in() {
    revoked_replay(
        false,
        "gateway_run_playbook",
        json!({"name":"protected-plan", "arguments":{"record":"original"}}),
        json!({"name":"protected-plan", "arguments":{"record":"changed"}}),
        &[FIRST, SECOND],
    );
}

#[test]
fn sub4_preflight_preserves_legacy_unkeyed_per_step_authorization() {
    for tool in ["gateway_execute", "gateway_run_playbook"] {
        let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
            .with_code_mode(tool == "gateway_execute");
        if tool == "gateway_run_playbook" {
            install_plan(&meta, original_plan());
        }
        let policy = MutablePolicy::new(SECOND);
        policy.revoked.store(true, Ordering::SeqCst);
        let retry = RetryFields::default();
        let mut caller = context(&policy, &retry);
        caller.is_modern = false;
        let args = if tool == "gateway_run_playbook" {
            json!({"name":"protected-plan", "arguments":{}})
        } else {
            json!({"chain":[{"tool":"alpha:read_record"},{"tool":"beta:read_private"}]})
        };
        assert!(
            matches!(
                admit(&meta, &caller, tool, &args, 1),
                Ok(SyncAdmission::Unprotected)
            ),
            "legacy unkeyed orchestration keeps its existing per-step checks"
        );
        assert!(
            policy.seen.lock().is_empty(),
            "new eager preflight must be keyed-only"
        );
    }
}

fn profile_replay(tool: &str, args: Value, changed_args: Value) {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let profiles = std::collections::HashMap::from([
        (
            "restricted".into(),
            RoutingProfileConfig {
                deny_tools: Some(vec![SECOND.1.into()]),
                ..RoutingProfileConfig::default()
            },
        ),
        ("open".into(), RoutingProfileConfig::default()),
    ]);
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_code_mode(tool == "gateway_execute")
        .with_profile_registry(ProfileRegistry::from_config(&profiles, "open"));
    if tool == "gateway_run_playbook" {
        install_plan(&meta, original_plan());
    }
    let policy = MutablePolicy::new(SECOND);
    let retry = RetryFields {
        idempotency_key: Some("profile-bound-owner".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    caller.is_modern = false;
    retained_operation(&meta, &caller, tool, &args);
    meta.session_profiles()
        .set_profile("legacy:session", "restricted");
    assert!(meta.active_profile(None).check(SECOND.0, SECOND.1).is_ok());
    for request in [&args, &changed_args] {
        let error = refusal(admit(&meta, &caller, tool, request, 3));
        assert!(
            matches!(&error, Error::Protocol(message)
                if message.contains("routing profile") && message.contains(SECOND.1)),
            "the current session profile must refuse before mismatch/replay: {error}"
        );
    }
    meta.session_profiles()
        .set_profile("legacy:session", "open");
    assert_replay(admit(&meta, &caller, tool, &args, 4), 4);
}

#[test]
fn sub4_replay_current_profile_playbook() {
    profile_replay(
        "gateway_run_playbook",
        json!({"name":"protected-plan", "arguments":{"record":"original"}}),
        json!({"name":"protected-plan", "arguments":{"record":"changed"}}),
    );
}

#[test]
fn sub4_replay_current_profile_code_mode() {
    profile_replay(
        "gateway_execute",
        json!({"chain":[{"tool":format!("{}:{}",FIRST.0,FIRST.1)},
            {"tool":format!("{}:{}",SECOND.0,SECOND.1),"arguments":{"record":"original"}}]}),
        json!({"chain":[{"tool":format!("{}:{}",FIRST.0,FIRST.1)},
            {"tool":format!("{}:{}",SECOND.0,SECOND.1),"arguments":{"record":"changed"}}]}),
    );
}

#[test]
fn sub4_replay_current_profile_single_target() {
    profile_replay(
        "gateway_invoke",
        json!({"server":SECOND.0,"tool":SECOND.1,"arguments":{"record":"original"}}),
        json!({"server":SECOND.0,"tool":SECOND.1,"arguments":{"record":"changed"}}),
    );
}

/// SUB4.REPLAY.PLAN.1: the definition fingerprinted at admission must also
/// supply the attempted dispatch after a concurrent engine replacement.
/// No backend outcome is claimed: the recording authorizer observes the real
/// invoker target before the deliberately absent backend refuses execution.
#[tokio::test]
async fn sub4_playbook_dispatch_uses_admitted_definition() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let original = original_plan();
    install_plan(&meta, original.clone());
    let policy = MutablePolicy::new(SECOND);
    let retry = RetryFields {
        idempotency_key: Some("snapshot-owner".into()),
        ..RetryFields::default()
    };
    let mut caller = context(&policy, &retry);
    let args = json!({"name":"protected-plan", "arguments":{}});
    let SyncAdmission::Owned(lease) =
        admit(&meta, &caller, "gateway_run_playbook", &args, 1).expect("initial plan is admitted")
    else {
        panic!("first keyed call must own execution");
    };
    let mut changed = original;
    changed.steps[0].server = "replacement".into();
    install_plan(&meta, changed);
    caller.execution = Some(&lease);
    policy.seen.lock().clear();
    let _outcome = meta.run_playbook(&args, &caller).await;
    assert_eq!(
        *policy.seen.lock(),
        vec![
            (FIRST.0.to_string(), FIRST.1.to_string()),
            (SECOND.0.to_string(), SECOND.1.to_string()),
        ],
        "dispatch must use the admitted definition, not the replacement engine"
    );

    // A new owner must observe the new definition. This rules out preserving
    // an old/global plan or ignoring engine replacement altogether.
    let fresh_retry = RetryFields {
        idempotency_key: Some("replacement-owner".into()),
        ..RetryFields::default()
    };
    let mut fresh_caller = context(&policy, &fresh_retry);
    let SyncAdmission::Owned(fresh_lease) =
        admit(&meta, &fresh_caller, "gateway_run_playbook", &args, 2)
            .expect("replacement plan is admitted")
    else {
        panic!("fresh key must own the replacement execution");
    };
    fresh_caller.execution = Some(&fresh_lease);
    policy.seen.lock().clear();
    let _outcome = meta.run_playbook(&args, &fresh_caller).await;
    assert_eq!(
        *policy.seen.lock(),
        vec![
            ("replacement".to_string(), FIRST.1.to_string()),
            (SECOND.0.to_string(), SECOND.1.to_string()),
        ]
    );
}
