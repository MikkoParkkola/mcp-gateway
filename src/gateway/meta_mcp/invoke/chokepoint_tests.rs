// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 b1: the chokepoint's own rows, at the meta layer (gpt i1 on #3688).

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::gateway::auth::QuotaPrincipal;
use crate::gateway::authz::{
    AllowAll, AuthorizationError, Decision, ToolAuthorizer, ToolTarget, Transport,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{
    counted_backend, counted_listing_backend, ctx, invoke_args,
};

/// Allows the first `allowed` decisions, then refuses: a grant revoked after
/// the call was authorized and before it is sent.
struct RevokedAfter {
    allowed: usize,
    decided: AtomicUsize,
}

impl ToolAuthorizer for RevokedAfter {
    fn quota_principal(&self) -> Option<&QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> crate::gateway::authz::BackendGrant<'_> {
        crate::gateway::authz::BackendGrant::Unscoped
    }
    fn decide<'a>(&'a self, target: ToolTarget<'a>) -> Decision<'a> {
        if self.decided.fetch_add(1, Ordering::SeqCst) < self.allowed {
            return AllowAll.decide(target);
        }
        Decision::of(Err(AuthorizationError::forbidden(
            -32003,
            "grant revoked".to_owned(),
        )))
    }
    fn admits_backend(&self, _server: &str) -> bool {
        true
    }
    fn transport(&self) -> Transport {
        AllowAll.transport()
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// F5: a grant revoked between the call's authorization and its send is
/// refused at the chokepoint: the decision taken at admission is not reused,
/// and the backend is never reached. Control: the same call with the grant
/// kept is sent. Mutant: the chokepoint skipping `recheck_target`.
#[tokio::test]
async fn f5_a_grant_revoked_before_the_send_is_refused_at_dispatch() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let kept = RevokedAfter {
        allowed: usize::MAX,
        decided: AtomicUsize::new(0),
    };
    let sent = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&kept))
        .await;
    assert!(sent.is_ok(), "control: a kept grant is sent: {sent:?}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "control: the backend was reached"
    );

    // MIK-8361: the withheld gate decides first, so the grant holds for the
    // gate's and admission's decisions and is revoked before the send.
    let revoked = RevokedAfter {
        allowed: 2,
        decided: AtomicUsize::new(0),
    };
    let refused = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&revoked))
        .await;
    assert!(
        matches!(refused, Err(crate::Error::Forbidden { .. })),
        "refused at the chokepoint: {refused:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the revoked call reached its backend"
    );
    assert_eq!(
        revoked.decided.load(Ordering::SeqCst),
        3,
        "decided at the gate, at admission and again at dispatch"
    );
}

/// R-choke-fresh (MIK-8353 3a, gpt code r1): a signed call whose grant is
/// revoked before the send is refused at the chokepoint with nothing acted
/// (the schema warm, no mint, no continuation), so it keeps its witness and
/// gives the nonce back: a later call admits the same nonce. The control for
/// K-choke-consume. Mutants: mKeep, mCarryDrop.
#[tokio::test]
async fn a_chokepoint_refusal_with_nothing_acted_gives_the_nonce_back() {
    use crate::gateway::meta_mcp::refund_witness::RefundWitness;
    use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
    const NONCE: &str = "choke-fresh-nonce";
    let signed = |name: &str, arguments: &serde_json::Value| {
        let mut request = serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): NONCE}}});
        let context =
            SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
        (context, request["params"]["arguments"].clone())
    };
    let (registry, calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"choke-fresh-key-0123456789abcdef".to_vec(),
            None,
            "k1".into(),
        ),
        std::time::Duration::from_secs(300),
        true,
    );
    let warm = meta
        .invoke_tool(&invoke_args("alpha", "read"), None, &ctx(&AllowAll))
        .await;
    assert!(warm.is_ok(), "premise: the warm-up was sent: {warm:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // MIK-8361: admission decides twice and the withheld gate once, so the
    // grant is revoked at the fourth decision, the chokepoint's.
    let revoked = RevokedAfter {
        allowed: 3,
        decided: AtomicUsize::new(0),
    };
    let mut caller = ctx(&revoked);
    let (mut signing, arguments) = signed("gateway_invoke", &invoke_args("alpha", "read"));
    meta.prepare_signing_for_call(&mut signing, "gateway_invoke", &arguments, None, &caller)
        .expect("the refusal is the chokepoint's");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    // What admission leaves on the context on both adapters.
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        "gateway_invoke",
        arguments,
        None,
        caller,
    ))
    .await;
    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert!(
        wire.to_string().contains("grant revoked"),
        "refused at the chokepoint: {wire}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backend was not reached"
    );

    let (mut later, arguments) = signed("gateway_list_servers", &serde_json::json!({}));
    let permitted = ctx(&AllowAll);
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &permitted,
    )
    .expect("the nonce was given back");
    assert!(
        !later.awaits_admission(),
        "the nonce was kept though nothing acted: {wire}"
    );
}

/// K-choke-cold (MIK-8361, MIK-8353 3a): the twin of R-choke-fresh with no
/// warm-up, so the gate judges a cold catalogue and fills it before the
/// chokepoint refuses. The fill is an effect: the nonce stays spent.
/// Mutant: MW2 (the gate's fill not carried).
#[tokio::test]
async fn a_chokepoint_refusal_after_the_gate_fills_keeps_the_nonce() {
    use crate::gateway::meta_mcp::refund_witness::RefundWitness;
    use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
    const NONCE: &str = "choke-cold-nonce";
    let signed = |name: &str, arguments: &serde_json::Value| {
        let mut request = serde_json::json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): NONCE}}});
        let context =
            SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
        (context, request["params"]["arguments"].clone())
    };
    let (registry, calls) = counted_listing_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"choke-fresh-key-0123456789abcdef".to_vec(),
            None,
            "k1".into(),
        ),
        std::time::Duration::from_secs(300),
        true,
    );
    let alpha = meta
        .backends
        .for_test()
        .get("alpha")
        .expect("fixture backend");
    let fills = alpha.list_fills();

    let revoked = RevokedAfter {
        allowed: 3,
        decided: AtomicUsize::new(0),
    };
    let mut caller = ctx(&revoked);
    let (mut signing, arguments) = signed("gateway_invoke", &invoke_args("alpha", "read"));
    meta.prepare_signing_for_call(&mut signing, "gateway_invoke", &arguments, None, &caller)
        .expect("the refusal is the chokepoint's");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    // What admission leaves on the context on both adapters.
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(7),
        "gateway_invoke",
        arguments,
        None,
        caller,
    ))
    .await;
    let wire = serde_json::to_value(&response).expect("a response serializes");
    assert!(
        wire.to_string().contains("grant revoked"),
        "refused at the chokepoint: {wire}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the backend was not reached"
    );
    assert!(alpha.list_fills() > fills, "the gate filled tools/list");

    let (mut later, arguments) = signed("gateway_list_servers", &serde_json::json!({}));
    let permitted = ctx(&AllowAll);
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &permitted,
    )
    .expect_err("the gate's fill keeps the nonce spent");
}

/// The chokepoint's folder check, called directly: the route scan refuses an
/// outside path first, so no end-to-end row reaches it (defence in depth).
/// Dispatched arguments are scanned as `Arguments` and judged; a retry's
/// answers are scanned as `Answers` and never path-checked. Mutant M5b, the
/// arguments labelled as answers, must turn this red.
#[cfg(feature = "firewall")]
#[test]
fn the_chokepoint_judges_dispatched_arguments_not_answers() {
    use std::sync::Arc;

    use serde_json::json;

    use super::{Outbound, Source};
    use crate::backend::{Backend, BackendRegistry};
    use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
    use crate::gateway::meta_mcp::InvokeScope;
    use crate::gateway::router::CallerStanding;
    use crate::security::firewall::{
        Firewall, FirewallAction, FirewallConfig, FirewallRule, plain_rule,
    };

    let dir = tempfile::tempdir().expect("tempdir");
    for sub in ["safe", "outside"] {
        std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
    }
    let path = |rel: &str| dir.path().join(rel).to_string_lossy().into_owned();
    let registry = Arc::new(BackendRegistry::new());
    let stdio = TransportConfig::Stdio {
        command: "true".to_string(),
        cwd: None,
        protocol_version: None,
    };
    let fs = Arc::new(Backend::new(
        "fs",
        BackendConfig {
            transport: stdio,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&fs)));
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    let rule = FirewallRule {
        allowed_roots: Some(vec![path("safe")]),
        path_args: Some(vec!["path".to_string()]),
        ..plain_rule("read_file", FirewallAction::Block)
    };
    let config = FirewallConfig {
        rules: vec![rule],
        ..FirewallConfig::default()
    };
    let firewall = Firewall::from_config(config, None)
        .with_continuations(meta.continuation())
        .with_registries(Arc::clone(&registry), meta.capability_slot());
    meta.set_firewall(Some(Arc::new(firewall)));

    let send = |arguments: &serde_json::Value, answers: Option<&serde_json::Value>| {
        let outbound = Outbound {
            arguments,
            answers,
            backend: Some(&fs),
        };
        let scope = InvokeScope::allow_all(CallerStanding::Standard);
        meta.rescan_outbound(scope, None, ("fs", "read_file"), &outbound, Source::Invoke)
    };
    let outside = json!({"path": path("outside/f")});
    let inside = json!({"path": path("safe/f")});
    let refused = send(&outside, None).expect_err("outside arguments are refused");
    assert!(
        refused.to_string().contains("path_outside_root"),
        "judged by the folder check: {refused}"
    );
    send(&inside, None).expect("inside arguments pass");
    // A retry's answers carry no path argument and are not path-checked.
    let answers = json!({"approval": "yes"});
    send(&inside, Some(&answers)).expect("a retry of an inside call passes");
}
