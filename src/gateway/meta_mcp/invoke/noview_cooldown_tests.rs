// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 in-process rows: where the error-rate cooldown is met relative to
//! the invocation policy and the dispatch's resolution. R5 (shared backend,
//! admission), R10 (cooldown armed after the policy), R11 (the refund witness
//! after a resolving refusal), R12 (a reload from per-user to shared between
//! the policy and the dispatch), R13 (a profile set in that window). R10, R12
//! and R13 change state through [`super::dispatch_seam`].

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;

use super::dispatch_seam::before_dispatch_resolution;
use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::account_resolver_fixture::caller_as;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway, cooldown_refusal,
};
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx, invoke_args};
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::gateway::server::account_bindings::ServeMode;
use crate::kill_switch::KillSwitch;

const TOOL: &str = "read";

/// Push `server`'s `tool` into error-rate cooldown, as other callers'
/// failures would.
fn cool(kill_switch: &KillSwitch, server: &str, tool: &str) {
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(server, tool, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(server, tool),
        "premise: {server}:{tool} is in cooldown"
    );
}

/// The sole operator's stdio Meta-MCP over the managed per-user [`BACKEND`],
/// connected, its slot seeded so a dispatch stays in process.
fn per_user(arm: impl FnOnce(&mut MetaMcp)) -> (DirectAccountGateway, MetaMcp) {
    let mut gateway = DirectAccountGateway::new_in(
        ServeMode::Stdio,
        crate::config::AuthConfig::default(),
        &Binding::Connected,
    );
    let mut meta = gateway.take_meta();
    arm(&mut meta);
    let backend = gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend.keeps_per_user_catalogues(),
        "premise: {BACKEND} keeps per-user catalogues"
    );
    (gateway, meta)
}

fn operator() -> MetaMcpCallerContext<'static> {
    caller_as(None, Some(STDIO_CREDENTIAL_PRINCIPAL))
}

fn operator_args() -> serde_json::Value {
    json!({"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}})
}

/// R5 (control, green at base): on a shared backend the policy keeps the
/// cooldown check, so a plain `gateway_invoke` of a tool in cooldown is
/// refused at admission, before anything runs. Kills M4 (the policy skip
/// for every backend).
#[test]
fn r5_shared_backend_cooldown_is_refused_at_admission() {
    let (registry, calls) = counted_backend("beta");
    let meta = MetaMcp::new(registry);
    cool(&meta.kill_switch(), "beta", TOOL);
    let retry = crate::protocol::mrtr::RetryFields::default();
    let caller = MetaMcpCallerContext {
        retry: &retry,
        is_modern: true,
        credential_principal: Some("verified-credential-owner"),
        ..ctx(&AllowAll)
    };
    let admitted = meta.admit_meta_sync_for_test(
        AdmissionOwner::for_test(caller.owner_principal()),
        &caller,
        "gateway_invoke",
        &invoke_args("beta", TOOL),
        Some("legacy:session"),
        &crate::protocol::RequestId::Number(1),
    );
    let Err(error) = admitted else {
        panic!("R5: admission let a shared tool in cooldown through");
    };
    assert!(
        error.to_string().contains(&cooldown_refusal("beta", TOOL)),
        "R5: {error}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "R5: sent");
}

/// R10 (red at base): a shared backend, the tool not in cooldown when the
/// policy runs; it enters cooldown before the dispatch resolves. The
/// dispatch refuses it with the cooldown and sends nothing. RED at base:
/// nothing re-reads the cooldown after the policy, so the call is sent.
/// Kills M2 (no dispatch half) and M3′ (dispatch half per-user only).
#[tokio::test]
async fn r10_shared_backend_cooldown_after_the_policy_is_refused_at_dispatch() {
    let (registry, calls) = counted_backend("alpha");
    let meta = MetaMcp::new(registry);
    let kill_switch = meta.kill_switch();
    let _armed = before_dispatch_resolution(move || cool(&kill_switch, "alpha", TOOL));
    let answer = meta
        .invoke_tool(&invoke_args("alpha", TOOL), None, &ctx(&AllowAll))
        .await;
    assert!(
        meta.kill_switch().is_capability_disabled("alpha", TOOL),
        "premise: the seam fired and armed the cooldown"
    );
    let error = answer.expect_err("R10: a tool in cooldown at dispatch was answered");
    assert_eq!(error.to_rpc_code(), -32000, "R10: {error}");
    assert!(
        error.to_string().contains(&cooldown_refusal("alpha", TOOL)),
        "R10: {error}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "R10: sent");
}

/// R11 (red at base on its premise): in process, so no route stage runs and
/// no verdict is carried: the dispatch takes the fresh resolution, which
/// leases the operator's account credential and so spends the refund
/// witness. The cooldown refusal that follows keeps it spent: the slot is
/// empty. RED at base on the premises: the policy refuses before any
/// resolution (no lease; at base signing refuses the call before the nonce).
/// Kills M5 (the dispatch half above the carry: the `?` exit hands the
/// unspent witness back to the slot).
#[tokio::test]
async fn r11_a_resolving_cooldown_refusal_leaves_the_witness_spent() {
    use crate::gateway::meta_mcp::refund_witness::RefundWitness;
    use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
    let (gateway, meta) = per_user(|meta| {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"noview-cooldown-r11-key-0123456789abcdef".to_vec(),
                None,
                "r11".into(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
    });
    cool(&meta.kill_switch(), BACKEND, TOOL);
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": operator_args(),
            "_meta": {(NONCE_META): "noview-cooldown-r11"}}});
    let mut signing =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    let mut caller = operator();
    let prepared =
        meta.prepare_signing_for_call(&mut signing, "gateway_invoke", &arguments, None, &caller);
    assert!(
        prepared.is_ok(),
        "premise: signing admits the nonce before the cooldown: {prepared:?}"
    );
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    assert!(
        crate::gateway::meta_mcp::visible::memo::take_carried(BACKEND, TOOL).is_none(),
        "premise: no verdict is carried"
    );
    let releases = gateway.releases();
    let answer = meta.invoke_tool(&arguments, None, &caller).await;
    assert!(
        gateway.releases() > releases,
        "premise: the fresh resolution leased the account credential: {answer:?}"
    );
    let error = answer.expect_err("R11: a tool in cooldown was answered");
    assert!(
        error.to_string().contains(&cooldown_refusal(BACKEND, TOOL)),
        "R11: {error}"
    );
    assert!(
        signing.take_witness().is_none(),
        "R11: the witness went back to the slot after a resolution acted"
    );
    assert_eq!(gateway.tool_calls().len(), 0, "R11: sent");
}

/// R12 (red at base by design): a reload replaces the per-user [`BACKEND`]
/// with a shared one of the same name between the policy and the dispatch,
/// the tool still in cooldown. The dispatch refuses it and the shared
/// backend is never reached. Red at base by design: the policy refuses the
/// per-user cooldown first, so the reload window (the seam) is unreachable
/// until the policy skip lands. Kills M3′ (dispatch half guarded per-user: the policy skipped
/// it as per-user, the dispatch skips it as shared).
#[tokio::test]
async fn r12_a_reload_to_shared_between_policy_and_dispatch_keeps_the_cooldown() {
    let (gateway, meta) = per_user(|_| {});
    cool(&meta.kill_switch(), BACKEND, TOOL);
    let (shared_registry, shared_calls) = counted_backend(BACKEND);
    let shared = shared_registry.get(BACKEND).expect("the shared backend");
    assert!(
        !shared.keeps_per_user_catalogues(),
        "premise: the replacement is shared"
    );
    let registry = gateway.backends();
    let _armed = before_dispatch_resolution(move || {
        assert!(
            registry.remove(BACKEND),
            "premise: the per-user backend left"
        );
        assert!(registry.register(shared), "premise: the shared one came in");
    });
    let answer = meta.invoke_tool(&operator_args(), None, &operator()).await;
    assert!(
        !gateway
            .backends()
            .get(BACKEND)
            .expect("a backend")
            .keeps_per_user_catalogues(),
        "R12: the reload seam never fired (refused before the dispatch): {answer:?}"
    );
    let error = answer.expect_err("R12: a tool in cooldown was answered");
    assert_eq!(error.to_rpc_code(), -32000, "R12: {error}");
    assert!(
        error.to_string().contains(&cooldown_refusal(BACKEND, TOOL)),
        "R12: {error}"
    );
    assert_eq!(shared_calls.load(Ordering::SeqCst), 0, "R12: shared sent");
    assert_eq!(gateway.tool_calls().len(), 0, "R12: per-user sent");
}

const CAPS: &str = "caps";
const CAP: &str = "hook_or_day";
const SESSION: &str = "session-8439";

/// A Meta-MCP whose capability backend defines [`CAP`] (its endpoint a
/// closed local port), with profiles `open` (the default) and `restricted`
/// (denies [`CAP`]).
fn capability_meta() -> MetaMcp {
    let mut profiles = std::collections::HashMap::new();
    profiles.insert(
        "open".to_string(),
        crate::routing_profile::RoutingProfileConfig::default(),
    );
    profiles.insert(
        "restricted".to_string(),
        crate::routing_profile::RoutingProfileConfig {
            description: "MIK-8439 R13".to_string(),
            deny_tools: Some(vec![CAP.to_string()]),
            ..Default::default()
        },
    );
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()))
        .with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles, "open",
        ));
    let caps = Arc::new(crate::capability::CapabilityBackend::new(
        CAPS,
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let definition = format!(
        "name: {CAP}\n\
         description: A fixture capability\n\
         metadata:\n  exposure: public\n  read_only: true\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://127.0.0.1:9\n\
         \x20     path: /x\n\
         \x20     method: POST\n"
    );
    caps.register_capability(
        crate::capability::parse_capability(&definition).expect("the capability parses"),
    )
    .expect("the capability registers");
    meta.set_capabilities(caps);
    meta
}

/// R13 (red at base): a defined capability, not in cooldown; the session's
/// profile is switched to one that denies it between the policy and the
/// dispatch. The dispatch refuses it exactly as the policy refuses the same
/// profile set before the call (the undefined name's `ToolNotFound`).
/// RED at base: nothing re-reads the profile after the policy, so the call
/// is sent. Kills M7 (the dispatch half without the profile mapping answers
/// the raw "routing profile" text).
#[tokio::test]
async fn r13_a_profile_set_before_the_dispatch_is_refused_as_the_policy_refuses_it() {
    let args = invoke_args(CAPS, CAP);
    let before = capability_meta();
    before.session_profiles().set_profile(SESSION, "restricted");
    let raw = before
        .active_profile(Some(SESSION))
        .check(CAPS, CAP)
        .expect_err("premise: the restricted profile denies the capability");
    let control = before
        .invoke_tool(&args, Some(SESSION), &ctx(&AllowAll))
        .await
        .expect_err("premise: the profile set before the call refuses it");
    assert!(
        matches!(control, crate::Error::ToolNotFound(_)) && !control.to_string().contains(&raw),
        "premise: the policy maps the profile refusal ({raw}) to the undefined name: {control}"
    );

    let during = capability_meta();
    let profiles = during.session_profiles();
    let _armed = before_dispatch_resolution(move || profiles.set_profile(SESSION, "restricted"));
    let answer = during
        .invoke_tool(&args, Some(SESSION), &ctx(&AllowAll))
        .await;
    assert_eq!(
        during.active_profile(Some(SESSION)).name,
        "restricted",
        "premise: the seam fired and switched the profile"
    );
    let error = answer.expect_err("R13: a call its profile denies was answered");
    assert_eq!(
        error.to_string(),
        control.to_string(),
        "R13: mid-request vs before"
    );
}
