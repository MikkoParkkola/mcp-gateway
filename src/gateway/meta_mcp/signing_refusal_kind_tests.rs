// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3d-2 (NONCEFX.11, K7 and K8) at the dispatcher: a refusal
//! that asks for the nonce back gets it only while the call holds its refund
//! witness. The REFUND rows hold it as execution admission keeps it
//! (`admit_meta_sync`); the KEEP rows hold none, the state a may-effect step
//! leaves. No may-effect step precedes these refusals on any route, so the
//! KEEP rows build that state directly; each premise pins that nothing acted
//! (no backend call, no tool-list fill; this fixture propagates no identity,
//! so nothing mints). That a real effect keeps the nonce is proven by the
//! witnessed KEEP rows of 3a and 3c.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{captured, elicit_caller, nonce_is_free, undeliverable_proxy};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};

/// Whether execution admission ran, and so whether the call holds a witness.
#[derive(Clone, Copy)]
enum Witness {
    Kept,
    None,
}

/// Signing on, Code Mode on, over one counted backend `alpha`; with
/// `attested`, plan attestation is enforced. Returns the backend's call count.
fn counted(attested: bool) -> (MetaMcp, Arc<AtomicUsize>) {
    use crate::attestation::{AttestationMode, AttestationValidator, BnautAttestationSigner};
    let (registry, calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry).with_code_mode(true);
    if attested {
        let signer = BnautAttestationSigner::new(b"plan-key".to_vec(), "plan");
        let validator = AttestationValidator::new(signer.with_audience("test-gateway"));
        meta = meta.with_attestation(Arc::new(validator), AttestationMode::Enforce);
    }
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"signing-kinds-key-0123456789abcdef".to_vec(),
            None,
            "kinds-current".into(),
        ),
        Duration::from_secs(300),
        false,
    );
    (meta, calls)
}

/// Nothing acted: no backend call and no tool-list fill.
fn assert_nothing_acted(meta: &MetaMcp, calls: &AtomicUsize, name: &str) {
    assert_eq!(calls.load(Ordering::SeqCst), 0, "premise: {name} sent");
    let alpha = meta.backends.get("alpha").expect("alpha");
    assert_eq!(alpha.list_fills(), 0, "premise: {name} filled");
}

/// Runs `name` signed with `elicit-nonce` through the dispatcher as `caller`.
async fn signed(
    meta: &MetaMcp,
    (name, arguments): (&str, Value),
    mut caller: MetaMcpCallerContext<'_>,
    witness: Witness,
) -> Value {
    let id = crate::protocol::RequestId::Number(7);
    let (mut context, arguments) = captured(name, &arguments, "elicit-nonce");
    meta.prepare_signing_for_call(&mut context, name, &arguments, Some(""), &caller)
        .expect("the nonce is admitted");
    caller.signing = Some(&context);
    if let Witness::Kept = witness {
        let owner = AdmissionOwner::local_operator();
        meta.admit_meta_sync_for_test(owner, &caller, name, &arguments, Some(""), &id)
            .expect("execution admission passes");
    }
    let response = Box::pin(meta.handle_tools_call(id, name, arguments, Some(""), caller)).await;
    serde_json::to_value(&response).expect("a response serializes")
}

fn refused_with(wire: &Value, needle: &str) -> bool {
    let refused = wire.get("error").is_some() || wire["result"]["isError"] == true;
    refused && wire.to_string().contains(needle)
}

/// K7-R: the confirmation question could not be delivered and the call
/// holds its witness: the nonce comes back once (the accepted-once oracle).
/// Green on base, whose give-back read no witness. Mutant mK7-ask: the ask
/// at `RefuseUnasked` removed.
#[tokio::test]
async fn an_undelivered_question_with_its_witness_gives_the_nonce_back() {
    use crate::gateway::destructive_confirmation::ConfirmationPolicy;
    let ((meta, calls), proxy) = (counted(false), undeliverable_proxy());
    let caller = elicit_caller(&proxy, ConfirmationPolicy::for_modern());
    let kill = ("gateway_kill_server", json!({"server": "x"}));
    let wire = signed(&meta, kill, caller, Witness::Kept).await;
    let needle = "none could be obtained";
    assert!(refused_with(&wire, needle), "premise: undelivered: {wire}");
    assert_nothing_acted(&meta, &calls, "the kill");
    assert!(nonce_is_free(&meta), "the refused call kept its nonce");
    assert!(!nonce_is_free(&meta), "the nonce was given back twice");
}

/// The meta-tool setup refusals of K8: a call its own parse refuses, the
/// refusal's text, and whether plan attestation is enforced.
fn setup_refusals() -> [(&'static str, Value, &'static str, bool); 11] {
    let unattested = "multi-step plans carry no attestation";
    [
        ("gateway_search", json!({}), "Missing 'query'", false),
        ("gateway_search", json!({"query": "r", "detail": "l9"}), "l9", false),
        ("gateway_search_tools", json!({}), "Missing 'query'", false),
        ("gateway_list_tools", json!({"role": "bogus"}), "Invalid role filter", false),
        ("gateway_execute", json!({"chain": []}), "Chain must not be empty", false),
        ("gateway_execute", json!({}), "Missing 'tool'", false),
        ("gateway_execute", json!({"tool": "read"}), "missing server prefix", false),
        ("gateway_execute", json!({"tool": "alpha:read", "arguments": 5}), "Invalid 'arguments'", false),
        ("gateway_execute", json!({"tool": "alpha:read"}), unattested, true),
        ("gateway_run_playbook", json!({"name": "nosuch"}), "Playbook not found", false),
        ("gateway_run_playbook", json!({"name": "nosuch"}), unattested, true),
    ]
}

/// K8-K: each setup refusal asks, but a call holding no witness keeps its
/// nonce. Green on base. Mutants mK8-*-uncond: a site gives the nonce back
/// past the witness.
#[tokio::test]
async fn a_setup_refusal_without_its_witness_keeps_the_nonce() {
    for (name, arguments, needle, attested) in setup_refusals() {
        let (meta, calls) = counted(attested);
        let wire = signed(&meta, (name, arguments), ctx(&AllowAll), Witness::None).await;
        assert!(refused_with(&wire, needle), "premise: {name} {needle}: {wire}");
        assert_nothing_acted(&meta, &calls, name);
        assert!(
            !nonce_is_free(&meta),
            "{name} {needle}: a call with no witness got its nonce back"
        );
    }
}

/// K8-R at the dispatcher: the same refusals holding the witness give the
/// nonce back once. Red on base.
#[tokio::test]
async fn a_setup_refusal_with_its_witness_gives_the_nonce_back() {
    for (name, arguments, needle, attested) in setup_refusals() {
        let (meta, calls) = counted(attested);
        let wire = signed(&meta, (name, arguments), ctx(&AllowAll), Witness::Kept).await;
        assert!(refused_with(&wire, needle), "premise: {name} {needle}: {wire}");
        assert_nothing_acted(&meta, &calls, name);
        assert!(nonce_is_free(&meta), "{name} {needle}: kept its nonce");
        assert!(!nonce_is_free(&meta), "{name} {needle}: given back twice");
    }
}
