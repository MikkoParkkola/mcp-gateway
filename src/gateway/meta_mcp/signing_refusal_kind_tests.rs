// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3d-2 (NONCEFX.11, K5, K7 and K8) at the dispatcher: a refusal
//! that asks for the nonce back gets it only while the call holds its refund
//! witness. The REFUND rows hold it as execution admission keeps it
//! (`admit_meta_sync`); the KEEP rows hold none, the state a may-effect step
//! leaves. No may-effect step precedes these refusals on any route, so the
//! KEEP rows build that state directly; each premise pins that nothing acted
//! (no backend call, no tool-list fill; this fixture propagates no identity,
//! so nothing mints). That a real effect keeps the nonce is proven by the
//! witnessed KEEP rows of 3a and 3c, and for these kinds by the transport
//! rows after a fill, a consume or a sent step
//! (`router/mcp_setup_refusal_tests.rs`, `server/tests/s3d2_stdio_task_intent.rs`).

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
    let alpha = meta.backends.for_test().get("alpha").expect("alpha");
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
fn setup_refusals() -> [(&'static str, Value, &'static str, bool); 13] {
    let unattested = "multi-step plans carry no attestation";
    [
        ("gateway_search", json!({}), "Missing 'query'", false),
        (
            "gateway_search",
            json!({"query": "r", "detail": "l9"}),
            "l9",
            false,
        ),
        ("gateway_search_tools", json!({}), "Missing 'query'", false),
        (
            "gateway_list_tools",
            json!({"role": "bogus"}),
            "Invalid role filter",
            false,
        ),
        (
            "gateway_execute",
            json!({"chain": []}),
            "Chain must not be empty",
            false,
        ),
        ("gateway_execute", json!({}), "Missing 'tool'", false),
        (
            "gateway_execute",
            json!({"tool": "read"}),
            "missing server prefix",
            false,
        ),
        (
            "gateway_execute",
            json!({"tool": "alpha:read", "arguments": 5}),
            "Invalid 'arguments'",
            false,
        ),
        (
            "gateway_execute",
            json!({"tool": "alpha:read"}),
            unattested,
            true,
        ),
        ("gateway_run_playbook", json!({}), "Missing 'name'", false),
        (
            "gateway_run_playbook",
            json!({"name": "x", "arguments": 5}),
            "Invalid 'arguments'",
            false,
        ),
        (
            "gateway_run_playbook",
            json!({"name": "nosuch"}),
            "Playbook not found",
            false,
        ),
        (
            "gateway_run_playbook",
            json!({"name": "nosuch"}),
            unattested,
            true,
        ),
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
        assert!(
            refused_with(&wire, needle),
            "premise: {name} {needle}: {wire}"
        );
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
        assert!(
            refused_with(&wire, needle),
            "premise: {name} {needle}: {wire}"
        );
        assert_nothing_acted(&meta, &calls, name);
        assert!(nonce_is_free(&meta), "{name} {needle}: kept its nonce");
        assert!(!nonce_is_free(&meta), "{name} {needle}: given back twice");
    }
}

/// A backend `alpha` whose `tools/list` gives `read` a structurally invalid
/// input schema; it answers no `tools/call`.
struct InvalidRead;

#[async_trait::async_trait]
impl crate::transport::Transport for InvalidRead {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/list", "premise: nothing but the listing");
        let tools = json!({"tools": [{"name": "read", "inputSchema": {"type": "string"}}]});
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            tools,
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Signing on, surfacing `alpha:read`, with alpha's catalogue already warm,
/// so the surfaced name is withheld for its schema at dispatch (the `_ =>`
/// arm of `call_dispatch.rs`) and nothing lists or sends during the call.
async fn surfacing_invalid_read() -> MetaMcp {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::r2_off(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(InvalidRead));
    let _ = registry.register(Arc::clone(&backend));
    backend.get_tools().await.expect("alpha lists");
    let mut meta =
        MetaMcp::new(registry).with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
            server: "alpha".to_string(),
            tool: "read".to_string(),
        }]);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"signing-kinds-key-0123456789abcdef".to_vec(),
            None,
            "kinds-current".into(),
        ),
        Duration::from_secs(300),
        false,
    );
    meta
}

/// K5 at the dispatcher: the withheld surfaced name asks, and the witness
/// decides. KEEP without it (the state a per-user caller verdict's fill
/// leaves before this arm), REFUND once with it. Green on base (the arm
/// already asked). Mutants mK5-ask (REFUND) and mK5-uncond (KEEP).
#[tokio::test]
async fn a_withheld_surfaced_name_gives_the_nonce_back_only_with_its_witness() {
    for (witness, freed) in [(Witness::None, false), (Witness::Kept, true)] {
        let meta = surfacing_invalid_read().await;
        let fills = meta
            .backends
            .for_test()
            .get("alpha")
            .expect("alpha")
            .list_fills();
        let wire = signed(&meta, ("read", json!({})), ctx(&AllowAll), witness).await;
        assert_eq!(wire["error"]["code"], -32601, "premise: absent: {wire}");
        let alpha = meta.backends.for_test().get("alpha").expect("alpha");
        assert_eq!(alpha.list_fills(), fills, "premise: nothing listed");
        assert_eq!(nonce_is_free(&meta), freed, "witness kept: {freed}");
        assert!(!nonce_is_free(&meta), "the nonce was given back twice");
    }
}

/// A backend `alpha` whose `tools/list` offers `read` with a credential in
/// its description, which the discovery firewall's Block rule refuses; it
/// counts any `tools/call`.
#[cfg(feature = "firewall")]
struct CredentialListing(Arc<AtomicUsize>);

#[cfg(feature = "firewall")]
#[async_trait::async_trait]
impl crate::transport::Transport for CredentialListing {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method != "tools/list" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        let token = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz1234567890");
        let tools = json!({"tools": [{
            "name": "read",
            "description": format!("token: {token} for auth"),
            "inputSchema": {"type": "object"}
        }]});
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            tools,
        ))
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// NONCEFX.10, catalogue collection: signing on, Code Mode on, over a cold
/// `alpha` ([`CredentialListing`]), with a firewall whose Block rule on
/// `tools/list` refuses a discovery answer carrying a credential, after the
/// answer has been collected.
#[cfg(feature = "firewall")]
fn collecting_then_refused() -> (MetaMcp, Arc<AtomicUsize>) {
    use crate::security::firewall::{Firewall, FirewallAction, FirewallConfig, FirewallRule};
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "alpha",
        crate::config::BackendConfig::r2_off(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(CredentialListing(Arc::clone(&calls))));
    let _ = registry.register(backend);
    let mut meta = MetaMcp::new(registry).with_code_mode(true);
    let rule = FirewallRule {
        tool_match: "tools/list".to_string(),
        action: FirewallAction::Block,
        reason: None,
        scan: Vec::new(),
        servers: None,
        keys: None,
        except: None,
    };
    let config = FirewallConfig {
        rules: vec![rule],
        ..FirewallConfig::default()
    };
    let firewall = Firewall::from_config(config, None).with_continuations(meta.continuation());
    meta.set_firewall(Some(Arc::new(firewall)));
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

/// NONCEFX.10 KEEP, catalogue collection: each discovery call holds the
/// witness admission keeps, fills alpha's cold catalogue on its own path (a
/// `server:` query or a named server), and is then refused by the discovery
/// firewall. An unscoped read and `gateway_search_tools` never fill a shared
/// slot on the call's path: they fill behind the answer (`discovery_fetch.rs`,
/// `backend_tools_for_discovery` with no empty-cache fetch). The nonce
/// stays spent. Today no refusal that asks follows collection
/// (`search::asking` wraps only the parse before it), so this row pins that a
/// later refusal never gives back a nonce a fill spent. Green on base.
/// Planted bug mCollect: the discovery refusal asks.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_refusal_after_catalogue_collection_keeps_the_nonce() {
    let cases = [
        ("gateway_search", json!({"query": "alpha:read"})),
        ("gateway_list_tools", json!({"server": "alpha"})),
    ];
    for (name, arguments) in cases {
        let (meta, calls) = collecting_then_refused();
        let alpha = meta.backends.for_test().get("alpha").expect("alpha");
        assert_eq!(alpha.list_fills(), 0, "premise: {name}: alpha is cold");
        let wire = signed(&meta, (name, arguments), ctx(&AllowAll), Witness::Kept).await;
        assert_eq!(
            wire["error"]["code"], -32600,
            "premise: {name}: the discovery firewall refused: {wire}"
        );
        // Only the collected listing carries the credential the Block rule
        // refuses, so this refusal also proves collection ran on the call's path.
        assert_eq!(
            wire["error"]["message"], "Response blocked by security firewall",
            "premise: {name}: the refusal is the discovery firewall's: {wire}"
        );
        assert!(alpha.list_fills() > 0, "premise: {name}: collection filled");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "premise: {name}: unsent");
        assert!(
            !nonce_is_free(&meta),
            "{name}: a refusal after a fill gave the nonce back"
        );
    }
}
