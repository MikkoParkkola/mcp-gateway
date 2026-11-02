// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 per-user rows (test plan v3: P1, P4, C2-C4) on MIK-8356's
//! per-user backend: a name withheld from the caller without any catalogue
//! (the routing profile denies it) answers -32601 at the gate with no fill
//! and no credential resolution, on `/mcp` `gateway_invoke` and the direct
//! route; a refused direct call resolves no credential (ORACLE.3/.4).

use crate::security::transparency_log::temp::TempLog;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::r2_identity_keys_tests::transparency_logger;
use super::tests::direct_route_state_with_identity;
use crate::config::InputSchemaEnforcement;
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    Asked, BACKEND, CallerSlot, CountingMint, Surfaced, TOOL, Warmth, per_user_backend, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

/// MIK-8382 UNIFY.1b rows on this fixture.
mod lacked_warn;

/// A per-user backend hidden from the caller, and the caller's own slot.
mod hidden;

/// The router over one per-user backend, with what it was asked.
struct Gateway {
    router: axum::Router,
    state: Arc<super::AppState>,
    backend: Arc<crate::backend::Backend>,
    caller: Arc<Asked>,
    shared: Arc<Asked>,
    mints: Arc<AtomicUsize>,
    _store: crate::gateway::router::tests::FixtureDir,
    _audit: [TempLog; 2],
}

impl Gateway {
    fn mints(&self) -> usize {
        self.mints.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn dispatched(&self) -> usize {
        self.caller.calls() + self.shared.calls()
    }
}

/// alpha's slot `slot` in `warmth`, the active profile denying `denied`, the
/// request firewall on when `firewalled`.
async fn gateway(slot: CallerSlot, warmth: Warmth, denied: &str, firewalled: bool) -> Gateway {
    gateway_shared(slot, &valid(), warmth, denied, firewalled).await
}

/// [`gateway`] with the shared slot's schema for [`TOOL`] set to `shared`.
async fn gateway_shared(
    slot: CallerSlot,
    shared: &Value,
    warmth: Warmth,
    denied: &str,
    firewalled: bool,
) -> Gateway {
    let state =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    gateway_on(state, (slot, shared, warmth), (denied, firewalled), |_| {})
}

/// [`gateway`] behind `auth` (MIK-8382 E4/E5: API-key callers), with
/// `configure` run on the Meta-MCP before it is mounted.
async fn gateway_authed(
    auth: &crate::config::AuthConfig,
    (slot, warmth, denied): (CallerSlot, Warmth, &str),
    configure: impl FnOnce(&crate::gateway::test_helpers::MetaMcp),
) -> Gateway {
    let state = super::tests::test_router_app_state_with_auth(auth).await;
    gateway_on(state, (slot, &valid(), warmth), (denied, false), configure)
}

/// The per-user fixture over `state`: alpha's slot, the shared schema and the
/// warmth, the active profile denying `denied`, the firewall when asked,
/// and `configure` run on the Meta-MCP before it is mounted.
fn gateway_on(
    (mut state, store): (
        Arc<super::AppState>,
        crate::gateway::router::tests::FixtureDir,
    ),
    (slot, shared, warmth): (CallerSlot, &Value, Warmth),
    (denied, firewalled): (&str, bool),
    configure: impl FnOnce(&crate::gateway::test_helpers::MetaMcp),
) -> Gateway {
    let (backend, caller, shared) =
        per_user_backend(slot, shared, warmth, InputSchemaEnforcement::Closed);
    let kept = Arc::clone(&backend);
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let audit = [TempLog::new(), TempLog::new()];
    let mut profiles = std::collections::HashMap::new();
    profiles.insert(
        "restricted".to_string(),
        crate::routing_profile::RoutingProfileConfig {
            description: "MIK-8361 per-user".to_string(),
            deny_tools: Some(vec![denied.to_string()]),
            ..Default::default()
        },
    );
    let mut meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends))
        .with_surfaced_tools(Surfaced::No.configs())
        .with_profile_registry(crate::routing_profile::ProfileRegistry::from_config(
            &profiles,
            "restricted",
        ));
    let mints = Arc::new(AtomicUsize::new(0));
    meta.set_identity_propagation(Arc::new(CountingMint(Arc::clone(&mints))));
    meta.enable_transparency_log(transparency_logger(&audit[0]));
    meta.set_multi_user(true);
    if firewalled {
        let config = crate::security::firewall::FirewallConfig {
            enabled: true,
            scan_requests: true,
            ..crate::security::firewall::FirewallConfig::default()
        };
        state_mut.firewall = Some(Arc::new(crate::security::firewall::Firewall::from_config(
            config.clone(),
            None,
        )));
        meta.set_firewall(Some(Arc::new(
            crate::security::firewall::Firewall::from_config(config, None),
        )));
    }
    configure(&meta);
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&audit[1]));
    Gateway {
        router: create_router(Arc::clone(&state)),
        state,
        backend: kept,
        caller,
        shared,
        mints,
        _store: store,
        _audit: audit,
    }
}

/// Where a row's call enters.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Invoke,
    Direct,
}

/// alpha's call of [`TOOL`] on `entry` with `args`, the body without `id`.
async fn call(gw: &Gateway, entry: Entry, args: Value) -> (StatusCode, Value) {
    call_as(gw, entry, args, true).await
}

/// [`call`], as alpha (`identified`) or as a caller with no principal.
async fn call_as(gw: &Gateway, entry: Entry, args: Value, identified: bool) -> (StatusCode, Value) {
    let (uri, params) = match entry {
        Entry::Invoke => (
            "/mcp".to_string(),
            json!({"name": "gateway_invoke",
                "arguments": {"server": BACKEND, "tool": TOOL, "arguments": args}}),
        ),
        Entry::Direct => (
            format!("/mcp/{BACKEND}"),
            json!({"name": TOOL, "arguments": args}),
        ),
    };
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    if identified {
        request.extensions_mut().insert(VerifiedIdentity {
            subject: "alpha".to_string(),
            email: "alpha@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.example.invalid".to_string(),
        });
    }
    let response = gw.router.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let mut value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if let Some(obj) = value.as_object_mut() {
        obj.remove("id");
    }
    (status, value)
}

/// P1 / C3 / C4: a profile-withheld name on a cold caller slot answers
/// exactly as the allowed-but-missing name (P2, reached through MIK-8356's
/// one fill), with no credential resolution, no fill and no dispatch. RED on
/// base: the profile refusal names the tool.
#[tokio::test]
async fn p1_a_policy_withheld_name_answers_absent_with_no_fill_or_mint() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        let withheld = gateway(CallerSlot::Valid, Warmth::Cold, TOOL, false).await;
        let absent = gateway(CallerSlot::Lacks, Warmth::Cold, "other", false).await;
        let w = call(&withheld, entry, json!({"q": "x"})).await;
        let a = call(&absent, entry, json!({"q": "x"})).await;
        if w != a {
            cells.push(format!("P1 {entry:?}: withheld {w:?} vs missing {a:?}"));
        }
        // Calibration (v2 item 8): the missing name's fill does mint, so the
        // withheld side's zero is not a counter that never moves.
        if absent.mints() == 0 {
            cells.push(format!(
                "P1 {entry:?}: premise: the missing name minted nothing"
            ));
        }
        let (mints, lists, sent) = (
            withheld.mints(),
            withheld.caller.lists(),
            withheld.dispatched(),
        );
        if (mints, lists, sent) != (0, 0, 0) {
            cells.push(format!(
                "P1 {entry:?}: withheld minted {mints}, listed {lists}, sent {sent}"
            ));
        }
    }
    assert!(cells.is_empty(), "P1:\n{}", cells.join("\n"));
}

/// P4: when the caller's fill fails, the withheld name still answers -32601
/// with no fill or mint; the missing name answers backend-unavailable (the
/// stated outage-only residual, pinned).
#[tokio::test]
async fn p4_a_failed_fill_leaves_the_withheld_name_absent() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        let withheld = gateway(CallerSlot::Valid, Warmth::ColdFailing, TOOL, false).await;
        let absent = gateway(CallerSlot::Lacks, Warmth::ColdFailing, "other", false).await;
        let w = call(&withheld, entry, json!({"q": "x"})).await;
        let a = call(&absent, entry, json!({"q": "x"})).await;
        if w.1.pointer("/error/code") != Some(&json!(-32601)) {
            cells.push(format!("P4 {entry:?}: withheld answered {w:?}"));
        }
        if (withheld.mints(), withheld.caller.lists()) != (0, 0) {
            cells.push(format!(
                "P4 {entry:?}: withheld minted {}, listed {}",
                withheld.mints(),
                withheld.caller.lists()
            ));
        }
        if a.1.pointer("/error/code") == Some(&json!(-32601)) {
            cells.push(format!(
                "P4 {entry:?}: the residual moved, missing answered {a:?}"
            ));
        }
    }
    assert!(cells.is_empty(), "P4:\n{}", cells.join("\n"));
}

/// C2 (ORACLE.4): a direct call the request firewall refuses resolves no
/// credential. RED on base: the direct route resolves before the firewall.
#[tokio::test]
async fn c2_a_firewall_refused_direct_call_resolves_no_credential() {
    let gw = gateway(CallerSlot::Valid, Warmth::Warm, "other", true).await;
    let cmd = [";", " rm", " -rf", " / "].concat();
    let answer = call(&gw, Entry::Direct, json!({ "cmd": cmd })).await;
    assert!(
        answer
            .1
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("Firewall")),
        "premise: the firewall refused: {answer:?}"
    );
    assert_eq!(
        gw.mints(),
        0,
        "C2: a refused call resolved a credential: {answer:?}"
    );
    assert_eq!(gw.dispatched(), 0, "C2: sent: {answer:?}");
}

/// alpha's `tools/list` on the direct route: fills alpha's own slot.
async fn list_as_alpha(gw: &Gateway) {
    let body = json!({"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    });
    let response = gw.router.clone().oneshot(request).await.expect("response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: alpha's listing answered"
    );
}

/// P3: the per-user lifecycle. Cold slot, then listed (warm), then evicted:
/// at each step the withheld name answers as the missing one, unsent, and its
/// own call mints nothing.
#[tokio::test]
async fn p3_parity_holds_across_the_caller_slot_lifecycle() {
    let withheld = gateway(CallerSlot::Valid, Warmth::Cold, TOOL, false).await;
    let absent = gateway(CallerSlot::Lacks, Warmth::Cold, "other", false).await;
    let mut cells = Vec::new();
    for step in ["cold", "listed", "evicted"] {
        match step {
            "listed" => {
                list_as_alpha(&withheld).await;
                list_as_alpha(&absent).await;
            }
            "evicted" => {
                // Eviction drops the scripted slot with its transport; the
                // same catalogue is served again, so the refill succeeds.
                withheld.backend.evict_identity_slots("alpha");
                absent.backend.evict_identity_slots("alpha");
                rescript(&withheld, true);
                rescript(&absent, false);
            }
            _ => {}
        }
        let minted = withheld.mints();
        let w = call(&withheld, Entry::Invoke, json!({"q": "x"})).await;
        let a = call(&absent, Entry::Invoke, json!({"q": "x"})).await;
        if w != a {
            cells.push(format!("P3 {step}: withheld {w:?} vs missing {a:?}"));
        }
        if withheld.mints() != minted || withheld.dispatched() != 0 {
            cells.push(format!(
                "P3 {step}: the withheld call minted {} and sent {}",
                withheld.mints() - minted,
                withheld.dispatched()
            ));
        }
    }
    assert!(cells.is_empty(), "P3:\n{}", cells.join("\n"));
}

/// P5: each caller's verdict comes from its own slot. alpha's slot offers
/// [`TOOL`] while the shared slot withholds it (invalid schema): alpha's
/// call dispatches once. GREEN on base (MIK-8356); mutant MP1 (the gate
/// judges a per-user backend by its shared slot) must fail it.
#[tokio::test]
async fn p5_the_caller_slot_not_the_shared_one_decides() {
    let gw = gateway_shared(
        CallerSlot::Valid,
        &crate::gateway::meta_mcp::slot_verdict_fixture::invalid(),
        Warmth::Warm,
        "other",
        false,
    )
    .await;
    let answer = call(&gw, Entry::Invoke, json!({"q": "x"})).await;
    assert_eq!(
        gw.caller.calls(),
        1,
        "P5: alpha's offered tool was not sent: {answer:?}"
    );
}

/// alpha's upstream after an eviction: the catalogue it served before
/// ([`TOOL`] valid when `holds`, else only the sibling), counted into the
/// gateway's own caller counters.
struct Rescripted {
    holds: bool,
    asked: Arc<Asked>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Rescripted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = if method == "tools/list" {
            self.asked
                .lists
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut tools = vec![json!({"name": "note", "description": "A ledger tool.",
                "inputSchema": valid()})];
            if self.holds {
                tools.push(json!({"name": TOOL, "description": "A ledger tool.",
                    "inputSchema": valid()}));
            }
            json!({ "tools": tools })
        } else {
            self.asked
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            body,
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

/// Seed alpha's slot again after an eviction, serving what it served before.
fn rescript(gw: &Gateway, holds: bool) {
    let key = crate::backend::PoolKey::PerUser {
        binding: crate::gateway::meta_mcp::slot_verdict_fixture::BINDING.to_string(),
    };
    let upstream = Rescripted {
        holds,
        asked: Arc::clone(&gw.caller),
    };
    gw.backend
        .set_pooled_transport_for_test(&key, Arc::new(upstream));
}

/// ORACLE.4, no principal (lead ruling 2026-10-11, MIK-8356 R3.7): on the
/// direct route, a caller with no principal on a required per-user backend
/// answers -32601 as on every other entry, not the identity refusal (403,
/// -32003), and resolves no credential. RED on base: `propagate_identity`
/// answers it first.
#[tokio::test]
async fn c5_direct_no_principal_answers_absent_and_resolves_nothing() {
    let gw = gateway(CallerSlot::Valid, Warmth::Warm, "other", false).await;
    let answer = call_as(&gw, Entry::Direct, json!({"q": "x"}), false).await;
    let mut cells = Vec::new();
    if (answer.0, answer.1.pointer("/error/code")) != (StatusCode::OK, Some(&json!(-32601))) {
        cells.push(format!("C5: answered {answer:?}"));
    }
    if (gw.mints(), gw.dispatched()) != (0, 0) {
        cells.push(format!(
            "C5: minted {}, sent {}",
            gw.mints(),
            gw.dispatched()
        ));
    }
    assert!(cells.is_empty(), "C5:\n{}", cells.join("\n"));
}

/// P6 (seat finding, 2026-10-12): a name withheld for its description on a
/// per-user backend answers exactly as the allowed-but-missing name, on
/// `gateway_invoke` and the direct route, with no credential resolution, no
/// fill and no dispatch. MIK-8356's caller verdict leaves such a name to this
/// gate (its step 0); before it answered, the call reached admission and was
/// refused by its reason, and the direct route minted before judging it.
#[tokio::test]
async fn p6_a_descriptor_withheld_name_answers_absent_with_no_fill_or_mint() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        let withheld = gateway(CallerSlot::Valid, Warmth::Cold, "other", false).await;
        withheld.backend.block_descriptor_for_test(TOOL);
        let absent = gateway(CallerSlot::Lacks, Warmth::Cold, "other", false).await;
        let w = call(&withheld, entry, json!({"q": "x"})).await;
        let a = call(&absent, entry, json!({"q": "x"})).await;
        if w != a {
            cells.push(format!("P6 {entry:?}: withheld {w:?} vs missing {a:?}"));
        }
        if absent.mints() == 0 {
            cells.push(format!(
                "P6 {entry:?}: premise: the missing name minted nothing"
            ));
        }
        let (mints, lists, sent) = (
            withheld.mints(),
            withheld.caller.lists(),
            withheld.dispatched(),
        );
        if (mints, lists, sent) != (0, 0, 0) {
            cells.push(format!(
                "P6 {entry:?}: withheld minted {mints}, listed {lists}, sent {sent}"
            ));
        }
    }
    assert!(cells.is_empty(), "P6:\n{}", cells.join("\n"));
}

/// MIK-8361 A5 ruling A, addition 1: a keyed `gateway_execute` chain
/// `[note, read]` whose last step the caller's own catalogue withholds
/// behaves on a first call exactly as the chain whose last step that
/// catalogue lacks: hidden means hidden on every path, so admission leaves
/// the step to its gate in both, the same answer and the same sends.
#[tokio::test]
async fn p7_a_keyed_chain_with_a_per_user_withheld_step_answers_as_a_missing_one() {
    async fn chain(slot: CallerSlot) -> ((StatusCode, Value), usize) {
        let gw = gateway(slot, Warmth::Warm, "other", false).await;
        let params = json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{BACKEND}:note"), "arguments": {}},
            {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}}
        ]}, "_meta": {crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "p7"}});
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request");
        request.extensions_mut().insert(VerifiedIdentity {
            subject: "alpha".to_string(),
            email: "alpha@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.example.invalid".to_string(),
        });
        let response = gw.router.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        ((status, value), gw.dispatched())
    }
    let withheld = chain(CallerSlot::Invalid).await;
    let missing = chain(CallerSlot::Lacks).await;
    assert_eq!(
        missing.1, 1,
        "premise: the twin runs its visible step: {:?}",
        missing.0
    );
    assert_eq!(withheld, missing, "P7: withheld vs missing");
}
