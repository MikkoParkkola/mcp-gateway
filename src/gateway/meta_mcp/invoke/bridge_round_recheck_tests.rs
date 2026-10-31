// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Every bridged round reuses the first round's credential, and every one of
//! its sends runs that credential's check again (ADR-007 IDP.7). A grant
//! revoked between two rounds sends nothing on the second and evicts the
//! slot; a grant rotated between them refuses that loan and keeps the slot:
//! the new credential is not resolved mid-call, the user's retry mints it.
//!
//! The backend is a real HTTP transport to a loopback peer, so each send goes
//! through the lender's check exactly as in production.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{BridgeDispatcher, MetaMcp};
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::input_bridge::BackendInvoker;
use crate::gateway::meta_mcp::InvokeScope;
use crate::gateway::router::CallerStanding;
use crate::identity_propagation::{
    CallerProof, IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::transport::{LentCredential, Refusal};

const BACKEND: &str = "ledger";
const TOOL: &str = "lookup";
const BINDING: &str = "alpha@ledger";

/// What the credential's check answers now.
const VALID: u8 = 0;
const REVOKED: u8 = 1;
const ROTATED: u8 = 2;

/// A streamable HTTP MCP peer on loopback; returns its URL and how many
/// `tools/call` requests reached it.
async fn peer() -> (String, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let app = axum::Router::new().fallback(move |axum::Json(message): axum::Json<Value>| {
        let counted = Arc::clone(&counted);
        async move {
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            let result = match message["method"].as_str().unwrap_or_default() {
                "server/discover" => json!({
                    "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                    "capabilities": {"tools": {}}
                }),
                "tools/list" => json!({"tools": [{
                    "name": TOOL,
                    "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                }]}),
                "tools/call" => {
                    counted.fetch_add(1, Ordering::SeqCst);
                    json!({"content": [{"type": "text", "text": "ok"}]})
                }
                _ => json!({}),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, calls)
}

/// A required per-user backend at `url`, registered alone.
fn meta_over(url: String) -> MetaMcp {
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://ledger.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    MetaMcp::new(registry)
}

/// The dispatch's credential, whose check answers as `state` says at each
/// send: the managed lease's recheck, reduced to its three outcomes.
fn credential(state: &Arc<AtomicU8>) -> LentCredential {
    let state = Arc::clone(state);
    LentCredential {
        headers: vec![(
            "Authorization".to_owned(),
            "Bearer alpha-ledger-grant".to_owned(),
        )]
        .into(),
        check: Some(Arc::new(move || {
            let now = state.load(Ordering::SeqCst);
            Box::pin(async move {
                match now {
                    VALID => Ok(()),
                    REVOKED => Err(Refusal::Definitive),
                    _ => Err(Refusal::ThisLoan),
                }
            })
        })),
    }
}

/// What two bridged rounds left: the second round's outcome, the
/// `tools/call` count after each round, whether the caller's slot survived,
/// and the decision kind the second round noted.
type TwoRounds = (
    Result<Value, String>,
    [usize; 2],
    bool,
    Option<crate::security::decision_record::DecisionKind>,
);

/// Run two bridged rounds of one call, with the grant moved to `between`
/// after the first.
async fn two_rounds(between: u8) -> TwoRounds {
    let (url, calls) = peer().await;
    let meta = meta_over(url);
    let state = Arc::new(AtomicU8::new(VALID));
    let headers = credential(&state);
    let arguments = json!({"q": "x"});
    let ctx = crate::gateway::meta_mcp::authz_tests::ctx(&crate::gateway::authz::AllowAll);
    let account_refusal = parking_lot::Mutex::new(None);
    let reservation = parking_lot::Mutex::new(None);
    let relay_refused = parking_lot::Mutex::new(None);
    let round = BridgeDispatcher {
        meta: &meta,
        caller: &ctx,
        server: BACKEND,
        tool: TOOL,
        arguments: &arguments,
        prompt_cache_key: None,
        inbound_meta: None,
        want_full: false,
        session_id: None,
        arm_key: None,
        caller_identity: None,
        caller_proof: CallerProof::Anonymous,
        credential_owner: None,
        headers: &headers,
        cache_binding: Some(BINDING),
        account_credential: super::propagation::DispatchAccount::default(),
        api_key_name: None,
        trace_id: "bridge-recheck",
        policy_epoch: 0,
        protocol_revision: None,
        routing_profile: "default",
        scope: InvokeScope::allow_all(CallerStanding::Standard),
        captured: meta.backends.for_test().get(BACKEND),
        managed: None,
        account_refusal: &account_refusal,
        reservation: &reservation,
        relay: super::relay::RelayKey::unkeyed_for_test("bridge-recheck"),
        relay_refused: &relay_refused,
    };
    round
        .invoke(json!({}))
        .await
        .expect("premise: the first round is sent");
    let first = calls.load(Ordering::SeqCst);
    state.store(between, Ordering::SeqCst);
    let (second, noted) = super::audit::with_route_scope(async {
        let second = round.invoke(json!({})).await.map_err(|e| format!("{e:?}"));
        (second, super::audit::take_refusal_kind())
    })
    .await;
    let slot = PoolKey::PerUser {
        binding: BINDING.to_owned(),
    };
    let kept = meta
        .backends
        .for_test()
        .get(BACKEND)
        .expect("the backend")
        .pool_has_slot_for_test(&slot);
    (second, [first, calls.load(Ordering::SeqCst)], kept, noted)
}

#[tokio::test]
async fn a_grant_revoked_between_bridge_rounds_sends_nothing_and_evicts_the_slot() {
    let (second, calls, kept, _) = two_rounds(REVOKED).await;
    assert_eq!(calls[0], 1, "premise: the first round reached the peer");
    assert!(second.is_err(), "the second round was answered: {second:?}");
    assert_eq!(calls[1], 1, "the second round reached the peer");
    assert!(!kept, "the revoked caller's slot was kept");
}

#[tokio::test]
async fn a_grant_rotated_between_bridge_rounds_refuses_that_loan_and_keeps_the_slot() {
    let (second, calls, kept, _) = two_rounds(ROTATED).await;
    assert_eq!(calls[0], 1, "premise: the first round reached the peer");
    assert!(second.is_err(), "the second round was answered: {second:?}");
    assert_eq!(calls[1], 1, "the second round reached the peer");
    assert!(kept, "a rotation evicted the caller's slot");
}

/// A later round refused at its send notes `unrecorded`, as the first
/// round's dispatch would: the record never reads `default_allow`.
#[tokio::test]
async fn a_send_refused_on_a_later_bridged_round_notes_unrecorded() {
    let (second, _, _, noted) = two_rounds(ROTATED).await;
    assert!(second.is_err(), "premise: the second round was refused");
    assert_eq!(
        noted,
        Some(crate::security::decision_record::DecisionKind::Unrecorded),
        "{second:?}"
    );
}
