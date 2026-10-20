// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 PR-W (NONCEFX.10, frozen r4 §70): a signed call that joins
//! another request's in-flight `tools/list` fill keeps its nonce spent when a
//! later refusal asks for it back. The join is observed through the fill's
//! waiter count, never timed. Red on base: a join never moves `list_fills`,
//! so the spend refusal's ask gives the nonce back.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::authz_tests::{ctx, invoke_args};
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

const NONCE: &str = "waiter-nonce";

/// A backend whose every `tools/list` is held until released, counting the
/// lists it received and the calls that reached it.
struct Holding {
    lists: AtomicUsize,
    calls: AtomicUsize,
    release: tokio::sync::Semaphore,
}

impl Default for Holding {
    fn default() -> Self {
        Self {
            lists: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

#[async_trait::async_trait]
impl Transport for Holding {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.release.acquire().await.expect("never closed").forget();
            let tools = json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]});
            return Ok(JsonRpcResponse::success(id, tools));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ok = json!({"content": [{"type": "text", "text": "ok"}], "isError": false});
        Ok(JsonRpcResponse::success(id, ok))
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

/// Signed `MetaMcp` over one checked (`standard`) backend `alpha` answering
/// through `wire`, with spend governance refusing `k-budget`'s first `read`.
fn gateway(wire: &Arc<Holding>) -> (MetaMcp, Arc<Backend>) {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let registry = Arc::new(BackendRegistry::new());
    let config = BackendConfig {
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Standard,
        ..BackendConfig::r2_off()
    };
    let backend = Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(wire) as Arc<dyn Transport>);
    let _ = registry.register(Arc::clone(&backend));
    let mut meta = MetaMcp::new(registry);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"waiter-key-0123456789abcdef-0123".to_vec(),
            None,
            "k1".into(),
        ),
        Duration::from_secs(300),
        true,
    );
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 0.5);
    let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        Arc::clone(&registry),
    ));
    (meta.with_cost_governance(enforcer, registry), backend)
}

fn signed(name: &str, arguments: &Value) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): NONCE}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    (context, request["params"]["arguments"].clone())
}

/// B: `k-budget`'s signed `gateway_invoke alpha read` under `NONCE`, holding
/// the witness as admission leaves it. Returns the wire answer.
async fn call_b(meta: &MetaMcp) -> Value {
    let allow = AllowAll;
    let mut caller = ctx(&allow);
    caller.api_key_name = Some("k-budget");
    // An API key: only an API key is charged per key (MIK-8507).
    caller.credential_kind = crate::security::audit::CredentialKind::ApiKey;
    let (mut signing, arguments) = signed("gateway_invoke", &invoke_args("alpha", "read"));
    meta.prepare_signing_for_call(&mut signing, "gateway_invoke", &arguments, None, &caller)
        .expect("the refusal is the dispatcher's");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(7),
        "gateway_invoke",
        arguments,
        None,
        caller,
    ))
    .await;
    serde_json::to_value(&response).expect("a response serializes")
}

/// What a later call presenting `NONCE` meets.
#[derive(Debug, PartialEq, Eq)]
enum Nonce {
    /// Admitted: the refused call gave it back.
    Free,
    /// Refused as a replay: the refused call kept it spent.
    Replayed,
}

/// Probe `NONCE` with an ordinary call. Any answer but admission or the
/// replay refusal fails the row, so a broken probe never reads as a KEEP.
fn nonce_state(meta: &MetaMcp) -> Nonce {
    let (mut later, arguments) = signed("gateway_list_servers", &json!({}));
    let allow = AllowAll;
    match meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &ctx(&allow),
    ) {
        Ok(()) if !later.awaits_admission() => Nonce::Free,
        Ok(()) => panic!("the probe was not admitted and not refused"),
        // `message_signing.rs`'s replay refusal: -32001, "Nonce replay detected".
        Err(e) if e.to_rpc_code() == -32001 && e.to_string().contains("Nonce replay detected") => {
            Nonce::Replayed
        }
        Err(e) => panic!("the probe failed for another reason: {e}"),
    }
}

/// Wait until `ready`, failing the row (not hanging it) after 10 s.
async fn until(what: &str, ready: impl Fn() -> bool) {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "timed out waiting for {what}");
}

/// A's fill held on the wire, B started only once A is past `admit_fill`,
/// A released only once B's join is observed and B has not returned. The
/// premises are asserted here; B's answer is returned for the oracle.
async fn b_joins_a_held_fill(meta: &MetaMcp, alpha: &Backend, wire: &Holding) -> Value {
    let fills = alpha.list_fills();
    let (a_listed, b_done) = (AtomicBool::new(false), AtomicBool::new(false));
    let a = async {
        alpha.get_tools_shared().await.expect("A's fill answers");
    };
    let b = async {
        until("A's tools/list on the wire", || {
            a_listed.load(Ordering::SeqCst)
        })
        .await;
        let wire = call_b(meta).await;
        b_done.store(true, Ordering::SeqCst);
        wire
    };
    let control = async {
        until("A's tools/list on the wire", || {
            wire.lists.load(Ordering::SeqCst) == 1
        })
        .await;
        assert_eq!(
            alpha.list_fills(),
            fills + 1,
            "premise: A's fill was admitted"
        );
        a_listed.store(true, Ordering::SeqCst);
        until("B to join A's fill", || alpha.tools_waiters_for_test() >= 1).await;
        assert!(
            !b_done.load(Ordering::SeqCst),
            "premise: B waits on A's fill"
        );
        wire.release.add_permits(1);
    };
    let ((), answer, ()) = tokio::join!(a, b, control);
    assert!(
        answer
            .to_string()
            .to_lowercase()
            .contains("budget exceeded"),
        "premise: B is refused by the spend budget: {answer}"
    );
    assert_eq!(
        wire.lists.load(Ordering::SeqCst),
        1,
        "premise: one tools/list, A's"
    );
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        0,
        "premise: nothing was dispatched"
    );
    answer
}

/// K-waiter: the gate skipped, so B's first catalogue read is the
/// undeclared-key check (invoke.rs, the `schema_effect` carry), and it joins
/// A's fill there. Mutant: mW (the join bump at backend/metadata.rs:414).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_spend_refusal_after_joining_a_fill_keeps_the_nonce() {
    let wire = Arc::new(Holding::default());
    let (meta, alpha) = gateway(&wire);
    let _skip = crate::gateway::meta_mcp::withheld_gate::seams::skip_gate_for_test();
    let answer = b_joins_a_held_fill(&meta, &alpha, &wire).await;
    assert_eq!(
        nonce_state(&meta),
        Nonce::Replayed,
        "the nonce was given back after joining a fill: {answer}"
    );
}

/// K-waiter-gate: B's gate (`gated`, `gate_answer` → `shared_verdict` →
/// `catalogue_verdict`) is its first catalogue read, before invoke.rs takes its
/// own fill mark, so B joins A's fill at the gate. Mutants: mW; mGateCarry
/// (the gate's `witness.carry(schema_effect(..))` removed: the invoke check's
/// mark is read after the join, so it sees no fill).
#[tokio::test]
async fn a_spend_refusal_after_the_gate_joins_a_fill_keeps_the_nonce() {
    let wire = Arc::new(Holding::default());
    let (meta, alpha) = gateway(&wire);
    let answer = b_joins_a_held_fill(&meta, &alpha, &wire).await;
    assert_eq!(
        nonce_state(&meta),
        Nonce::Replayed,
        "the nonce was given back after the gate joined a fill: {answer}"
    );
}

/// R-waiter-warm (control): A's fill done, so B's checks hit the cache and
/// never call `waiting`; nothing acted, and the refusal gives the nonce back.
/// Green on base and after PR-W: the join bump must not over-spend.
#[tokio::test]
async fn a_spend_refusal_on_a_warm_slot_gives_the_nonce_back() {
    let wire = Arc::new(Holding::default());
    wire.release.add_permits(1);
    let (meta, alpha) = gateway(&wire);
    alpha.get_tools_shared().await.expect("A's fill answers");
    let fills = alpha.list_fills();
    let answer = call_b(&meta).await;
    assert!(
        answer
            .to_string()
            .to_lowercase()
            .contains("budget exceeded"),
        "premise: B is refused by the spend budget: {answer}"
    );
    assert_eq!(alpha.list_fills(), fills, "premise: B filled nothing");
    assert_eq!(
        wire.lists.load(Ordering::SeqCst),
        1,
        "premise: A's list only"
    );
    assert_eq!(
        nonce_state(&meta),
        Nonce::Free,
        "the nonce was kept though nothing acted: {answer}"
    );
}
