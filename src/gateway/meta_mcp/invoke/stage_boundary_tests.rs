// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8488: characterisation rows at the stage boundaries of
//! `invoke_tool_traced` that no earlier row pins. Each drives the real call
//! path (`invoke_tool`), so it reads the same before and after the stages
//! moved into child modules; each was shown red against a mutant that breaks
//! its stage (the design note's mutant table) and green on the code it pins.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::protocol::{JsonRpcResponse, RequestId};

/// A backend that answers every `tools/call` and, at the moment the call
/// reaches it, records whether the call's signing context still held a
/// refund witness. The probe puts a witness it finds back, so it observes
/// without changing what the call settles.
struct Probe {
    signing: Option<Arc<SigningInvocationContext>>,
    witness_at_dispatch: AtomicBool,
    calls: AtomicUsize,
    /// The arguments of the last `tools/call` the backend received.
    sent: std::sync::Mutex<Option<Value>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Probe {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.sent.lock().expect("probe lock") =
                params.and_then(|params| params.get("arguments").cloned());
            if let Some(signing) = &self.signing
                && let Some(witness) = signing.take_witness()
            {
                self.witness_at_dispatch.store(true, Ordering::SeqCst);
                signing.keep_witness(witness);
            }
        }
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "done"}], "isError": false}),
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

fn gateway(probe: &Arc<Probe>) -> MetaMcp {
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(probe) as Arc<dyn crate::transport::Transport>);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));
    MetaMcp::new(registry)
}

/// S7 (mutant m18): the witness goes with the send. While the backend holds
/// the call, the signing context keeps no witness, so nothing could refund a
/// nonce whose call the backend is running. A witness dropped back into the
/// context before the dispatch is the fault: `mark_dispatched` would still
/// veto the refund, which is why only this boundary sees it.
#[tokio::test]
async fn the_signing_context_holds_no_witness_while_the_backend_runs() {
    let signing = Arc::new(SigningInvocationContext::external_for_test(Some("n-8488")));
    signing.keep_witness(RefundWitness::at_capture());
    let probe = Arc::new(Probe {
        signing: Some(Arc::clone(&signing)),
        witness_at_dispatch: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        sent: std::sync::Mutex::new(None),
    });
    let meta = gateway(&probe);
    let caller = MetaMcpCallerContext {
        signing: Some(&signing),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    let outcome = meta.invoke_tool(&args, Some("session-8488"), &caller).await;
    assert!(outcome.is_ok(), "the control call failed: {outcome:?}");
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "the call never reached the backend"
    );
    assert!(
        !probe.witness_at_dispatch.load(Ordering::SeqCst),
        "the signing context held a refund witness while the backend ran"
    );
}

/// S8 (mutant m11): an answer the backend gave and a post-dispatch gate then
/// refused settles the call's key as executed. A same-key retry is told the
/// side effect ran, and the backend is not called a second time. Released
/// instead, the key would readmit the retry and run the side effect again.
#[tokio::test]
async fn a_refused_answer_settles_its_key_so_a_retry_does_not_run_again() {
    let probe = Arc::new(Probe {
        signing: None,
        witness_at_dispatch: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        sent: std::sync::Mutex::new(None),
    });
    let mut meta = gateway(&probe);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    // Every answer is refused after the dispatch: no contract is declared.
    meta.set_response_contract(crate::config::ResponseContractConfig {
        enabled: true,
        action_mode: true,
        fail_closed: true,
        ..Default::default()
    });
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("k-8488".to_owned()),
        ..Default::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    let first = meta.invoke_tool(&args, Some("session-8488"), &caller).await;
    assert!(
        first.is_err(),
        "the contract gate did not refuse: {first:?}"
    );
    let second = meta.invoke_tool(&args, Some("session-8488"), &caller).await;
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "the retry ran the call again"
    );
    let served = format!("{second:?}");
    assert!(
        served.contains("Side effect executed"),
        "the retry was not told the side effect ran: {served}"
    );
}

/// S2 (mutant m20): `_full` is a gateway directive. It is stripped before the
/// keys and the dispatch, so the backend receives the caller's own arguments
/// and never the directive (MIK-3533).
#[tokio::test]
async fn the_full_directive_never_reaches_the_backend() {
    let probe = Arc::new(Probe {
        signing: None,
        witness_at_dispatch: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        sent: std::sync::Mutex::new(None),
    });
    let meta = gateway(&probe);
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let args = json!({"server": "svc", "tool": "act", "arguments": {"q": 1, "_full": true}});
    let outcome = meta.invoke_tool(&args, Some("session-8488"), &caller).await;
    assert!(outcome.is_ok(), "the control call failed: {outcome:?}");
    let sent = probe.sent.lock().expect("probe lock").clone();
    assert_eq!(sent, Some(json!({"q": 1})), "the backend received {sent:?}");
}

/// S2 (mutant m20): `_full` is stripped before the key's fingerprint is taken,
/// so a same-key retry that drops the directive is the same request: it is
/// served the first answer and the backend runs once.
#[tokio::test]
async fn toggling_full_under_one_key_replays_the_first_answer() {
    let probe = Arc::new(Probe {
        signing: None,
        witness_at_dispatch: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        sent: std::sync::Mutex::new(None),
    });
    let mut meta = gateway(&probe);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("k-8488-full".to_owned()),
        ..Default::default()
    };
    let caller = MetaMcpCallerContext {
        retry: &retry,
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let with_full = json!({"server": "svc", "tool": "act", "arguments": {"q": 1, "_full": true}});
    let without = json!({"server": "svc", "tool": "act", "arguments": {"q": 1}});
    let first = meta
        .invoke_tool(&with_full, Some("session-8488"), &caller)
        .await;
    assert!(first.is_ok(), "the first call failed: {first:?}");
    let second = meta
        .invoke_tool(&without, Some("session-8488"), &caller)
        .await;
    assert!(second.is_ok(), "the same-key retry was refused: {second:?}");
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "the retry ran the call again"
    );
}

/// S10 (mutant m17): a live MCP backend's own answer that every gate passed
/// through is delivered as the backend's, so it is eligible for the response
/// chain (A3). Delivered as the gateway's, it would silently lose that.
#[tokio::test]
async fn a_live_backend_answer_is_delivered_as_the_backends() {
    let probe = Arc::new(Probe {
        signing: None,
        witness_at_dispatch: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        sent: std::sync::Mutex::new(None),
    });
    let meta = gateway(&probe);
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    let outcome = meta
        .invoke_tool_traced(&args, Some("session-8488"), &caller, "trace-8488")
        .await;
    let Ok(super::TracedOutcome::Live(guarded)) = outcome else {
        panic!("a live call was not answered live");
    };
    let (_, source, _) = guarded.into_parts();
    assert_eq!(source, crate::protocol::ChainSource::Backend);
}

/// The files the send path of `invoke_tool_traced` lives in.
const SEND_PATH: [(&str, &str); 2] = [
    ("invoke.rs", include_str!("../invoke.rs")),
    ("post_dispatch.rs", include_str!("post_dispatch.rs")),
];

/// S7 (design r3 item 5): the dispatch is boxed once, and the spend admission
/// is given back right after its await. A second box would be a per-call
/// allocation the differential allocation rows cancel out; a drop moved later
/// would hold the spend reservation across the dispatch error's settlement.
#[test]
fn the_send_path_boxes_one_dispatch_and_drops_the_admission_right_after_it() {
    // Per file, so a failure names where the extra or missing site is.
    let sites = |needle: &str| -> Vec<(&str, usize)> {
        SEND_PATH
            .iter()
            .map(|(file, source)| (*file, source.matches(needle).count()))
            .filter(|(_, n)| *n > 0)
            .collect()
    };
    let box_sites = sites("Box::pin(");
    assert_eq!(
        box_sites.iter().map(|(_, n)| n).sum::<usize>(),
        1,
        "boxes: {box_sites:?}"
    );
    let drop_sites = sites("drop(admission);");
    assert_eq!(
        drop_sites.iter().map(|(_, n)| n).sum::<usize>(),
        1,
        "drops: {drop_sites:?}"
    );
    let (_, source) = SEND_PATH
        .iter()
        .find(|(_, source)| source.contains("Box::pin("))
        .expect("counted above");
    let boxed = source.find("Box::pin(").expect("counted above");
    let awaited = boxed
        + source[boxed..]
            .find(".await;")
            .expect("the boxed dispatch is awaited");
    let between = &source[awaited + ".await;".len()..];
    let dropped = between
        .find("drop(admission);")
        .expect("the drop follows the await");
    let only_comments = between[..dropped]
        .lines()
        .all(|line| line.trim().is_empty() || line.trim_start().starts_with("//"));
    assert!(
        only_comments,
        "code runs between the dispatch's await and the admission's drop"
    );
}
