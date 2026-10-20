// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 stage 4 stdio guard: G25's S leg. The rig is
//! `collusion_stdio_plan_replay`'s, reused.
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::collusion_stdio_plan_replay::{
    OTHER_PROSE, PROSE, WINDOW_SECS, dispatch, keyed_request, relayed_by_bob,
};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// The gateway's recovery advice for a tool error it reads as a parameter
/// problem: the gateway's own text, longer than a k-gram.
const SUGGEST: &str =
    "Check the tool's input schema, correct the offending parameter(s), and retry.";

/// G25's playbook over stdio: `on_error: continue`, one step on each of
/// `alpha:a` and `alpha:b`, its output mapping both steps' text.
const PLAYBOOK: &str = "name: replay\ndescription: plan steps\non_error: continue\ninputs: {}\nsteps:\n\
                        \x20 - name: s1\n    server: alpha\n    tool: a\n\
                        \x20 - name: s2\n    server: alpha\n    tool: b\n\
                        output:\n  type: object\n  properties:\n\
                        \x20   a:\n      path: $s1.content[0].text\n\
                        \x20   b:\n      path: $s2.content[0].text\n";

/// Backend `alpha`: `a` answers [`PROSE`]; `b` answers a tool error with
/// no text block, in kind the parameter-style error R9 uses, so the
/// gateway writes [`SUGGEST`] into its result; every call counted.
struct SuggestSteps(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for SuggestSteps {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tools: Vec<Value> = ["a", "b"]
                .iter()
                .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
                .collect();
            return Ok(JsonRpcResponse::success(id, json!({ "tools": tools })));
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default();
        let answer = if name == "a" {
            json!({"content": [{"type": "text", "text": PROSE}], "isError": false})
        } else {
            json!({"content": [], "isError": true})
        };
        Ok(JsonRpcResponse::success(id, answer))
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

/// `meta` with G25's [`PLAYBOOK`] registered.
fn with_replay_playbook(meta: &mut MetaMcp) {
    let definition: crate::playbook::PlaybookDefinition =
        crate::yaml::from_str(PLAYBOOK).expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
}

/// G25-S's detection-on gateway over `off`'s admission, with its
/// freshly keyed relay firewall and the playbook registered.
fn detection_on_gateway(
    registry: Arc<BackendRegistry>,
    off: &Arc<MetaMcp>,
) -> (Arc<Firewall>, Arc<MetaMcp>) {
    let firewall = Arc::new(
        Firewall::from_config(
            FirewallConfig {
                rules: crate::yaml::from_str("[{match: \"*\", action: allow}]")
                    .expect("the fixture rules parse: fixture"),
                collusion: CollusionConfig {
                    action: CollusionAction::Block,
                    min_matches: 1,
                    sources: vec!["alpha:*".to_string()],
                    window_secs: WINDOW_SECS,
                    ..CollusionConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test()
        .keeping_every_kgram(),
    );
    firewall.advance_collusion_clock_for_test(Duration::ZERO);
    let mut on = MetaMcp::new(registry);
    on.share_execution_admission_for_test(Arc::clone(off.execution_admission()));
    on.set_firewall(Some(Arc::clone(&firewall)));
    on.share_keyring_with_for_test(&firewall);
    with_replay_playbook(&mut on);
    (firewall, Arc::new(on))
}

/// G25 (S): a keyed stdio plan delivered with relay detection off,
/// then the firewall swapped on over the same retained answers
/// (the same `ExecutionAdmission`, as R9s swaps it). The repeat
/// serves the retained answer and renews nothing, counted
/// `reason=absent`, and receipts no gateway text: the stored answer
/// carries [`SUGGEST`] (premise); a live delivery on the new gateway
/// then receipts as usual (control).
/// Mutants killed: open the provenance scope only when relay is
/// active (a rebuild at replay would receipt the stored answer:
/// bob would be refused); no gateway-writes scope with detection off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g25_a_detection_off_stdio_plan_renews_nothing_once_detection_is_on() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(SuggestSteps(Arc::clone(&calls))));
    assert!(registry.register(backend), "premise: the backend registers");
    let mut off_meta = MetaMcp::new(Arc::clone(&registry));
    with_replay_playbook(&mut off_meta);
    let off = Arc::new(off_meta);
    let playbook_args = json!({"name": "replay", "arguments": {}});
    let first = dispatch(
        &off,
        &keyed_request(1, "gateway_run_playbook", &playbook_args),
    )
    .await;
    assert!(
        first.get("error").is_none(),
        "base: delivered with detection off: {first}"
    );
    assert!(
        first.to_string().contains(SUGGEST),
        "premise: stored answer carries the gateway's advice: {first}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "premise: both steps dispatched"
    );

    let (firewall, on) = detection_on_gateway(registry, &off);
    let request = keyed_request(2, "gateway_run_playbook", &playbook_args);
    let measured = dispatch(&on, &request);
    #[cfg(feature = "metrics")]
    let (replay, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
    #[cfg(not(feature = "metrics"))]
    let replay = measured.await;
    assert!(replay.get("error").is_none(), "base: replayed: {replay}");
    assert_eq!(
        replay["result"], first["result"],
        "premise: retained answer replayed unchanged"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "P2: the replay dispatched nothing"
    );
    for text in [PROSE, OTHER_PROSE] {
        assert!(
            !relayed_by_bob(&firewall, text),
            "the replay renewed a detection-off plan for {text:.40}"
        );
    }
    assert!(
        !relayed_by_bob(&firewall, SUGGEST),
        "the replay receipted the gateway's own advice"
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        absent, 1,
        "not counted exactly once reason=absent for the one absent lookup"
    );
    let live_args = json!({"server": "alpha", "tool": "a", "arguments": {}});
    // A fresh key: `keyed_request`'s key already holds the playbook
    // call, and reusing it for this different request is a 409.
    let mut live_call = keyed_request(3, "gateway_invoke", &live_args);
    live_call["params"]["_meta"]["io.mcp-gateway/idempotency-key"] = json!("stdio-g25-live");
    let live = dispatch(&on, &live_call).await;
    assert!(
        live.get("error").is_none(),
        "control premise: live delivery succeeds: {live}"
    );
    assert!(
        relayed_by_bob(&firewall, PROSE),
        "control: detection on receipts its own deliveries"
    );
}
