// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final): fixture for the meta-layer call-path rows.
//!
//! A multi-user gateway with one per-user backend. The shared slot and the
//! caller's (alpha's) slot are set independently, and every request the
//! upstream answers is counted, so a row can tell "answered as absent" from
//! "dispatched, then answered the same way" (O2). Kept apart from
//! `withheld_catalogue_tests.rs`, which #3807 is still changing.

use crate::security::transparency_log::temp::TempLog;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use super::catalogue_per_caller_tests::{PerIdentityMint, identity};
use super::identified_caller;
use crate::backend::{Backend, BackendRegistry, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId};

pub(crate) const BACKEND: &str = "ledger_hub";
/// The slot `PerIdentityMint` binds subject `alpha` to on audience `ledger`.
pub(crate) const BINDING: &str = "alpha@ledger";
pub(crate) const TOOL: &str = "read";
const SIBLING: &str = "note";

pub(crate) fn valid() -> Value {
    json!({"type": "object", "properties": {"q": {"type": "string"}}})
}

pub(crate) fn invalid() -> Value {
    json!({"type": "array"})
}

fn tool(name: &str, schema: &Value) -> crate::protocol::Tool {
    serde_json::from_value(json!({
        "name": name, "description": "A ledger tool.", "inputSchema": schema
    }))
    .expect("a tool")
}

/// What alpha's own catalogue holds for [`TOOL`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum CallerSlot {
    /// The tool, with a structurally invalid schema ("withheld").
    Invalid,
    /// The tool, with a valid schema.
    Valid,
    /// A complete list without the tool ("lacked").
    Lacks,
}

/// Whether alpha's slot is already filled when the row starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Warmth {
    Warm,
    Cold,
    /// Cold, and alpha's upstream refuses `tools/list`.
    ColdFailing,
}

/// Whether [`TOOL`] is surfaced (answers to its own name). `No` builds the
/// canonical absent twin: a name the gateway does not know at all.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Surfaced {
    Yes,
    No,
}

impl Surfaced {
    /// The `surfaced_tools` configuration this choice means.
    pub(crate) fn configs(self) -> Vec<crate::config::SurfacedToolConfig> {
        match self {
            Self::Yes => vec![crate::config::SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }],
            Self::No => Vec::new(),
        }
    }
}

/// Counts of what an upstream was asked.
#[derive(Default)]
pub(crate) struct Asked {
    pub(crate) lists: AtomicUsize,
    pub(crate) calls: AtomicUsize,
}

impl Asked {
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn lists(&self) -> usize {
        self.lists.load(Ordering::SeqCst)
    }
}

/// An upstream serving a fixed catalogue, counting each request.
struct Upstream {
    tools: Value,
    asked: Arc<Asked>,
    fail_list: bool,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Upstream {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            self.asked.lists.fetch_add(1, Ordering::SeqCst);
            if self.fail_list {
                return Err(crate::Error::Transport(
                    "upstream refused tools/list".into(),
                ));
            }
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({"tools": self.tools}),
            ));
        }
        self.asked.calls.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
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

/// [`PerIdentityMint`], counting each resolution (O2: "resolved N times").
pub(crate) struct CountingMint(pub(crate) Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::identity_propagation::IdentityPropagation for CountingMint {
    async fn propagate(
        &self,
        identity: &crate::key_server::oidc::VerifiedIdentity,
        backend: &crate::identity_propagation::BackendDescriptor,
    ) -> Result<
        crate::identity_propagation::PropagatedCredential,
        crate::identity_propagation::PropagationError,
    > {
        self.0.fetch_add(1, Ordering::SeqCst);
        PerIdentityMint.propagate(identity, backend).await
    }
}

/// One built fixture: the gateway and what its upstreams and mint saw.
pub(crate) struct PerUser {
    pub(crate) meta: MetaMcp,
    /// alpha's upstream (its own slot).
    pub(crate) caller: Arc<Asked>,
    /// The shared upstream.
    pub(crate) shared: Arc<Asked>,
    pub(crate) mints: Arc<AtomicUsize>,
    _audit: TempLog,
}

impl PerUser {
    pub(crate) fn mints(&self) -> usize {
        self.mints.load(Ordering::SeqCst)
    }
}

/// The per-user gateway: `shared` is the shared slot's schema for [`TOOL`],
/// `slot` alpha's own catalogue, `warmth` whether alpha's slot is filled.
/// With `Surfaced::Yes`, [`TOOL`] answers to its own name.
pub(crate) fn per_user(
    slot: CallerSlot,
    shared: &Value,
    warmth: Warmth,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
) -> PerUser {
    let (backend, caller_asked, shared_asked) = per_user_backend(slot, shared, warmth, enforcement);
    per_user_on(backend, caller_asked, shared_asked, surfaced)
}

/// The per-user backend alone, with its two upstreams' counters (alpha's
/// slot, then the shared one), for a fixture that mounts it elsewhere (the
/// router rows).
pub(crate) fn per_user_backend(
    slot: CallerSlot,
    shared: &Value,
    warmth: Warmth,
    enforcement: InputSchemaEnforcement,
) -> (Arc<Backend>, Arc<Asked>, Arc<Asked>) {
    per_user_backend_with(slot, shared, warmth, enforcement, |_| {})
}

/// [`per_user_backend`] with `configure` applied to the backend's config
/// (the P2 order guard needs a required signature chain).
pub(crate) fn per_user_backend_with(
    slot: CallerSlot,
    shared: &Value,
    warmth: Warmth,
    enforcement: InputSchemaEnforcement,
    configure: impl FnOnce(&mut BackendConfig),
) -> (Arc<Backend>, Arc<Asked>, Arc<Asked>) {
    build_per_user_backend(
        (slot, shared, warmth),
        enforcement,
        configure,
        SharedSlot::Listed,
    )
}

/// Whether the backend's shared slot has ever been listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SharedSlot {
    Listed,
    /// Never enumerated: only alpha's own slot can be known.
    NeverListed,
}

/// The per-user gateway with alpha's slot `slot` and warm, and the shared
/// slot in state `shared_slot` (the known-ness rows).
pub(crate) fn per_user_shared(slot: CallerSlot, shared_slot: SharedSlot) -> PerUser {
    let (backend, caller_asked, shared_asked) = build_per_user_backend(
        (slot, &valid(), Warmth::Warm),
        InputSchemaEnforcement::Closed,
        |_| {},
        shared_slot,
    );
    per_user_on(backend, caller_asked, shared_asked, Surfaced::Yes)
}

/// Re-attach alpha's scripted per-user upstream after a real eviction
/// dropped its slot, as a gateway reconnects a per-user slot (the pattern of
/// `backend/slot_eviction_tests.rs` `rearm`). Its catalogue lists `TOOL`
/// valid; the returned counts are the new upstream's.
pub(crate) fn rearm_alpha_slot(backend: &Backend) -> Arc<Asked> {
    rearm_alpha_slot_with(backend, &valid(), false)
}

/// [`rearm_alpha_slot`] with `read`'s schema chosen and, with `fail_list`,
/// every `tools/list` refused (MIK-8392 C2, L1).
pub(crate) fn rearm_alpha_slot_with(
    backend: &Backend,
    schema: &Value,
    fail_list: bool,
) -> Arc<Asked> {
    let asked = Arc::new(Asked::default());
    let tools = vec![tool(SIBLING, &valid()), tool(TOOL, schema)];
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: BINDING.to_string(),
        },
        Arc::new(Upstream {
            tools: serde_json::to_value(&tools).expect("tools"),
            asked: Arc::clone(&asked),
            fail_list,
        }),
    );
    asked
}

fn build_per_user_backend(
    (slot, shared, warmth): (CallerSlot, &Value, Warmth),
    enforcement: InputSchemaEnforcement,
    configure: impl FnOnce(&mut BackendConfig),
    shared_slot: SharedSlot,
) -> (Arc<Backend>, Arc<Asked>, Arc<Asked>) {
    let mut config = BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "ledger".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        input_schema_enforcement: enforcement,
        ..Default::default()
    };
    configure(&mut config);
    let backend = Arc::new(Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let shared_tools = vec![tool(TOOL, shared), tool(SIBLING, &valid())];
    let mut caller_tools = vec![tool(SIBLING, &valid())];
    match slot {
        CallerSlot::Invalid => caller_tools.push(tool(TOOL, &invalid())),
        CallerSlot::Valid => caller_tools.push(tool(TOOL, &valid())),
        CallerSlot::Lacks => {}
    }
    let shared_asked = Arc::new(Asked::default());
    let caller_asked = Arc::new(Asked::default());
    backend.set_transport_for_test(Arc::new(Upstream {
        tools: serde_json::to_value(&shared_tools).expect("tools"),
        asked: Arc::clone(&shared_asked),
        fail_list: false,
    }));
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: BINDING.to_string(),
        },
        Arc::new(Upstream {
            tools: serde_json::to_value(&caller_tools).expect("tools"),
            asked: Arc::clone(&caller_asked),
            fail_list: warmth == Warmth::ColdFailing,
        }),
    );
    if shared_slot == SharedSlot::Listed {
        backend.store_shared_tools_for_test(shared_tools);
    }
    if warmth == Warmth::Warm {
        backend.store_per_user_tools_for_test(BINDING, caller_tools);
    }
    (backend, caller_asked, shared_asked)
}

pub(crate) fn per_user_on(
    backend: Arc<Backend>,
    caller_asked: Arc<Asked>,
    shared_asked: Arc<Asked>,
    surfaced: Surfaced,
) -> PerUser {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(registry).with_surfaced_tools(surfaced.configs());
    let audit = TempLog::new();
    meta.enable_transparency_log(Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::TransparencyLogConfig {
                enabled: true,
                path: audit.path().to_string_lossy().to_string(),
                key_id: "slot-verdict".to_string(),
                ..crate::security::TransparencyLogConfig::default()
            },
        ))
        .expect("transparency logger opens"),
    ));
    let mints = Arc::new(AtomicUsize::new(0));
    meta.set_identity_propagation(Arc::new(CountingMint(Arc::clone(&mints))));
    meta.set_multi_user(true);
    PerUser {
        meta,
        caller: caller_asked,
        shared: shared_asked,
        mints,
        _audit: audit,
    }
}

/// Give `subject` its own upstream slot on [`BACKEND`] (binding
/// `{subject}@ledger`, as `PerIdentityMint` names it), serving [`TOOL`] with
/// `schema`. For rows that need a second principal.
pub(crate) fn add_caller(meta: &MetaMcp, subject: &str, schema: &Value) -> Arc<Asked> {
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let asked = Arc::new(Asked::default());
    let tools = vec![tool(TOOL, schema), tool(SIBLING, &valid())];
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: format!("{subject}@ledger"),
        },
        Arc::new(Upstream {
            tools: serde_json::to_value(&tools).expect("tools"),
            asked: Arc::clone(&asked),
            fail_list: false,
        }),
    );
    asked
}

/// Replace alpha's upstream with one whose catalogue is empty: a complete,
/// successful list of no tools.
pub(crate) fn serve_alpha_empty(meta: &MetaMcp) -> Arc<Asked> {
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let asked = Arc::new(Asked::default());
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: BINDING.to_string(),
        },
        Arc::new(Upstream {
            tools: json!([]),
            asked: Arc::clone(&asked),
            fail_list: false,
        }),
    );
    asked
}

/// alpha's call of `name` with `arguments`, as the JSON the client receives.
pub(crate) async fn call_as_alpha(meta: &MetaMcp, name: &str, arguments: Value) -> Value {
    let alpha = identity("alpha");
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        name,
        arguments,
        None,
        identified_caller(&alpha),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}

/// The binding the caller-slot index holds for `subject` on [`BACKEND`].
pub(crate) fn indexed_binding_for(meta: &MetaMcp, subject: &str) -> Option<String> {
    let who = identity(subject);
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let caller = identified_caller(&who);
    meta.caller_slot_binding_for(&backend, MetaMcp::proof_of(&caller))
}

// Shared by the MIK-8356 row files (call path, listings, index).

/// alpha lists `BACKEND` through `gateway_list_tools`: a real fill of alpha's
/// own slot, the way a caller's slot becomes warm (and indexed).
pub(crate) async fn warm_by_listing(meta: &MetaMcp) {
    let alpha = identity("alpha");
    meta.list_tools(
        &json!({"server": BACKEND}),
        None,
        &identified_caller(&alpha),
    )
    .await
    .expect("gateway_list_tools answers");
}

/// The disabled-capability list as alpha sees it, with [`TOOL`] disabled.
pub(crate) fn disabled_as_alpha(meta: &MetaMcp) -> Value {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch
            .record_capability_failure(BACKEND, TOOL, &cfg);
    }
    let alpha = identity("alpha");
    meta.list_disabled_capabilities(identified_caller(&alpha).scope(), None)
        .expect("the disabled list answers")
}

pub(crate) fn names_tool(listed: &Value) -> bool {
    listed["disabled_capabilities"]
        .as_array()
        .is_some_and(|all| all.iter().any(|e| e["capability"] == TOOL))
}

/// The next-tool predictions alpha is given after `ledger_hub:note`, once
/// another session has taught the shared tracker that `read` follows it.
pub(crate) fn predictions_for_alpha(meta: &MetaMcp) -> Vec<Value> {
    let tracker = std::sync::Arc::new(crate::transition::TransitionTracker::new());
    meta.set_transition_tracker(std::sync::Arc::clone(&tracker));
    let (from, to) = ("ledger_hub:note", "ledger_hub:read");
    for _ in 0..8 {
        tracker.record_transition("teacher", from);
        tracker.record_transition("teacher", to);
    }
    let alpha = identity("alpha");
    meta.record_and_predict(
        None,
        Some("alpha-session"),
        from,
        identified_caller(&alpha).scope(),
    )
}

pub(crate) fn predicts_tool(predicted: &[Value]) -> bool {
    predicted.iter().any(|p| p["tool"] == "ledger_hub:read")
}

/// The surfaced [`TOOL`] entry in alpha's plain `tools/list`, if listed.
pub(crate) fn surfaced_entry_for_alpha(meta: &MetaMcp) -> Option<Value> {
    let alpha = identity("alpha");
    let response = meta.handle_tools_list_for_session(
        crate::protocol::RequestId::Number(1),
        None,
        identified_caller(&alpha).scope(),
    );
    let body = serde_json::to_value(&response).expect("a response serialises");
    body.pointer("/result/tools")?
        .as_array()?
        .iter()
        .find(|t| t["name"] == TOOL)
        .cloned()
}

/// The binding the caller-slot index holds for alpha on `BACKEND`.
pub(crate) fn indexed_binding_for_alpha(meta: &MetaMcp) -> Option<String> {
    indexed_binding_for(meta, "alpha")
}

/// The I2e invariant: every per-user slot whose catalogue has ever been
/// stored is pointed at by the index. A fill site that stores without
/// recording fails here. (After the implementation lands it runs at the end
/// of every row; on the stub it would turn the guards red, so for now it is
/// its own row.)
pub(crate) fn assert_index_covers_populated_slots(meta: &MetaMcp, row: &str) {
    let backend = meta.backends.for_test().get(BACKEND).expect("the backend");
    let populated = backend.populated_per_user_bindings_for_test();
    let indexed = backend.indexed_bindings_for_test();
    let missing: Vec<_> = populated.iter().filter(|b| !indexed.contains(b)).collect();
    assert!(
        missing.is_empty(),
        "{row}: populated per-user slots with no index entry: {missing:?}"
    );
}

/// [`TOOL`] disabled, then the disabled list as `caller` sees it.
pub(crate) fn disabled_for(meta: &MetaMcp, caller: &super::MetaMcpCallerContext<'_>) -> Value {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch
            .record_capability_failure(BACKEND, TOOL, &cfg);
    }
    meta.list_disabled_capabilities(caller.scope(), None)
        .expect("the disabled list answers")
}
