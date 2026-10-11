// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final): fixture for the meta-layer call-path rows.
//!
//! A multi-user gateway with one per-user backend. The shared slot and the
//! caller's (alpha's) slot are set independently, and every request the
//! upstream answers is counted, so a row can tell "answered as absent" from
//! "dispatched, then answered the same way" (O2). Kept apart from
//! `withheld_catalogue_tests.rs`, which #3807 is still changing.

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
    _audit: tempfile::NamedTempFile,
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
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
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
        },
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
    backend.store_shared_tools_for_test(shared_tools);
    if warmth == Warmth::Warm {
        backend.store_per_user_tools_for_test(BINDING, caller_tools);
    }
    (backend, caller_asked, shared_asked)
}

fn per_user_on(
    backend: Arc<Backend>,
    caller_asked: Arc<Asked>,
    shared_asked: Arc<Asked>,
    surfaced: Surfaced,
) -> PerUser {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    let mut meta = MetaMcp::new(registry).with_surfaced_tools(surfaced.configs());
    let audit = tempfile::NamedTempFile::new().expect("tempfile");
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
    let backend = meta.backends.get(BACKEND).expect("the backend");
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
