// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3, C3 and the stdio twin of C10: a stdio `tools/call`
//! of a surfaced per-user tool is judged by the caller's own catalogue slot.
//!
//! Production stdio carries no verified identity, so the per-user fixture is
//! the supported stdio case: a managed account held by the sole operator
//! (`DirectAccountGateway`, production compile, install and custody). The
//! loopback twin harness (`withheld_parity_stdio`) builds through
//! `Gateway::new`, which cannot carry a managed binding without opening a
//! real store, so these rows use the managed door instead of extending
//! `withheld_twin_tests::Spec`.
//!
//! Twins differ only in the sole operator's slot (or, for the absent twin,
//! in whether the name is surfaced); the shared slot always holds the tool
//! with a valid schema, so on base the shared verdict lets it dispatch.

use std::sync::Arc;

use serde_json::{Value, json};

use super::super::{STDIO_SESSION_ID, StdioClient, StdioTelemetry};
use crate::config::{AuthConfig, InputSchemaEnforcement, SurfacedToolConfig};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::gateway::server::account_bindings::ServeMode;
use crate::protocol::meta::Declared;

const TOOL: &str = "read";
const SIBLING: &str = "note";

/// What the sole operator's own slot holds for [`TOOL`].
#[derive(Clone, Copy, Debug)]
enum Slot {
    Valid,
    /// Structurally invalid schema ("withheld").
    Invalid,
    /// A complete list without it ("lacked").
    Lacks,
}

fn tool(name: &str, schema: &Value) -> crate::protocol::Tool {
    serde_json::from_value(
        json!({"name": name, "description": "A mail tool.", "inputSchema": schema}),
    )
    .expect("a tool")
}

fn valid() -> Value {
    json!({"type": "object", "properties": {"folder": {"type": "string"}}})
}

/// A stdio gateway over the sole operator's managed backend, both slots warm.
struct Stdio {
    gateway: DirectAccountGateway,
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
}

impl Stdio {
    fn new(slot: Slot, surfaced: bool, enforcement: InputSchemaEnforcement) -> Self {
        let mut gateway = DirectAccountGateway::new_with(
            ServeMode::Stdio,
            AuthConfig::default(),
            &Binding::Connected,
            Some(enforcement),
        );
        let surfaced = if surfaced {
            vec![SurfacedToolConfig {
                server: BACKEND.to_string(),
                tool: TOOL.to_string(),
            }]
        } else {
            Vec::new()
        };
        let meta = Arc::new(gateway.take_meta().with_surfaced_tools(surfaced));
        let backend = gateway.backends().get(BACKEND).expect("the backend");
        assert_eq!(
            backend.input_schema_enforcement_for_test(),
            enforcement,
            "premise: the fixture's enforcement did not survive compilation"
        );
        backend.store_shared_tools_for_test(vec![tool(TOOL, &valid()), tool(SIBLING, &valid())]);
        let mut own = vec![tool(SIBLING, &valid())];
        match slot {
            Slot::Valid => own.push(tool(TOOL, &valid())),
            Slot::Invalid => own.push(tool(TOOL, &json!({"type": "array"}))),
            Slot::Lacks => {}
        }
        backend.store_per_user_tools_for_test(&DirectAccountGateway::operator_binding(), own);
        Self { gateway, meta }
    }

    /// One stdio `tools/call` of [`TOOL`]: the answer, and the `tools/call`
    /// sends it added at the backend.
    async fn call(&self) -> (Value, usize) {
        let before = self.gateway.tool_calls().len();
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": TOOL, "arguments": {"folder": "inbox"}}});
        let answer = Gateway::dispatch_single_with_sink(
            &self.meta,
            &Arc::new(crate::security::ToolPolicy::default()),
            &Arc::new(crate::mtls::MtlsPolicy::from_config(
                &crate::mtls::MtlsConfig::default(),
            )),
            request,
            StdioClient {
                session_id: STDIO_SESSION_ID,
                channel: &crate::gateway::input_bridge::NoClientChannel,
                handshake_capabilities: Declared::NONE,
                tasks: None,
                modern: false,
                sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
            },
            &StdioTelemetry::default(),
        )
        .await
        .expect("a request is answered");
        (answer, self.gateway.tool_calls().len() - before)
    }
}

/// The twin rule at `enforcement`: the caller-Valid control dispatches (the
/// fixture resolves the sole operator's slot), the unknown name answers
/// -32601, then withheld and lacked each answer exactly as the unknown name
/// and send nothing.
async fn assert_twins(row: &str, enforcement: InputSchemaEnforcement) {
    let (control, sent) = Stdio::new(Slot::Valid, true, enforcement).call().await;
    assert_eq!(
        sent, 1,
        "{row} premise: the caller-Valid control did not dispatch: {control}"
    );
    let (absent, _) = Stdio::new(Slot::Lacks, false, enforcement).call().await;
    assert_eq!(
        absent.pointer("/error/code"),
        Some(&json!(-32601)),
        "{row} premise: an unknown name answers -32601: {absent}"
    );
    for slot in [Slot::Invalid, Slot::Lacks] {
        let (answer, sent) = Stdio::new(slot, true, enforcement).call().await;
        assert_eq!(sent, 0, "{row} {slot:?}: dispatched; answer {answer}");
        assert_eq!(
            answer, absent,
            "{row} {slot:?}: {answer} vs unknown {absent}"
        );
    }
}

/// C3 (withheld, lacked): stdio `tools/call` by surfaced name. RED on base:
/// the shared slot (valid) decides, so it dispatches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_stdio_per_user_caller_slot_withholds() {
    assert_twins("C3", InputSchemaEnforcement::Closed).await;
}

/// C10, stdio twin: the same at argument-key enforcement Off. RED on base,
/// as C3.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c10_stdio_per_user_visibility_runs_with_enforcement_off() {
    assert_twins("C10-stdio", InputSchemaEnforcement::Off).await;
}
