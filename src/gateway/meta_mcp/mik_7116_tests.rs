// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.5 — the summarising wrapper must sit on every path that
//! returns backend content, not only on `tools/call`.
//!
//! The defect these guard: `apply_context_integrity` had exactly one call
//! site (`invoke.rs`, the `gateway_invoke` path). `resources/read` and
//! `prompts/get` returned the backend's payload verbatim, so a document
//! carrying personal data reached the agent whole, with no classification
//! and no `_context_integrity` audit record — the two paths that return raw
//! documents by definition were the two the kernel never saw.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::context_integrity::{
    ContextIntegrityDecisionKind, ContextIntegrityKernel, ContextIntegrityPolicy,
    ContextIntegrityPolicyMode,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// An SSN-shaped string: `PERSONAL_DATA_PATTERNS` matches it, so the fixture
/// turns on the classifier rather than on any one backend's phrasing.
const RAW_SECRET: &str = "employee ssn 123-45-6789";

/// A backend that owns one resource and one prompt, both of which answer with
/// personal data.
struct DocumentTransport;

#[async_trait::async_trait]
impl Transport for DocumentTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let result = match method {
            "resources/list" => json!({
                "resources": [{"uri": "file:///hr/roster.csv", "name": "roster"}]
            }),
            "resources/read" => json!({
                "contents": [{
                    "uri": "file:///hr/roster.csv",
                    "mimeType": "text/csv",
                    "text": RAW_SECRET
                }]
            }),
            "prompts/get" => json!({
                "messages": [{
                    "role": "user",
                    "content": {"type": "text", "text": RAW_SECRET}
                }]
            }),
            _ => json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            result,
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

/// A `MetaMcp` whose kernel summarises personal data instead of passing it on.
fn meta_summarising_personal_data() -> MetaMcp {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "docs",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(DocumentTransport));
    let _ = registry.register(backend);

    let policy = ContextIntegrityPolicy {
        mode: ContextIntegrityPolicyMode::Enforce,
        personal_data_decision: ContextIntegrityDecisionKind::Summarize,
        ..ContextIntegrityPolicy::default()
    };
    MetaMcp::new(registry).with_context_integrity_kernel(ContextIntegrityKernel::new(policy))
}

#[tokio::test]
async fn a_read_resource_is_summarised_rather_than_passed_through_whole() {
    let meta = meta_summarising_personal_data();

    let response = meta
        .handle_resources_read(
            RequestId::Number(1),
            Some(&json!({"uri": "file:///hr/roster.csv"})),
        )
        .await;

    let result = response.result.expect("resources/read succeeds");
    // Both halves are asserted: the audit record proves the kernel ran, and
    // the absence of the raw string proves its decision was applied. Either
    // alone would pass on a result that leaked.
    assert_eq!(
        result["_context_integrity"]["policy"]["decision"], "summarize",
        "the kernel must classify resource content: {result:#}"
    );
    assert!(
        !result.to_string().contains(RAW_SECRET),
        "raw personal data must not reach the agent: {result:#}"
    );
}

#[tokio::test]
async fn a_fetched_prompt_is_summarised_rather_than_passed_through_whole() {
    let meta = meta_summarising_personal_data();

    let response = meta
        .handle_prompts_get(RequestId::Number(1), Some(&json!({"name": "docs/onboard"})))
        .await;

    let result = response.result.expect("prompts/get succeeds");
    assert_eq!(
        result["_context_integrity"]["policy"]["decision"], "summarize",
        "the kernel must classify prompt content: {result:#}"
    );
    assert!(
        !result.to_string().contains(RAW_SECRET),
        "raw personal data must not reach the agent: {result:#}"
    );
}
