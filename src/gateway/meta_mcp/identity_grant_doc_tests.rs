// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `docs/identity_grants.md` examples, driven through real dispatch.
//!
//! The grant file and the capability `metadata` block are read out of the
//! doc itself, so an example that stops matching what the gateway emits reds
//! here. The caller is built the way production builds an API-key caller:
//! `api_key_name` set, no `grant_subject`, no proven agent id.

use std::sync::Arc;

use serde_json::json;

use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::destructive_confirmation::ConfirmationChannel;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::identity_grants::{IdentityGrantFile, LocalIdentityGrantStore};

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

const DOC: &str = include_str!("../../../docs/identity_grants.md");

/// The body of the first fenced YAML block whose first line is `first_line`.
fn doc_yaml_block(first_line: &str) -> &'static str {
    DOC.split("```yaml\n")
        .skip(1)
        .map(|block| block.split("```").next().unwrap())
        .find(|block| block.starts_with(first_line))
        .unwrap_or_else(|| panic!("docs/identity_grants.md has no block starting {first_line}"))
}

/// Dispatch the doc's grant, with its scope replaced by `scope`, against a
/// capability carrying the doc's metadata with `read_only` as given.
///
/// A grant refusal is an `Err` from the authorization chokepoint; a call that
/// passed it comes back `Ok` as a result envelope.
async fn dispatch_doc_example(scope: &str, read_only: bool) -> Result<serde_json::Value, String> {
    let grants: IdentityGrantFile = serde_yaml::from_str(
        &doc_yaml_block("schema_version:").replace("scope: read", &format!("scope: {scope}")),
    )
    .expect("doc grant file parses");
    let capability = grants.grants[0].capability.clone();
    let metadata =
        doc_yaml_block("metadata:").replace("read_only: true", &format!("read_only: {read_only}"));

    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(format!("{capability}.yaml")),
        format!(
            "fulcrum: \"1.0\"\nname: {capability}\ndescription: Read one calendar day\n\
             schema:\n  input:\n    type: object\n    properties:\n      day:\n        type: string\n    required: [day]\n\
             {metadata}providers:\n  primary:\n    service: rest\n    config:\n      base_url: \"https://example.invalid\"\n      path: /calendar\n      method: GET\n"
        ),
    )
    .unwrap();
    let cap_backend = Arc::new(CapabilityBackend::new(
        "personal_caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    cap_backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();

    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_identity_grants(LocalIdentityGrantStore::from_grants(grants.grants));
    meta.set_capabilities(cap_backend);

    let context = MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        api_key_name: Some("alice"),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    let result = meta
        .invoke_tool(
            &json!({"server": "personal_caps", "tool": capability, "arguments": {}}),
            Some("session-1"),
            &context,
        )
        .await;
    result.map_err(|error| error.to_string())
}

/// Past the grant, the empty call reaches schema validation and fails there:
/// an `isError` envelope naming the missing `day`, not a refusal.
fn assert_passed_the_grant(outcome: Result<serde_json::Value, String>) {
    let envelope = outcome.expect("a caller the grant covers must not be refused");
    assert_eq!(envelope["isError"], true, "{envelope:#}");
    let text = envelope["content"][0]["text"].as_str().unwrap_or_default();
    assert!(text.contains("day"), "{envelope:#}");
    assert!(!text.contains("Identity grant denied"), "{envelope:#}");
}

#[tokio::test]
async fn the_documented_grant_allows_the_api_key_caller_it_names() {
    assert_passed_the_grant(dispatch_doc_example("read", true).await);
}

#[tokio::test]
async fn an_execute_grant_allows_a_read_only_capability() {
    assert_passed_the_grant(dispatch_doc_example("execute", true).await);
}

#[tokio::test]
async fn the_documented_read_grant_does_not_allow_a_mutating_capability() {
    let refusal = dispatch_doc_example("read", false)
        .await
        .expect_err("a read grant must not reach a mutating capability");
    assert!(refusal.contains("Identity grant denied"), "{refusal}");
}
