// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A read-only call refuses, at the executor, a capability whose running
//! definition is not read-only.

use std::sync::Arc;

use serde_json::json;

use super::read_only_call_as;
use crate::capability::{CapabilityBackend, CapabilityExecutor};

fn capability(read_only: bool) -> crate::capability::CapabilityDefinition {
    with_auth(read_only, "")
}

fn with_auth(read_only: bool, auth: &str) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  read_only: {read_only}
{auth}
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /probe
"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

#[tokio::test]
async fn a_read_only_call_refuses_a_capability_that_is_not_read_only() {
    let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
    backend
        .register_capability(capability(false))
        .expect("registered");
    let refused = read_only_call_as(false, backend.call_tool("probe", json!({})))
        .await
        .expect_err("refused");
    assert!(
        refused.to_string().contains("not read-only"),
        "refused before any request: {refused}"
    );
}

#[test]
fn only_a_read_only_call_judges_the_definition() {
    assert!(super::refuse_unless_read_only(&capability(false)).is_ok());
    assert!(super::refuse_unless_read_only(&capability(true)).is_ok());
}

/// A shared watch poll expects a capability that needs no credential: one a
/// reload made credentialed is refused at the definition about to run, so no
/// sharer's credential answers for every principal.
#[tokio::test]
async fn a_credential_free_call_refuses_a_credentialed_capability() {
    let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
    backend
        .register_capability(with_auth(true, "auth:\n  required: true"))
        .expect("registered");
    let refused = read_only_call_as(true, backend.call_tool("probe", json!({})))
        .await
        .expect_err("refused");
    assert!(
        refused.to_string().contains("needs a credential"),
        "refused before any request: {refused}"
    );
}

/// MIK-7720 (U1): a read-only call runs only a capability served over REST.
/// One a reload moved to GraphQL after the watch read its targets is refused
/// at the definition about to run, before any request.
#[tokio::test]
async fn a_read_only_call_refuses_a_capability_not_served_over_rest() {
    let backend = CapabilityBackend::new("test", Arc::new(CapabilityExecutor::new()));
    let yaml = "name: probe\ndescription: Test capability\nmetadata:\n  read_only: true\n\
                providers:\n  primary:\n    service: graphql\n    config:\n      \
                endpoint: https://example.invalid/graphql\n      body: \"{ probe }\"\n";
    backend
        .register_capability(crate::capability::parse_capability(yaml).expect("capability"))
        .expect("registered");
    let refused = read_only_call_as(false, backend.call_tool("probe", json!({})))
        .await
        .expect_err("refused");
    assert!(
        refused.to_string().contains("not served over REST"),
        "refused before any request: {refused}"
    );
}
