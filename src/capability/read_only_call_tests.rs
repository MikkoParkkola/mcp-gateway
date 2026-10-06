// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A read-only call refuses, at the executor, a capability whose running
//! definition is not read-only.

use std::sync::Arc;

use serde_json::json;

use super::read_only_call;
use crate::capability::{CapabilityBackend, CapabilityExecutor};

fn capability(read_only: bool) -> crate::capability::CapabilityDefinition {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  read_only: {read_only}
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
    let refused = read_only_call(backend.call_tool("probe", json!({})))
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
