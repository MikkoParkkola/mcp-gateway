// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1441 T10: on the direct route the firewall redacts credential-shaped
//! text before the list is normalised. Withholding must judge the raw
//! descriptor, or a redaction that swallows the blocking text serves a tool
//! the cached catalogue withholds.

use std::sync::Arc;

use serde_json::json;

use super::super::issue_555_listing_scope::post;
use super::{CLEAN, build, names, tool};
use crate::config::BackendConfig;
use crate::protocol::Tool;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::validator::{Rule, Severity, ToolPoisoningRule};

const SWALLOWED: &str = "evil_conf";
/// `.env` is a blocking path; the connection-string redaction consumes the
/// whole token around it.
const RAW: &str = "Reads settings from postgres://db.local/app/.env for q.";
const REDACTED_EQUIVALENT: &str = "Reads settings from [REDACTED] for q.";

fn severity(description: &str) -> Severity {
    let tool: Tool = serde_json::from_value(tool(SWALLOWED, description)).expect("a tool");
    ToolPoisoningRule
        .check(&tool)
        .expect("the rule runs")
        .severity
}

#[tokio::test]
async fn t10_the_direct_route_judges_the_raw_descriptor() {
    // Precondition: the raw text fails, the redacted text would not.
    assert_eq!(severity(RAW), Severity::Fail, "raw must be blocking");
    assert_ne!(
        severity(REDACTED_EQUIVALENT),
        Severity::Fail,
        "the redacted form must not be blocking, or this cell proves nothing"
    );
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            ..FirewallConfig::default()
        },
        None,
    ));
    let e = build(
        BackendConfig::default(),
        vec![tool(CLEAN, "Echoes q."), tool(SWALLOWED, RAW)],
        Some(firewall),
    )
    .await;
    let (_, listed) = post(&e.router, "/mcp/evil", None, "tools/list", json!({})).await;
    let listed_names = names(&listed);
    assert!(listed_names.iter().any(|n| n == CLEAN), "control: {listed}");
    assert!(
        !listed.to_string().contains("postgres://db.local"),
        "control: the firewall must have redacted the connection string: {listed}"
    );
    assert!(
        !listed_names.iter().any(|n| n == SWALLOWED),
        "served after redaction removed its blocking text: {listed}"
    );
}
