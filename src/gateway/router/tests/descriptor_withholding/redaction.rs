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
    let firewall = redacting_firewall();
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

fn redacting_firewall() -> Arc<Firewall> {
    Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            ..FirewallConfig::default()
        },
        None,
    ))
}

/// T10b: a tool pinned by the digest of its raw description is served on the
/// direct route even when redaction changes that text and the redacted text
/// still fails the check. The raw list decided; redacted text is not
/// re-judged against the pin.
#[tokio::test]
async fn t10b_a_pinned_tool_survives_redaction_on_the_direct_route() {
    const PINNED: &str = "evil_pinned";
    const TEXT: &str = "Reads id_rsa via postgres://db.local/app for q.";
    let raw: Tool = serde_json::from_value(tool(PINNED, TEXT)).expect("a tool");
    assert_eq!(
        ToolPoisoningRule
            .check(&raw)
            .expect("the rule runs")
            .severity,
        Severity::Fail,
        "precondition: the raw text is blocking"
    );
    let digest = crate::backend::descriptor_digest(&raw);
    let config = BackendConfig {
        allow_flagged_tools: [(PINNED.to_string(), digest.clone())].into(),
        ..BackendConfig::default()
    };
    // `id_rsa` is a blocking response finding, and a blocked list is refused
    // whole (#2349). An operator rule that downgrades listings to Warn keeps
    // the redacted list served, which is the case this cell is about.
    let warn_lists = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            credential_redaction: true,
            rules: vec![crate::security::firewall::FirewallRule {
                tool_match: "tools/list".to_string(),
                action: crate::security::firewall::FirewallAction::Warn,
                reason: None,
                scan: Vec::new(),
            }],
            ..FirewallConfig::default()
        },
        None,
    ));
    let e = build(config, vec![tool(PINNED, TEXT)], Some(warn_lists)).await;
    let (_, listed) = post(&e.router, "/mcp/evil", None, "tools/list", json!({})).await;
    assert!(
        !listed.to_string().contains("postgres://db.local"),
        "control: the firewall must have redacted the connection string: {listed}"
    );
    let served = listed["result"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|t| t["name"] == PINNED))
        .unwrap_or_else(|| panic!("a pinned tool was withheld after redaction: {listed}"));
    // The cell only means something if re-judging the served text would
    // have withheld it: still blocking, and no longer the pinned digest.
    let redacted: Tool = serde_json::from_value(served.clone()).expect("a tool");
    assert_eq!(
        ToolPoisoningRule
            .check(&redacted)
            .expect("the rule runs")
            .severity,
        Severity::Fail,
        "precondition: the redacted text still blocks: {served}"
    );
    assert_ne!(
        crate::backend::descriptor_digest(&redacted),
        digest,
        "precondition: redaction changed the digested text: {served}"
    );
}
