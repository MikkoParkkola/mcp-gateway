// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-5843: Willow competitive landscape page must keep its claims.

use std::process::Command;

fn willow_page() -> String {
    std::fs::read_to_string("docs/competitive/willow-enterprise-agent-governance.md")
        .expect("docs/competitive/willow-enterprise-agent-governance.md must exist")
}

fn rfc0132() -> String {
    std::fs::read_to_string("docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md")
        .expect("RFC-0132 must exist")
}

#[test]
fn mik_5843_willow_page_names_competitor_and_sovereign_wedge() {
    let page = willow_page();
    for needle in [
        "Willow",
        "Webrix",
        "withwillow.ai",
        "sovereign",
        "self-hosted",
        "not a signed `.state`",
        "attestation receipt",
        "audit log",
    ] {
        assert!(
            page.contains(needle),
            "Willow page missing required differentiator phrase: {needle}"
        );
    }
}

#[test]
fn mik_5843_willow_page_has_feature_bar_and_verdicts() {
    let page = willow_page();
    assert!(
        page.contains("Connectors")
            && page.contains("IdP")
            && page.contains("Shadow")
            && page.contains("Runtime guards")
            && page.contains("Audit")
            && page.contains("Attestation"),
        "feature-bar headings missing"
    );
    for needle in [
        "LEAD",
        "MATCH",
        "LAG",
        "1000+",
        "Okta",
        "Entra",
        "JumpCloud",
    ] {
        assert!(
            page.contains(needle),
            "feature-bar vocabulary missing: {needle}"
        );
    }
    let shadow_row = page
        .lines()
        .find(|l| l.starts_with("| Shadow-AI / unmanaged MCP |"))
        .expect("shadow row");
    assert!(
        shadow_row.contains("**LAG**"),
        "enterprise shadow discovery must be LAG, not MATCH: {shadow_row}"
    );
    let audit_row = page
        .lines()
        .find(|l| l.starts_with("| Audit |"))
        .expect("audit row");
    assert!(
        audit_row.contains("**LAG**"),
        "audit completeness must be LAG: {audit_row}"
    );
    assert!(
        page.contains("SaaS, self-hosted, and on-prem")
            && page.contains("not a unique mcp-gateway property"),
        "must not treat self-hosting as unique"
    );
}

#[test]
fn mik_5843_shadow_ai_scope_and_implementation_anchors() {
    let combined = format!("{}\n{}", willow_page(), rfc0132());
    for needle in [
        "shadow-AI",
        "unmanaged MCP",
        "config_scanner.rs",
        "process_scanner.rs",
        "network proxy",
        "SIEM",
        "discover --shadow",
    ] {
        assert!(
            combined.contains(needle),
            "shadow-AI scope or implementation pointer missing: {needle}"
        );
    }
}

#[test]
fn mik_5843_rfc_names_the_shipped_shadow_commands() {
    let rfc =
        std::fs::read_to_string("docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md")
            .expect("read RFC-0132");
    assert!(rfc.contains("Shipped in `mcp-gateway cap discover --shadow`"));
    assert!(rfc.contains("Shipped in `mcp-gateway doctor --shadow`"));
    assert!(!rfc.contains("`mcp-gateway discover --shadow`"));
    assert!(!rfc.contains("shadow flagging missing"));
    assert!(rfc.contains("Host and URI selectors remain\nunimplemented candidates"));
    assert!(rfc.contains("Nginx log filter config snippets (not HAProxy syntax)"));
}

#[test]
fn mik_5843_shipped_shadow_cli_matches_the_documented_scope() {
    let discover_help = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(["cap", "discover", "--help"])
        .output()
        .expect("run cap discover --help");
    assert!(discover_help.status.success());
    assert!(String::from_utf8_lossy(&discover_help.stdout).contains("--shadow"));

    let doctor = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
        .args(["doctor", "--shadow", "--shadow-format", "nginx"])
        .output()
        .expect("run doctor --shadow");
    assert!(doctor.status.success());
    let output = String::from_utf8_lossy(&doctor.stdout);
    assert!(output.contains("nginx log-phase map snippet"));
    assert!(output.contains("$request_body"));
    assert!(output.contains("\"~*("));
    assert!(!output.contains("if ($request_body"));
    assert!(!output.contains("httpHost"));
    assert!(!output.contains("httpRequestURI"));
}

#[test]
fn mik_5843_page_is_linked_from_the_competitive_index() {
    let index = std::fs::read_to_string("docs/competitive/README.md")
        .expect("read docs/competitive/README.md");
    assert!(
        index.contains("willow-enterprise-agent-governance"),
        "competitive index does not reference willow-enterprise-agent-governance"
    );
}

#[test]
fn mik_5843_page_is_linked_from_the_project_readme() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    assert!(
        readme.contains("docs/competitive/willow-enterprise-agent-governance.md"),
        "project README does not reference the Willow comparison"
    );
    assert!(
        readme.contains("[ShadowRadar](docs/SHADOW_SCAN.md)"),
        "project README does not link the operator-facing shadow documentation"
    );
}

#[test]
fn mik_5843_shadow_docs_expose_static_rule_export_without_enterprise_overclaim() {
    let docs = std::fs::read_to_string("docs/SHADOW_SCAN.md").expect("read SHADOW_SCAN.md");
    for format in ["grep", "nginx", "yaml"] {
        assert!(docs.contains(&format!(
            "mcp-gateway doctor --shadow --shadow-format {format}"
        )));
    }
    assert!(docs.contains("does not inspect traffic or publish findings to a SIEM"));
    assert!(docs.contains("remain enterprise workflow capabilities"));
    assert!(docs.contains("ggrep -P"));
    assert!(docs.contains("not a commercial-use grant"));
    assert!(docs.contains("[`COMMERCIAL.md`](../COMMERCIAL.md)"));
}

#[test]
fn mik_5843_public_competitive_allowlist_matches_gitignore_exceptions() {
    let gitignore = std::fs::read_to_string(".gitignore").expect("read .gitignore");
    for path in [
        "docs/competitive/README.md",
        "docs/competitive/willow-enterprise-agent-governance.md",
    ] {
        assert!(
            gitignore.lines().any(|line| line == format!("!{path}")),
            "{path} must have a matching .gitignore exception"
        );
    }
}
