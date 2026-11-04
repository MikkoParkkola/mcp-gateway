// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The human text of `cap discover`: the listing and the shadow report.
//! Every value a client config or the operator's command line can reach is
//! escaped for the terminal through `shown`, once, here.

use std::fmt::Write as _;

use mcp_gateway::cli_support::{Shown, shown, shows_unchanged};
use mcp_gateway::discovery::shadow::{
    ShadowRemediationAction, ShadowScanReport, ShadowTrustStatus,
};

/// One `   Label: value` line. The value is client-reachable text, so it
/// arrives escaped: a renderer cannot hand this a raw string.
fn field(out: &mut String, label: &str, value: &Shown) {
    let _ = writeln!(out, "   {label}: {value}");
}

/// A runnable command line, or fixed guidance in its place when escaping
/// would change it: an altered command could break its own shell quoting.
fn command_field(out: &mut String, label: &str, command: &str) {
    if shows_unchanged(command) {
        field(out, label, &shown(command));
    } else {
        let _ = writeln!(
            out,
            "   {label}: withheld (it holds characters a terminal cannot show safely); \
             run the command with your own --gateway-config path"
        );
    }
}

/// The human shadow report. Every value that a client config or the
/// operator's command line can reach goes through `shown`; the enum
/// fields printed with `{:?}` are the gateway's own.
pub(super) fn render_shadow_report(report: &ShadowScanReport) -> String {
    let mut out = String::new();
    if report.assets.is_empty() {
        out.push_str("✅ No shadow servers found — all discovered MCP servers are registered.\n");
        out.push_str("Passive scan only; no discovered tools were invoked.\n");
        return out;
    }
    if let Some(note) = &report.ids_note {
        // The gateway's own sentence; no client value reaches it.
        let _ = writeln!(out, "Note: {note}.\n");
    }

    let _ = writeln!(
        out,
        "⚠️  Found {} shadow (unregistered) MCP server(s). Passive scan only; no discovered tools were invoked.\n",
        report.summary.unmanaged_total
    );
    out.push_str("Action groups:\n");
    for group in &report.action_groups {
        let _ = writeln!(out, "  {:?}: {} asset(s)", group.action, group.count);
    }
    out.push('\n');

    for asset in &report.assets {
        let _ = writeln!(out, "📦 {}", shown(&asset.name));
        field(&mut out, "ID", &shown(&asset.id));
        let _ = writeln!(out, "   Severity: {:?}", asset.severity);
        let _ = writeln!(out, "   Source: {:?}", asset.source);
        let _ = writeln!(out, "   Trust: {:?}", asset.trust_status);
        field(&mut out, "Transport", &shown(&asset.transport.kind));
        if let Some(endpoint) = &asset.transport.endpoint {
            field(&mut out, "Endpoint", &shown(endpoint));
        }
        if let Some(path) = &asset.evidence.config_path {
            field(&mut out, "Config", &shown(path));
        }
        if let Some(pid) = asset.evidence.pid {
            let _ = writeln!(out, "   PID: {pid}");
        }
        if let Some(executable) = &asset.evidence.executable {
            let _ = writeln!(
                out,
                "   Executable: {} (arguments redacted)",
                shown(executable)
            );
        }
        let _ = writeln!(out, "   Auth exposure: {:?}", asset.auth_exposure);
        let _ = writeln!(out, "   Data risk: {:?}", asset.data_risk);
        let _ = writeln!(out, "   Recommended action: {:?}", asset.remediation.action);
        let _ = writeln!(out, "   Confidence: {:?}", asset.remediation.confidence);
        let _ = writeln!(
            out,
            "   Confirmation required: {}",
            asset.remediation.confirmation_required
        );
        command_field(&mut out, "Verify", &asset.remediation.verification_step);
        if asset.remediation.action == ShadowRemediationAction::AdoptIntoGateway
            && let Some(command) = &asset.remediation.apply_command
        {
            command_field(&mut out, "Apply after review", command);
        }
        if asset.trust_status == ShadowTrustStatus::Unmanaged {
            field(&mut out, "Reason", &shown(&asset.risk_reasons.join(", ")));
        }
        out.push('\n');
    }

    out.push_str(
        "Default mode is dry-run. To adopt reviewed local unmanaged servers, rerun with:\n",
    );
    out.push_str("   mcp-gateway cap discover --shadow --write-config\n");
    out
}

/// One find of the human listing. The command and URL are summarized or
/// redacted first, then escaped: `shown` is always the last step.
pub(super) fn render_server_entry(server: &mcp_gateway::discovery::DiscoveredServer) -> String {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::security::{diagnostic_url, summarize_stdio_command};

    let mut out = String::new();
    let _ = writeln!(out, "📦 {}", shown(&server.name));
    field(&mut out, "Description", &shown(&server.description));
    let _ = writeln!(out, "   Source: {:?}", server.source);
    let (kind, target, value) = match &server.transport {
        TransportConfig::Stdio { command, .. } => {
            ("stdio", "Command", summarize_stdio_command(command))
        }
        TransportConfig::Http { http_url, .. } => ("http", "URL", diagnostic_url(http_url)),
        TransportConfig::WebSocket { ws_url, .. } => ("websocket", "URL", diagnostic_url(ws_url)),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => ("a2a", "URL", diagnostic_url(a2a_url)),
    };
    let _ = writeln!(out, "   Transport: {kind}");
    field(&mut out, target, &shown(&value));
    if let Some(path) = &server.metadata.config_path {
        field(&mut out, "Config", &shown(&path.display().to_string()));
    }
    if let Some(pid) = server.metadata.pid {
        let _ = writeln!(out, "   PID: {pid}");
    }
    out.push('\n');
    out
}

#[cfg(test)]
#[path = "cap_render_tests.rs"]
mod tests;
