// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool-annotation inference: fills in MCP `ToolAnnotations` hints
//! (read-only / destructive / idempotent / open-world) that a backend did not
//! declare itself, from naming conventions.

use crate::protocol::param_headers::mirrored_params;
use crate::protocol::{Tool, ToolAnnotations};
use tracing::warn;

fn normalize_tool_annotations(server: &str, tools: &mut [Tool]) {
    for tool in tools {
        let inferred_read_only = infer_read_only_tool(&tool.name);
        let annotations = tool
            .annotations
            .get_or_insert_with(ToolAnnotations::default);
        let read_only = annotations.read_only_hint.unwrap_or(inferred_read_only);
        let destructive = annotations
            .destructive_hint
            .unwrap_or_else(|| infer_destructive_tool(&tool.name, read_only));

        annotations.read_only_hint = Some(read_only);
        annotations.destructive_hint = Some(destructive);
        annotations.idempotent_hint = Some(
            annotations
                .idempotent_hint
                .unwrap_or_else(|| infer_idempotent_tool(&tool.name, read_only, destructive)),
        );
        annotations.open_world_hint = Some(
            annotations
                .open_world_hint
                .unwrap_or_else(|| infer_open_world_tool(server, &tool.name)),
        );
    }
}

fn infer_read_only_tool(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let read_prefixes = [
        "analyze",
        "auth_lookup",
        "benchmark",
        "calculate",
        "check",
        "classify",
        "count",
        "describe",
        "detect",
        "estimate",
        "fetch",
        "find",
        "fingerprint",
        "get",
        "health",
        "info",
        "list",
        "lookup",
        "preview",
        "query",
        "read",
        "recall",
        "search",
        "status",
        "suggest",
        "validate",
        "verify",
    ];
    read_prefixes
        .iter()
        .any(|prefix| name == *prefix || name.starts_with(&format!("{prefix}_")))
}

fn infer_destructive_tool(name: &str, read_only: bool) -> bool {
    if read_only {
        return false;
    }

    let name = name.to_ascii_lowercase();
    let destructive_words = [
        "archive", "bash", "clear", "delete", "forget", "kill", "login", "post", "remove", "run",
        "send", "submit", "type", "write",
    ];
    destructive_words.iter().any(|word| name.contains(word))
}

fn infer_idempotent_tool(name: &str, read_only: bool, destructive: bool) -> bool {
    if read_only {
        return true;
    }
    if destructive {
        return false;
    }

    let name = name.to_ascii_lowercase();
    name.starts_with("set_")
        || name.starts_with("clear_")
        || name.starts_with("focus_")
        || name.starts_with("connect")
}

fn infer_open_world_tool(server: &str, name: &str) -> bool {
    let server = server.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();

    if matches!(
        server.as_str(),
        "hebb" | "metacognition" | "pithy" | "cached-grep" | "haiku-file-reader"
    ) {
        return false;
    }

    if name.contains("validate") || name.contains("fingerprint") || name.contains("auth_lookup") {
        return false;
    }

    true
}

/// Drops every tool whose `inputSchema` breaches an `x-mcp-header` constraint
/// (MIK-7214.HEADER.8).
///
/// Exclusion changes the surfaced tool set, so it runs on the same
/// tool-metadata path as the destructive-annotation gate rather than in a
/// second filter of its own. A violation is per-tool: the rest of the
/// backend's list is unaffected.
fn exclude_invalid_header_tools(server: &str, tools: &mut Vec<Tool>) {
    tools.retain(|tool| match mirrored_params(&tool.input_schema) {
        Ok(_) => true,
        Err(violation) => {
            warn!(
                server = %server,
                tool = %tool.name,
                reason = %violation,
                "Excluding tool from tools/list: invalid x-mcp-header annotation"
            );
            false
        }
    });
}

/// Prepares one backend's `tools/list` for a client: drops tools whose
/// `x-mcp-header` declarations breach a constraint, then fills the annotation
/// hints the backend omitted.
///
/// This is the ONLY entry point, and both steps are private behind it, because
/// the two callers — the cached backend metadata every aggregate path reads,
/// and the direct passthrough response — must not be able to disagree about
/// which of the two ran. They already did: exclusion reached the passthrough
/// response only, so an invalid tool stayed visible through
/// `BackendMetadata::get_tools_shared`. Order is load-bearing: a tool that is
/// about to be dropped is not worth annotating.
pub(crate) fn prepare_tool_metadata(server: &str, tools: &mut Vec<Tool>) {
    exclude_invalid_header_tools(server, tools);
    normalize_tool_annotations(server, tools);
}
