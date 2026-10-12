// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool-annotation inference: fills in MCP `ToolAnnotations` hints
//! (read-only / destructive / idempotent / open-world) that a backend did not
//! declare itself, from naming conventions.

use std::collections::HashSet;

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

/// Prepares one backend's `tools/list` for a client: withholds tools whose
/// description fails the tool-poisoning check (#1441), drops tools whose
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
///
/// Returns the tools whose backend-declared annotations grant resend
/// permission explicitly. They are read before `normalize_tool_annotations`
/// runs, because it replaces every omitted hint with an inference: afterwards
/// `get_and_increment` carries `readOnlyHint: true` like any tool that
/// declared one, and the distinction ADR-012 amendment A1 rests on — only an
/// explicit `true` grants permission, absent and false both deny — no longer
/// exists to be read.
pub(crate) fn prepare_tool_metadata(
    server: &str,
    pins: &std::collections::BTreeMap<String, String>,
    judging: super::descriptor_gate::Judging,
    tools: &mut Vec<Tool>,
) -> PreparedTools {
    // MIK-8399: a name is safe only if EVERY listed occurrence of it is. Read
    // before the gates below drop anything, so a filtered unsafe occurrence
    // still keeps its name out (a conflicting duplicate cannot launder a
    // write through the one occurrence that survives).
    let not_resend_safe = names_failing(tools, |hints| {
        hints.read_only_hint == Some(true) || hints.idempotent_hint == Some(true)
    });
    let not_read_only = names_failing(tools, |hints| hints.read_only_hint == Some(true));
    // First, so a poisoned tool that also breaks a header rule is still
    // recorded as withheld and refused by name (#1441).
    let verdicts = match judging {
        super::descriptor_gate::Judging::Judge => super::descriptor_gate::judge(tools, pins),
        super::descriptor_gate::Judging::AlreadyJudged => {
            super::descriptor_gate::Verdicts::default()
        }
    };
    exclude_invalid_header_tools(server, tools);
    let resend_permitted = names_passing(tools, &not_resend_safe);
    // MIK-8393 (#3773): read from the declarations before the inference below
    // fills omitted hints, so a `get_`-named tool the backend never declared
    // read-only stays out. Only an explicit `readOnlyHint: true` counts; an
    // idempotent write may be retried, but must never be answered from cache.
    let read_only_declared = names_passing(tools, &not_read_only);
    normalize_tool_annotations(server, tools);
    PreparedTools {
        resend_permitted,
        read_only_declared,
        verdicts,
    }
}

/// Names with at least one occurrence whose declared hints fail `safe`.
fn names_failing(
    tools: &[Tool],
    safe: impl Fn(&crate::protocol::ToolAnnotations) -> bool,
) -> HashSet<String> {
    tools
        .iter()
        .filter(|tool| !tool.annotations.as_ref().is_some_and(&safe))
        .map(|tool| tool.name.clone())
        .collect()
}

/// The listed names not in `failing`: those whose every occurrence passed.
fn names_passing(tools: &[Tool], failing: &HashSet<String>) -> HashSet<String> {
    tools
        .iter()
        .filter(|tool| !failing.contains(&tool.name))
        .map(|tool| tool.name.clone())
        .collect()
}

/// [`prepare_tool_metadata`]'s result: the explicitly resend-safe tools, and
/// the tool-poisoning verdicts to commit once the listing's store is accepted.
pub(crate) struct PreparedTools {
    pub(crate) resend_permitted: HashSet<String>,
    /// The tools declared `readOnlyHint: true`: the only ones the response
    /// cache may store or serve (MIK-8393).
    pub(crate) read_only_declared: HashSet<String>,
    pub(crate) verdicts: super::descriptor_gate::Verdicts,
}
