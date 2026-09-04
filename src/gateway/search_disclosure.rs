// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Progressive disclosure for `gateway_search` results (MIK-7084).
//!
//! Search is a selection step. Default L0 answers "is this the tool?"
//! Ranking diagnostics stay a debug surface (`explain: true`).

use serde_json::{Value, json};

use crate::ranking::SearchResult;
use crate::{Error, Result};

/// Maximum characters for L0 `description` (one-line purpose).
pub(crate) const ONE_LINE_MAX: usize = 120;
/// Maximum characters for L1 `when_to_use`.
pub(crate) const WHEN_TO_USE_MAX: usize = 280;

/// Response tier for `gateway_search`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SearchDetail {
    /// Name, one-line purpose, score.
    L0,
    /// L0 plus signature, when-to-use, required params.
    L1,
    /// Full `input_schema` (legacy `include_schema: true`).
    L2,
}

/// Parsed disclosure controls for one `gateway_search` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SearchDisclosure {
    pub detail: SearchDetail,
    pub explain: bool,
}

/// Parse `detail`, `include_schema`, and `explain` from tool arguments.
///
/// `detail` wins when both `detail` and `include_schema` are set.
/// Absent both → L0. Explicit `include_schema: true` → L2.
pub(crate) fn resolve_search_disclosure(args: &Value) -> Result<SearchDisclosure> {
    let explain = args
        .get("explain")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let detail = match args.get("detail") {
        None | Some(Value::Null) => {
            if args.get("include_schema").and_then(Value::as_bool) == Some(true) {
                SearchDetail::L2
            } else {
                SearchDetail::L0
            }
        }
        Some(Value::String(s)) => parse_detail(s)?,
        Some(_) => {
            return Err(Error::json_rpc(
                -32602,
                "detail must be a string (l0|l1|l2)",
            ));
        }
    };
    Ok(SearchDisclosure { detail, explain })
}

fn parse_detail(raw: &str) -> Result<SearchDetail> {
    match raw.to_ascii_lowercase().as_str() {
        "l0" => Ok(SearchDetail::L0),
        "l1" => Ok(SearchDetail::L1),
        "l2" => Ok(SearchDetail::L2),
        other => Err(Error::json_rpc(
            -32602,
            format!("Invalid 'detail' '{other}' (expected l0|l1|l2)"),
        )),
    }
}

/// Ranking diagnostics object. Emitted only when `explain` is true.
///
/// Pruning happens here rather than at the emitters, because there are two of
/// them and only one used to prune: the ordinary `gateway_search` path shipped
/// all sixteen signals while the Code Mode path shipped three. Pruning at the
/// single place both call means a third emitter cannot reintroduce the gap.
pub(crate) fn ranking_debug_object(result: &SearchResult) -> Value {
    crate::gateway::meta_mcp::prune_constant_signals(&json!({
        "included": result.explanation.included,
        "reasons": result.explanation.reasons,
        "signals": result.signals,
    }))
}

/// Project a collected (and possibly ranked) Code Mode match onto a tier.
///
/// Unknown extra keys are dropped. `score` is kept when present. `ranking`
/// is kept only when `explain` is true.
pub(crate) fn project_code_mode_match(value: Value, disclosure: SearchDisclosure) -> Value {
    let Value::Object(map) = value else {
        return value;
    };
    let schema = map
        .get("input_schema")
        .cloned()
        .unwrap_or_else(|| json!({"type": "object"}));
    let raw_desc = map
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let tool = map.get("tool").cloned().unwrap_or(Value::Null);
    let score = map.get("score").cloned();
    let ranking = map.get("ranking").cloned();
    let status = map.get("status").cloned();

    let mut out = serde_json::Map::new();
    out.insert("tool".to_string(), tool);

    match disclosure.detail {
        SearchDetail::L0 => {
            out.insert(
                "description".to_string(),
                json!(one_line_purpose(&raw_desc)),
            );
        }
        SearchDetail::L1 => {
            out.insert(
                "description".to_string(),
                json!(one_line_purpose(&raw_desc)),
            );
            out.insert("when_to_use".to_string(), json!(when_to_use(&raw_desc)));
            out.insert("required".to_string(), json!(required_params(&schema)));
            out.insert("signature".to_string(), json!(schema_signature(&schema)));
            if let Some(status) = status {
                out.insert("status".to_string(), status);
            }
        }
        SearchDetail::L2 => {
            out.insert("description".to_string(), json!(raw_desc));
            out.insert("input_schema".to_string(), schema);
            if let Some(status) = status {
                out.insert("status".to_string(), status);
            }
        }
    }

    if let Some(score) = score {
        out.insert("score".to_string(), score);
    }
    if disclosure.explain
        && let Some(ranking) = ranking
    {
        out.insert("ranking".to_string(), ranking);
    }
    Value::Object(out)
}

/// Drop L0-hidden disabled tools, attach a glob score when ranking was skipped,
/// then project onto the requested tier.
pub(crate) fn finalize_search_matches(
    mut matches: Vec<Value>,
    disclosure: SearchDisclosure,
    glob: bool,
    limit: usize,
) -> Vec<Value> {
    if disclosure.detail == SearchDetail::L0 {
        matches.retain(|m| m.get("status").and_then(Value::as_str) != Some("disabled"));
    }
    if glob {
        for m in &mut matches {
            if m.get("score").is_none()
                && let Some(obj) = m.as_object_mut()
            {
                obj.insert("score".to_string(), json!(1.0));
            }
        }
    }
    matches.truncate(limit);
    matches
        .into_iter()
        .map(|m| project_code_mode_match(m, disclosure))
        .collect()
}

/// First sentence of `description`, keywords suffix stripped, capped.
pub(crate) fn one_line_purpose(description: &str) -> String {
    let stripped = strip_keyword_suffix(description);
    clip_chars(first_sentence(stripped), ONE_LINE_MAX)
}

/// First paragraph of `description`, keywords suffix stripped, capped.
pub(crate) fn when_to_use(description: &str) -> String {
    let stripped = strip_keyword_suffix(description);
    clip_chars(first_paragraph(stripped), WHEN_TO_USE_MAX)
}

/// `input_schema.required` names, empty when absent or not an array.
pub(crate) fn required_params(schema: &Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Compact param list: `name: type` required, `name?: type` optional.
pub(crate) fn schema_signature(schema: &Value) -> String {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return String::new();
    };
    let required = required_params(schema);
    let mut parts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in &required {
        if let Some(prop) = properties.get(name) {
            parts.push(format!("{name}: {}", schema_type_name(prop)));
            seen.insert(name.clone());
        }
    }
    let mut optional: Vec<&String> = properties.keys().filter(|k| !seen.contains(*k)).collect();
    optional.sort();
    for name in optional {
        if let Some(prop) = properties.get(name) {
            parts.push(format!("{name}?: {}", schema_type_name(prop)));
        }
    }
    parts.join(", ")
}

fn schema_type_name(schema: &Value) -> String {
    match schema.get("type") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .find(|s| *s != "null")
            .unwrap_or("any")
            .to_string(),
        _ => "any".to_string(),
    }
}

fn strip_keyword_suffix(description: &str) -> &str {
    match description.find("[keywords:") {
        Some(i) => description[..i].trim_end(),
        None => description.trim(),
    }
}

fn first_sentence(text: &str) -> &str {
    let text = text.trim();
    if text.is_empty() {
        return text;
    }
    let line = text.split('\n').next().unwrap_or(text).trim();
    if let Some(i) = line.find(". ") {
        return line[..=i].trim_end();
    }
    line
}

fn first_paragraph(text: &str) -> &str {
    let text = text.trim();
    match text.find("\n\n") {
        Some(i) => text[..i].trim(),
        None => text,
    }
}

fn clip_chars(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let keep = max.saturating_sub(3);
    let mut buf = String::new();
    for (i, c) in trimmed.chars().enumerate() {
        if i >= keep {
            break;
        }
        buf.push(c);
    }
    if let Some(idx) = buf.rfind(' ')
        && idx >= keep / 2
    {
        buf.truncate(idx);
    }
    buf.push_str("...");
    buf
}

#[cfg(test)]
#[path = "search_disclosure_tests.rs"]
mod tests;
