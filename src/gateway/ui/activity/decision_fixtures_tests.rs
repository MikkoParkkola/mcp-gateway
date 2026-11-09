// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Records with a decision object, shared by the rule-filter, receipt and
//! export rows. Every record carries nested secret sentinels that
//! no row may ever serve.

use std::path::Path;

use serde_json::{Value, json};

use crate::security::transparency_log::recompute_entry_hash;

/// The prefix of every secret the fixtures plant.
pub(super) const SENTINEL: &str = "SENTINEL-";

/// A v2 decision naming `rule`, decided fresh, with a read-only effect, and
/// an unnamed key holding a sentinel.
pub(super) fn decision(rule: Option<&str>) -> Value {
    let mut d = json!({
        "v": 2, "kind": "tool_policy", "decided": "fresh",
        "request_findings": [], "declared_effect": "read_only",
        "declared_effect_source": "tool_annotation",
        "SENTINEL-unnamed-key": "SENTINEL-in-decision",
    });
    if let Some(rule) = rule {
        d["rule_id"] = rule.into();
    }
    d
}

/// One request finding, as the writer records it.
pub(super) fn finding(scan_type: &str, severity: &str, location: &str) -> Value {
    json!({"scan_type": scan_type, "severity": severity, "location": location})
}

/// A call on `server`/`tool` carrying `decision` (when given); not yet
/// chained. Its principal and payload hold sentinels.
pub(super) fn call(server: &str, tool: &str, decision: Option<Value>) -> Value {
    let mut e = json!({
        "outcome": "ok", "server": server, "tool": tool,
        "route": "meta_invoke", "request_hash": "sha256:aa",
        "timestamp": "2026-10-26T10:00:00+00:00",
        "who": {"account": "acct", "principal": "SENTINEL-principal"},
        "payload": "SENTINEL-payload",
    });
    if let Some(d) = decision {
        e["decision"] = d;
    }
    e
}

/// Write `entries` chained from genesis in order (the first is the oldest),
/// hashed, unsigned.
pub(super) fn write_chained(path: &Path, entries: &mut [Value]) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, e) in entries.iter_mut().enumerate() {
        e["counter"] = (i + 1).into();
        e["prev_entry_hash"] = prev.clone().into();
        let hash = recompute_entry_hash(e).unwrap();
        e["entry_hash"] = hash.clone().into();
        body.push_str(&(e.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

/// Fail when `text` carries any planted sentinel.
pub(super) fn assert_no_sentinel(text: &str) {
    assert!(!text.contains(SENTINEL), "a sentinel leaked: {text}");
}
