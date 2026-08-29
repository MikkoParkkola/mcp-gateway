// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! W3C trace context carried through `_meta` (MCP 2026-07-28, SEP-414).
//!
//! Two things at once. It makes one trace span the client, the gateway and the
//! backend — the hop nobody could previously see through. And it supplies the
//! correlation key the transparency log lost when sessions were removed: a
//! trace id spans the whole call rather than one connection, which is a better
//! key than the one it replaces.
//!
//! Propagated, never re-minted. A gateway that started a fresh trace would make
//! its own hop the root and hide the caller that caused it.

use serde_json::{Value, json};

/// A `traceparent`, and whatever vendor state travelled with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    traceparent: String,
    trace_id: String,
    tracestate: Option<String>,
}

impl TraceContext {
    /// Read a trace context from a request's `_meta`.
    ///
    /// `None` when absent or malformed. Malformed is deliberately not
    /// half-parsed: a caller writes this field, and a partially-read trace id
    /// would correlate one caller's audit records with another's.
    #[must_use]
    pub fn from_meta(meta: &Value) -> Option<Self> {
        let traceparent = meta.get("traceparent").and_then(Value::as_str)?;

        // version-traceid-spanid-flags, per W3C. Checked rather than assumed:
        // the shape is the only thing standing between a trace id and an
        // arbitrary string used as a correlation key.
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let (version, trace_id, span_id, flags) = (parts[0], parts[1], parts[2], parts[3]);
        let hex = |s: &str, len: usize| s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit());
        if !hex(version, 2) || !hex(trace_id, 32) || !hex(span_id, 16) || !hex(flags, 2) {
            return None;
        }
        // An all-zero trace id is the W3C "invalid" value, and using it as a
        // key would collapse every such call into one correlated group.
        if trace_id.chars().all(|c| c == '0') {
            return None;
        }

        Some(Self {
            traceparent: traceparent.to_string(),
            trace_id: trace_id.to_string(),
            tracestate: meta
                .get("tracestate")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }

    /// The trace id, which is what correlates records across the hop.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The `_meta` fields to send onward, unchanged.
    #[must_use]
    pub fn to_meta(&self) -> Value {
        let mut meta = json!({ "traceparent": self.traceparent });
        if let Some(ref state) = self.tracestate
            && let Some(object) = meta.as_object_mut()
        {
            object.insert("tracestate".to_string(), Value::String(state.clone()));
        }
        meta
    }
}
