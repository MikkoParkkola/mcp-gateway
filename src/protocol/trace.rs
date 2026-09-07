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
///
/// Every field is independently optional because the three are governed by two
/// specifications, not one: `tracestate` is defined by W3C trace-context as an
/// annotation *on* a `traceparent` and dies with it, while `baggage` is its own
/// specification with no dependency on trace context at all. Suppressing all
/// three when a `traceparent` is missing would drop valid data from
/// baggage-only callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    parent: Option<Parent>,
    tracestate: Option<String>,
    baggage: Option<String>,
}

/// A validated `traceparent` and the trace id read out of it.
///
/// One value rather than two fields on [`TraceContext`], so the bytes received
/// and the id parsed from them cannot be set independently and drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parent {
    /// Exactly what arrived, forwarded byte-for-byte.
    raw: String,
    trace_id: String,
}

impl Parent {
    /// `version-traceid-spanid-flags`, per W3C trace-context.
    ///
    /// A later version may append fields, and the spec tells a version-`00`
    /// parser to read the first four and ignore the rest rather than reject the
    /// whole context — so this splits without requiring an exact count.
    fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let span_id = parts.next()?;
        let flags = parts.next()?;

        // Lowercase only. `is_ascii_hexdigit` would accept uppercase, which the
        // grammar does not, and a gateway that normalised it would be repairing
        // a field this module is required to forward unchanged.
        let hex = |s: &str, len: usize| {
            s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        if !hex(version, 2) || !hex(trace_id, 32) || !hex(span_id, 16) || !hex(flags, 2) {
            return None;
        }
        // `ff` is reserved by the spec and is never a valid version.
        if version == "ff" {
            return None;
        }
        // All-zero is the W3C "invalid" value for both ids. Accepting either as
        // a correlation key would collapse every such call into one group.
        let all_zero = |s: &str| s.bytes().all(|b| b == b'0');
        if all_zero(trace_id) || all_zero(span_id) {
            return None;
        }

        Some(Self {
            raw: raw.to_string(),
            trace_id: trace_id.to_string(),
        })
    }
}

/// Printable US-ASCII — the intersection of what the `tracestate` and `baggage`
/// grammars permit.
///
/// Deliberately weaker than either grammar. This gateway does not parse the
/// list structure of those fields, so it does not enforce the delimiter rules
/// that structure implies; being a subset of both, it cannot reject a value
/// either spec calls valid. What it does enforce is the part that matters when
/// relaying a caller's bytes onward: no control characters, no CR or LF, and
/// nothing outside ASCII, so a field can never carry a header break or a
/// smuggled line into a downstream request.
fn is_printable_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

impl TraceContext {
    /// Read a trace context from a request's `_meta`.
    ///
    /// `None` when nothing propagable arrived. A field that fails its check is
    /// **dropped, never repaired**, and its absence never fails the request: a
    /// half-parsed trace id would correlate one caller's audit records with
    /// another's, and a repaired one would launder a caller's malformed input
    /// into a trusted-looking identity.
    #[must_use]
    pub fn from_meta(meta: &Value) -> Option<Self> {
        let field = |key: &str| meta.get(key).and_then(Value::as_str);

        let parent = field("traceparent").and_then(Parent::parse);
        // Dropped with the parent it annotates: vendor state relayed without
        // one reaches a backend with nothing to correlate it to.
        let tracestate = parent
            .as_ref()
            .and_then(|_| field("tracestate"))
            .filter(|value| is_printable_ascii(value))
            .map(str::to_string);
        // Independent of the parent, by its own specification.
        let baggage = field("baggage")
            .filter(|value| is_printable_ascii(value))
            .map(str::to_string);

        if parent.is_none() && baggage.is_none() {
            return None;
        }
        Some(Self {
            parent,
            tracestate,
            baggage,
        })
    }

    /// The trace id, which is what correlates records across the hop.
    ///
    /// `None` when the caller propagated `baggage` alone: baggage is its own
    /// W3C specification and carries no trace id, so there is nothing to
    /// correlate on. A caller that sent none is never given one.
    #[must_use]
    pub fn trace_id(&self) -> Option<&str> {
        self.parent.as_ref().map(|parent| parent.trace_id.as_str())
    }

    /// The `_meta` fields to send onward, unchanged.
    ///
    /// `traceparent` is emitted exactly as received, including any fields a
    /// later version appended: the parse reads the first four, the emit is
    /// byte-for-byte, and truncating to four would silently delete valid
    /// future context.
    #[must_use]
    pub fn to_meta(&self) -> Value {
        let mut meta = serde_json::Map::new();
        if let Some(parent) = &self.parent {
            meta.insert("traceparent".to_string(), json!(parent.raw));
        }
        for (key, value) in [
            ("tracestate", self.tracestate.as_ref()),
            ("baggage", self.baggage.as_ref()),
        ] {
            if let Some(value) = value {
                meta.insert(key.to_string(), Value::String(value.clone()));
            }
        }
        Value::Object(meta)
    }
}

#[cfg(test)]
mod tests {
    use super::TraceContext;
    use serde_json::json;

    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn baggage_survives_the_hop() {
        // MIK-7272.OTEL.1 names three fields; baggage carries the application
        // state that makes the other two useful to the caller.
        let inbound = json!({
            "traceparent": TRACEPARENT,
            "tracestate": "vendor=opaque",
            "baggage": "userId=alice,region=eu-north-1",
        });

        let onward = TraceContext::from_meta(&inbound)
            .expect("a well-formed traceparent parses")
            .to_meta();

        assert_eq!(onward["baggage"], json!("userId=alice,region=eu-north-1"));
        assert_eq!(onward["tracestate"], json!("vendor=opaque"));
        assert_eq!(onward["traceparent"], json!(TRACEPARENT));
    }

    #[test]
    fn absent_baggage_emits_no_key() {
        // A caller that sent no baggage must not have an empty one invented,
        // or every backend sees a field the client never wrote.
        let onward = TraceContext::from_meta(&json!({ "traceparent": TRACEPARENT }))
            .expect("a well-formed traceparent parses")
            .to_meta();

        assert!(onward.get("baggage").is_none(), "got {onward}");
        assert!(onward.get("tracestate").is_none(), "got {onward}");
    }

    #[test]
    fn baggage_alone_is_never_a_correlation_key() {
        // Guards the parse order: baggage must never become a correlation key
        // in its own right. It still PROPAGATES on its own — that is
        // `baggage_alone_propagates_without_any_traceparent` — so the property
        // this row owns is the key, not the presence.
        let context = TraceContext::from_meta(&json!({ "baggage": "userId=alice" }))
            .expect("baggage alone propagates");
        assert_eq!(context.trace_id(), None);
    }

    // ── T7: the four §3.4b grammar predicates, one row each (A9: each input
    // breaks exactly one thing, and its permitted neighbour is asserted).

    #[test]
    fn uppercase_hex_is_rejected_and_the_lowercase_neighbour_accepted() {
        // W3C trace-context: traceparent is lowercase hex only.
        let upper = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01";
        assert!(parent_of(upper).is_none(), "uppercase must be refused");
        assert!(parent_of(TRACEPARENT).is_some(), "lowercase must be kept");
    }

    #[test]
    fn version_ff_is_rejected_and_version_00_accepted() {
        // W3C reserves ff; it is never a valid version.
        let ff = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(parent_of(ff).is_none(), "version ff must be refused");
        assert!(parent_of(TRACEPARENT).is_some());
    }

    #[test]
    fn all_zero_parent_id_is_rejected_and_a_nonzero_one_accepted() {
        // The span id has the same invalid-value rule as the trace id.
        let zero = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        assert!(
            parent_of(zero).is_none(),
            "all-zero parent-id must be refused"
        );
        assert!(parent_of(TRACEPARENT).is_some());
    }

    #[test]
    fn a_five_field_traceparent_is_accepted_and_emitted_verbatim() {
        // A future version may carry more fields: read the first four, ignore
        // the rest, and emit byte-for-byte what arrived.
        let five = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra";
        let onward = TraceContext::from_meta(&json!({ "traceparent": five }))
            .expect("a valid future version parses")
            .to_meta();
        assert_eq!(onward["traceparent"], json!(five));
    }

    // ── T8a: charset, one row per opaque field. traceparent's charset is the
    // hex rule above, so it has no separate row.

    #[test]
    fn tracestate_carrying_a_control_character_is_dropped() {
        let onward = TraceContext::from_meta(&json!({
            "traceparent": TRACEPARENT,
            "tracestate": "vendor=a\rb",
        }))
        .expect("the traceparent is valid")
        .to_meta();
        assert!(onward.get("tracestate").is_none(), "got {onward}");
        assert_eq!(
            onward["traceparent"],
            json!(TRACEPARENT),
            "the parent survives"
        );
    }

    #[test]
    fn baggage_carrying_a_control_character_is_dropped() {
        let onward = TraceContext::from_meta(&json!({
            "traceparent": TRACEPARENT,
            "baggage": "userId=a\nb",
        }))
        .expect("the traceparent is valid")
        .to_meta();
        assert!(onward.get("baggage").is_none(), "got {onward}");
        assert_eq!(
            onward["traceparent"],
            json!(TRACEPARENT),
            "the parent survives"
        );
    }

    // ── T5/T6: baggage is its own W3C specification and does not depend on a
    // trace context. T5b/T6b: tracestate annotates a parent and dies with it.

    #[test]
    fn baggage_alone_propagates_without_any_traceparent() {
        let onward = TraceContext::from_meta(&json!({ "baggage": "userId=alice" }))
            .expect("baggage alone still propagates")
            .to_meta();
        assert_eq!(onward["baggage"], json!("userId=alice"));
        assert!(onward.get("traceparent").is_none(), "nothing is minted");
    }

    #[test]
    fn baggage_survives_a_malformed_traceparent() {
        let onward = TraceContext::from_meta(&json!({
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "baggage": "userId=alice",
        }))
        .expect("baggage propagates even when the parent is refused")
        .to_meta();
        assert_eq!(onward["baggage"], json!("userId=alice"));
        assert!(
            onward.get("traceparent").is_none(),
            "a refused parent is dropped"
        );
    }

    #[test]
    fn tracestate_alone_is_dropped_without_a_traceparent() {
        assert_eq!(
            TraceContext::from_meta(&json!({ "tracestate": "vendor=opaque" })),
            None,
            "orphaned tracestate has nothing to annotate"
        );
    }

    #[test]
    fn tracestate_is_dropped_with_a_malformed_traceparent() {
        assert_eq!(
            TraceContext::from_meta(&json!({
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
                "tracestate": "vendor=opaque",
            })),
            None,
            "tracestate dies with the parent it annotates"
        );
    }

    /// Parse helper: did a `traceparent` survive as a correlation key?
    fn parent_of(traceparent: &str) -> Option<String> {
        TraceContext::from_meta(&json!({ "traceparent": traceparent }))
            .and_then(|tc| tc.trace_id().map(str::to_string))
    }
}
