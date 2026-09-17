// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Prompt cache key derivation and stable tool ordering for OpenAI-compatible backends.
//!
//! OpenAI-compatible APIs (including Anthropic) support `prompt_cache_key` to enable
//! prefix caching. This module:
//!
//! 1. Derives a stable `prompt_cache_key` from conversation context, user ID, or an
//!    explicit client-supplied header value (`X-Cache-Key`).
//! 2. Maintains stable tool ordering so that re-ordered tool lists do not bust the
//!    cached prefix.
//! 3. Exposes helpers for wiring the key into backend request metadata.
//!
//! # Architectural boundary
//!
//! `mcp-gateway` is not a general chat-completions proxy. This module lives under
//! `gateway/meta_mcp` because `gateway_invoke` sometimes needs to preserve
//! `prompt_cache_key` behavior when forwarding a tool call into an OpenAI-compatible
//! backend or capability. If prompt-cache handling ever grows beyond Meta-MCP
//! invocation, the long-term home is a backend-adapter layer rather than the core
//! gateway router.
//!
//! # Rate-limit awareness
//!
//! Anthropic enforces ~15 RPM per (prefix, key) pair. To spread load the deriver
//! can rotate among a small pool of keys derived from the same base — callers
//! select a key by index using [`CacheKeyDeriver::key_for_slot`].

use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hashing::{canonical_json, sha256_hex_chunks};

/// Derives and manages `prompt_cache_key` values.
///
/// # Thread safety
///
/// `CacheKeyDeriver` is stateless and `Clone + Send + Sync`.  All methods take
/// `&self` and produce new values; no interior mutability is involved.
#[derive(Debug, Clone, Default)]
pub struct CacheKeyDeriver {
    /// Number of load-balanced key slots (default: 1).
    ///
    /// Setting this to `N > 1` produces N distinct but deterministic keys from
    /// the same base, useful for distributing load within the ~15 RPM per key
    /// limit imposed by Anthropic.
    pub slots: u8,
}

impl CacheKeyDeriver {
    /// Create a deriver with a single key slot (no load balancing).
    #[must_use]
    pub fn new() -> Self {
        Self { slots: 1 }
    }

    /// Create a deriver with `slots` load-balanced key slots.
    ///
    /// # Panics
    ///
    /// Panics if `slots` is 0.
    #[must_use]
    pub fn with_slots(slots: u8) -> Self {
        assert!(slots > 0, "slots must be at least 1");
        Self { slots }
    }

    // ========================================================================
    // Key derivation
    // ========================================================================

    /// Derive a `prompt_cache_key` from an explicit header value.
    ///
    /// When a client sends `X-Cache-Key: <value>`, the gateway forwards it
    /// verbatim (truncated to 64 bytes for safety).  This is the highest-priority
    /// source and is used unchanged across retries.
    #[must_use]
    pub fn from_header(header_value: &str) -> String {
        // Truncate to 64 chars; Anthropic's key length limit is undocumented but small
        header_value.chars().take(64).collect()
    }

    /// Derive a `prompt_cache_key` from a conversation context string (e.g. session ID).
    ///
    /// Produces a short, stable hex prefix by hashing the context with SHA-256
    /// and taking the first 16 bytes (32 hex chars).  The result is consistent
    /// across gateway restarts and independent of argument order.
    #[must_use]
    pub fn from_context(context: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(context.as_bytes());
        let digest = hasher.finalize();
        // Take first 16 bytes → 32 hex chars — short enough to fit Anthropic limits
        digest[..16]
            .iter()
            .fold(String::with_capacity(32), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
    }

    /// Derive a `prompt_cache_key` from a combination of session and user context.
    ///
    /// Combines `session_id` and `user_id` into a single hash to produce a key
    /// that is unique per (session, user) pair but stable for the same pair.
    #[must_use]
    pub fn from_session_and_user(session_id: &str, user_id: &str) -> String {
        let combined = format!("{session_id}:{user_id}");
        Self::from_context(&combined)
    }

    /// Return the key for a given load-balancing slot index.
    ///
    /// If `slots == 1`, the base key is returned unchanged.  Otherwise a
    /// deterministic slot suffix is appended so each slot produces a unique key.
    ///
    /// `slot` is taken modulo `self.slots` so out-of-range values wrap around.
    #[must_use]
    pub fn key_for_slot(&self, base_key: &str, slot: u8) -> String {
        if self.slots <= 1 {
            return base_key.to_string();
        }
        let s = slot % self.slots;
        format!("{base_key}-s{s}")
    }

    /// Select the slot for a given request index to spread load across keys.
    ///
    /// Uses a simple modulo on `request_index` — callers can use an atomic
    /// counter incremented per backend request.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn slot_for_request(&self, request_index: u64) -> u8 {
        if self.slots <= 1 {
            return 0;
        }
        (request_index % u64::from(self.slots)) as u8
    }
}

// ============================================================================
// Stable tool ordering
// ============================================================================

/// Sort tool definitions into a canonical stable order to prevent cache busts.
///
/// Tool order in the cached prefix **must not change** between requests or the
/// entire prefix cache is invalidated. This function sorts tools by their
/// `"name"` field alphabetically, which is deterministic regardless of the
/// order backends return them.
///
/// Returns a new `Vec` with the tools sorted; the originals are cloned.
///
/// # Behaviour on non-object tools
///
/// Tools that lack a `"name"` field sort to the front (empty string key),
/// preserving relative ordering among themselves.
#[must_use]
pub fn stable_tool_order(tools: &[Value]) -> Vec<Value> {
    let mut indexed: Vec<(String, &Value)> = tools
        .iter()
        .map(|t| {
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            (name, t)
        })
        .collect();
    indexed.sort_by(|a, b| a.0.cmp(&b.0));
    indexed.into_iter().map(|(_, v)| v.clone()).collect()
}

/// Build a canonical fingerprint for a slice of tool definitions.
///
/// The fingerprint is a SHA-256 hex digest of the sorted, serialised tool
/// schemas.  Any change to a tool's name, description, or input schema will
/// change the fingerprint; order changes alone will not (because tools are
/// sorted before hashing).
///
/// Use this to detect schema changes that would bust the cached prefix.
#[must_use]
pub fn tool_schema_fingerprint(tools: &[Value]) -> String {
    // Use a BTreeMap to collect (name → canonical_json) pairs so that
    // the hash is independent of slice order.
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let serialised = canonical_json(tool);
        by_name.insert(name, serialised);
    }

    let mut chunks: Vec<&[u8]> = Vec::with_capacity(by_name.len() * 4);
    for (name, schema) in &by_name {
        chunks.extend([name.as_bytes(), &b":"[..], schema.as_bytes(), &b"\n"[..]]);
    }
    sha256_hex_chunks(chunks)
}

// ============================================================================
// Request metadata injection
// ============================================================================

/// Build the outbound `_meta` for a backend `tools/call`, from what the caller
/// sent and the prompt-cache key this hop derived.
///
/// One function rather than two, because `_meta` is one object: a trace writer
/// and a cache-key writer that each own the key would each have to know about
/// the other's field. This is the sole writer of the outbound object — the
/// separate cache-key injector it replaced was the second (design §3.4a).
///
/// `None` when there is nothing to send — the caller carried no propagable
/// trace context and this hop has no cache key. Absent, never empty: a backend
/// is entitled to read the presence of `_meta` as meaning something.
///
/// `progressToken` is relayed, and is the only inbound field that is. A
/// progress token is the caller's own correlation handle: a backend that never
/// receives one cannot emit progress the caller can match, and the
/// notification arrives carrying `null` instead. It is relayed only as a
/// string or a number, the two shapes the specification allows, so the one
/// permitted field cannot become a hole for an arbitrary object.
///
/// Nothing else from `inbound_meta` is relayed. The gateway already strips
/// peer-supplied `_meta.provenance` from backend responses; the same refusal
/// applies on the way out.
#[must_use]
pub fn build_outbound_meta(inbound_meta: Option<&Value>, cache_key: Option<&str>) -> Option<Value> {
    let mut meta = inbound_meta
        .and_then(crate::protocol::trace::TraceContext::from_meta)
        .map(|trace| trace.to_meta())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();

    if let Some(token) = inbound_meta
        .and_then(|meta| meta.get("progressToken"))
        .filter(|token| token.is_string() || token.is_number())
    {
        meta.insert("progressToken".to_string(), token.clone());
    }

    if let Some(key) = cache_key {
        meta.insert(
            "prompt_cache_key".to_string(),
            Value::String(key.to_string()),
        );
    }

    (!meta.is_empty()).then_some(Value::Object(meta))
}

/// Extract `prompt_cache_key` from response usage data (OpenAI-compatible format).
///
/// Returns the number of cached tokens reported by the backend, or `0` if the
/// field is absent or the format is unexpected.
///
/// Supports both Anthropic-style (`usage.cache_read_input_tokens`) and
/// OpenAI-style (`usage.prompt_tokens_details.cached_tokens`) response shapes.
#[must_use]
pub fn extract_cached_tokens(response: &Value) -> u64 {
    // Anthropic: response.usage.cache_read_input_tokens
    if let Some(tokens) = response
        .get("usage")
        .and_then(|u| u.get("cache_read_input_tokens"))
        .and_then(Value::as_u64)
    {
        return tokens;
    }

    // OpenAI: response.usage.prompt_tokens_details.cached_tokens
    if let Some(tokens) = response
        .get("usage")
        .and_then(|u| u.get("prompt_tokens_details"))
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64)
    {
        return tokens;
    }

    0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── CacheKeyDeriver ───────────────────────────────────────────────

    #[test]
    fn from_header_returns_value_unchanged_for_short_input() {
        // GIVEN: a short header value
        let key = CacheKeyDeriver::from_header("my-session-key");
        // THEN: returned verbatim
        assert_eq!(key, "my-session-key");
    }

    #[test]
    fn from_header_truncates_to_64_chars() {
        // GIVEN: a 100-character value
        let long = "a".repeat(100);
        let key = CacheKeyDeriver::from_header(&long);
        // THEN: truncated to 64
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn from_context_is_deterministic() {
        // GIVEN: same context string
        let k1 = CacheKeyDeriver::from_context("session-abc");
        let k2 = CacheKeyDeriver::from_context("session-abc");
        // THEN: always same key
        assert_eq!(k1, k2);
    }

    #[test]
    fn from_context_produces_32_hex_chars() {
        let key = CacheKeyDeriver::from_context("any-context");
        // 16 bytes → 32 hex chars
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn from_context_differs_for_different_inputs() {
        let k1 = CacheKeyDeriver::from_context("session-1");
        let k2 = CacheKeyDeriver::from_context("session-2");
        assert_ne!(k1, k2);
    }

    #[test]
    fn from_session_and_user_combines_both() {
        // GIVEN: different session/user combos
        let k1 = CacheKeyDeriver::from_session_and_user("s1", "u1");
        let k2 = CacheKeyDeriver::from_session_and_user("s1", "u2");
        let k3 = CacheKeyDeriver::from_session_and_user("s2", "u1");
        // THEN: all distinct
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    #[test]
    fn key_for_slot_single_slot_returns_base_key() {
        let deriver = CacheKeyDeriver::new();
        let key = deriver.key_for_slot("base-key", 5);
        assert_eq!(key, "base-key");
    }

    #[test]
    fn key_for_slot_multi_slot_appends_suffix() {
        let deriver = CacheKeyDeriver::with_slots(4);
        let k0 = deriver.key_for_slot("base", 0);
        let k1 = deriver.key_for_slot("base", 1);
        let k2 = deriver.key_for_slot("base", 2);
        assert_eq!(k0, "base-s0");
        assert_eq!(k1, "base-s1");
        assert_eq!(k2, "base-s2");
    }

    #[test]
    fn key_for_slot_wraps_around() {
        let deriver = CacheKeyDeriver::with_slots(3);
        // slot 5 % 3 == 2
        assert_eq!(deriver.key_for_slot("base", 5), "base-s2");
        // slot 3 % 3 == 0
        assert_eq!(deriver.key_for_slot("base", 3), "base-s0");
    }

    #[test]
    fn slot_for_request_distributes_evenly() {
        let deriver = CacheKeyDeriver::with_slots(4);
        assert_eq!(deriver.slot_for_request(0), 0);
        assert_eq!(deriver.slot_for_request(1), 1);
        assert_eq!(deriver.slot_for_request(4), 0);
        assert_eq!(deriver.slot_for_request(7), 3);
    }

    #[test]
    fn slot_for_request_single_slot_always_zero() {
        let deriver = CacheKeyDeriver::new();
        for i in 0..20 {
            assert_eq!(deriver.slot_for_request(i), 0);
        }
    }

    // ── stable_tool_order ─────────────────────────────────────────────

    #[test]
    fn stable_tool_order_sorts_alphabetically_by_name() {
        let tools = vec![
            json!({"name": "zebra", "description": "z"}),
            json!({"name": "alpha", "description": "a"}),
            json!({"name": "middle", "description": "m"}),
        ];
        let sorted = stable_tool_order(&tools);
        assert_eq!(sorted[0]["name"], "alpha");
        assert_eq!(sorted[1]["name"], "middle");
        assert_eq!(sorted[2]["name"], "zebra");
    }

    #[test]
    fn stable_tool_order_is_idempotent() {
        let tools = vec![
            json!({"name": "b"}),
            json!({"name": "a"}),
            json!({"name": "c"}),
        ];
        let once = stable_tool_order(&tools);
        let twice = stable_tool_order(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn stable_tool_order_handles_empty_list() {
        let sorted = stable_tool_order(&[]);
        assert!(sorted.is_empty());
    }

    #[test]
    fn stable_tool_order_preserves_all_fields() {
        let tools = vec![
            json!({"name": "b", "input_schema": {"type": "object"}}),
            json!({"name": "a", "description": "first"}),
        ];
        let sorted = stable_tool_order(&tools);
        assert_eq!(sorted[0]["name"], "a");
        assert_eq!(sorted[0]["description"], "first");
        assert_eq!(sorted[1]["input_schema"]["type"], "object");
    }

    // ── tool_schema_fingerprint ───────────────────────────────────────

    #[test]
    fn fingerprint_is_order_independent() {
        let tools_ab = vec![
            json!({"name": "a", "description": "first"}),
            json!({"name": "b", "description": "second"}),
        ];
        let tools_ba = vec![
            json!({"name": "b", "description": "second"}),
            json!({"name": "a", "description": "first"}),
        ];
        // Same tools, different order → same fingerprint
        assert_eq!(
            tool_schema_fingerprint(&tools_ab),
            tool_schema_fingerprint(&tools_ba)
        );
    }

    #[test]
    fn fingerprint_changes_when_schema_changes() {
        let tools_before = vec![json!({"name": "a", "description": "old"})];
        let tools_after = vec![json!({"name": "a", "description": "new"})];
        assert_ne!(
            tool_schema_fingerprint(&tools_before),
            tool_schema_fingerprint(&tools_after)
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let tools =
            vec![json!({"name": "x", "input_schema": {"type": "object", "properties": {}}})];
        let f1 = tool_schema_fingerprint(&tools);
        let f2 = tool_schema_fingerprint(&tools);
        assert_eq!(f1, f2);
    }

    #[test]
    fn fingerprint_empty_is_stable() {
        let f = tool_schema_fingerprint(&[]);
        assert_eq!(f.len(), 64); // SHA-256 → 64 hex chars
    }

    // ── build_outbound_meta: the hop (OTEL.1.b/.c/.d) ─────────────────
    //
    // Fixture direction is inbound-only in every row: trace values are placed
    // on the caller's `_meta` and asserted on what goes out. A row that seeded
    // the outbound object would have verified serde, not the hop.

    const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    /// The inbound `_meta` every row below starts from: three trace fields and
    /// one unrelated key that must not be relayed.
    fn inbound_with_poison() -> Value {
        json!({
            "traceparent": TRACEPARENT,
            "tracestate": "vendor=abc",
            "baggage": "k=v",
            "example.test/poison": "must not be relayed",
        })
    }

    #[test]
    fn t1_trace_propagates_with_no_cache_key_and_the_poison_key_does_not() {
        let outbound = build_outbound_meta(Some(&inbound_with_poison()), None)
            .expect("a propagable trace context yields _meta");

        // Exact key set: a contains-check would pass an implementation that
        // clones inbound `_meta` wholesale and relays attacker metadata.
        let mut keys: Vec<&str> = outbound
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["baggage", "traceparent", "tracestate"]);
        assert_eq!(outbound["traceparent"], json!(TRACEPARENT));
        assert_eq!(outbound["tracestate"], json!("vendor=abc"));
        assert_eq!(outbound["baggage"], json!("k=v"));
    }

    #[test]
    fn t2_the_cache_key_merges_with_the_trace_keys_rather_than_replacing_them() {
        let outbound = build_outbound_meta(Some(&inbound_with_poison()), Some("my-key"))
            .expect("both sources present");

        let mut keys: Vec<&str> = outbound
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["baggage", "prompt_cache_key", "traceparent", "tracestate"]
        );
        assert_eq!(outbound["prompt_cache_key"], json!("my-key"));
    }

    #[test]
    fn a_progress_token_is_relayed_and_only_in_the_two_shapes_the_spec_allows() {
        // The caller's handle has to survive the hop or the backend emits
        // progress carrying `null`, which no caller can match to its call.
        assert_eq!(
            build_outbound_meta(Some(&json!({ "progressToken": "tok-a" })), None),
            Some(json!({ "progressToken": "tok-a" }))
        );
        assert_eq!(
            build_outbound_meta(Some(&json!({ "progressToken": 7 })), None),
            Some(json!({ "progressToken": 7 }))
        );
        // The one permitted field is not a hole: a token of any other shape is
        // refused rather than passed through to the backend.
        assert_eq!(
            build_outbound_meta(Some(&json!({ "progressToken": { "smuggled": 1 } })), None),
            None
        );
    }

    #[test]
    fn t3_no_trace_arrives_so_none_is_minted() {
        // Asserted as absence of the whole object, not as an empty value: a
        // minted root would be a non-empty value and is what this refuses.
        assert_eq!(
            build_outbound_meta(Some(&json!({ "other": 1 })), None),
            None
        );
    }

    #[test]
    fn t4_a_malformed_traceparent_is_dropped_not_minted_and_not_repaired() {
        // Three parts, everything else valid (A9: one thing broken).
        let inbound = json!({
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
        });
        assert_eq!(build_outbound_meta(Some(&inbound), None), None);
    }

    #[test]
    fn t5_baggage_alone_reaches_the_backend_without_a_traceparent() {
        let outbound = build_outbound_meta(Some(&json!({ "baggage": "k=v" })), None)
            .expect("baggage propagates on its own");
        assert_eq!(outbound["baggage"], json!("k=v"));
        assert!(outbound.get("traceparent").is_none(), "got {outbound}");
    }

    #[test]
    fn t5b_orphaned_tracestate_is_not_relayed() {
        assert_eq!(
            build_outbound_meta(Some(&json!({ "tracestate": "vendor=abc" })), None),
            None
        );
    }

    #[test]
    fn build_outbound_meta_carries_the_cache_key_when_the_caller_sent_nothing() {
        // The pre-existing behaviour this function subsumes: a hop with a cache
        // key and no inbound `_meta` still sends the key.
        let outbound = build_outbound_meta(None, Some("my-key")).expect("a cache key alone");
        assert_eq!(outbound, json!({ "prompt_cache_key": "my-key" }));
    }

    // ── extract_cached_tokens ─────────────────────────────────────────

    #[test]
    fn extract_cached_tokens_anthropic_format() {
        let response = json!({
            "usage": {
                "input_tokens": 1000,
                "cache_read_input_tokens": 800,
                "output_tokens": 100
            }
        });
        assert_eq!(extract_cached_tokens(&response), 800);
    }

    #[test]
    fn extract_cached_tokens_openai_format() {
        let response = json!({
            "usage": {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {
                    "cached_tokens": 600
                },
                "completion_tokens": 100
            }
        });
        assert_eq!(extract_cached_tokens(&response), 600);
    }

    #[test]
    fn extract_cached_tokens_returns_zero_when_absent() {
        let response = json!({"usage": {"input_tokens": 100}});
        assert_eq!(extract_cached_tokens(&response), 0);
    }

    #[test]
    fn extract_cached_tokens_returns_zero_for_empty_response() {
        assert_eq!(extract_cached_tokens(&json!({})), 0);
    }

    #[test]
    fn extract_cached_tokens_anthropic_takes_priority() {
        // GIVEN: both fields present (hypothetical)
        let response = json!({
            "usage": {
                "cache_read_input_tokens": 500,
                "prompt_tokens_details": {"cached_tokens": 300}
            }
        });
        // Anthropic field takes priority
        assert_eq!(extract_cached_tokens(&response), 500);
    }
}
