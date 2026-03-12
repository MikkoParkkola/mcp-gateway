//! Distributed tracing for tool call chains — Issue #63.
//!
//! Generates W3C Trace Context (`traceparent` / `tracestate`) headers,
//! propagates them to backend transports, and emits structured JSON spans
//! via the existing [`tracing`] infrastructure.
//!
//! # Span hierarchy
//!
//! ```text
//! client → gateway   (kind = SERVER)
//!   gateway → backend (kind = CLIENT / transport)
//!     backend → tool  (kind = INTERNAL / execution)
//! ```
//!
//! # W3C Trace Context
//!
//! `traceparent` format: `00-<32 hex trace-id>-<16 hex span-id>-<flags>`
//!
//! Flags: `01` = sampled.  We always sample at the gateway level;
//! downstream backends may downsample independently.
//!
//! # Structured log output
//!
//! Each span is emitted as a JSON object on stdout via `tracing::info!`.
//! The JSON keys follow the OpenTelemetry semantic conventions where practical.
//!
//! ```json
//! {
//!   "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
//!   "span_id": "00f067aa0ba902b7",
//!   "parent_span_id": null,
//!   "span_kind": "SERVER",
//!   "name": "gateway.invoke",
//!   "status": "OK",
//!   "duration_ms": 12,
//!   "attributes": { "tool": "search", "server": "brave" }
//! }
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fmt;
use std::time::Instant;

use rand::Rng;
use serde::{Deserialize, Serialize};

// ============================================================================
// IDs
// ============================================================================

/// A 128-bit trace identifier (W3C Trace Context).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId([u8; 16]);

/// A 64-bit span identifier (W3C Trace Context).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId([u8; 8]);

impl TraceId {
    /// Generate a random `TraceId`.
    #[must_use]
    pub fn generate() -> Self {
        Self(rand::rng().random())
    }

    /// Parse from a 32-character lowercase hex string.
    ///
    /// Returns `None` if the string is not exactly 32 hex characters.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        // All-zeros trace ID is invalid per spec
        if bytes == [0u8; 16] {
            return None;
        }
        Some(Self(bytes))
    }

    /// Encode as a 32-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().fold(String::with_capacity(32), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl SpanId {
    /// Generate a random `SpanId`.
    #[must_use]
    pub fn generate() -> Self {
        Self(rand::rng().random())
    }

    /// Parse from a 16-character lowercase hex string.
    ///
    /// Returns `None` if the string is not exactly 16 hex characters.
    #[must_use]
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 16 {
            return None;
        }
        let mut bytes = [0u8; 8];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_nibble(chunk[0])?;
            let lo = hex_nibble(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        if bytes == [0u8; 8] {
            return None;
        }
        Some(Self(bytes))
    }

    /// Encode as a 16-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().fold(String::with_capacity(16), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        })
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// W3C Trace Context headers
// ============================================================================

/// Parsed W3C `traceparent` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceParent {
    /// 128-bit trace identifier.
    pub trace_id: TraceId,
    /// 64-bit span identifier (the *parent* span from the caller's perspective).
    pub parent_span_id: SpanId,
    /// Trace flags byte (bit 0 = sampled).
    pub flags: u8,
}

impl TraceParent {
    /// Create a new root `traceparent` (no upstream parent).
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            trace_id: TraceId::generate(),
            parent_span_id: SpanId::generate(),
            flags: 0x01, // sampled
        }
    }

    /// Parse from a `traceparent` header value.
    ///
    /// Returns `None` if the header does not conform to
    /// `00-<32hex>-<16hex>-<2hex>`.
    #[must_use]
    pub fn parse(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.splitn(4, '-').collect();
        if parts.len() != 4 {
            return None;
        }
        // Only version 00 is defined
        if parts[0] != "00" {
            return None;
        }
        let trace_id = TraceId::from_hex(parts[1])?;
        let parent_span_id = SpanId::from_hex(parts[2])?;
        let flags = u8::from_str_radix(parts[3], 16).ok()?;
        Some(Self {
            trace_id,
            parent_span_id,
            flags,
        })
    }

    /// Serialize to a `traceparent` header value string.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id.to_hex(),
            self.parent_span_id.to_hex(),
            self.flags
        )
    }

    /// Return `true` if the sampled flag is set.
    #[must_use]
    pub fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

// ============================================================================
// Span kind
// ============================================================================

/// W3C / OpenTelemetry span kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanKind {
    /// Synchronous incoming remote call (client → gateway).
    Server,
    /// Synchronous outgoing remote call (gateway → backend).
    Client,
    /// Internal / non-remote span (backend → tool execution).
    Internal,
    /// Async fire-and-forget (notifications, events).
    Producer,
    /// Async consumption.
    Consumer,
}

impl fmt::Display for SpanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Server => "SERVER",
            Self::Client => "CLIENT",
            Self::Internal => "INTERNAL",
            Self::Producer => "PRODUCER",
            Self::Consumer => "CONSUMER",
        };
        f.write_str(s)
    }
}

// ============================================================================
// Span status
// ============================================================================

/// Span completion status (mirrors OpenTelemetry `StatusCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpanStatus {
    /// Not yet set.
    Unset,
    /// Operation completed successfully.
    Ok,
    /// Operation completed with an error.
    Error,
}

impl fmt::Display for SpanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unset => "UNSET",
            Self::Ok => "OK",
            Self::Error => "ERROR",
        };
        f.write_str(s)
    }
}

// ============================================================================
// SpanContext — the immutable identity of a span
// ============================================================================

/// Immutable identity context for a single span.
#[derive(Debug, Clone)]
pub struct SpanContext {
    /// Trace-wide identifier (same for all spans in a trace).
    pub trace_id: TraceId,
    /// This span's own identifier.
    pub span_id: SpanId,
    /// The parent's span identifier, if any.
    pub parent_span_id: Option<SpanId>,
}

impl SpanContext {
    /// Create a root span context (no parent).
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            trace_id: TraceId::generate(),
            span_id: SpanId::generate(),
            parent_span_id: None,
        }
    }

    /// Create a child span context under the given parent.
    #[must_use]
    pub fn child_of(parent: &SpanContext) -> Self {
        Self {
            trace_id: parent.trace_id.clone(),
            span_id: SpanId::generate(),
            parent_span_id: Some(parent.span_id.clone()),
        }
    }

    /// Build the W3C `traceparent` header value for propagation.
    ///
    /// The `parent_span_id` field in the header is *this* span's `span_id`
    /// (i.e. the downstream service should treat us as its parent).
    #[must_use]
    pub fn traceparent_header(&self) -> String {
        format!(
            "00-{}-{}-01",
            self.trace_id.to_hex(),
            self.span_id.to_hex()
        )
    }

    /// Inject tracing headers into a `HashMap` for outbound HTTP.
    pub fn inject_headers(&self, headers: &mut HashMap<String, String>) {
        headers.insert("traceparent".to_string(), self.traceparent_header());
        headers.insert(
            "tracestate".to_string(),
            format!("mcp-gateway={}", self.span_id.to_hex()),
        );
    }
}

// ============================================================================
// Span — the mutable, in-progress unit of work
// ============================================================================

/// A mutable span that records timing and attributes, then emits a structured
/// JSON log line on finish.
pub struct Span {
    /// Immutable identity.
    pub ctx: SpanContext,
    /// Human-readable operation name.
    pub name: String,
    /// Span kind.
    pub kind: SpanKind,
    /// Completion status.
    pub status: SpanStatus,
    /// Optional error message.
    pub error_message: Option<String>,
    /// Key-value attributes.
    pub attributes: HashMap<String, String>,
    /// Wall-clock start time.
    start: Instant,
}

impl Span {
    /// Start a new root span.
    #[must_use]
    pub fn new_root(name: impl Into<String>, kind: SpanKind) -> Self {
        Self {
            ctx: SpanContext::new_root(),
            name: name.into(),
            kind,
            status: SpanStatus::Unset,
            error_message: None,
            attributes: HashMap::new(),
            start: Instant::now(),
        }
    }

    /// Start a child span under `parent`.
    #[must_use]
    pub fn child_of(
        parent: &SpanContext,
        name: impl Into<String>,
        kind: SpanKind,
    ) -> Self {
        Self {
            ctx: SpanContext::child_of(parent),
            name: name.into(),
            kind,
            status: SpanStatus::Unset,
            error_message: None,
            attributes: HashMap::new(),
            start: Instant::now(),
        }
    }

    /// Set a string attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Mark the span as succeeded.
    pub fn set_ok(&mut self) {
        self.status = SpanStatus::Ok;
    }

    /// Mark the span as failed with `message`.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.status = SpanStatus::Error;
        self.error_message = Some(message.into());
    }

    /// Finish and emit the span to the structured log.
    ///
    /// Emits a single `tracing::info!` call whose JSON representation follows
    /// OpenTelemetry semantic conventions.
    pub fn finish(self) {
        let duration_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let parent_hex = self.ctx.parent_span_id.as_ref().map(SpanId::to_hex);
        emit_span_json(
            &self.ctx.trace_id.to_hex(),
            &self.ctx.span_id.to_hex(),
            parent_hex.as_deref(),
            &self.name,
            self.kind,
            self.status,
            self.error_message.as_deref(),
            duration_ms,
            &self.attributes,
        );
    }
}

// ============================================================================
// JSON emission
// ============================================================================

/// Emit a single span as a structured JSON log event.
///
/// The span is serialized inline so that JSON-formatted log subscribers
/// (enabled via `setup_tracing("info", Some("json"))`) nest it cleanly.
#[allow(clippy::too_many_arguments)]
fn emit_span_json(
    trace_id: &str,
    span_id: &str,
    parent_span_id: Option<&str>,
    name: &str,
    kind: SpanKind,
    status: SpanStatus,
    error_message: Option<&str>,
    duration_ms: u64,
    attributes: &HashMap<String, String>,
) {
    let attrs_json = serde_json::to_string(attributes).unwrap_or_else(|_| "{}".to_string());
    let parent = parent_span_id
        .map_or_else(|| "null".to_string(), |p| format!("\"{p}\""));
    let err = error_message.map_or_else(|| "null".to_string(), |e| format!("\"{e}\""));

    tracing::info!(
        trace_id = trace_id,
        span_id = span_id,
        name = name,
        span_kind = %kind,
        status = %status,
        duration_ms = duration_ms,
        "span {{ \"trace_id\": \"{trace_id}\", \"span_id\": \"{span_id}\", \
         \"parent_span_id\": {parent}, \"span_kind\": \"{kind}\", \
         \"name\": \"{name}\", \"status\": \"{status}\", \
         \"duration_ms\": {duration_ms}, \"error\": {err}, \
         \"attributes\": {attrs_json} }}"
    );
}

// ============================================================================
// GatewayTrace — one trace per gateway_invoke call
// ============================================================================

/// Tracks the three-tier span hierarchy for a single `gateway_invoke` call.
///
/// Usage:
///
/// ```rust,ignore
/// let mut trace = GatewayTrace::start("search", "brave");
/// trace.set_auth("api_key");
/// trace.record_routing("direct");
/// // perform transport call…
/// trace.finish_transport(true);
/// // perform tool execution…
/// trace.finish_execution(true, None);
/// trace.finish(true);
/// ```
pub struct GatewayTrace {
    /// Root span: client → gateway.
    root_ctx: SpanContext,
    root_start: Instant,
    root_attributes: HashMap<String, String>,
    /// Transport span context (gateway → backend).
    transport_ctx: SpanContext,
    transport_start: Instant,
    transport_attributes: HashMap<String, String>,
    transport_ok: Option<bool>,
    /// Execution span context (backend → tool).
    exec_ctx: SpanContext,
    exec_start: Instant,
    exec_attributes: HashMap<String, String>,
    exec_ok: Option<bool>,
    exec_error: Option<String>,
}

impl GatewayTrace {
    /// Start a new gateway trace for `tool` on `server`.
    #[must_use]
    pub fn start(tool: &str, server: &str) -> Self {
        let root_ctx = SpanContext::new_root();
        let transport_ctx = SpanContext::child_of(&root_ctx);
        let exec_ctx = SpanContext::child_of(&transport_ctx);
        let now = Instant::now();
        let mut root_attributes = HashMap::new();
        root_attributes.insert("tool".to_string(), tool.to_string());
        root_attributes.insert("server".to_string(), server.to_string());
        Self {
            root_ctx,
            root_start: now,
            root_attributes,
            transport_ctx,
            transport_start: now,
            transport_attributes: HashMap::new(),
            transport_ok: None,
            exec_ctx,
            exec_start: now,
            exec_attributes: HashMap::new(),
            exec_ok: None,
            exec_error: None,
        }
    }

    /// Return the root trace ID (useful for correlating with `gateway_invoke`
    /// response `trace_id` field).
    #[must_use]
    pub fn trace_id(&self) -> String {
        self.root_ctx.trace_id.to_hex()
    }

    /// Build outbound HTTP headers for backend transport.
    #[must_use]
    pub fn outbound_headers(&self) -> HashMap<String, String> {
        let mut h = HashMap::new();
        self.transport_ctx.inject_headers(&mut h);
        h
    }

    /// Record auth mechanism used at the gateway.
    pub fn set_auth(&mut self, mechanism: &str) {
        self.root_attributes
            .insert("auth.mechanism".to_string(), mechanism.to_string());
    }

    /// Record the routing decision.
    pub fn record_routing(&mut self, strategy: &str) {
        self.root_attributes
            .insert("routing.strategy".to_string(), strategy.to_string());
    }

    /// Record transport layer details.
    pub fn set_transport(&mut self, transport: &str, url: &str) {
        self.transport_attributes
            .insert("transport.type".to_string(), transport.to_string());
        self.transport_attributes
            .insert("transport.url".to_string(), url.to_string());
    }

    /// Mark the transport span as finished.
    pub fn finish_transport(&mut self, ok: bool) {
        self.transport_ok = Some(ok);
    }

    /// Record a tool execution attribute.
    pub fn set_exec_attribute(&mut self, key: &str, value: &str) {
        self.exec_attributes
            .insert(key.to_string(), value.to_string());
    }

    /// Mark the execution span as finished.
    pub fn finish_execution(&mut self, ok: bool, error: Option<&str>) {
        self.exec_ok = Some(ok);
        self.exec_error = error.map(String::from);
    }

    /// Emit all three spans and consume the trace.
    pub fn finish(self, root_ok: bool) {
        let now = Instant::now();
        let trace_hex = self.root_ctx.trace_id.to_hex();
        let root_span_hex = self.root_ctx.span_id.to_hex();
        let transport_span_hex = self.transport_ctx.span_id.to_hex();
        let exec_span_hex = self.exec_ctx.span_id.to_hex();
        // Parent of exec span: use transport span (or root as fallback)
        let exec_parent = self
            .exec_ctx
            .parent_span_id
            .as_ref()
            .map_or_else(|| root_span_hex.clone(), SpanId::to_hex);
        // Parent of transport span: use root span
        let transport_parent = self
            .transport_ctx
            .parent_span_id
            .as_ref()
            .map_or_else(|| root_span_hex.clone(), SpanId::to_hex);

        let ms = |d: std::time::Duration| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
        };

        // Execution span
        emit_span_json(
            &trace_hex,
            &exec_span_hex,
            Some(exec_parent.as_str()),
            "tool.execute",
            SpanKind::Internal,
            if self.exec_ok.unwrap_or(root_ok) { SpanStatus::Ok } else { SpanStatus::Error },
            self.exec_error.as_deref(),
            ms(now.duration_since(self.exec_start)),
            &self.exec_attributes,
        );
        // Transport span
        emit_span_json(
            &trace_hex,
            &transport_span_hex,
            Some(transport_parent.as_str()),
            "gateway.transport",
            SpanKind::Client,
            if self.transport_ok.unwrap_or(root_ok) { SpanStatus::Ok } else { SpanStatus::Error },
            None,
            ms(now.duration_since(self.transport_start)),
            &self.transport_attributes,
        );
        // Root span
        emit_span_json(
            &trace_hex,
            &root_span_hex,
            None,
            "gateway.invoke",
            SpanKind::Server,
            if root_ok { SpanStatus::Ok } else { SpanStatus::Error },
            None,
            ms(now.duration_since(self.root_start)),
            &self.root_attributes,
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── TraceId ───────────────────────────────────────────────────────

    #[test]
    fn trace_id_generate_is_32_hex_chars() {
        let id = TraceId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn trace_id_generate_produces_unique_ids() {
        let a = TraceId::generate();
        let b = TraceId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn trace_id_roundtrip_hex() {
        let id = TraceId::generate();
        let hex = id.to_hex();
        let parsed = TraceId::from_hex(&hex).expect("must parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn trace_id_from_hex_rejects_wrong_length() {
        assert!(TraceId::from_hex("abc").is_none());
        assert!(TraceId::from_hex("").is_none());
        // 33 chars
        assert!(TraceId::from_hex("0000000000000000000000000000000000").is_none());
    }

    #[test]
    fn trace_id_from_hex_rejects_all_zeros() {
        assert!(TraceId::from_hex("00000000000000000000000000000000").is_none());
    }

    #[test]
    fn trace_id_from_hex_rejects_invalid_chars() {
        assert!(TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4zzz").is_none());
    }

    // ── SpanId ────────────────────────────────────────────────────────

    #[test]
    fn span_id_generate_is_16_hex_chars() {
        let id = SpanId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 16);
    }

    #[test]
    fn span_id_roundtrip_hex() {
        let id = SpanId::generate();
        let hex = id.to_hex();
        let parsed = SpanId::from_hex(&hex).expect("must parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn span_id_from_hex_rejects_all_zeros() {
        assert!(SpanId::from_hex("0000000000000000").is_none());
    }

    // ── TraceParent ───────────────────────────────────────────────────

    #[test]
    fn traceparent_new_root_serializes_correctly() {
        let tp = TraceParent::new_root();
        let hdr = tp.to_header_value();
        assert!(hdr.starts_with("00-"), "must start with version 00");
        let parts: Vec<&str> = hdr.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1].len(), 32);
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
    }

    #[test]
    fn traceparent_parse_roundtrip() {
        let tp = TraceParent::new_root();
        let hdr = tp.to_header_value();
        let parsed = TraceParent::parse(&hdr).expect("must parse");
        assert_eq!(parsed.trace_id, tp.trace_id);
        assert_eq!(parsed.parent_span_id, tp.parent_span_id);
        assert_eq!(parsed.flags, tp.flags);
    }

    #[test]
    fn traceparent_parse_rejects_missing_parts() {
        assert!(TraceParent::parse("00-abc").is_none());
        assert!(TraceParent::parse("").is_none());
    }

    #[test]
    fn traceparent_parse_rejects_unknown_version() {
        assert!(TraceParent::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .is_none());
    }

    #[test]
    fn traceparent_is_sampled_flag() {
        let mut tp = TraceParent::new_root();
        tp.flags = 0x01;
        assert!(tp.is_sampled());
        tp.flags = 0x00;
        assert!(!tp.is_sampled());
    }

    // ── SpanContext ───────────────────────────────────────────────────

    #[test]
    fn span_context_new_root_has_no_parent() {
        let ctx = SpanContext::new_root();
        assert!(ctx.parent_span_id.is_none());
    }

    #[test]
    fn span_context_child_inherits_trace_id() {
        let root = SpanContext::new_root();
        let child = SpanContext::child_of(&root);
        assert_eq!(root.trace_id, child.trace_id);
        assert_ne!(root.span_id, child.span_id);
        assert_eq!(child.parent_span_id.as_ref(), Some(&root.span_id));
    }

    #[test]
    fn span_context_traceparent_header_valid() {
        let ctx = SpanContext::new_root();
        let hdr = ctx.traceparent_header();
        let parsed = TraceParent::parse(&hdr).expect("must parse");
        assert_eq!(parsed.trace_id, ctx.trace_id);
        assert_eq!(parsed.parent_span_id, ctx.span_id);
        assert!(parsed.is_sampled());
    }

    #[test]
    fn span_context_inject_headers() {
        let ctx = SpanContext::new_root();
        let mut headers = HashMap::new();
        ctx.inject_headers(&mut headers);
        assert!(headers.contains_key("traceparent"));
        assert!(headers.contains_key("tracestate"));
        let tp = headers["traceparent"].as_str();
        assert!(TraceParent::parse(tp).is_some());
    }

    // ── Span ──────────────────────────────────────────────────────────

    #[test]
    fn span_new_root_sets_name_and_kind() {
        let span = Span::new_root("gateway.invoke", SpanKind::Server);
        assert_eq!(span.name, "gateway.invoke");
        assert_eq!(span.kind, SpanKind::Server);
        assert_eq!(span.status, SpanStatus::Unset);
    }

    #[test]
    fn span_child_of_shares_trace_id() {
        let parent = SpanContext::new_root();
        let child = Span::child_of(&parent, "gateway.transport", SpanKind::Client);
        assert_eq!(child.ctx.trace_id, parent.trace_id);
        assert_eq!(child.ctx.parent_span_id.as_ref(), Some(&parent.span_id));
    }

    #[test]
    fn span_set_ok_changes_status() {
        let mut span = Span::new_root("op", SpanKind::Internal);
        span.set_ok();
        assert_eq!(span.status, SpanStatus::Ok);
    }

    #[test]
    fn span_set_error_changes_status_and_message() {
        let mut span = Span::new_root("op", SpanKind::Internal);
        span.set_error("something broke");
        assert_eq!(span.status, SpanStatus::Error);
        assert_eq!(span.error_message.as_deref(), Some("something broke"));
    }

    #[test]
    fn span_attributes_stored() {
        let mut span = Span::new_root("op", SpanKind::Server);
        span.set_attribute("tool", "search");
        span.set_attribute("server", "brave");
        assert_eq!(span.attributes.get("tool").map(String::as_str), Some("search"));
        assert_eq!(span.attributes.get("server").map(String::as_str), Some("brave"));
    }

    // finish() emits tracing output — we just verify it doesn't panic.
    #[test]
    fn span_finish_does_not_panic() {
        let mut span = Span::new_root("test.op", SpanKind::Internal);
        span.set_ok();
        span.finish();
    }

    // ── GatewayTrace ──────────────────────────────────────────────────

    #[test]
    fn gateway_trace_trace_id_is_32_hex() {
        let trace = GatewayTrace::start("search", "brave");
        let tid = trace.trace_id();
        assert_eq!(tid.len(), 32);
        assert!(tid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn gateway_trace_outbound_headers_contain_traceparent() {
        let trace = GatewayTrace::start("search", "brave");
        let headers = trace.outbound_headers();
        assert!(headers.contains_key("traceparent"));
        assert!(headers.contains_key("tracestate"));
    }

    #[test]
    fn gateway_trace_finish_does_not_panic() {
        let mut trace = GatewayTrace::start("call_tool", "my_server");
        trace.set_auth("bearer_token");
        trace.record_routing("direct");
        trace.set_transport("http", "https://example.com/mcp");
        trace.finish_transport(true);
        trace.set_exec_attribute("tool.input_size", "128");
        trace.finish_execution(true, None);
        trace.finish(true);
    }

    #[test]
    fn gateway_trace_finish_with_error_does_not_panic() {
        let mut trace = GatewayTrace::start("write_file", "fs_server");
        trace.finish_transport(false);
        trace.finish_execution(false, Some("permission denied"));
        trace.finish(false);
    }
}
