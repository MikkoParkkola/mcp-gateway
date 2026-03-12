use super::*;
use std::collections::HashMap;

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
    assert!(
        TraceParent::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none()
    );
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
    assert_eq!(
        span.attributes.get("tool").map(String::as_str),
        Some("search")
    );
    assert_eq!(
        span.attributes.get("server").map(String::as_str),
        Some("brave")
    );
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
