// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7215 — stateless request handling, the
//! second increment of MCP revision 2026-07-28 support.
//!
//! Plan: `docs/requirements/RELEASE-4.0.0-test-plan.md` §"Increment 2".
//!
//! Request frames here are transcribed from the specification's examples, not
//! built from the gateway's own types. Increment 1 shipped a nonconforming
//! discovery document that every test passed, because the tests asserted the
//! same invented field names. Once was enough.

use mcp_gateway::protocol::meta::{RequestShape, classify_request};
use serde_json::json;

/// A modern request, as the specification writes one.
fn modern_params() -> serde_json::Value {
    json!({
        "name": "get_weather",
        "arguments": { "location": "Helsinki" },
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "ExampleClient",
                "version": "1.0.0"
            }
        }
    })
}

// ===========================================================================
// MIK-7215.STATELESS.1 — a request carrying its own protocol version is served
// with no prior handshake, and dispatch is per request.
// ===========================================================================

#[test]
fn ac_stateless_1_a_request_carrying_its_own_version_is_modern() {
    match classify_request(Some(&modern_params())) {
        RequestShape::Modern(fields) => {
            assert_eq!(fields.protocol_version, "2026-07-28");
            assert_eq!(
                fields.client_info_name.as_deref(),
                Some("ExampleClient"),
                "clientInfo travels as context, and is read — but never trusted for authorization"
            );
        }
        other => panic!("a request carrying the protocol fields is modern, got {other:?}"),
    }
}

#[test]
fn ac_stateless_1_each_request_carries_its_own_version() {
    // Per REQUEST, not per connection. Two requests declaring different
    // versions are each classified under their own; an implementation that
    // remembered the first would serve the second wrongly, which is exactly
    // what the removal of the handshake is meant to prevent.
    let mut first = modern_params();
    first["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
    let mut second = modern_params();
    second["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2027-01-01");

    let a = classify_request(Some(&first));
    let b = classify_request(Some(&second));

    match (a, b) {
        (RequestShape::Modern(x), RequestShape::Modern(y)) => {
            assert_eq!(x.protocol_version, "2026-07-28");
            assert_eq!(y.protocol_version, "2027-01-01");
        }
        other => panic!("both are modern requests, got {other:?}"),
    }
}

// ===========================================================================
// MIK-7215.STATELESS.9 — both protocol fields are required. A request missing
// either is malformed: -32602, HTTP 400.
// ===========================================================================

#[test]
fn ac_stateless_9_missing_protocol_version_is_malformed() {
    let mut params = modern_params();
    params["_meta"]
        .as_object_mut()
        .expect("_meta is an object")
        .remove("io.modelcontextprotocol/protocolVersion");

    match classify_request(Some(&params)) {
        RequestShape::Malformed { missing } => assert!(
            missing.contains(&"io.modelcontextprotocol/protocolVersion"),
            "the error must name what was missing, got {missing:?}"
        ),
        other => panic!("a modern request without its version is malformed, got {other:?}"),
    }
}

#[test]
fn ac_stateless_9_missing_client_capabilities_is_malformed() {
    // The one an implementer skips, because the field looks optional and
    // nothing appears to break without it. The specification lists it as
    // Required: Yes, alongside the version.
    let mut params = modern_params();
    params["_meta"]
        .as_object_mut()
        .expect("_meta is an object")
        .remove("io.modelcontextprotocol/clientCapabilities");

    match classify_request(Some(&params)) {
        RequestShape::Malformed { missing } => assert!(
            missing.contains(&"io.modelcontextprotocol/clientCapabilities"),
            "the error must name what was missing, got {missing:?}"
        ),
        other => {
            panic!("a modern request without declared capabilities is malformed, got {other:?}")
        }
    }
}

#[test]
fn ac_stateless_9_a_request_with_no_protocol_meta_is_legacy_not_malformed() {
    // THE ROW THAT DECIDES THE DESIGN.
    //
    // A 2025 client sends no `_meta` protocol fields at all — and so does a
    // 2026 client that forgot a required one. One must be served and the other
    // refused, so absence alone cannot be the discriminator.
    //
    // Resolution: malformed means "declared itself modern and then omitted
    // something". A request that declares nothing has not declared itself
    // modern, so it is legacy. Refusing it would break every 2025 client, which
    // is a worse error than telling a broken 2026 client its method is unknown.
    let legacy = json!({ "name": "get_weather", "arguments": {} });
    assert!(
        matches!(classify_request(Some(&legacy)), RequestShape::Legacy),
        "a request with no protocol metadata is a 2025 client, not a broken 2026 one"
    );

    // Including the shape with an empty `_meta` — `_meta` is a general-purpose
    // extension field and its mere presence declares nothing about the era.
    let empty_meta = json!({ "name": "get_weather", "_meta": {} });
    assert!(
        matches!(classify_request(Some(&empty_meta)), RequestShape::Legacy),
        "`_meta` carries more than protocol fields; an empty one declares no era"
    );

    // And no params at all.
    assert!(matches!(classify_request(None), RequestShape::Legacy));
}

#[test]
fn ac_stateless_9_a_partially_declared_request_is_malformed_not_legacy() {
    // The complement of the row above, and the reason it is not circular: a
    // request carrying ONE protocol field has declared itself modern, so the
    // missing one is an error rather than an absence.
    let params = json!({
        "name": "get_weather",
        "_meta": { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }
    });
    assert!(
        matches!(
            classify_request(Some(&params)),
            RequestShape::Malformed { .. }
        ),
        "declaring a version and omitting capabilities is a broken modern request"
    );
}

#[test]
fn ac_stateless_9_other_meta_keys_do_not_make_a_request_modern() {
    // `_meta` is shared with tracing, extensions and anything else. A request
    // carrying only a trace context is a 2025 client with a tracing header, and
    // reading it as a broken modern request would refuse a working client.
    let params = json!({
        "name": "get_weather",
        "_meta": { "traceparent": "00-abc-def-01", "vendor.example/thing": 1 }
    });
    assert!(
        matches!(classify_request(Some(&params)), RequestShape::Legacy),
        "unrelated _meta keys declare no era"
    );
}
