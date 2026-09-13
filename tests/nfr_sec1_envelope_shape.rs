// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.SEC.1 — the JSON-RPC envelope-shape control, driven through the route.
//!
//! `docs/requirements/nfr-sec1-control-inventory.md` flags this control as the
//! one whose only coverage calls `parse_request` directly. A gate exercised by
//! calling it is a gate that cannot tell enforced from unenforced: unwire it
//! from the route and every direct-call test still passes. These drive the only
//! route a modern caller has — `POST /mcp` — with each required envelope field
//! removed in turn, and assert both the code and the refusal text, because
//! `-32600` is emitted by several other gates on the same path.
//!
//! Gate under test: `parse_request`, `src/gateway/router/helpers.rs:260`
//! (arms at `:266`, `:280`, `:288`), reached from the handler's dispatch at
//! `src/gateway/router/handlers.rs:766`.

mod common;
use common::*;

/// The `_meta` block a modern caller carries, lifted out so each case can build
/// a frame with one field missing rather than mutating a well-formed one.
fn params() -> Value {
    json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
        }
    })
}

fn assert_envelope_refusal(status: StatusCode, body: &Value, message: &str) {
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the envelope gate refuses with 400; body: {body}"
    );
    assert_eq!(
        body["error"]["code"], -32600,
        "envelope refusal must carry Invalid Request; body: {body}"
    );
    assert_eq!(
        body["error"]["message"], message,
        "the code alone does not identify this gate — several others on the \
         route also answer -32600; body: {body}"
    );
}

// ============================================================================
// The `jsonrpc` version field is required.
// ============================================================================
#[tokio::test]
async fn a_modern_frame_without_the_jsonrpc_field_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post(
        &app,
        json!({ "id": 1, "method": "tools/list", "params": params() }),
        &[],
    )
    .await;
    assert_envelope_refusal(status, &body, "Invalid JSON-RPC version");
    // Falsifier: the same frame carrying the field is served.
    let (served, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

#[tokio::test]
async fn a_modern_frame_declaring_a_wrong_jsonrpc_version_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post(
        &app,
        json!({ "jsonrpc": "1.0", "id": 1, "method": "tools/list", "params": params() }),
        &[],
    )
    .await;
    assert_envelope_refusal(status, &body, "Invalid JSON-RPC version");
    // Falsifier: the identical frame declaring 2.0 is served.
    let (served, body) = post(
        &app,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params() }),
        &[],
    )
    .await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

// ============================================================================
// The `method` field is required.
//
// `post` mirrors the body's method into `MCP-Method`; a body with no method
// would leave that header absent and the mirrored-header check would refuse
// first, so the header is supplied by hand. That keeps the envelope gate the
// only thing this case can be measuring.
// ============================================================================
#[tokio::test]
async fn a_modern_frame_without_a_method_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post(
        &app,
        json!({ "jsonrpc": "2.0", "id": 1, "params": params() }),
        &[("mcp-method", "tools/list")],
    )
    .await;
    assert_envelope_refusal(status, &body, "Missing method");
    // Falsifier: the same frame with the method restored is served.
    let (served, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

// ============================================================================
// A request — anything that is not a notification — must carry an `id`.
// ============================================================================
#[tokio::test]
async fn a_modern_request_without_an_id_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post(
        &app,
        json!({ "jsonrpc": "2.0", "method": "tools/list", "params": params() }),
        &[],
    )
    .await;
    assert_envelope_refusal(status, &body, "Missing id");
    // Falsifier: the same frame carrying an id is served.
    let (served, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}
