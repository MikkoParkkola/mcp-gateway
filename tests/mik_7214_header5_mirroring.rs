// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7214.HEADER.5 — SEP-2243 outbound header mirroring.
//!
//! A tool argument whose `inputSchema` property carries `x-mcp-header` must be
//! mirrored onto an `Mcp-Param-{name}` header of the outbound `tools/call`.
//! The declaration is server-side: a caller cannot name a header by sending
//! one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};
use mcp_gateway::protocol::headers::decode_header_value;
use mcp_gateway::protocol::param_headers::mirror_headers;

/// What the mock backend saw on the `tools/call` POST.
#[derive(Default)]
struct Captured {
    headers: Option<HeaderMap>,
    body: Option<Value>,
}

/// A mock Streamable HTTP backend surfacing one tool, `echo`, whose `tenant`
/// property is annotated for mirroring and whose `plain` property is not.
async fn mcp_handler(
    State(captured): State<Arc<Mutex<Captured>>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    match body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "initialize" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                // Echo the requested version so the handshake cannot mismatch.
                "protocolVersion": body["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "mock", "version": "0"}
            }
        })),
        "tools/list" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": [{
                "name": "echo",
                "description": "echo",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tenant": {"type": "string", "x-mcp-header": "Tenant"},
                        "plain": {"type": "string"}
                    }
                }
            }]}
        })),
        "tools/call" => {
            let mut slot = captured.lock().expect("capture mutex poisoned");
            slot.headers = Some(headers);
            slot.body = Some(body.clone());
            Json(json!({"jsonrpc": "2.0", "id": id, "result": {"content": []}}))
        }
        // Any other method is captured too, so a test can assert what a
        // non-`tools/call` request carries.
        _ => {
            let mut slot = captured.lock().expect("capture mutex poisoned");
            slot.headers = Some(headers);
            slot.body = Some(body.clone());
            Json(json!({"jsonrpc": "2.0", "id": id, "result": {}}))
        }
    }
}

async fn start_mock() -> (String, Arc<Mutex<Captured>>) {
    let captured = Arc::new(Mutex::new(Captured::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/mcp", post(mcp_handler))
        .with_state(Arc::clone(&captured));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), captured)
}

fn backend_for(url: &str) -> Backend {
    let config = BackendConfig {
        description: "header mirroring mock".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        stop_when_idle_for: None,
        max_frame_bytes: None,
        timeout: Duration::from_secs(10),
        env: HashMap::default(),
        headers: HashMap::default(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: false,
        allow_cleartext_credentials: false,
        input_schema_enforcement: mcp_gateway::config::InputSchemaEnforcement::default(),
        allow_flagged_tools: std::collections::BTreeMap::new(),
        runtime_profile: None,
        identity_propagation: None,
        account: None,
        signature_chain: mcp_gateway::config::ChainMode::default(),
        chain_origins: Vec::new(),
        chain_signer: None,
        ..BackendConfig::default()
    };
    Backend::new(
        "mirror-mock",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    )
}

fn captured_header(captured: &Arc<Mutex<Captured>>, name: &str) -> Option<String> {
    let slot = captured.lock().expect("capture mutex poisoned");
    let headers = slot.headers.as_ref().expect("no request reached the mock");
    headers
        .get(name)
        .map(|value| value.to_str().expect("header not ASCII").to_string())
}

#[tokio::test]
async fn ac_header_5_annotated_argument_is_mirrored_onto_mcp_param_header() {
    let (url, captured) = start_mock().await;
    let backend = backend_for(&url);

    // Discovery first: a tools/call always follows a tools/list in the gateway,
    // and the schema the mirror reads is the cached one.
    backend.get_tools().await.expect("tools/list");

    backend
        .request(
            "tools/call",
            Some(json!({"name": "echo", "arguments": {"tenant": "acme", "plain": "x"}})),
        )
        .await
        .expect("tools/call");

    assert_eq!(
        captured_header(&captured, "Mcp-Param-Tenant").as_deref(),
        Some("acme"),
        "annotated argument must be mirrored onto Mcp-Param-Tenant"
    );
    assert_eq!(
        captured_header(&captured, "Mcp-Param-Plain"),
        None,
        "an unannotated property must produce no header"
    );

    // Mirroring is a copy, not a move: the argument stays in the JSON-RPC body.
    let slot = captured.lock().expect("capture mutex poisoned");
    let body = slot.body.as_ref().expect("tools/call body");
    assert_eq!(
        body["params"]["arguments"]["tenant"],
        json!("acme"),
        "the mirrored argument must still be sent in the request body"
    );
}

#[tokio::test]
async fn ac_header_5_caller_supplied_param_header_cannot_forge_a_declaration() {
    let (url, captured) = start_mock().await;
    let backend = backend_for(&url);
    backend.get_tools().await.expect("tools/list");

    backend
        .request_with_headers(
            "tools/call",
            Some(json!({"name": "echo", "arguments": {"tenant": "acme"}})),
            &[
                ("Mcp-Param-Tenant".to_string(), "attacker".to_string()),
                ("Mcp-Param-Plain".to_string(), "attacker".to_string()),
            ],
            None,
        )
        .await
        .expect("tools/call");

    assert_eq!(
        captured_header(&captured, "Mcp-Param-Tenant").as_deref(),
        Some("acme"),
        "the schema declaration wins over a caller-supplied header of the same name"
    );
    assert_eq!(
        captured_header(&captured, "Mcp-Param-Plain"),
        None,
        "a caller cannot introduce a mirrored header the schema never declared"
    );
}

#[tokio::test]
async fn param_namespace_is_stripped_on_a_method_that_mirrors_nothing() {
    let (url, captured) = start_mock().await;
    let backend = backend_for(&url);

    // `ping` declares no schema and mirrors nothing, so the gateway-owned
    // namespace must arrive empty rather than carrying the caller's value.
    backend
        .request_with_headers(
            "ping",
            None,
            &[("Mcp-Param-Tenant".to_string(), "attacker".to_string())],
            None,
        )
        .await
        .expect("ping");

    assert_eq!(
        captured_header(&captured, "Mcp-Param-Tenant"),
        None,
        "the Mcp-Param- namespace must be stripped on every method, not only tools/call"
    );
}

/// Preserves numeric and boolean cases. Red if control-character strings are dropped instead of encoded.
#[test]
fn only_losslessly_renderable_values_are_mirrored() {
    let schema = json!({
        "type": "object",
        "properties": {
            "count": {"type": "integer", "x-mcp-header": "Count"},
            "ratio": {"type": "integer", "x-mcp-header": "Ratio"},
            "huge": {"type": "integer", "x-mcp-header": "Huge"},
            "text": {"type": "string", "x-mcp-header": "Text"},
            "flag": {"type": "boolean", "x-mcp-header": "Flag"}
        }
    });
    let arguments = json!({
        "count": 42,
        // A double has no lossless header rendering.
        "ratio": 1.5,
        // One past the IEEE-754 exact range.
        "huge": 9_007_199_254_740_992_i64,
        // A bare CR in a field value is request splitting.
        "text": "acme\rX-Injected: 1",
        "flag": true
    });

    let mirrored = mirror_headers(&schema, &arguments);

    assert_eq!(
        mirrored,
        vec![
            ("Mcp-Param-Count".to_string(), "42".to_string()),
            ("Mcp-Param-Flag".to_string(), "true".to_string()),
            (
                "Mcp-Param-Text".to_string(),
                "=?base64?YWNtZQ1YLUluamVjdGVkOiAx?=".to_string(),
            ),
        ],
        "a float and an out-of-range integer must be dropped; a control character must be encoded"
    );
    assert_eq!(
        decode_header_value(&mirrored[2].1).as_deref(),
        Some("acme\rX-Injected: 1")
    );
}

/// Keeps an empty argument lossless. Red if the empty string is sentinel-wrapped.
#[test]
fn an_empty_string_argument_mirrors_as_an_empty_value() {
    let schema = json!({"type": "object", "properties": {
        "tenant": {"type": "string", "x-mcp-header": "Tenant"}
    }});
    let mirrored = mirror_headers(&schema, &json!({"tenant": ""}));

    assert_eq!(mirrored, vec![("Mcp-Param-Tenant".to_string(), String::new())]);
    assert_eq!(decode_header_value(&mirrored[0].1).as_deref(), Some(""));
}

/// Encodes controls without losing the argument. Red if CR or tab values are dropped.
#[test]
fn a_control_character_value_is_encoded_not_dropped() {
    let schema = json!({"type": "object", "properties": {
        "tenant": {"type": "string", "x-mcp-header": "Tenant"}
    }});
    for (original, encoded) in [
        ("a\rb", "=?base64?YQ1i?="),
        ("tab\there", "=?base64?dGFiCWhlcmU=?="),
    ] {
        let mirrored = mirror_headers(&schema, &json!({"tenant": original}));

        assert_eq!(
            mirrored,
            vec![("Mcp-Param-Tenant".to_string(), encoded.to_string())],
            "control-character value {original:?} must be sentinel-encoded"
        );
        let value = &mirrored[0].1;
        assert!(!value.contains('\r') && !value.contains('\n'));
        assert_eq!(decode_header_value(value).as_deref(), Some(original));
    }
}

/// Rejects a duplicate across schema levels. Red if a nested case-insensitive duplicate emits headers.
#[test]
fn a_nested_duplicate_header_name_excludes_the_tool() {
    let schema = json!({"type": "object", "properties": {
        "tenant": {"type": "string", "x-mcp-header": "Tenant"},
        "filter": {"type": "object", "properties": {
            "tenant": {"type": "string", "x-mcp-header": "tenant"}
        }}
    }});
    let arguments = json!({"tenant": "outer", "filter": {"tenant": "inner"}});

    assert!(mirror_headers(&schema, &arguments).is_empty());
}

#[test]
fn nested_annotated_property_is_mirrored_and_spaced_value_is_encoded() {
    let schema = json!({
        "type": "object",
        "properties": {
            "owner": {"type": "string", "x-mcp-header": "Owner"},
            "filter": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string", "x-mcp-header": "Repo"}
                }
            }
        }
    });
    let arguments = json!({
        "owner": "unity",
        "filter": {"repo": "two words"}
    });

    let mirrored = mirror_headers(&schema, &arguments);

    assert_eq!(
        mirrored,
        vec![
            ("Mcp-Param-Owner".to_string(), "unity".to_string()),
            (
                "Mcp-Param-Repo".to_string(),
                "=?base64?dHdvIHdvcmRz?=".to_string()
            ),
        ]
    );
}
