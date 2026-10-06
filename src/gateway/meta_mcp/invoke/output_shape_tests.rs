// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The output-schema mismatch log runs before the response firewall, so it
//! names where a result broke its schema and the types involved, never a
//! value or an undeclared key: either can be a credential the backend
//! returned, which the firewall has not yet seen.

use serde_json::json;

use super::enforce_output_schema;
use crate::test_log_capture::{count, records};

const TOKEN: &str = "tok-7f3a9c-do-not-log";
const WARNING: &str = "did not match its declared output schema";

fn schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {"count": {"type": "integer"}, "name": {"type": "string"}},
        "required": ["name"],
    })
}

/// One warning per result, carrying `expected` and no trace of [`TOKEN`],
/// for the bare payload and for the same payload inside an MCP envelope.
fn assert_logged_without_token(payload: &serde_json::Value, expected: &[&str]) {
    let envelope = json!({"content": [{"type": "text", "text": payload.to_string()}]});
    for result in [payload.clone(), envelope] {
        let logs = records(|| {
            let _ = enforce_output_schema("srv", "tool", result.clone(), Some(&schema()));
        });
        assert_eq!(count(&logs, "WARN", WARNING), 1, "{logs:?}");
        let text = serde_json::to_string(&logs).unwrap();
        assert!(
            !text.contains(TOKEN),
            "a backend value reached the log: {text}"
        );
        let warning = logs
            .iter()
            .find(|r| {
                r["fields"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(WARNING))
            })
            .unwrap();
        let mismatch = warning["fields"]["mismatch"].as_str().unwrap_or_default();
        for part in expected {
            assert!(mismatch.contains(part), "{part:?} not in {mismatch:?}");
        }
    }
}

/// A token in an integer-typed field: the path and both types, not the token.
#[test]
fn a_type_mismatch_log_names_the_path_and_types_not_the_value() {
    assert_logged_without_token(
        &json!({"name": "n", "count": TOKEN}),
        &["count: expected integer, got string"],
    );
}

/// A token as an undeclared key (with a required field missing, which the
/// validator reports in the same pass): the key is never named.
#[test]
fn an_undeclared_key_is_never_named_in_the_log() {
    assert_logged_without_token(
        &json!({TOKEN: 1}),
        &["undeclared key", "name: expected string, got missing"],
    );
}

/// A token as the whole result, where an object was declared: the root's
/// type is logged, never the value.
#[test]
fn a_root_type_mismatch_log_names_the_type_not_the_value() {
    assert_logged_without_token(&json!(TOKEN), &["$: got string"]);
}

/// MIK-7959: an array root published under `items` is validated in its
/// declared shape, as the capability route runs it, and the text content is
/// not rewritten into the wrapped shape.
#[test]
fn a_wrapped_output_root_is_validated_unwrapped_and_keeps_its_text() {
    let declared = json!({ "type": "array", "items": { "type": "string" } });
    let payload = json!(["a", "b"]);
    let text = serde_json::to_string_pretty(&payload).unwrap();
    let mut envelope = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": crate::capability::published_output(&declared, payload.clone()),
        "isError": false,
    });

    assert!(crate::capability::unwrap_published_output(
        &declared,
        &mut envelope
    ));
    let mut validated = enforce_output_schema("caps", "listing", envelope, Some(&declared));
    crate::capability::rewrap_published_output(&mut validated);

    assert_eq!(validated["structuredContent"], json!({ "items": payload }));
    assert_eq!(validated["content"][0]["text"], json!(text));
}

/// MIK-7959 through the dispatch tail: a capability whose declared root is an
/// array answers a `gateway_invoke` with that array under `items` in
/// `structuredContent`, and its text content in the declared shape. Dispatch
/// reads the result unwrapped (transform, schema) and wraps it again after.
#[tokio::test]
async fn an_array_root_is_published_under_items_through_dispatch() {
    use std::sync::Arc;

    use crate::capability::{CapabilityBackend, CapabilityExecutor, parse_capability};
    use crate::gateway::meta_mcp::MetaMcp;
    use crate::gateway::meta_mcp::grant_decision_audit_tests::{api_key, context};

    let names = json!(["ada", "grace"]);
    let served = names.clone();
    let app = axum::Router::new().route(
        "/names",
        axum::routing::get(move || {
            let served = served.clone();
            async move { axum::Json(served) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });

    let definition = parse_capability(&format!(
        "name: name_list\n\
         description: List two names\n\
         schema:\n\
         \x20 output:\n\
         \x20   type: array\n\
         \x20   items:\n\
         \x20     type: string\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: http://localhost:{port}\n\
         \x20     path: /names\n\
         \x20     method: GET\n"
    ))
    .expect("the capability parses");
    let executor = Arc::new(
        CapabilityExecutor::new()
            .with_test_http_client(reqwest::Client::builder().no_proxy().build().unwrap()),
    );
    let backend = Arc::new(CapabilityBackend::new("caps", executor));
    backend.register_capability(definition).expect("registers");
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new())).with_code_mode(true);
    meta.set_capabilities(backend);

    let who = api_key("alice");
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "gateway_invoke",
        json!({ "server": "caps", "tool": "name_list", "arguments": {} }),
        Some("output-root"),
        context(&who),
    ))
    .await;
    let answer = serde_json::to_value(&response).unwrap();
    // `gateway_invoke` answers with the tool's result wrapped as JSON text.
    let result: serde_json::Value = answer["result"]["content"][0]["text"]
        .as_str()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| panic!("no wrapped tool result: {answer}"));
    assert_eq!(
        result["structuredContent"],
        json!({ "items": names }),
        "{answer}"
    );
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(text).ok(),
        Some(names),
        "the text content keeps the declared shape: {answer}"
    );
}
