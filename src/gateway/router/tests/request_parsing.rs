// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request id, tool-call parameter, client meta and JSON-RPC request parsing.

use super::*;
use pretty_assertions::assert_eq;

// =====================================================================
// extract_request_id
// =====================================================================

#[test]
fn extract_request_id_string_value() {
    let val = json!("abc-123");
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::String("abc-123".to_string()));
}

#[test]
fn extract_request_id_positive_integer() {
    let val = json!(42);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(42));
}

#[test]
fn extract_request_id_negative_integer() {
    let val = json!(-1);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(-1));
}

#[test]
fn extract_request_id_zero() {
    let val = json!(0);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(0));
}

/// An id above `i64::MAX` is unrecognised rather than wrapped into a
/// negative id that would answer a different request.
#[test]
fn extract_request_id_beyond_i64_is_unrecognised() {
    assert!(extract_request_id(&json!(u64::MAX)).is_none());
    assert_eq!(
        extract_request_id(&json!(i64::MAX)),
        Some(RequestId::Number(i64::MAX))
    );
}

#[test]
fn extract_request_id_null_returns_none() {
    let val = json!(null);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_bool_returns_none() {
    let val = json!(true);
    assert!(extract_request_id(&val).is_none());
}

#[test]
#[allow(clippy::approx_constant)] // 3.14 tests float input, not π
fn extract_request_id_float_returns_none() {
    let val = json!(3.14);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_array_returns_none() {
    let val = json!([1, 2]);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_object_returns_none() {
    let val = json!({"id": 1});
    assert!(extract_request_id(&val).is_none());
}

// =====================================================================
// is_notification_method
// =====================================================================

#[test]
fn notification_method_recognized() {
    assert!(is_notification_method("notifications/initialized"));
    assert!(is_notification_method("notifications/cancelled"));
    assert!(is_notification_method("notifications/"));
}

#[test]
fn regular_method_not_notification() {
    assert!(!is_notification_method("initialize"));
    assert!(!is_notification_method("tools/list"));
    assert!(!is_notification_method("tools/call"));
    assert!(!is_notification_method("ping"));
    assert!(!is_notification_method(""));
}

// =====================================================================
// extract_tools_call_params
// =====================================================================

#[test]
fn extract_tools_call_params_full() {
    let params = json!({"name": "my_tool", "arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_name() {
    let params = json!({"arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_arguments() {
    let params = json!({"name": "my_tool"});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_none_input() {
    let (name, args) = extract_tools_call_params(None);
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_empty_object() {
    let params = json!({});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

// =====================================================================
// merge_client_meta (MIK-7215.CONTROL.3b)
// =====================================================================

#[test]
fn ac_control_3b_meta_tool_receives_the_clients_params_meta() {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "s", "tool": "t"},
        "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    });
    let (_, args) = extract_tools_call_params(Some(&params));
    let merged = merge_client_meta(args, Some(&params), true);
    assert_eq!(
        merged["_meta"]["traceparent"],
        json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        "the meta layer reads `_meta` off the argument object, so a conforming \
         client's `params._meta` has to reach it or the trace id can never be the key"
    );
}

#[test]
fn ac_control_3b_direct_route_payload_is_byte_identical() {
    let params = json!({
        "name": "backend__tool",
        "arguments": {"q": 1},
        "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    });
    let (_, args) = extract_tools_call_params(Some(&params));
    let merged = merge_client_meta(args, Some(&params), false);
    assert_eq!(
        merged,
        json!({"q": 1}),
        "the direct route reaches a backend that never asked for `_meta`; \
         synthesising one there invents a field the client did not send it"
    );
}

#[test]
fn ac_control_3b_an_argument_meta_the_client_wrote_is_not_overwritten() {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"_meta": {"traceparent": "inner"}},
        "_meta": {"traceparent": "outer"}
    });
    let (_, args) = extract_tools_call_params(Some(&params));
    let merged = merge_client_meta(args, Some(&params), true);
    assert_eq!(merged["_meta"]["traceparent"], json!("inner"));
}

#[test]
fn ac_control_3b_absent_params_meta_changes_nothing() {
    let params = json!({"name": "gateway_invoke", "arguments": {"q": 1}});
    let (_, args) = extract_tools_call_params(Some(&params));
    assert_eq!(
        merge_client_meta(args, Some(&params), true),
        json!({"q": 1})
    );
}

/// BLOCK-3: the predicate the router feeds to `merge_client_meta` answers
/// "would this gateway confirm the name exists", not "is this one of ours".
/// A surfaced backend tool answers yes to the first question, so the client's
/// `_meta` was injected into arguments the backend never asked for.
#[test]
fn block3_a_surfaced_backend_tool_does_not_take_the_clients_meta() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let params = json!({
        "name": "backend__tool",
        "arguments": {"city": "Oslo"},
        "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
    });
    let (name, args) = extract_tools_call_params(Some(&params));
    let merged = merge_client_meta(args, Some(&params), meta.exposes_meta_tool(name));
    assert_eq!(
        merged,
        json!({"city": "Oslo"}),
        "`backend__tool` is not a gateway meta-tool, so the direct route must \
         hand the backend the arguments the client actually sent"
    );
}

/// BLOCK-3, the other half: narrowing the predicate must not drop the merge for
/// a name the gateway does own. An admin tool is included deliberately — the
/// router asks this predicate *before* its admin pre-check, so an admin name
/// missing from the roster would lose the client's `_meta` silently.
#[test]
fn block3_a_governed_meta_tool_still_takes_the_clients_meta() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    for tool in ["gateway_invoke", "gateway_kill_server"] {
        let params = json!({
            "name": tool,
            "arguments": {"server": "weather"},
            "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
        });
        let (name, args) = extract_tools_call_params(Some(&params));
        let merged = merge_client_meta(args, Some(&params), meta.exposes_meta_tool(name));
        assert_eq!(
            merged,
            json!({
                "server": "weather",
                "_meta": {"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
            }),
            "{tool} is a gateway meta-tool, so its handler must still see the \
             client's `_meta`"
        );
    }
}

// =====================================================================
// parse_request - valid requests
// =====================================================================

#[test]
fn parse_request_valid_with_string_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/list"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("req-1".to_string())));
    assert_eq!(method, "tools/list");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_numeric_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "ping"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(42)));
    assert_eq!(method, "ping");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_params() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "my_tool", "arguments": {"q": "test"}}
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(1)));
    assert_eq!(method, "tools/call");
    assert!(params.is_some());
    let p = params.unwrap();
    assert_eq!(p["name"], "my_tool");
}

#[test]
fn parse_request_notification_without_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert!(id.is_none());
    assert_eq!(method, "notifications/initialized");
}

#[test]
fn parse_request_notification_with_id_accepted() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "notifications/cancelled"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(99)));
    assert_eq!(method, "notifications/cancelled");
}

// =====================================================================
// parse_request - error cases
// =====================================================================

#[test]
fn parse_request_missing_jsonrpc_field() {
    let req = json!({"id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert!(err.error.is_some());
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(
        err.error
            .as_ref()
            .unwrap()
            .message
            .contains("JSON-RPC version")
    );
}

#[test]
fn parse_request_wrong_jsonrpc_version() {
    let req = json!({"jsonrpc": "1.0", "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_missing_method() {
    let req = json!({"jsonrpc": "2.0", "id": 1});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("method"));
}

#[test]
fn parse_request_non_notification_without_id() {
    let req = json!({"jsonrpc": "2.0", "method": "tools/list"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("id"));
}

#[test]
fn parse_request_null_jsonrpc() {
    let req = json!({"jsonrpc": null, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_numeric_jsonrpc() {
    let req = json!({"jsonrpc": 2, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_method_is_not_string() {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": 123});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_empty_object() {
    let req = json!({});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_initialize_method() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("init-1".to_string())));
    assert_eq!(method, "initialize");
    assert!(params.is_some());
}

// =====================================================================
// MIK-7650: no sub-path alias under the direct route
// =====================================================================

/// `uri` answered by the full router, with a JSON-RPC `ping` as the body.
async fn answer(state: &Arc<AppState>, method: &str, uri: &str) -> (StatusCode, Vec<u8>) {
    let request = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        ))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

/// The direct route once had a wildcard sub-path alias whose handler extracts
/// one path parameter, so every request answered 500 before the handler ran.
/// A sub-path is no route: an empty 404, not the handler's JSON-RPC answer and
/// never 500. The control shows the empty-body check tells the two apart: the
/// direct route itself still reaches its handler, which answers an unknown
/// backend with a JSON-RPC 404.
#[tokio::test]
async fn a_sub_path_under_the_direct_route_is_not_a_route() {
    let (state, _store) = test_router_app_state().await;
    for (method, uri) in [
        ("POST", "/mcp/b/extra"),
        ("POST", "/mcp/b/x/y"),
        ("GET", "/mcp/b/extra"),
    ] {
        let (status, body) = answer(&state, method, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
        assert!(
            body.is_empty(),
            "{method} {uri} reached a handler: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let (status, body) = answer(&state, "POST", "/mcp/b").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the direct route");
    let json: Value = serde_json::from_slice(&body).expect("a JSON-RPC body");
    assert!(
        json.pointer("/error/code").is_some(),
        "the direct route reached its handler: {json}"
    );
}
