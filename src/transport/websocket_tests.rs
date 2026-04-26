use super::*;
use serde_json::json;
use std::sync::atomic::Ordering;
use tokio::sync::{mpsc::channel, oneshot};
use tokio_tungstenite::tungstenite::Message;

// =========================================================================
// McpFrame::from_text — parsing
// =========================================================================

#[test]
fn parses_request_frame() {
    let text = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let frame = McpFrame::from_text(text).unwrap();
    match frame {
        McpFrame::Request(req) => {
            assert_eq!(req.method, "tools/list");
            assert_eq!(req.id, RequestId::Number(1));
        }
        other => panic!("Expected Request, got {other:?}"),
    }
}

#[test]
fn parses_response_success() {
    let text = r#"{"jsonrpc":"2.0","id":42,"result":{"tools":[]}}"#;
    let frame = McpFrame::from_text(text).unwrap();
    match frame {
        McpFrame::Response(res) => {
            assert!(res.result.is_some());
            assert!(res.error.is_none());
        }
        other => panic!("Expected Response, got {other:?}"),
    }
}

#[test]
fn parses_response_error() {
    let text = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"Method not found"}}"#;
    let frame = McpFrame::from_text(text).unwrap();
    match frame {
        McpFrame::Response(res) => {
            let err = res.error.unwrap();
            assert_eq!(err.code, -32601);
        }
        other => panic!("Expected Response, got {other:?}"),
    }
}

#[test]
fn parses_notification_with_params() {
    let text = r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}"#;
    let frame = McpFrame::from_text(text).unwrap();
    match frame {
        McpFrame::Notification { method, params } => {
            assert_eq!(method, "notifications/progress");
            assert_eq!(params.unwrap()["progress"], 50);
        }
        other => panic!("Expected Notification, got {other:?}"),
    }
}

#[test]
fn parses_notification_without_params() {
    let text = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let frame = McpFrame::from_text(text).unwrap();
    match frame {
        McpFrame::Notification { method, params } => {
            assert_eq!(method, "notifications/initialized");
            assert!(params.is_none());
        }
        other => panic!("Expected Notification, got {other:?}"),
    }
}

#[test]
fn parses_application_ping() {
    let frame = McpFrame::from_text(r#"{"type":"ping"}"#).unwrap();
    assert!(matches!(frame, McpFrame::Ping));
}

#[test]
fn parses_application_pong() {
    let frame = McpFrame::from_text(r#"{"type":"pong"}"#).unwrap();
    assert!(matches!(frame, McpFrame::Pong));
}

#[test]
fn rejects_invalid_json() {
    assert!(McpFrame::from_text("not json { [").is_err());
}

#[test]
fn rejects_wrong_jsonrpc_version() {
    let text = r#"{"jsonrpc":"1.0","id":1,"method":"foo"}"#;
    let err = McpFrame::from_text(text).unwrap_err();
    assert!(matches!(err, Error::Protocol(_)));
}

#[test]
fn rejects_unclassifiable_frame() {
    // Valid JSON-RPC 2.0 envelope but no method, result, or error.
    let text = r#"{"jsonrpc":"2.0","mystery":"data"}"#;
    let err = McpFrame::from_text(text).unwrap_err();
    assert!(matches!(err, Error::Protocol(_)));
}

// =========================================================================
// McpFrame::to_ws_message — serialisation
// =========================================================================

#[test]
fn request_serialises_to_text_message() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(3),
        method: "tools/list".to_string(),
        params: None,
    };
    let msg = McpFrame::Request(req).to_ws_message().unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text message");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 3);
    assert_eq!(v["method"], "tools/list");
}

#[test]
fn notification_serialises_without_id() {
    let msg = McpFrame::Notification {
        method: "notifications/initialized".to_string(),
        params: None,
    }
    .to_ws_message()
    .unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text message");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["method"], "notifications/initialized");
    assert!(v.get("id").is_none());
    assert!(v.get("params").is_none());
}

#[test]
fn ping_serialises_to_type_ping() {
    let msg = McpFrame::Ping.to_ws_message().unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text message");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "ping");
}

#[test]
fn pong_serialises_to_type_pong() {
    let msg = McpFrame::Pong.to_ws_message().unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text message");
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "pong");
}

// =========================================================================
// McpFrame roundtrips
// =========================================================================

#[test]
fn request_roundtrip() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(10),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "search"})),
    };
    let frame = McpFrame::Request(req.clone());
    let Message::Text(text) = frame.to_ws_message().unwrap() else {
        panic!("Expected text");
    };
    let parsed = McpFrame::from_text(&text).unwrap();
    match parsed {
        McpFrame::Request(r) => {
            assert_eq!(r.method, req.method);
            assert_eq!(r.id, req.id);
        }
        other => panic!("Expected Request, got {other:?}"),
    }
}

#[test]
fn notification_roundtrip() {
    let frame = McpFrame::Notification {
        method: "test/event".to_string(),
        params: Some(json!({"k": "v"})),
    };
    let Message::Text(text) = frame.to_ws_message().unwrap() else {
        panic!("Expected text");
    };
    let parsed = McpFrame::from_text(&text).unwrap();
    match parsed {
        McpFrame::Notification { method, params } => {
            assert_eq!(method, "test/event");
            assert_eq!(params.unwrap()["k"], "v");
        }
        other => panic!("Expected Notification, got {other:?}"),
    }
}

#[test]
fn ping_roundtrip() {
    let msg = McpFrame::Ping.to_ws_message().unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text");
    };
    let parsed = McpFrame::from_text(&text).unwrap();
    assert!(matches!(parsed, McpFrame::Ping));
}

#[test]
fn pong_roundtrip() {
    let msg = McpFrame::Pong.to_ws_message().unwrap();
    let Message::Text(text) = msg else {
        panic!("Expected text");
    };
    let parsed = McpFrame::from_text(&text).unwrap();
    assert!(matches!(parsed, McpFrame::Pong));
}

// =========================================================================
// WebSocketSession
// =========================================================================

#[test]
fn session_ids_are_unique() {
    let s1 = WebSocketSession::new();
    let s2 = WebSocketSession::new();
    assert_ne!(s1.session_id, s2.session_id);
}

#[test]
fn session_id_is_valid_uuid() {
    let s = WebSocketSession::new();
    assert!(
        Uuid::parse_str(s.id()).is_ok(),
        "session_id must be a valid UUID"
    );
}

#[test]
fn session_default_counters_are_zero() {
    let s = WebSocketSession::default();
    assert_eq!(s.messages_received, 0);
    assert_eq!(s.messages_sent, 0);
}

// =========================================================================
// WebSocketTransport construction
// =========================================================================

#[test]
fn new_transport_is_not_connected() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    assert!(!t.is_connected());
}

#[test]
fn new_transport_stores_url() {
    let t = WebSocketTransport::new("ws://example.com/mcp");
    assert_eq!(t.url, "ws://example.com/mcp");
}

#[test]
fn request_id_increments_sequentially() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    assert_eq!(t.next_id(), RequestId::Number(1));
    assert_eq!(t.next_id(), RequestId::Number(2));
    assert_eq!(t.next_id(), RequestId::Number(3));
}

// =========================================================================
// dispatch_inbound
// =========================================================================

#[tokio::test]
async fn dispatch_routes_response_to_pending_sender() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    let (tx, mut rx) = oneshot::channel::<JsonRpcResponse>();
    t.inner.pending.insert("1".to_string(), tx);

    let text = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
    WebSocketTransport::dispatch_inbound(&t.inner, text).unwrap();

    let response = rx.try_recv().unwrap();
    assert!(response.result.is_some());
}

#[tokio::test]
async fn dispatch_handles_notification_without_panic() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    let text = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
    // Must not error even with no pending entry.
    WebSocketTransport::dispatch_inbound(&t.inner, text).unwrap();
}

#[tokio::test]
async fn dispatch_returns_error_on_bad_json() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    let result = WebSocketTransport::dispatch_inbound(&t.inner, "!!not-json");
    assert!(result.is_err());
}

#[tokio::test]
async fn dispatch_silently_ignores_unknown_response_id() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    // No pending entry — should not panic or error.
    let text = r#"{"jsonrpc":"2.0","id":999,"result":{}}"#;
    WebSocketTransport::dispatch_inbound(&t.inner, text).unwrap();
}

// =========================================================================
// close / connected flag
// =========================================================================

#[tokio::test]
async fn close_marks_transport_disconnected() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    t.inner.connected.store(true, Ordering::Relaxed);
    t.close().await.unwrap();
    assert!(!t.is_connected());
}

#[tokio::test]
async fn close_is_idempotent() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    t.close().await.unwrap();
    t.close().await.unwrap(); // Must not panic on second call.
}

#[tokio::test]
async fn connected_flag_toggles_correctly() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    assert!(!t.is_connected());
    t.inner.connected.store(true, Ordering::Relaxed);
    assert!(t.is_connected());
    t.inner.connected.store(false, Ordering::Relaxed);
    assert!(!t.is_connected());
}

// =========================================================================
// send_message — backpressure / not-connected guard
// =========================================================================

#[tokio::test]
async fn send_message_errors_when_not_connected() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    // outbound_tx slot is None — simulates pre-connect state.
    let result = t.send_message(Message::Text("hello".into())).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::Transport(_)));
}

#[tokio::test]
async fn send_message_succeeds_with_live_channel() {
    let t = WebSocketTransport::new("ws://localhost:9999");
    let (tx, mut rx) = channel::<Message>(8);
    *t.inner.outbound_tx.lock().await = Some(tx);

    t.send_message(Message::Text("hello".into())).await.unwrap();

    let msg = rx.try_recv().unwrap();
    assert_eq!(msg, Message::Text("hello".into()));
}
