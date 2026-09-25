// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// F17-T2: a `ws_url` backend end to end through the gateway binary.
//
// Included from `command_backend.rs` (and so into `mik_7272_sub2b_acs.rs`)
// for the same harness reason as its parent: `stdio_session` and `invoke`.

/// A WebSocket MCP peer: answers `initialize`, lists one tool, and answers
/// every `tools/call` with the arguments it received. Returns its `ws://` URL.
async fn spawn_ws_peer() -> String {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws peer");
    let url = format!("ws://{}/mcp", listener.local_addr().expect("local addr"));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut write, mut read) = ws.split();
                while let Some(Ok(Message::Text(text))) = read.next().await {
                    let frame: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let Some(id) = frame.get("id").cloned() else {
                        continue;
                    };
                    let result = match frame["method"].as_str().unwrap_or_default() {
                        "initialize" => json!({
                            "protocolVersion": frame["params"]["protocolVersion"],
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "ws-fixture", "version": "0"},
                        }),
                        "tools/list" => json!({"tools": [{
                            "name": "ws_echo",
                            "description": "echoes its arguments",
                            "inputSchema": {"type": "object"},
                        }]}),
                        "tools/call" => json!({"content": [{
                            "type": "text",
                            "text": format!("ws-echo:{}", frame["params"]["arguments"]),
                        }]}),
                        "ping" => json!({}),
                        // A legacy peer: anything else, `server/discover`
                        // included, is not a method it has.
                        _ => {
                            let error = json!({"code": -32601, "message": "method not found"});
                            let reply = json!({"jsonrpc": "2.0", "id": id, "error": error});
                            if write.send(Message::Text(reply.to_string().into())).await.is_err() {
                                return;
                            }
                            continue;
                        }
                    };
                    // F16: a call that carries a progress token gets one
                    // progress frame, carrying that token, before its result.
                    let token = frame["params"]["_meta"]["progressToken"].clone();
                    let mut replies = Vec::new();
                    if frame["method"] == "tools/call" && !token.is_null() {
                        replies.push(json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/progress",
                            "params": {"progressToken": token, "progress": 1, "total": 2},
                        }));
                    }
                    replies.push(json!({"jsonrpc": "2.0", "id": id, "result": result}));
                    for reply in replies {
                        if write.send(Message::Text(reply.to_string().into())).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    url
}

/// T2: `gateway_invoke` on a `ws_url` backend round-trips the peer's answer.
#[tokio::test]
async fn f17_a_ws_url_backend_answers_a_gateway_invoke() {
    let url = spawn_ws_peer().await;
    let home = tempfile::tempdir().expect("temp home");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.path().join("gateway.yaml"),
        format!("backends:\n  {BACKEND}:\n    ws_url: \"{url}\"\n"),
    )
    .expect("write gateway.yaml");
    let mut session = stdio_session(home.path()).await;
    session
        .send(&invoke(2, "ws_echo", &json!({"marker": "f17-t2"}), &json!({})))
        .await;
    let (seen, result) = session.read_until(|frame| has_id(frame, 2)).await;
    let result = result.unwrap_or_else(|| panic!("no answer to the invoke; frames: {seen:?}"));
    let text = result.to_string();
    assert!(
        text.contains("ws-echo:") && text.contains("f17-t2"),
        "the peer's answer must come back through the gateway: {text}"
    );
    session.shutdown().await;
}

/// F16: a `ws_url` backend's `notifications/progress` for a `gateway_invoke`
/// reaches the caller before the result, carrying the caller's own token (the
/// backend saw only the gateway-minted one), exactly as on stdio.
#[tokio::test]
async fn f16_a_ws_url_backends_progress_reaches_the_caller_with_its_own_token() {
    let url = spawn_ws_peer().await;
    let home = tempfile::tempdir().expect("temp home");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        home.path().join("gateway.yaml"),
        format!("backends:\n  {BACKEND}:\n    ws_url: \"{url}\"\n"),
    )
    .expect("write gateway.yaml");
    let mut session = stdio_session(home.path()).await;
    let client_token = "client-token-ws";
    session
        .send(&invoke(
            2,
            "ws_echo",
            &json!({}),
            &json!({"progressToken": client_token}),
        ))
        .await;
    let (frames, result) = session.read_until(|frame| has_id(frame, 2)).await;
    assert!(result.is_some(), "the call must complete; frames: {frames:?}");
    let progress = frames
        .iter()
        .find(|frame| is_method(frame, "notifications/progress"))
        .unwrap_or_else(|| panic!("no progress reached the caller before the result: {frames:?}"));
    assert_eq!(
        progress_token_of(progress),
        Some(&json!(client_token)),
        "the caller gets its own token back, not the gateway-minted one"
    );
    session.shutdown().await;
}
