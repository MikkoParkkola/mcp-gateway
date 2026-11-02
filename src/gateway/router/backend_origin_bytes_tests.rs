// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! BEO.1: a backend's own error keeps the bytes its client always got. Each
//! answer equals the status and body captured on the code before the
//! backend's variant existed, on the direct route (400, 404, 409, one
//! carrying data, a 500 control) and the meta route (an in-band error, one
//! carrying data).

use super::*;

fn peer(status: reqwest::StatusCode, error: Value) -> crate::Error {
    let body = json!({"jsonrpc": "2.0", "id": 1, "error": error}).to_string();
    crate::transport::peer_refusal_for_test(&body, &RequestId::Number(1), status)
        .expect("premise: a body answering this request is surfaced")
}

fn refused() -> Value {
    json!({"code": -32001, "message": "backend says no"})
}

fn peer_404() -> crate::Error {
    peer(reqwest::StatusCode::NOT_FOUND, refused())
}

fn peer_409() -> crate::Error {
    peer(reqwest::StatusCode::CONFLICT, refused())
}

fn peer_400_data() -> crate::Error {
    peer(
        reqwest::StatusCode::BAD_REQUEST,
        json!({"code": -32001, "message": "backend says no", "data": {"detail": "quota"}}),
    )
}

fn peer_500() -> crate::Error {
    peer(reqwest::StatusCode::INTERNAL_SERVER_ERROR, refused())
}

/// Each case's route and answer, and the bytes captured on the base.
fn cases() -> Vec<(&'static str, bool, Answer, &'static str)> {
    vec![
        (
            "direct 400",
            true,
            Answer::FailsWith(peer_400),
            GOLDEN_DIRECT_400,
        ),
        (
            "direct 404",
            true,
            Answer::FailsWith(peer_404),
            GOLDEN_DIRECT_404,
        ),
        (
            "direct 409",
            true,
            Answer::FailsWith(peer_409),
            GOLDEN_DIRECT_409,
        ),
        (
            "direct 400 data",
            true,
            Answer::FailsWith(peer_400_data),
            GOLDEN_DIRECT_400_DATA,
        ),
        (
            "direct 500",
            true,
            Answer::FailsWith(peer_500),
            GOLDEN_DIRECT_500,
        ),
        ("meta in-band", false, Answer::RpcError(-32001), GOLDEN_META),
        (
            "meta in-band data",
            false,
            Answer::RpcErrorData("quota"),
            GOLDEN_META_DATA,
        ),
    ]
}

const GOLDEN_DIRECT_400: &str = r#"500 {"error":{"code":-32001,"message":"JSON-RPC error -32001: backend says no"},"id":1,"jsonrpc":"2.0"}"#;
const GOLDEN_DIRECT_404: &str = r#"500 {"error":{"code":-32001,"message":"JSON-RPC error -32001: backend says no"},"id":1,"jsonrpc":"2.0"}"#;
const GOLDEN_DIRECT_409: &str = r#"500 {"error":{"code":-32001,"message":"JSON-RPC error -32001: backend says no"},"id":1,"jsonrpc":"2.0"}"#;
const GOLDEN_DIRECT_400_DATA: &str = r#"500 {"error":{"code":-32001,"message":"JSON-RPC error -32001: backend says no"},"id":1,"jsonrpc":"2.0"}"#;
const GOLDEN_DIRECT_500: &str = r#"500 {"error":{"code":-32001,"message":"JSON-RPC error -32001 carried on retryable status 500: backend says no"},"id":1,"jsonrpc":"2.0"}"#;
const GOLDEN_META: &str = r#"200 {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"{\n  \"_recovery\": {\n    \"error_code\": \"BACKEND_ERROR\",\n    \"message\": \"backend says no\",\n    \"retry\": true,\n    \"suggest\": \"Inspect the error message for details. The issue may be a transient server error — retrying once is safe.\"\n  },\n  \"_trace_id\": \"gw-TRACE\",\n  \"content\": [\n    {\n      \"text\": \"JSON-RPC error -32001: backend says no\",\n      \"type\": \"text\"\n    }\n  ],\n  \"isError\": true\n}","type":"text"}],"isError":true}}"#;
const GOLDEN_META_DATA: &str = r#"200 {"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"{\n  \"_recovery\": {\n    \"error_code\": \"BACKEND_ERROR\",\n    \"message\": \"backend says no\",\n    \"retry\": true,\n    \"suggest\": \"Inspect the error message for details. The issue may be a transient server error — retrying once is safe.\"\n  },\n  \"_trace_id\": \"gw-TRACE\",\n  \"content\": [\n    {\n      \"text\": \"JSON-RPC error -32001: backend says no\",\n      \"type\": \"text\"\n    }\n  ],\n  \"isError\": true\n}","type":"text"}],"isError":true}}"#;

/// `text` with every trace id (`gw-` and a UUID) read as `gw-TRACE`: the
/// one part of an answer that differs per request.
fn without_trace_ids(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("gw-") {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let id = tail.get(3..39).filter(|id| {
            id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') && id.matches('-').count() == 4
        });
        if id.is_some() {
            out.push_str("gw-TRACE");
            rest = &tail[39..];
        } else {
            out.push_str("gw-");
            rest = &tail[3..];
        }
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn a_backends_error_keeps_the_bytes_its_client_got() {
    let mut moved = Vec::new();
    for (name, direct, answer, golden) in cases() {
        let fx = fixture(answer, |_| {}).await;
        let (status, body) = if direct {
            post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await
        } else {
            invoke(&fx).await
        };
        let got = without_trace_ids(&format!("{} {body}", status.as_u16()));
        if got != golden {
            moved.push(format!("{name}:\n  got    {got}\n  golden {golden}"));
        }
    }
    assert!(
        moved.is_empty(),
        "{} answers moved:\n{}",
        moved.len(),
        moved.join("\n")
    );
}
