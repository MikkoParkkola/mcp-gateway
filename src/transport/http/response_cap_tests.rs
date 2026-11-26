// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An HTTP backend's answer is counted while it is read, and one
//! over the cap is refused as `Error::ResponseTooLarge`, never held whole.

use super::*;

const CAP: usize = 64 * 1024;

/// A body template that is exactly `len` bytes once the shared server swaps
/// `{id}` for a one-digit request id (each row sends fewer than ten requests).
fn sized_template(len: usize) -> &'static str {
    let head = r#"{"jsonrpc":"2.0","id":{id},"result":{"content":[{"type":"text","text":""#;
    let tail = r#""}]}}"#;
    let pad = len + "{id}".len() - 1 - head.len() - tail.len();
    Box::leak(format!("{head}{}{tail}", "a".repeat(pad)).into_boxed_str())
}

async fn sized_server(
    status: axum::http::StatusCode,
    len: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let (addr, _hits, server) = spawn_fixed_response_server(status, sized_template(len)).await;
    (addr, server)
}

fn capped_transport(addr: std::net::SocketAddr) -> Arc<HttpTransport> {
    let transport = make_transport(&format!("http://{addr}/mcp"));
    *transport.message_url.write() = Some(format!("http://{addr}/mcp"));
    transport.set_max_response_bytes(CAP);
    transport
}

/// CAP.1/CAP.2: a 2xx JSON answer one byte over the cap is refused, typed.
#[tokio::test]
async fn a_json_answer_over_the_cap_is_refused_as_too_large() {
    let (addr, server) = sized_server(axum::http::StatusCode::OK, CAP + 1).await;
    let err = capped_transport(addr)
        .request("tools/call", None)
        .await
        .expect_err("an answer over the cap must be refused");
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "expected ResponseTooLarge {{ limit: {CAP} }}, got: {err:?}"
    );
    server.abort();
}

/// The boundary: an answer of exactly the cap is read whole.
#[tokio::test]
async fn a_json_answer_of_exactly_the_cap_is_read() {
    let (addr, server) = sized_server(axum::http::StatusCode::OK, CAP).await;
    let answer = capped_transport(addr)
        .request("tools/call", None)
        .await
        .expect("an answer of exactly the cap must be read");
    assert!(answer.result.is_some(), "{answer:?}");
    server.abort();
}

/// CAP.1: a non-2xx body is counted the same way.
#[tokio::test]
async fn an_error_body_over_the_cap_is_refused_as_too_large() {
    let (addr, server) = sized_server(axum::http::StatusCode::INTERNAL_SERVER_ERROR, CAP + 1).await;
    let err = capped_transport(addr)
        .request("tools/call", None)
        .await
        .expect_err("an error body over the cap must be refused");
    assert!(
        matches!(err, Error::ResponseTooLarge { limit: CAP }),
        "expected ResponseTooLarge {{ limit: {CAP} }}, got: {err:?}"
    );
    server.abort();
}

/// Not sticky: after one over-cap answer, the next answer under the cap on the
/// same transport is read (a per-transport budget would refuse it forever).
#[tokio::test]
async fn one_over_cap_answer_does_not_refuse_the_next_call() {
    let (big, big_server) = sized_server(axum::http::StatusCode::OK, CAP + 1).await;
    let transport = capped_transport(big);
    assert!(transport.request("tools/call", None).await.is_err());
    big_server.abort();
    let (small, small_server) = sized_server(axum::http::StatusCode::OK, 200).await;
    *transport.message_url.write() = Some(format!("http://{small}/mcp"));
    let answer = transport
        .request("tools/call", None)
        .await
        .expect("the next small answer must be read");
    assert!(answer.result.is_some(), "{answer:?}");
    small_server.abort();
}

/// Without a configured cap, the stdio default bounds an HTTP answer too.
#[test]
fn the_default_cap_is_the_stdio_frame_default() {
    let transport = make_transport("http://127.0.0.1:1/mcp");
    assert_eq!(
        transport.max_response_bytes(),
        crate::transport::DEFAULT_MAX_FRAME_BYTES
    );
}
