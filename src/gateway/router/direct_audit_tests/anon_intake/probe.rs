// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 fail-fast probes (design d2 §4.0): one keyed no-principal call to
//! targets that differ only in what lies behind the name. Every target's
//! answer is collected before the one assert, so a red run reports all of
//! them.

use super::{
    Caller, Fixture, KEY, NO_PRINCIPAL, Ordering, StatusCode, Value, fixture, idempotent, json,
    keyed_invoke, poisoned_listing,
};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use axum::body::to_bytes;
use axum::http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

/// One answer as sent: status, headers, raw body.
type Raw = (StatusCode, HeaderMap, axum::body::Bytes);

/// The probe call: a keyed `tools/call` of `t`, id 7.
fn probe_call() -> String {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
        "name": "t", "arguments": {"customer_id": "c"},
        "_meta": {(crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY}}})
    .to_string()
}

/// POST `body` to `uri` with no credential and no identity, carrying the
/// fixture's session header when `caller` is [`Caller::Session`].
async fn post_raw(fx: &Fixture, uri: &str, body: &str, caller: &Caller) -> Raw {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if matches!(caller, Caller::Session) {
        builder = builder.header("mcp-session-id", "sess-d2");
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("a static request builds");
    let response = fx
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("an in-memory body reads");
    (status, headers, bytes)
}

fn show(case: &str, (status, headers, bytes): &Raw) -> String {
    format!(
        "{case}: {status} headers={headers:?} body={}",
        String::from_utf8_lossy(bytes)
    )
}

/// The parts of an answer a byte-identity row compares, minus `drop_header`.
fn compared(raw: &Raw, drop_header: Option<&str>) -> (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>) {
    let mut headers: Vec<(String, Vec<u8>)> = raw
        .1
        .iter()
        .filter(|(name, _)| Some(name.as_str()) != drop_header)
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    (raw.0, headers, raw.2.to_vec())
}

/// Every failed check over `answers` (all must equal the first, be HTTP 400
/// and carry the intake refusal with id `id`), then the backend count.
fn failures(answers: &[(&str, Raw)], drop_header: Option<&str>, id: i64) -> Vec<String> {
    let mut wrong = Vec::new();
    let first = compared(&answers[0].1, drop_header);
    for (case, raw) in answers {
        if compared(raw, drop_header) != first {
            wrong.push(format!("{case}: differs from {}", answers[0].0));
        }
        if raw.0 != StatusCode::BAD_REQUEST {
            wrong.push(format!("{case}: status {}", raw.0));
        }
        let body: Value = serde_json::from_slice(&raw.2).unwrap_or(Value::Null);
        if body.pointer("/error/message").and_then(Value::as_str) != Some(NO_PRINCIPAL)
            || body.get("id") != Some(&json!(id))
        {
            wrong.push(format!("{case}: not the intake refusal with id {id}"));
        }
    }
    wrong
}

/// P0 (ORDER.1/.2 kill-or-proceed): the direct route, three targets.
/// (a) `alpha`, a counting backend; (b) `dead`, an HTTP backend whose socket
/// is bound but never listening, so connecting is refused (as
/// `tests/mik_7272_sub4_adr012_acs.rs` `pre_dispatch_failure_releases_its_key`
/// builds it); (c) `nope`, no backend. Kill: all three byte-identical
/// (status, every header, body), -32003 / 400 / id 7, and (a) counted zero
/// backend requests. Anything else proceeds. The fixture is the auth-off
/// gateway, where an anonymous caller has no principal.
#[tokio::test]
async fn p0_three_way_probe() {
    let fx = fixture(idempotent()).await;
    // Bound for the whole test and never listening (MIK-7984).
    let closed = tokio::net::TcpSocket::new_v4().expect("socket");
    closed
        .bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind without listening");
    let address = closed.local_addr().expect("local addr");
    let dead = BackendConfig {
        transport: TransportConfig::Http {
            http_url: format!("http://{address}/mcp"),
            streamable_http: Some(true),
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    assert!(
        fx.state.backends.register(Arc::new(Backend::new(
            "dead",
            dead,
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ))),
        "p0 premise: `dead` registers"
    );
    assert!(
        fx.state.backends.get("nope").is_none(),
        "p0 premise: `nope` is not registered"
    );
    let body = probe_call();
    let answers = [
        (
            "a counting",
            post_raw(&fx, "/mcp/alpha", &body, &Caller::Anonymous).await,
        ),
        (
            "b unreachable",
            post_raw(&fx, "/mcp/dead", &body, &Caller::Anonymous).await,
        ),
        (
            "c missing",
            post_raw(&fx, "/mcp/nope", &body, &Caller::Anonymous).await,
        ),
    ];
    let (lists, calls) = (
        fx.lists.load(Ordering::SeqCst),
        fx.calls.load(Ordering::SeqCst),
    );
    let mut wrong = failures(&answers, None, 7);
    if lists + calls != 0 {
        wrong.push(format!("a counting: tools/list {lists}, tools/call {calls}"));
    }
    let shown: Vec<String> = answers.iter().map(|(case, raw)| show(case, raw)).collect();
    assert!(
        wrong.is_empty(),
        "p0 proceeds:\n{}\nanswers:\n{}",
        wrong.join("\n"),
        shown.join("\n")
    );
}

/// P0 /mcp twin: a keyed no-principal `gateway_invoke` of a policy-withheld
/// target (`alpha/blocked`, the C1b descriptor) against an existing one
/// (`alpha/t`). Identical (status, headers except `Mcp-Session-Id`, body),
/// -32003 / 400 / id 5 and no backend request: ORDER.3 and C1b hold already.
/// The /mcp intake ships either way; this classifies rows only.
#[tokio::test]
async fn p0_mcp_probe() {
    let fx = fixture(idempotent()).await;
    let alpha = fx.state.backends.get("alpha").expect("alpha");
    alpha.remember_listed_tools(None, false, &poisoned_listing());
    assert!(alpha.is_blocked_tool("blocked"), "p0 mcp premise: not blocked");
    assert!(!alpha.is_blocked_tool("t"), "p0 mcp premise: `t` is blocked");
    let answers = [
        (
            "existing",
            post_raw(&fx, "/mcp", &keyed_invoke("alpha", "t"), &Caller::Session).await,
        ),
        (
            "withheld",
            post_raw(&fx, "/mcp", &keyed_invoke("alpha", "blocked"), &Caller::Session).await,
        ),
    ];
    let (lists, calls) = (
        fx.lists.load(Ordering::SeqCst),
        fx.calls.load(Ordering::SeqCst),
    );
    let mut wrong = failures(&answers, Some("mcp-session-id"), 5);
    if lists + calls != 0 {
        wrong.push(format!("backend: tools/list {lists}, tools/call {calls}"));
    }
    let shown: Vec<String> = answers.iter().map(|(case, raw)| show(case, raw)).collect();
    assert!(
        wrong.is_empty(),
        "p0 mcp differs:\n{}\nanswers:\n{}",
        wrong.join("\n"),
        shown.join("\n")
    );
}
