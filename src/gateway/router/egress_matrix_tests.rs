// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The egress matrix on HTTP (design `2026-10-08-one-egress-scan.md`, the
//! MIK-8139 family: MIK-8139, MIK-8146, MIK-8155, MIK-8161, MIK-8112): a
//! credential a backend plants in any part of any method's answer never
//! reaches a `POST /mcp` or `POST /mcp/{name}` client. One cell per
//! method x route x part; every failing cell is reported, not the first.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Fx, fixture_firewalled_on};
use crate::gateway::egress_fixture::{BACKEND_METHODS, NAME, Part, Planted, URI, secret};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// `POST /mcp`: `tools/call` through `gateway_invoke`, the rest native.
    Meta,
    /// `POST /mcp/alpha`.
    Direct,
}

const ROUTES: [Route; 2] = [Route::Meta, Route::Direct];

/// The request `route` sends for `method`, naming the backend's one
/// tool, prompt or resource.
fn request(route: Route, method: &str, part: Part) -> (&'static str, Value) {
    let mut params = match (route, method) {
        (Route::Meta, "tools/call") => json!({"name": "gateway_invoke", "arguments": {
            "server": "alpha", "tool": NAME, "arguments": {}
        }}),
        (Route::Direct, "tools/call") => json!({"name": NAME, "arguments": {}}),
        (Route::Meta, "prompts/get") => json!({"name": format!("alpha/{NAME}")}),
        (Route::Direct, "prompts/get") => json!({"name": NAME}),
        (_, "resources/read") => json!({"uri": URI}),
        _ => json!({}),
    };
    if part.is_notification() {
        params["_meta"] = json!({"progressToken": "p1"});
    }
    let uri = match route {
        Route::Meta => "/mcp",
        Route::Direct => "/mcp/alpha",
    };
    (uri, params)
}

/// POST one request accepting a streamed answer; the whole body as text, so
/// a notification frame is read as surely as the answer.
async fn post(fx: &Fx, uri: &str, method: &str, params: &Value) -> String {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

/// One cell: `text` planted at `part` of `method`'s answer, sent on `route`.
/// Returns what the client read and how often the backend answered.
async fn cell(route: Route, method: &'static str, part: Part, text: String) -> (String, usize) {
    let backend = Arc::new(Planted::with_text(method, part, text));
    let calls = Arc::clone(&backend.calls);
    let fx = fixture_firewalled_on(backend).await;
    let (uri, params) = request(route, method, part);
    let body = post(&fx, uri, method, &params).await;
    (body, calls.load(Ordering::SeqCst))
}

/// Whether the client was refused delivery, as the firewall refuses.
fn refused(body: &str) -> bool {
    body.contains("Response blocked by security firewall") || body.contains("\"code\":-32600")
}

/// The matrix: the credential never arrives, an interim question carrying
/// one is refused on every route rather than rewritten (MIK-8155), and every
/// cell reached its backend (a cell that never dispatched proves nothing).
#[tokio::test]
async fn egress_no_planted_credential_reaches_an_http_client() {
    let leak = secret();
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in Part::ALL.into_iter().filter(|p| p.applies_to(method)) {
            for route in ROUTES {
                let at = format!("{route:?} {method} {part:?}");
                let (body, calls) = cell(route, method, part, leak.clone()).await;
                if calls == 0 {
                    failures.push(format!("{at}: never reached the backend: {body}"));
                }
                if body.contains(&leak) {
                    failures.push(format!("{at}: credential delivered: {body}"));
                }
                if part == Part::InterimQuestion && !refused(&body) {
                    failures.push(format!("{at}: question rewritten, not refused: {body}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Controls: harmless text at the same places is delivered, so the matrix
/// above reads frames that do reach the client. Notifications are not relayed
/// on the direct route (`backend_handlers.rs`), so their controls are meta's.
#[tokio::test]
async fn egress_harmless_text_is_delivered_unchanged() {
    let mut failures = Vec::new();
    for method in BACKEND_METHODS {
        for part in [Part::ResultText, Part::Progress, Part::CustomNote] {
            for route in ROUTES {
                if part.is_notification() && (route == Route::Direct || method != "tools/call") {
                    continue;
                }
                let at = format!("{route:?} {method} {part:?}");
                let text = format!("harmless-{}", method.replace('/', "-"));
                let (body, _) = cell(route, method, part, text.clone()).await;
                if !body.contains(&text) {
                    failures.push(format!("{at}: not delivered: {body}"));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cells failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// A meta-route answer cached under an idempotency key and replayed to the
/// direct route is scanned there too: the cache proves no provenance.
#[tokio::test]
async fn egress_a_cross_route_replay_is_scanned() {
    let leak = secret();
    for part in [Part::ResultText, Part::ErrorMessage] {
        let backend = Arc::new(Planted::new("tools/call", part));
        let fx = fixture_firewalled_on(backend).await;
        let idem = json!({ IDEMPOTENCY_KEY_META: "egress-replay" });
        let (uri, mut params) = request(Route::Meta, "tools/call", part);
        params["_meta"] = idem.clone();
        let first = post(&fx, uri, "tools/call", &params).await;
        let (uri, mut params) = request(Route::Direct, "tools/call", part);
        params["_meta"] = idem;
        let replay = post(&fx, uri, "tools/call", &params).await;
        assert!(!first.contains(&leak), "{part:?} meta: {first}");
        assert!(!replay.contains(&leak), "{part:?} direct replay: {replay}");
    }
}

/// Completeness of the method axis: every method the `POST /mcp` dispatcher
/// serves is either a backend's answer (a matrix row) or the gateway's own.
/// A new arm in neither list fails here, so it cannot skip the matrix.
#[test]
fn egress_every_dispatched_method_is_a_matrix_row_or_gateway_own() {
    const GATEWAY_OWN: [&str; 12] = [
        "initialize",
        "server/discover",
        "ping",
        "subscriptions/listen",
        "resources/subscribe",
        "resources/unsubscribe",
        "elicitation/create",
        "tools/resolve",
        "tasks/get",
        "tasks/update",
        "tasks/cancel",
        "logging/setLevel",
    ];
    let source = include_str!("handlers.rs");
    let mut missing = Vec::new();
    for line in source.lines() {
        let arm = line.trim_start();
        if !arm.starts_with('"') || !arm.contains("=>") {
            continue;
        }
        let head = arm.split("=>").next().unwrap_or_default();
        for name in head.split('|').map(|m| m.trim().trim_matches('"')) {
            // JSON keys in audit macros (`"method" => ...`) are not methods;
            // the two slash-less methods are.
            if !name.contains('/') && !matches!(name, "initialize" | "ping") {
                continue;
            }
            if !BACKEND_METHODS.contains(&name) && !GATEWAY_OWN.contains(&name) {
                missing.push(name.to_owned());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "dispatched methods outside the matrix: {missing:?}"
    );
}
