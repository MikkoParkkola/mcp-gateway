// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A request keeps the generation it arrived with (ADR-023).
//!
//! Each row publishes a reload from inside the request, at a test seam past
//! the point where the request took its generation, and flips
//! `security.sanitize_input` there. The request must still be judged by the
//! value it started with, in both directions. A reader that took the current
//! generation instead would see the flipped value and fail its row.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, auth_off, fixture_built, post_direct, post_meta_invoke, sanitizing,
};
use crate::gateway::meta_mcp::visible::seams;

const NUL: &str = "a\u{0}b";
const NUL_REFUSED: &str = "Protocol error: Input contains null bytes which are not allowed";

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// A hook that publishes `sanitize_input = on`, as a reload would.
fn reload_to(fx: &Fx, on: bool) -> impl FnOnce() + 'static {
    let live = Arc::clone(&fx.state.live_config);
    move || live.edit(|c| c.security.sanitize_input = on)
}

/// The call reached the backend and its tool answered without an error, so
/// "not refused" cannot be a tool failure carried inside the result.
fn assert_ran(fx: &Fx, body: &Value, what: &str) {
    assert!(body.get("error").is_none(), "{what}: {body}");
    assert_ne!(
        body.pointer("/result/isError"),
        Some(&json!(true)),
        "{what}: {body}"
    );
    assert!(
        fx.calls.load(Ordering::SeqCst) > 0,
        "{what}: nothing reached the backend"
    );
}

/// The reload ran: the published value is the flipped one.
fn assert_reloaded(fx: &Fx, on: bool) {
    assert_eq!(
        fx.state.live_config.get().security.sanitize_input,
        on,
        "the seam never ran, so this row tested nothing"
    );
}

async fn meta_call(fx: &Fx) -> Value {
    post_meta_invoke(
        fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await
    .1
}

async fn direct_call(fx: &Fx) -> Value {
    post_direct(
        fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await
    .1
}

/// G1 (`/mcp`): on at arrival, off by a reload after intake judged; the
/// request is still sanitised and nothing runs.
#[tokio::test]
async fn g1_mcp_held_on_then_off_is_still_refused() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    seams::after_intake(reload_to(&fx, false));
    let body = meta_call(&fx).await;
    assert_reloaded(&fx, false);
    assert_eq!(message(&body), NUL_REFUSED, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "dispatched");
}

/// G2 (`/mcp`): off at arrival, on by a reload after intake judged; the
/// request is not sanitised, which only a kept generation explains.
#[tokio::test]
async fn g2_mcp_held_off_then_on_is_still_unsanitised() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    seams::after_intake(reload_to(&fx, true));
    let body = meta_call(&fx).await;
    assert_reloaded(&fx, true);
    assert_ran(&fx, &body, "g2");
}

/// F1d (held, direct route): on at arrival, off by a reload once the caller
/// is resolved and before the body is read; still refused.
#[tokio::test]
async fn f1d_direct_held_on_then_off_is_still_refused() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    seams::after_caller(reload_to(&fx, false));
    let body = direct_call(&fx).await;
    assert_reloaded(&fx, false);
    assert_eq!(message(&body), NUL_REFUSED, "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "dispatched");
}

/// F1d (held, direct route): off at arrival, on by the same reload; still
/// unsanitised.
#[tokio::test]
async fn f1d_direct_held_off_then_on_is_still_unsanitised() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    seams::after_caller(reload_to(&fx, true));
    let body = direct_call(&fx).await;
    assert_reloaded(&fx, true);
    assert_ran(&fx, &body, "f1d off then on");
}

/// Lead ruling: with authentication off, nothing authenticates the request,
/// and it still keeps its generation (the pin is outside auth). Both
/// directions on `/mcp`.
#[tokio::test]
async fn auth_off_mcp_held_request_keeps_its_generation() {
    let fx = Box::pin(sanitizing(
        true,
        auth_off(fixture_built(Answer::Ok, |meta| meta)),
    ))
    .await;
    assert!(
        !fx.state.live_config.generation().auth().enabled,
        "fixture: auth is on"
    );
    seams::after_intake(reload_to(&fx, false));
    let body = meta_call(&fx).await;
    assert_reloaded(&fx, false);
    assert_eq!(message(&body), NUL_REFUSED, "on then off: {body}");

    seams::after_intake(reload_to(&fx, true));
    let body = meta_call(&fx).await;
    assert_reloaded(&fx, true);
    assert_ran(&fx, &body, "off then on");
}

/// F4 (held, direct route): `ssrf_protection` on at arrival for a backend
/// declared on loopback, off by a reload once the caller is resolved; the call
/// is still withheld and nothing runs. Authorization is judged after the seam,
/// so a judge that took the current generation would let it through.
#[tokio::test]
async fn f4_direct_held_ssrf_on_then_off_is_still_refused() {
    use crate::config::{BackendConfig, TransportConfig};
    let fx = Box::pin(fixture_built(Answer::Ok, |meta| meta)).await;
    let calls = super::direct_guards_fixture::replace_backend_configured(
        &fx,
        "alpha",
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "http://127.0.0.1:9/mcp".to_string(),
                streamable_http: Some(false),
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );
    fx.state
        .live_config
        .edit(|c| c.security.ssrf_protection = true);
    let live = Arc::clone(&fx.state.live_config);
    seams::after_caller(move || live.edit(|c| c.security.ssrf_protection = false));
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    assert!(
        !fx.state.live_config.get().security.ssrf_protection,
        "the seam never ran, so this row tested nothing"
    );
    // The direct route answers a refused target as absent, by design.
    assert!(
        body.pointer("/result/isError") == Some(&json!(true))
            && body
                .to_string()
                .contains("does not list a tool named `read`"),
        "admitted: {body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "dispatched");

    // The next call arrives with protection off, and runs.
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None).await;
    assert!(body.get("error").is_none(), "after: {body}");
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "after: nothing reached the backend"
    );
}
