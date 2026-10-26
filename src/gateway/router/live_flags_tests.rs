// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `security.sanitize_input` applies on reload (ADR-023), over HTTP.
//!
//! The flag was copied into the router state at startup, so a reload that
//! changed it had no effect until a restart. Each row here changes it by
//! reload and observes the next call, on the direct route and on `/mcp`
//! `gateway_invoke`. Red until the flag is read from the published config.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{
    Answer, Fx, fixture_built, post_direct, post_meta_invoke, sanitizing,
};

const NUL: &str = "a\u{0}b";
const NUL_REFUSED: &str = "Protocol error: Input contains null bytes which are not allowed";

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(Ordering::SeqCst)
}

/// Apply `edit` to the published config, as a reload would.
fn reload(fx: &Fx, edit: impl FnOnce(&mut crate::config::Config)) {
    let mut config = (*fx.state.live_config.get()).clone();
    edit(&mut config);
    fx.state.live_config.set(config);
}

/// F1 (direct route): started with sanitizing off, a NUL passes; a reload
/// turns it on and the next call is refused with the sanitizer's refusal and
/// nothing runs; a reload turns it off again and the NUL passes again.
#[tokio::test]
async fn f1_direct_sanitize_input_follows_a_reload() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;

    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off at start: {body}");
    let ran = calls(&fx);

    reload(&fx, |c| c.security.sanitize_input = true);
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert_eq!(message(&body), NUL_REFUSED, "on after reload: {body}");
    assert_eq!(calls(&fx), ran, "on after reload: dispatched");

    reload(&fx, |c| c.security.sanitize_input = false);
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off after reload: {body}");
}

/// F1 (`/mcp` `gateway_invoke`): the same through the meta route.
#[tokio::test]
async fn f1_mcp_sanitize_input_follows_a_reload() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;

    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert!(body.get("error").is_none(), "off at start: {body}");
    let ran = calls(&fx);

    reload(&fx, |c| c.security.sanitize_input = true);
    let (_, body) = post_meta_invoke(
        &fx,
        "k-std",
        "alpha",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert_eq!(message(&body), NUL_REFUSED, "on after reload: {body}");
    assert_eq!(calls(&fx), ran, "on after reload: dispatched");
}

/// F7: a reload whose new config fails to load never reaches the published
/// config, so the running flag is unchanged; here the published value is the
/// only path, and an unchanged publish leaves the next call as it was.
#[tokio::test]
async fn f7_an_unchanged_publish_keeps_the_running_flag() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    reload(&fx, |_| {});
    let (_, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": NUL}),
        None,
        None,
    )
    .await;
    assert_eq!(message(&body), NUL_REFUSED, "{body}");
}
