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
    Answer, Fx, fixture_built, post_direct, post_meta_invoke, replace_backend_configured,
    sanitizing,
};
use crate::config::{BackendConfig, TransportConfig};

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

/// F4: with `trust_configured_backends` off (the fixture's state), a reload
/// that turns `ssrf_protection` on refuses the next call to a backend
/// declared on a loopback address, and nothing runs; turned off again, the
/// call runs.
#[tokio::test]
async fn f4_ssrf_protection_follows_a_reload() {
    let fx = Box::pin(fixture_built(Answer::Ok, |meta| meta)).await;
    let calls = replace_backend_configured(
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
    let call = || post_direct(&fx, "alpha", "k-std", "read", json!({}), None, None);
    reload(&fx, |c| c.security.ssrf_protection = false);
    let (_, body) = call().await;
    assert!(body.get("error").is_none(), "off: {body}");
    let ran = calls.load(Ordering::SeqCst);
    assert!(ran > 0, "off: the call reached the backend");

    reload(&fx, |c| c.security.ssrf_protection = true);
    let (_, body) = call().await;
    // The direct route answers a refused target as absent (it never says
    // why), so the reason is read from the same judgement, on the generation
    // the reload published.
    assert!(
        body.pointer("/result/isError") == Some(&json!(true))
            && body
                .to_string()
                .contains("does not list a tool named `read`"),
        "on after reload: not withheld: {body}"
    );
    let refusal = super::authorization::authorize_tool_target(
        &fx.state,
        &fx.state.live_config.generation(),
        None,
        None,
        None,
        crate::gateway::authz::ToolTarget {
            server: "alpha",
            tool: "read",
            arguments: &json!({}),
        },
    )
    .expect_err("on after reload: the target is admitted");
    assert!(
        refusal
            .message
            .contains(crate::security::ssrf::SSRF_BLOCKED),
        "on after reload: refused, but not by SSRF: {}",
        refusal.message
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        ran,
        "on after reload: dispatched"
    );

    reload(&fx, |c| c.security.ssrf_protection = false);
    let (_, body) = call().await;
    assert!(body.get("error").is_none(), "off after reload: {body}");
}

/// F3 (HTTP resume): a task stored while `sanitize_input` was off, resumed
/// after a reload turned it on, is judged by the flag current at resume. Its
/// dirty key is refused by key validation and nothing is sent. Only a live
/// resume can pass: admission, with the flag off, never validated the key.
#[tokio::test]
async fn f3_a_resume_takes_the_flag_current_at_resume() {
    let fx = Box::pin(sanitizing(false, fixture_built(Answer::Ok, |meta| meta))).await;
    reload(&fx, |c| c.security.sanitize_input = true);
    let host = crate::gateway::task_service::host::LiveHost::Http(std::sync::Arc::clone(&fx.state));
    let call = crate::gateway::task_service::TaskCall {
        tool: "gateway_invoke".to_owned(),
        arguments: json!({"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}),
    };
    let caller = crate::gateway::meta_mcp::anonymous_caller();
    let refused = match host.readmit(&call, &caller, None).await {
        Ok((arguments, _)) => panic!("f3: re-admitted as {arguments}"),
        Err(refused) => serde_json::to_value(&*refused).expect("a response serializes"),
    };
    assert!(
        refused.to_string().contains("control characters"),
        "f3: not the key validation's refusal: {refused}"
    );
    assert_eq!(calls(&fx), 0, "f3: dispatched");
}
