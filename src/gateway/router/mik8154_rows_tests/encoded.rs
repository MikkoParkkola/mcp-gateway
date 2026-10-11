// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 S9 (implementation seat F1): tool arguments sent as a JSON string
//! (a client style) are decoded after the sanitize step, so the step reaches
//! into them: an escaped NUL is refused and an escaped control character
//! stripped before the decode can produce it, on every route.

use super::*;

/// `arguments` as the JSON string a client may send in place of the object.
fn encoded(arguments: &Value) -> Value {
    Value::String(arguments.to_string())
}

/// S9a: on the direct route, a NUL escaped inside string-encoded arguments is
/// refused with the sanitizer's refusal, and the backend does not run. RED
/// before the fix: the decode after the step produced the NUL and sent it.
#[tokio::test]
async fn s9a_direct_refuses_a_nul_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": NUL}));
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "s9a: {body}");
    assert_eq!(calls(&fx), 0, "s9a: dispatched");
}

/// S9b: the same through `/mcp` `gateway_invoke`, whose inner `arguments` is
/// the encoded string.
#[tokio::test]
async fn s9b_mcp_refuses_a_nul_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": NUL}));
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "s9b: {body}");
    assert_eq!(calls(&fx), 0, "s9b: dispatched");
}

/// S9c: a control character escaped inside encoded arguments is stripped: the
/// backend receives the clean value.
#[tokio::test]
async fn s9c_direct_strips_a_control_character_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": "a\u{7}b"}));
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert!(body.get("error").is_none(), "s9c: {body}");
    let seen = fx.seen.lock().expect("seen lock").last().cloned();
    assert_eq!(
        seen.as_ref().and_then(|p| p.pointer("/arguments/cmd")),
        Some(&json!("ab")),
        "s9c: {seen:?}"
    );
}
