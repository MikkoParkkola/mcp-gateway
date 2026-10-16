// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8433 (MIK-8361.STDIO.1, STDIO.3): on stdio with message signing, a
//! per-user tool in error-rate cooldown that the caller's own slot withholds
//! answers as a missing name; one the slot offers keeps the cooldown refusal.
//! Split out of `slot_verdict_g2_stdio.rs` to keep that file under its size
//! ceiling; it uses the parent's fixture.

use super::*;

const MISSING: &str = "no_such";

/// The cooldown refusal as the dispatch renders it (design §3.1 point 3).
fn dispatch_cooldown_text() -> String {
    format!(
        "JSON-RPC error -32000: Capability '{TOOL}' on server '{BACKEND}' is temporarily \
         disabled due to a high error rate. It will auto-recover after the cooldown period. \
         Use gateway_list_disabled_capabilities to see all disabled capabilities."
    )
}

/// The sole operator's stdio gateway, signing on (nonce required) when
/// `signed`, its slot `[TOOL with schema, SIBLING]`, and [`TOOL`] pushed into
/// error-rate cooldown as other callers' failures would.
fn cooling(signed: bool, schema: &Value) -> Stdio {
    let stdio = operator_stdio_armed(|meta| {
        if signed {
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"cooldown-stdio-signing-secret-at-least-32-bytes".to_vec(),
                    None,
                    "cooldown-stdio".to_owned(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
        }
    });
    let backend = stdio.gateway.backends().get(BACKEND).expect("the backend");
    backend.store_per_user_tools_for_test(
        &DirectAccountGateway::operator_binding(),
        vec![tool(TOOL, schema), tool(SIBLING, &valid())],
    );
    let kill_switch = stdio.meta.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
    stdio
}

/// A modern unkeyed `gateway_invoke` of `name`, its nonce in `arguments` when
/// given.
fn invoke(name: &str, nonce: Option<&str>) -> Value {
    let mut arguments = json!({"server": BACKEND, "tool": name, "arguments": {"folder": "inbox"}});
    if let Some(nonce) = nonce {
        arguments["nonce"] = json!(nonce);
    }
    json!({
        "name": "gateway_invoke",
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    })
}

/// `answer` with both twin names factored out, on either side alike ("read"
/// also sits inside words such as "already").
fn normalised(answer: &Value) -> String {
    answer
        .to_string()
        .replace(TOOL, "<tool>")
        .replace(MISSING, "<tool>")
}

/// One twin: a fresh-nonce call of `name`, then the same call reusing that
/// nonce. Both answers, and the `tools/call` sends the two added.
async fn twin(name: &str) -> (Value, Value, usize) {
    let stdio = cooling(true, &json!({"type": "array"}));
    let before = stdio.gateway.tool_calls().len();
    let first = stdio
        .rpc(1, "tools/call", invoke(name, Some("cooldown-twin-n1")))
        .await;
    let reuse = stdio
        .rpc(2, "tools/call", invoke(name, Some("cooldown-twin-n1")))
        .await;
    (first, reuse, stdio.gateway.tool_calls().len() - before)
}

/// STDIO.1 (red first): signed stdio, the sole operator's slot withholds
/// [`TOOL`] (invalid schema) while other callers pushed it into cooldown. Its
/// `gateway_invoke` answers byte-equal to a missing name's once the name is
/// factored out, sends nothing, and spends its nonce as the missing name does
/// (the acting verdict spends the witness for both). RED at base: signing
/// runs the policy first and answers the cooldown text, before the nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_signed_cooldown_hidden_tool_answers_as_missing() {
    let (missing, missing_reuse, missing_sent) = twin(MISSING).await;
    assert_eq!(
        missing.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: a missing name answers -32601: {missing}"
    );
    assert!(
        missing_reuse.to_string().contains("Nonce replay detected"),
        "premise: the missing name's nonce stays spent: {missing_reuse}"
    );
    assert_eq!(missing_sent, 0, "premise: the missing name was sent");
    let (hidden, hidden_reuse, hidden_sent) = twin(TOOL).await;
    assert_eq!(
        normalised(&hidden),
        normalised(&missing),
        "STDIO.1: hidden {hidden} vs missing {missing}"
    );
    assert!(
        !hidden.to_string().contains("temporarily disabled"),
        "STDIO.1: the cooldown named the hidden tool: {hidden}"
    );
    assert_eq!(
        normalised(&hidden_reuse),
        normalised(&missing_reuse),
        "STDIO.1 nonce parity: hidden reuse {hidden_reuse} vs missing reuse {missing_reuse}"
    );
    assert_eq!(hidden_sent, 0, "STDIO.1: the hidden tool was sent");
}

/// STDIO.3 (control for a caller with a view; red first on the text): the
/// slot offers [`TOOL`], so the signed call is still refused for its
/// cooldown, with the dispatch's text, and sends nothing. RED at base on the
/// prefix only: signing answers the raw message (signing.rs:17-22).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_signed_cooldown_visible_tool_refused_with_dispatch_text() {
    let stdio = cooling(true, &valid());
    let before = stdio.gateway.tool_calls().len();
    let answer = stdio
        .rpc(1, "tools/call", invoke(TOOL, Some("cooldown-visible-n1")))
        .await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32000)),
        "STDIO.3: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some(dispatch_cooldown_text().as_str()),
        "STDIO.3: {answer}"
    );
    assert_eq!(stdio.gateway.tool_calls().len(), before, "STDIO.3: sent");
}

/// The oracle for STDIO.3's text (green at base): unsigned stdio never meets
/// signing, so its cooldown refusal is the dispatch's rendering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_unsigned_cooldown_visible_tool_refused_with_dispatch_text() {
    let stdio = cooling(false, &valid());
    let before = stdio.gateway.tool_calls().len();
    let answer = stdio.rpc(1, "tools/call", invoke(TOOL, None)).await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32000)),
        "unsigned control: {answer}"
    );
    assert_eq!(
        answer.pointer("/error/message").and_then(Value::as_str),
        Some(dispatch_cooldown_text().as_str()),
        "unsigned control: {answer}"
    );
    assert_eq!(
        stdio.gateway.tool_calls().len(),
        before,
        "unsigned control: sent"
    );
}
