// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8439 (MIK-8361.NOVIEW.1, NOVIEW.3) on stdio: the sole operator with no
//! current grant has no view of the managed per-user backend, so a tool
//! other callers pushed into error-rate cooldown answers as a missing name
//! does (the account's connect offer), signed or not; an operator with a
//! grant keeps the cooldown refusal. Uses the parent's fixture.

use super::*;

const MISSING: &str = "no_such";

/// Whether message signing is on (a nonce required on every call).
#[derive(Clone, Copy, Debug)]
enum Signing {
    Off,
    On,
}

/// The operator's stdio gateway with its grant in state `binding`, signing
/// on as `signing` says, the shared slot warm and [`TOOL`] in
/// error-rate cooldown.
fn cooling(binding: &Binding, signing: Signing) -> Stdio {
    let mut gateway =
        DirectAccountGateway::new_in(ServeMode::Stdio, AuthConfig::default(), binding);
    let mut meta = gateway.take_meta();
    if matches!(signing, Signing::On) {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"noview-cooldown-stdio-signing-secret-32-bytes".to_vec(),
                None,
                "noview-cooldown-stdio".to_owned(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
    }
    let meta = Arc::new(meta);
    let backend = gateway.backends().get(BACKEND).expect("the backend");
    backend.store_shared_tools_for_test(vec![tool(TOOL, &valid())]);
    let kill_switch = meta.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
    Stdio {
        gateway,
        meta,
        tasks: None,
    }
}

/// A modern unkeyed `gateway_invoke` of `name`, its nonce in `arguments`
/// when given.
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

/// `answer` with both twin names factored out, on either side alike.
fn normalised(answer: &Value) -> String {
    answer
        .to_string()
        .replace(TOOL, "<tool>")
        .replace(MISSING, "<tool>")
}

/// One twin on its own gateway: the answer of a call of `name` (its nonce
/// re-sent when signing is on), and the `tools/call` sends both added.
async fn twin(name: &str, signing: Signing) -> (Value, Option<Value>, usize) {
    let stdio = cooling(&Binding::Unconnected, signing);
    let nonce = matches!(signing, Signing::On).then_some("noview-cooldown-n1");
    let first = stdio.rpc(1, "tools/call", invoke(name, nonce)).await;
    let resent = match nonce {
        Some(_) => Some(stdio.rpc(2, "tools/call", invoke(name, nonce)).await),
        None => None,
    };
    (first, resent, stdio.gateway.tool_calls().len())
}

/// R3 under `signing`: the in-cooldown twin answers as the missing one, the
/// missing one carries the offer, nothing is sent, and when signing is on both
/// re-sent nonces are refused as a replay.
async fn assert_noview_twin(signing: Signing) {
    let row = format!("R3 signing {signing:?}");
    let (missing, missing_resent, missing_sent) = twin(MISSING, signing).await;
    assert!(
        missing.to_string().contains("no connected account"),
        "premise ({row}): the missing name gets the account answer: {missing}"
    );
    let (hidden, hidden_resent, hidden_sent) = twin(TOOL, signing).await;
    assert!(
        !hidden.to_string().contains("temporarily disabled"),
        "{row}: the cooldown named the tool: {hidden}"
    );
    assert_eq!(
        normalised(&hidden),
        normalised(&missing),
        "{row}: {hidden} vs {missing}"
    );
    if let (Some(hidden_resent), Some(missing_resent)) = (hidden_resent, missing_resent) {
        assert!(
            missing_resent.to_string().contains("Nonce replay detected"),
            "premise ({row}): the missing name's nonce stays spent: {missing_resent}"
        );
        assert_eq!(
            normalised(&hidden_resent),
            normalised(&missing_resent),
            "{row} nonce parity: {hidden_resent} vs {missing_resent}"
        );
    }
    assert_eq!(missing_sent + hidden_sent, 0, "{row}: sent");
}

/// R3 (NOVIEW.1 stdio unsigned, red first). RED at base: admission answers
/// the cooldown text, naming the tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_noview_cooldown_twin_answers_as_missing_stdio() {
    assert_noview_twin(Signing::Off).await;
}

/// R3 (NOVIEW.1 stdio signed, red first). RED at base: signing answers the
/// cooldown text before the nonce is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_noview_cooldown_twin_answers_as_missing_stdio_signed() {
    assert_noview_twin(Signing::On).await;
}

/// R4 (NOVIEW.3 control on stdio, signed; green at base): an operator with
/// a grant is still refused for the cooldown (-32000, the text naming the
/// tool, with or without the dispatch's prefix, which MIK-8433's STDIO.3
/// pins) and nothing is sent. Kills M2: with the policy skip and no dispatch
/// half, the call is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r4_view_caller_still_gets_cooldown_stdio() {
    let stdio = cooling(&Binding::Connected, Signing::On);
    let before = stdio.gateway.tool_calls().len();
    let answer = stdio
        .rpc(
            1,
            "tools/call",
            invoke(TOOL, Some("noview-cooldown-view-n1")),
        )
        .await;
    assert_eq!(
        answer.pointer("/error/code"),
        Some(&json!(-32000)),
        "R4: {answer}"
    );
    // The prefix the dispatch adds is MIK-8433's to pin (its STDIO.3 row).
    let refusal =
        crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::cooldown_refusal(
            BACKEND, TOOL,
        );
    assert!(
        answer
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.ends_with(&refusal)),
        "R4: {answer}"
    );
    assert_eq!(stdio.gateway.tool_calls().len(), before, "R4: sent");
}
