// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8150 NONCE.1 on `/mcp` beyond #3626's N1a/N1b: a signed call that
//! execution admission refuses (after its nonce was admitted, before anything
//! ran) gives the nonce back, so the honest call re-sent under it is judged on
//! its merits; a call admission answers from a stored run is a delivered call
//! and keeps it. Design: handoff/secC-design-8150.md r2.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::{code, dispatched};
use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed, send_with_headers};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// The replay refusal's message, as the signing layer words it.
const REPLAY: &str = "replay";

/// A hardened, signed, keyed `gateway_invoke alpha/read` on `/mcp` with `args`.
async fn keyed_invoke(fx: &Fx, key: &str, nonce: &str, args: Value) -> (StatusCode, Value) {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": args, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            IDEMPOTENCY_KEY_META: key,
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers).await
}

fn refused_as_replay(body: &Value) -> bool {
    body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.to_lowercase().contains(REPLAY))
}

/// A-mcp (NONCE.1, admission): a key reused for other arguments is refused by
/// execution admission (409) after the nonce was admitted. The honest call
/// re-sent under that nonce with its own key is served, once; a third send
/// under the nonce is a replay. Red on base: the re-send is refused as a
/// replay. Mutant: the admission give-back removed.
#[tokio::test]
async fn an_admission_refusal_gives_the_nonce_back_on_mcp() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let (_, first) = keyed_invoke(&fx, "a-k1", "a-n1", json!({})).await;
    assert!(first.get("error").is_none(), "setup: {first}");
    let (_, refused) = keyed_invoke(&fx, "a-k1", "a-n2", json!({"cmd": "other"})).await;
    assert_eq!(
        code(&refused),
        Some(409),
        "premise: admission's own refusal: {refused}"
    );
    let before = dispatched(&fx);
    let (status, honest) = keyed_invoke(&fx, "a-k2", "a-n2", json!({"cmd": "other"})).await;
    assert!(
        status == StatusCode::OK && honest.get("error").is_none(),
        "the refused call kept its nonce: {honest}"
    );
    assert_eq!(dispatched(&fx), before + 1, "the honest call did not run");
    let (_, third) = keyed_invoke(&fx, "a-k3", "a-n2", json!({"cmd": "other"})).await;
    assert!(
        refused_as_replay(&third),
        "the nonce was given back twice: {third}"
    );
}

/// KEEP-replay (green pin): a keyed call admission answers from its stored run
/// is a delivered call, so its nonce stays spent. Mutant: the give-back on
/// `SyncAdmission::Replay`.
#[tokio::test]
async fn an_admission_replay_keeps_its_nonce_on_mcp() {
    let fx = fixture_hardened_signed(Answer::Ok, true).await;
    let (_, first) = keyed_invoke(&fx, "r-k1", "r-n1", json!({})).await;
    assert!(first.get("error").is_none(), "setup: {first}");
    let (_, replayed) = keyed_invoke(&fx, "r-k1", "r-n2", json!({})).await;
    assert!(
        replayed.get("error").is_none(),
        "premise: the stored run is served: {replayed}"
    );
    assert_eq!(dispatched(&fx), 1, "premise: the replay did not run");
    let (_, reuse) = keyed_invoke(&fx, "r-k2", "r-n2", json!({})).await;
    assert!(
        refused_as_replay(&reuse),
        "a delivered replay gave its nonce back: {reuse}"
    );
}

/// SENT (NONCE.2, green pin; R24b on `/mcp`): a call that may have reached its
/// backend (the stream died after sending) keeps its nonce, so re-sending it
/// under that nonce is refused as a replay and the backend is not reached again.
/// Mutant: the nonce given back on every failure.
#[tokio::test]
async fn a_failure_after_sending_keeps_the_nonce_on_mcp() {
    let fx = fixture_hardened_signed(Answer::Transport, true).await;
    let (_, failed) = keyed_invoke(&fx, "s-k1", "s-n1", json!({})).await;
    assert_eq!(
        failed["result"]["isError"], true,
        "premise: the send failed as a tool error: {failed}"
    );
    let (_, again) = keyed_invoke(&fx, "s-k2", "s-n1", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "a possibly-sent call gave its nonce back: {again}"
    );
    assert_eq!(dispatched(&fx), 1, "the re-send reached the backend");
}
