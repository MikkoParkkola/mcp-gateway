// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8139 `ERRSCAN.FW.3` on the meta and direct routes, A2A arm: what an
//! A2A agent plants in its answer is screened by the same egress scan as an
//! MCP backend's (`dispatch_parity_tests.rs` errscan rows). Each row shows
//! the agent was reached (one `SendMessage`), so a refusal before dispatch
//! cannot pass for screening. The tasks-worker arm is in
//! `tests/task_execution_adapter/egress_task.rs`.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, Fx, post_direct, post_meta_invoke};
use super::direct_guards_fixture_a2a::{A2A_BACKEND, A2aAnswer, fixture_firewalled_with_a2a};
use crate::security::firewall::FirewallAction;

/// A credential the response firewall redacts, built at compile time so no
/// key-shaped literal sits in the source.
const REDACTED_SECRET: &str = concat!("gh", "p_", "0123456789abcdefghij0123456789abcdef");
const WITH_SECRET: &str = concat!(
    "benign prefix ",
    "gh",
    "p_",
    "0123456789abcdefghij0123456789abcdef"
);

/// One call of the agent's one tool on `/mcp/alpha-a2a` (`direct`) or
/// through `gateway_invoke` on `/mcp`.
async fn a2a_call(fx: &Fx, direct: bool, idem: Option<&str>) -> (u16, Value) {
    let args = json!({"message": "hi"});
    let (status, body) = if direct {
        post_direct(fx, A2A_BACKEND, "k-std", "send_message", args, idem, None).await
    } else {
        post_meta_invoke(fx, "k-std", A2A_BACKEND, "send_message", args, idem, None).await
    };
    (status.as_u16(), body)
}

async fn routed(a2a: A2aAnswer, rule: Option<FirewallAction>, direct: bool) -> (Value, usize) {
    let (fx, sends) = fixture_firewalled_with_a2a(Answer::Ok, a2a, rule).await;
    let (_, body) = a2a_call(&fx, direct, None).await;
    (body, sends.load(Ordering::SeqCst))
}

/// A credential in the agent's error message, a failed task's status, its
/// answer text, or its one data part never reaches the caller on either
/// route, after one `SendMessage`.
#[tokio::test]
async fn fw3_an_a2a_answer_with_a_credential_is_screened_on_both_routes() {
    let answers = [
        ("error", A2aAnswer::RpcError(WITH_SECRET)),
        ("failed", A2aAnswer::Failed(WITH_SECRET)),
        ("text", A2aAnswer::Text(WITH_SECRET)),
        ("data", A2aAnswer::DataNote(WITH_SECRET)),
    ];
    for (shape, answer) in answers {
        for direct in [false, true] {
            let at = format!("{shape} direct={direct}");
            let (body, sends) = routed(answer, None, direct).await;
            assert_eq!(sends, 1, "{at}: the agent was not reached: {body}");
            assert!(
                !body.to_string().contains(REDACTED_SECRET),
                "{at}: the agent's credential reached the caller unscanned: {body}"
            );
            // The default Block refused it: screening, not an unrelated error.
            assert_eq!(
                body["error"]["message"], "Response blocked by security firewall",
                "{at}: {body}"
            );
        }
    }
}

/// The data-part cell reaches the caller as the translator's
/// `structuredContent` (one object part), so the row above screens that
/// shape and not a plain text rendering of it. Under Warn the object
/// arrives, redacted.
#[tokio::test]
async fn fw3_an_a2a_data_part_arrives_as_structured_content_redacted() {
    for direct in [false, true] {
        let at = format!("direct={direct}");
        let (body, sends) = routed(
            A2aAnswer::DataNote(WITH_SECRET),
            Some(FirewallAction::Warn),
            direct,
        )
        .await;
        assert_eq!(sends, 1, "{at}: {body}");
        let text = body.to_string();
        assert!(
            text.contains("structuredContent"),
            "{at}: no structuredContent: {body}"
        );
        assert!(
            text.contains("benign prefix"),
            "{at}: the note did not arrive: {body}"
        );
        assert!(!text.contains(REDACTED_SECRET), "{at}: {body}");
    }
}

/// Under an explicit Warn rule the agent's error is delivered redacted on
/// both routes, as an MCP backend's is.
#[tokio::test]
async fn fw3_warn_delivers_a_redacted_a2a_error_on_both_routes() {
    for direct in [false, true] {
        let at = format!("direct={direct}");
        let (body, sends) = routed(
            A2aAnswer::RpcError(WITH_SECRET),
            Some(FirewallAction::Warn),
            direct,
        )
        .await;
        assert_eq!(sends, 1, "{at}: {body}");
        let text = body.to_string();
        assert!(text.contains("benign prefix"), "warn {at}: {body}");
        assert!(!text.contains(REDACTED_SECRET), "warn {at}: {body}");
    }
}

/// Under the default Block a credentialed agent error is withheld whole on
/// both routes: the delivery refusal, not a redacted copy.
#[tokio::test]
async fn fw3_a_blocked_a2a_error_is_withheld_whole_on_both_routes() {
    for direct in [false, true] {
        let at = format!("direct={direct}");
        let (fx, sends) =
            fixture_firewalled_with_a2a(Answer::Ok, A2aAnswer::RpcError(WITH_SECRET), None).await;
        let (status, body) = a2a_call(&fx, direct, None).await;
        assert_eq!(sends.load(Ordering::SeqCst), 1, "{at}: {body}");
        assert_eq!(status, 200, "{at}: {body}");
        assert_eq!(body["error"]["code"], -32600, "{at}: {body}");
        assert_eq!(
            body["error"]["message"], "Response blocked by security firewall",
            "{at}: {body}"
        );
    }
}

/// A clean agent error is delivered as the agent's, unchanged, on the direct
/// route: screening never rewrites a plain refusal.
#[tokio::test]
async fn fw3_a_clean_a2a_error_is_delivered_unchanged() {
    let (body, sends) = routed(A2aAnswer::RpcError("benign refusal"), None, true).await;
    assert_eq!(sends, 1, "{body}");
    assert_eq!(body["error"]["code"], -32001, "{body}");
    assert_eq!(
        body["error"]["message"], "A2A agent error: benign refusal",
        "{body}"
    );
}

/// A keyed direct call whose agent error was screened replays the screened
/// answer without reaching the agent again.
#[tokio::test]
async fn fw3_a_screened_a2a_error_replays_without_redispatch() {
    let (fx, sends) =
        fixture_firewalled_with_a2a(Answer::Ok, A2aAnswer::RpcError(WITH_SECRET), None).await;
    let (_, first) = a2a_call(&fx, true, Some("errscan-a2a")).await;
    let (_, replay) = a2a_call(&fx, true, Some("errscan-a2a")).await;
    assert!(!replay.to_string().contains(REDACTED_SECRET), "{replay}");
    assert_eq!(replay["error"], first["error"]);
    assert_eq!(sends.load(Ordering::SeqCst), 1, "re-dispatched");
}

/// Discard regression, not egress proof: the A2A client keeps only an agent
/// error's code and message, so a credential planted in its `data` never
/// reaches the egress scan, or the caller. Checked on the raw transport
/// answer first, then on both routes.
#[tokio::test]
async fn fw3_an_a2a_error_data_is_discarded_before_egress() {
    use crate::transport::Transport as _;
    let base = crate::a2a::test_agent::serve(
        |body: Value| -> futures::future::BoxFuture<'static, Value> {
            let reply = json!({"jsonrpc": "2.0", "id": body["id"],
            "error": {"code": -32001, "message": "benign refusal", "data": WITH_SECRET}});
            Box::pin(async move { reply })
        },
    )
    .await;
    let raw = crate::a2a::test_agent::started(&base)
        .await
        .request(
            "tools/call",
            Some(json!({"name": "send_message", "arguments": {"message": "hi"}})),
        )
        .await
        .expect("the agent answers");
    let error = raw.error.expect("the agent's error is passed on");
    assert!(
        error.data.is_none(),
        "the transport kept the agent's data: {error:?}"
    );

    for direct in [false, true] {
        let (body, sends) = routed(A2aAnswer::RpcErrorData(WITH_SECRET), None, direct).await;
        assert_eq!(sends, 1, "direct={direct}: {body}");
        assert!(
            !body.to_string().contains(REDACTED_SECRET),
            "direct={direct}: {body}"
        );
    }
}
