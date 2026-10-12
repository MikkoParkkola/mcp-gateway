// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F5(a) over stdio (MIK-8361): split out of `slot_verdict_g2_stdio.rs` to keep
//! that file under its size ceiling; it uses the parent's fixture.

use super::*;

/// `body` with every occurrence of `tool` replaced by a placeholder, and how
/// many there were: the twin bodies are compared byte for byte with only the
/// tool name factored out (MIK-8361, lead ruling on F5(a)).
fn normalised(body: &str, tool: &str) -> (String, usize) {
    (body.replace(tool, "<tool>"), body.matches(tool).count())
}

/// F5(a), stdio (guard, kills M18; MIK-8361 lead ruling 2026-10-12, per-user
/// class): a step route authorize refuses (`run_command`, on the default
/// tool-policy deny list) resolves no credential and sends nothing of its
/// own. `[read, run_command]` is measured against `[read]` alone: the same
/// resolutions and sends, so `run_command`'s share is zero. The caller sees
/// the answer the twin `[read, nosuch]` gets (tool name factored out).
/// Labelled residual (design A4): on this per-user backend the twin's
/// caller-slot fill resolves where the withheld name resolves nothing, a
/// count the caller cannot see.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f5a_stdio_route_authorize_refusal_resolves_nothing() {
    async fn chain(second: Option<&str>) -> (Value, usize, usize) {
        let stdio = operator_stdio();
        let mut steps =
            vec![json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}})];
        if let Some(second) = second {
            steps.push(json!({"tool": format!("{BACKEND}:{second}"), "arguments": {}}));
        }
        let answer = stdio
            .rpc(
                1,
                "tools/call",
                json!({"name": "gateway_execute", "arguments": {"chain": steps}}),
            )
            .await;
        (
            answer,
            stdio.gateway.releases(),
            stdio.gateway.requests().len(),
        )
    }
    let (hidden, releases, requests) = chain(Some("run_command")).await;
    let (missing, _, _) = chain(Some("nosuch")).await;
    let (alone, alone_releases, alone_requests) = chain(None).await;
    assert!(
        alone_releases >= 1 && alone_requests >= 1,
        "premise: the visible step alone resolves and sends: {alone}"
    );
    let (hidden_body, named) = normalised(&hidden.to_string(), "run_command");
    let (missing_body, twin_named) = normalised(&missing.to_string(), "nosuch");
    assert_eq!(
        named, twin_named,
        "premise: each answer names its own step as often: {hidden} / {missing}"
    );
    assert_eq!(
        hidden_body, missing_body,
        "F5(a) stdio: the hidden step's answer differs from a missing step's"
    );
    assert_eq!(
        (releases, requests),
        (alone_releases, alone_requests),
        "F5(a) stdio: run_command resolved or sent beyond the visible step: {hidden}"
    );
}
