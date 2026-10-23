// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8663 T7 relay half: a replayed `gateway_invoke` answer stages its relay
//! receipt from the unwrapped tool value. Split out of `relay_tests.rs`, which
//! is at its file-size ceiling; it reuses that module's fixtures.

use super::*;

/// MIK-8663 T7 (relay half, grok impl r1): a replayed `gateway_invoke`
/// answer stages its receipt from the tool value it wraps, read through the
/// strict payload reader. The value's lines are shorter than a fingerprint,
/// so every window crosses a newline: staged from the wrap as written, the
/// newlines would be escaped and the relayed lines would go unmatched.
#[tokio::test]
async fn a_replayed_invoke_answer_stages_its_unwrapped_value() {
    let (meta, firewall) = relay_meta();
    let lines = PROSE
        .split(' ')
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|words| words.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    let replay = crate::gateway::meta_mcp_helpers::wrap_tool_success(
        RequestId::Number(1),
        &text_result(&lines),
        false,
    );
    let caller = MetaMcpCallerContext {
        caller_key: Some("alice"),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let arguments = json!({"server": "alpha", "tool": "send", "arguments": {}});
    let ((), staged) = meta
        .collecting_staged(async {
            meta.stage_replay("gateway_invoke", &arguments, None, &caller, &replay);
        })
        .await;
    staged.commit(true);
    assert!(
        relayed_by_bob(&firewall, &lines),
        "the replayed value's lines lost their receipt"
    );
}
