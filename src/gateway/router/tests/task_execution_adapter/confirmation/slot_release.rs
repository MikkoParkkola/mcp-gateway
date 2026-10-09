// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 SLOT.5 (JSON arm): a destructive call's confirmation challenge
//! holds a slot. Withheld because its delivery record cannot be written, it
//! gives the slot back; delivered, it keeps it for the confirming retry.
use super::*;

use crate::gateway::meta_mcp::grant_audit_fixture::logger;
use crate::security::audit::AuditFailurePolicy;

async fn held(state: &Arc<AppState>) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    state.meta_mcp.continuation().in_flight().len(now).await
}

/// The fixture with a fail-closed log on its Meta-MCP.
async fn logged(
    mock: &Arc<MockBackend>,
) -> (
    Arc<AppState>,
    Arc<crate::security::TransparencyLogger>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    let dir = tempfile::tempdir().expect("a private log directory");
    let log = logger(&dir, AuditFailurePolicy::FailClosed);
    let sink = Arc::clone(&log);
    let (state, store) = fixture_with(mock, crate::config::Config::default(), move |meta| {
        meta.enable_transparency_log(sink);
    })
    .await;
    (state, log, (dir, store))
}

#[tokio::test]
async fn a_delivered_confirmation_challenge_keeps_its_slot() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _log, _dirs) = logged(&mock).await;
    let challenge = post(&state, "key-a", request("slot-kept")).await;
    std::assert_eq!(
        challenge.pointer("/result/resultType"),
        Some(&json!("input_required")),
        "control: a challenge is issued: {challenge}"
    );
    std::assert_eq!(held(&state).await, 1, "{challenge}");
}

#[tokio::test]
async fn a_withheld_confirmation_challenge_gives_its_slot_back() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, log, _dirs) = logged(&mock).await;
    log.fail_next_append_of_kind_for_test("response_delivery_attempt");
    let challenge = post(&state, "key-a", request("slot-freed")).await;
    std::assert_eq!(challenge["error"]["code"], json!(-32005), "{challenge}");
    std::assert_eq!(
        held(&state).await,
        0,
        "the withheld challenge kept its slot: {challenge}"
    );
    std::assert_eq!(mock.calls(), 0, "nothing ran");
}
