// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Remaining ORDER.2 FSM refusal, contaminated-state and compatibility cases.

use super::*;

const REFUSAL: &str = "Protocol error: The workflow state is per-session, and this connection has no session. MCP 2026-07-28 removed protocol-level sessions; capability visibility is decided by the authorization presented on each request.";

pub(super) fn assert_refusal(meta: &MetaMcp, response: &JsonRpcResponse) {
    let error = response
        .error
        .as_ref()
        .expect("state change must be refused");
    assert_eq!(error.code, -32600);
    assert_eq!(error.message, REFUSAL);
    assert!(
        response.result.is_none(),
        "refusal must not contain a result"
    );
    assert_eq!(meta.session_state.len(), 0, "refusal must not create state");
}

async fn assert_membership(meta: &MetaMcp, session: Option<&str>, expected: &[&str]) {
    for (label, value) in [
        ("list", meta.list_tools(&json!({}), session).await.unwrap()),
        (
            "single-server list",
            meta.list_tools(&json!({"server": "staged"}), session)
                .await
                .unwrap(),
        ),
        (
            "search tools",
            meta.search_tools(&json!({"query": "staged"}), session)
                .await
                .unwrap(),
        ),
        (
            "code-mode search",
            meta.code_mode_search(&json!({"query": "staged"}), session)
                .await
                .unwrap(),
        ),
    ] {
        assert_eq!(discovery_names(&value), expected, "{label}, {session:?}");
    }
}

/// MIK-7272.ORDER2.FSM.3: neither missing representation may mutate the store.
#[tokio::test]
async fn missing_and_empty_keys_are_explicitly_refused() {
    for session in [None, Some("")] {
        let meta = meta_with_state_staged_capabilities().await;
        let response = meta
            .handle_tools_call(
                RequestId::Number(31),
                "gateway_set_state",
                json!({"state": TARGET_STATE}),
                session,
                allow_all_ctx(),
            )
            .await;
        assert_refusal(&meta, &response);
        assert_membership(&meta, session, STAGED_DEFAULT_TOOLS).await;
    }
}

/// MIK-7272.ORDER2.FSM.4: a write guard alone cannot fix old contaminated state.
#[tokio::test]
async fn old_empty_key_state_cannot_influence_any_discovery_reader() {
    let meta = meta_with_state_staged_capabilities().await;
    // Only this fixture bypasses the writer: the old forbidden entry must exist
    // independently of the repaired writer so omission of the read guard fails.
    meta.session_state.set_state("", TARGET_STATE);
    assert_eq!(meta.session_state.get_state(""), TARGET_STATE);
    assert_eq!(meta.session_state.len(), 1);

    for session in [None, Some("")] {
        assert_membership(&meta, session, STAGED_DEFAULT_TOOLS).await;
    }
    assert_eq!(meta.session_state.get_state(""), TARGET_STATE);
}

/// MIK-7272.ORDER2.FSM.5: retain real mutations for legacy and stdio state owners.
#[tokio::test]
async fn nonempty_legacy_and_stdio_keys_retain_isolated_state_changes() {
    for owner in ["legacy-session", "stdio-session"] {
        let meta = meta_with_state_staged_capabilities().await;
        assert_membership(&meta, Some(owner), STAGED_DEFAULT_TOOLS).await;
        let response = meta
            .handle_tools_call(
                RequestId::Number(51),
                "gateway_set_state",
                json!({"state": TARGET_STATE}),
                Some(owner),
                allow_all_ctx(),
            )
            .await;
        assert!(response.error.is_none(), "{owner}: {:?}", response.error);
        assert!(response.result.is_some());
        assert_eq!(meta.session_state.get_state(owner), TARGET_STATE);
        assert_eq!(meta.session_state.len(), 1);
        assert_membership(&meta, Some(owner), STAGED_OTHER_STATE_TOOLS).await;
        assert_membership(&meta, Some("other-owner"), STAGED_DEFAULT_TOOLS).await;
        assert_membership(&meta, Some(""), STAGED_DEFAULT_TOOLS).await;
    }
}
