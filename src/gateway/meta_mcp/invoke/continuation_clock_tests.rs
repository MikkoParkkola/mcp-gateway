// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202, minting: a clock that reads before 1970 mints no continuation;
//! the real clock mints as today.

use serde_json::json;

use super::mint_continuation;
use crate::protocol::continuation::ContinuationState;
use crate::protocol::mrtr::PrincipalSource;

async fn mint(state: &ContinuationState) -> Option<(String, String)> {
    mint_continuation(
        state,
        PrincipalSource::Key("caller".into()),
        ("srv", None),
        "tool",
        &json!({}),
        Some("backend-state".into()),
    )
    .await
}

/// MIK-8202: a clock before 1970 refuses to mint, never stamping `issued_at = 0`.
#[tokio::test]
async fn a_clock_before_the_epoch_mints_no_continuation() {
    let state = ContinuationState::new();
    assert!(
        mint(&state).await.is_some(),
        "control: the real clock mints a continuation"
    );

    let _clock = crate::clock::test_clock::before_epoch();
    assert!(
        mint(&state).await.is_none(),
        "an unreadable clock minted a continuation"
    );
}
