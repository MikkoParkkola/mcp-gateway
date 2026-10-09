// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202, Meta-MCP rows: a clock that reads before 1970 refuses what the
//! real clock still admits. Each row's control is the same input on the real
//! clock, admitted as today.

use crate::clock::test_clock;
use crate::protocol::continuation::{ContinuationState, Payload};
use crate::protocol::mrtr::RetryFields;

/// A continuation for `srv`, valid now on the real clock.
async fn live_continuation(state: &ContinuationState) -> RetryFields {
    let now = crate::protocol::continuation::now_unix_secs();
    let hold_key = state
        .in_flight()
        .hold("srv", now + 300, now)
        .await
        .expect("the in-flight table has room for one exchange");
    let payload = Payload::mint(
        "srv".into(),
        Some("backend-state".into()),
        "caller".into(),
        "digest".into(),
        "replica-a".into(),
        hold_key,
        now,
    );
    RetryFields {
        request_state: Some(state.keyring().mint(&payload).expect("mint")),
        ..RetryFields::default()
    }
}

#[tokio::test]
async fn a_clock_before_the_epoch_refuses_a_live_continuation() {
    let state = ContinuationState::new();
    let retry = live_continuation(&state).await;
    assert!(
        matches!(
            crate::gateway::meta_mcp::invoke::retry_origin_backend(&state, &retry),
            Some(Ok(ref backend)) if backend == "srv"
        ),
        "control: a live continuation routes to its backend"
    );

    let _clock = test_clock::before_epoch();
    assert!(
        matches!(
            crate::gateway::meta_mcp::invoke::retry_origin_backend(&state, &retry),
            Some(Err(_))
        ),
        "an unreadable clock opened a continuation"
    );
}

/// MIK-8202: a retention sweep on a clock before 1970 keeps an idempotency
/// entry; guards the D2 trap, where an access-style `Expired` would delete it
/// and readmit a retry to run its side effect twice. Green before and after.
#[tokio::test]
async fn a_clock_before_the_epoch_keeps_an_idempotency_entry() {
    use crate::idempotency::admission::{Admission, Mode, Request, Settlement};

    // The production admission clock: the one the task runtime shares.
    let meta = crate::gateway::meta_mcp::MetaMcp::new(std::sync::Arc::new(
        crate::backend::BackendRegistry::new(),
    ));
    let admission = meta.execution_admission();
    let operation = serde_json::json!({"backend": "orders", "tool": "create"});
    let representation = serde_json::json!({"full": false});
    let request = || Request {
        principal: "owner",
        key: "key",
        operation: &operation,
        representation: &representation,
        mode: Mode::Sync,
    };
    let Ok(Admission::Owned(mut lease)) = admission.admit(request()) else {
        panic!("control: the first call owns its execution");
    };
    lease.mark_dispatched();
    assert_eq!(
        lease.complete_secured(&serde_json::json!({"done": true})),
        Settlement::Retained,
        "control: the result is retained on the real clock"
    );
    assert_eq!(
        admission.reclaim_completed(),
        0,
        "control: nothing aged out"
    );

    let _clock = test_clock::before_epoch();
    assert_eq!(
        admission.reclaim_completed(),
        0,
        "a sweep on an unreadable clock deleted an idempotency entry"
    );
    assert_eq!(admission.snapshot().entries, 1, "the entry is gone");
    assert!(
        !matches!(admission.admit(request()), Ok(Admission::Owned(_))),
        "an unreadable clock readmitted a completed call to run again"
    );
}
