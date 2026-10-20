// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `take_any_transient_resolution_error` (#3892 gpt round 2 improvement):
//! the task intake takes only a gateway-sealed transient, once, and only
//! from its own request's memo.

use super::{record_resolution_error, take_any_transient_resolution_error, take_resolution_error};
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;

fn sealed() -> crate::Error {
    crate::personal_accounts::refusal::transient_retry_error(None)
}

/// The sealed answer's shape without the gateway's seal, as a backend
/// could send it.
fn look_alike() -> crate::Error {
    crate::Error::JsonRpc {
        code: -32603,
        message: "temporarily unavailable, retry".into(),
        data: Some(serde_json::json!({"retryable": true})),
    }
}

/// Mutant: the helper takes the first carried error whatever it is (a
/// permanent refusal or a look-alike would then answer the intake retry).
#[tokio::test]
async fn take_any_transient_takes_only_a_sealed_transient_once() {
    with_visibility_memo(async {
        record_resolution_error("s", "permanent", crate::Error::Config("refused".into()));
        record_resolution_error("s", "look-alike", look_alike());
        assert!(
            take_any_transient_resolution_error().is_none(),
            "no sealed transient is held: nothing is taken"
        );
        record_resolution_error("s", "busy", sealed());
        let taken = take_any_transient_resolution_error().expect("the sealed transient is taken");
        assert!(
            crate::personal_accounts::refusal::transient_data(&taken).is_some(),
            "the taken error is the sealed transient"
        );
        assert!(
            take_any_transient_resolution_error().is_none(),
            "a transient is consumed once"
        );
        assert!(
            take_resolution_error("s", "permanent").is_some(),
            "a permanent refusal is left for its own dispatch"
        );
        assert!(
            take_resolution_error("s", "look-alike").is_some(),
            "a look-alike is left for its own dispatch"
        );
    })
    .await;
}

/// Mutant: a memo shared across requests (one request's transient would
/// answer another request's intake).
#[tokio::test]
async fn take_any_transient_sees_only_its_own_request() {
    with_visibility_memo(async {
        record_resolution_error("s", "busy", sealed());
    })
    .await;
    with_visibility_memo(async {
        assert!(
            take_any_transient_resolution_error().is_none(),
            "another request's transient is not this request's"
        );
    })
    .await;
    assert!(
        take_any_transient_resolution_error().is_none(),
        "outside any request scope there is nothing to take"
    );
}
