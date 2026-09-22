// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `substitute_progress_token` cases, split out of `ops.rs` to keep that
//! file under the line-count ceiling.
use super::*;
use crate::transport::notification_sink::{collect, publish, translate_back};
use serde_json::json;

fn token_of(params: &Value) -> Value {
    params["_meta"]["progressToken"].clone()
}

/// The security property itself: what leaves for the backend is never the
/// value the client sent.
#[tokio::test]
async fn inside_a_scope_the_callers_token_never_reaches_the_backend() {
    let ((), _) = collect(async {
        let outbound = substitute_progress_token(Some(json!({ "_meta": { "progressToken": 7 } })))
            .expect("params survive");
        let sent = token_of(&outbound);
        assert_ne!(sent, json!(7), "the caller's own token went out");
        assert!(
            sent.as_str().is_some_and(|t| t.starts_with("gw-")),
            "outbound token was {sent:?}"
        );
    })
    .await;
}

/// A health probe or the reaper has no client to translate back to, so its
/// `_meta` travels exactly as built.
#[tokio::test]
async fn outside_a_scope_params_travel_unchanged() {
    let params = json!({ "_meta": { "progressToken": 7 }, "name": "t" });
    assert_eq!(
        substitute_progress_token(Some(params.clone())),
        Some(params)
    );
}

/// The gateway never synthesises a token a client did not ask for.
#[tokio::test]
async fn a_call_with_no_token_gains_none() {
    let ((), _) = collect(async {
        let params = json!({ "_meta": { "traceparent": "00-a-b-01" } });
        assert_eq!(
            substitute_progress_token(Some(params.clone())),
            Some(params)
        );
    })
    .await;
}

/// The pair, end to end: whatever the mint sent out, the notification
/// coming back carries the client's own value again -- byte- and
/// type-identically. This is the contract the stdio backend leg relies on,
/// since it captures under the token this function wrote and republishes
/// it into the same scope.
#[tokio::test]
async fn a_minted_token_round_trips_to_the_callers_value() {
    let ((), drained) = collect(async {
        let outbound = substitute_progress_token(Some(json!({ "_meta": { "progressToken": 7 } })))
            .expect("params survive");
        let mut back = crate::protocol::JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/progress".to_string(),
            params: Some(json!({ "progressToken": token_of(&outbound), "progress": 1 })),
        };
        translate_back(&mut back);
        publish(vec![back]);
    })
    .await;

    assert_eq!(drained.len(), 1);
    assert_eq!(
        drained[0].params.as_ref().unwrap()["progressToken"],
        json!(7)
    );
}
