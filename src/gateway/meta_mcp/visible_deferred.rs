// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The site-1 replays a request deferred to its live dispatch (MIK-8392
//! STORED.2), kept in the request's visibility memo and taken once.

/// The memo's deferred replays: a retained single-call result the route
/// stage deferred to a live dispatch, keyed by the owning invocation. The
/// lift consumes it once; an untaken entry ends with the request.
pub(super) type Slot =
    parking_lot::Mutex<std::collections::HashMap<DeferredReplayKey, DeferredReplay>>;

/// Key of a deferred site-1 replay (MIK-8392 STORED.2): the owning
/// invocation. The server and presented tool are the replay's target (the
/// target-branch target, or a continuation retry's origin); the key and
/// discriminator are the client's, so a nested invocation's take never
/// matches another invocation's entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DeferredReplayKey {
    server: String,
    tool: String,
    key: String,
    discriminator: String,
}

/// A site-1 retained result deferred to a live dispatch (MIK-8392 STORED.2):
/// the stored answer, beside what the route stage would have passed to
/// `audit_replay` for it (E3: the presented tool name with the envelope for
/// `gateway_invoke`, the inner arguments for a surfaced name, so the lift's
/// record matches the route stage's exactly).
pub(crate) struct DeferredReplay {
    pub(crate) response: crate::protocol::JsonRpcResponse,
    pub(crate) audit: Option<super::super::admission::ReplayAudit>,
    pub(crate) tool_name: String,
    pub(crate) arguments: serde_json::Value,
}

/// The deferred-replay key for `(server, tool)` under `retry`, or `None` for
/// an unkeyed call, which admission never replays and so never defers.
pub(crate) fn deferred_replay_key(
    server: &str,
    tool: &str,
    retry: &crate::protocol::mrtr::RetryFields,
) -> Option<DeferredReplayKey> {
    // The key first: an unkeyed call builds nothing.
    let key = retry.idempotency_key.clone()?;
    Some(DeferredReplayKey {
        server: server.to_owned(),
        tool: tool.to_owned(),
        key,
        discriminator: retry.key_discriminator(),
    })
}

/// Record `entry` for `key` in the open request's memo. `false` outside a
/// memo: nothing was recorded, so no lift can serve it, and the caller must
/// not proceed as though it were deferred.
pub(crate) fn record_deferred_replay(key: DeferredReplayKey, entry: DeferredReplay) -> bool {
    super::VISIBILITY_MEMO
        .try_with(|memo| {
            memo.deferred_replay.lock().insert(key, entry);
        })
        .is_ok()
}

/// Take the entry recorded for `key`, consuming it: a second take returns
/// `None`, and a nested invocation's key never matches. `None` outside a memo.
pub(crate) fn take_deferred_replay(key: &DeferredReplayKey) -> Option<DeferredReplay> {
    super::VISIBILITY_MEMO
        .try_with(|memo| memo.deferred_replay.lock().remove(key))
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::{
        DeferredReplay, deferred_replay_key, record_deferred_replay, take_deferred_replay,
    };
    use crate::protocol::mrtr::RetryFields;
    use crate::protocol::{JsonRpcResponse, RequestId};

    fn entry() -> DeferredReplay {
        DeferredReplay {
            response: JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({})),
            audit: None,
            tool_name: "gateway_invoke".to_string(),
            arguments: serde_json::json!({}),
        }
    }

    fn keyed(key: &str) -> RetryFields {
        RetryFields {
            idempotency_key: Some(key.to_string()),
            ..Default::default()
        }
    }

    /// L3k (L3's other key parts): a deferred entry is taken only by the key
    /// that recorded it. Another server, another tool or another retry
    /// discriminator (a continuation's state) never takes it, so a nested or
    /// sibling invocation cannot surface it; the recording key takes it once.
    #[tokio::test]
    async fn l3k_only_the_recording_key_takes_a_deferred_entry() {
        super::super::with_visibility_memo(async {
            let plain = keyed("l3k");
            let continued = RetryFields {
                request_state: Some("state".to_string()),
                ..keyed("l3k")
            };
            assert_ne!(
                plain.key_discriminator(),
                continued.key_discriminator(),
                "premise: a continuation changes the discriminator"
            );
            let own = deferred_replay_key("alpha", "read", &plain).expect("a keyed call");
            assert!(
                record_deferred_replay(own.clone(), entry()),
                "premise: recorded"
            );
            for (server, tool, retry, part) in [
                ("beta", "read", &plain, "server"),
                ("alpha", "write", &plain, "tool"),
                ("alpha", "read", &continued, "discriminator"),
            ] {
                let other = deferred_replay_key(server, tool, retry).expect("a keyed call");
                assert!(
                    take_deferred_replay(&other).is_none(),
                    "L3k: a key differing in its {part} took the entry"
                );
            }
            assert!(
                take_deferred_replay(&own).is_some(),
                "L3k: the own key did not take it"
            );
            assert!(take_deferred_replay(&own).is_none(), "L3k: taken twice");
        })
        .await;
    }

    /// MIK-8498 VISIBLE characterisation: a second record under one key
    /// replaces the first, and outside a memo a record reports `false` and a
    /// take finds nothing.
    #[tokio::test]
    async fn a_second_record_replaces_the_first_and_outside_a_memo_nothing_is_kept() {
        let own = deferred_replay_key("alpha", "read", &keyed("l3r")).expect("a keyed call");
        let named = |tool: &str| DeferredReplay {
            tool_name: tool.to_string(),
            ..entry()
        };
        super::super::with_visibility_memo(async {
            assert!(record_deferred_replay(own.clone(), named("first")));
            assert!(record_deferred_replay(own.clone(), named("second")));
            let taken = take_deferred_replay(&own).map(|entry| entry.tool_name);
            assert_eq!(taken.as_deref(), Some("second"));
        })
        .await;
        assert!(!record_deferred_replay(own.clone(), named("outside")));
        assert!(take_deferred_replay(&own).is_none());
        super::super::with_visibility_memo(async {
            assert!(
                take_deferred_replay(&own).is_none(),
                "a later scope sees nothing"
            );
        })
        .await;
    }
}
