// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The site-1 replays a request deferred to its live dispatch (MIK-8392
//! STORED.2), kept in the request's visibility memo and taken once.

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

/// Record `entry` for `key` in the open request's memo. Outside a memo it is
/// dropped, and the dispatch serves live.
pub(crate) fn record_deferred_replay(key: DeferredReplayKey, entry: DeferredReplay) {
    let _ = super::VISIBILITY_MEMO.try_with(|memo| memo.deferred_replay.lock().insert(key, entry));
}

/// Take the entry recorded for `key`, consuming it: a second take returns
/// `None`, and a nested invocation's key never matches. `None` outside a memo.
pub(crate) fn take_deferred_replay(key: &DeferredReplayKey) -> Option<DeferredReplay> {
    super::VISIBILITY_MEMO
        .try_with(|memo| memo.deferred_replay.lock().remove(key))
        .ok()
        .flatten()
}
