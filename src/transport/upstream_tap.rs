// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Upstream notification taps (MIK-7630 I5, design
//! `docs/design/2026-10-02-mik-7630-i5-upstream-listener.md` §4): what a
//! transport hands the events listener. A backend frame never crosses the
//! channel; the producer classifies and projects it first, so a queued note
//! is bounded whatever the backend sends.

use serde_json::Value;

/// The `_meta` key a modern peer tags every frame of a listen with.
pub(crate) const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
/// Longest URI a note carries; a longer one is dropped and counted (§4).
pub(crate) const MAX_URI_BYTES: usize = 2048;
/// Notes a tap queues before it drops (§7 limits).
pub(crate) const TAP_CAPACITY: usize = 64;

const UPDATED: &str = "notifications/resources/updated";
const RESOURCES_CHANGED: &str = "notifications/resources/list_changed";
const PROMPTS_CHANGED: &str = "notifications/prompts/list_changed";
const ACKNOWLEDGED: &str = "notifications/subscriptions/acknowledged";

/// Which of the three upstream notifications a note stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum NoteKind {
    ResourceUpdated,
    ResourcesChanged,
    PromptsChanged,
}

/// The list-changed kinds a listen asked for or a peer honoured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KindSet {
    pub resources_changed: bool,
    pub prompts_changed: bool,
}

/// One projected frame of a listen or of the unsolicited stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpstreamNote {
    /// The acknowledgement, intersected with what the listen asked for.
    Ack { kinds: KindSet, uris: Vec<String> },
    /// One of the three notifications; `uri` only for `ResourceUpdated`.
    Notice { kind: NoteKind, uri: Option<String> },
    /// A validated terminal response to the listen (graceful end).
    End,
}

/// Why a frame was not turned into a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dropped {
    /// Not one of the three methods (or the acknowledgement).
    Other,
    /// A modern frame without the listen's tag, or with another one.
    Untagged,
    /// A `resources/updated` without a string `uri`, or one over the cap.
    Oversize,
}

/// The `notifications` filter a listen sends, from what it needs.
pub(crate) fn listen_filter(kinds: KindSet, uris: &[String]) -> Value {
    serde_json::json!({
        "notifications": {
            "toolsListChanged": false,
            "resourcesListChanged": kinds.resources_changed,
            "promptsListChanged": kinds.prompts_changed,
            "resourceSubscriptions": uris,
        }
    })
}

/// Whether `params` carries `_meta[SUBSCRIPTION_ID] == listen_id`.
fn tagged(params: Option<&Value>, listen_id: &Value) -> bool {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(SUBSCRIPTION_ID))
        .is_some_and(|id| id == listen_id)
}

/// Project a notification `method`/`params` into a note.
///
/// `listen` is `Some((id, requested))` on a modern listen stream: the frame
/// must carry that id, and an acknowledgement is intersected with
/// `requested`. `None` is the legacy unsolicited stream, which has no tag
/// and no acknowledgement.
pub(crate) fn project(
    method: &str,
    params: Option<&Value>,
    listen: Option<(&Value, &Requested)>,
) -> Result<UpstreamNote, Dropped> {
    let kind = match method {
        UPDATED => NoteKind::ResourceUpdated,
        RESOURCES_CHANGED => NoteKind::ResourcesChanged,
        PROMPTS_CHANGED => NoteKind::PromptsChanged,
        ACKNOWLEDGED if listen.is_some() => {
            let (id, requested) = listen.expect("guarded");
            if !tagged(params, id) {
                return Err(Dropped::Untagged);
            }
            return Ok(requested.honoured(params.and_then(|p| p.get("notifications"))));
        }
        _ => return Err(Dropped::Other),
    };
    if let Some((id, _)) = listen
        && !tagged(params, id)
    {
        return Err(Dropped::Untagged);
    }
    let uri = match kind {
        NoteKind::ResourceUpdated => {
            let uri = params
                .and_then(|p| p.get("uri"))
                .and_then(Value::as_str)
                .filter(|u| u.len() <= MAX_URI_BYTES)
                .ok_or(Dropped::Oversize)?;
            Some(uri.to_owned())
        }
        _ => None,
    };
    Ok(UpstreamNote::Notice { kind, uri })
}

/// What a listen asked for, to intersect its acknowledgement with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Requested {
    pub kinds: KindSet,
    pub uris: Vec<String>,
}

impl Requested {
    /// The acknowledgement's `notifications`, cut to what was asked: its size
    /// is bounded by this listen's own URI budget, not by the peer.
    fn honoured(&self, acked: Option<&Value>) -> UpstreamNote {
        let flag = |key: &str| {
            acked
                .and_then(|n| n.get(key))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        };
        let listed: Vec<&str> = acked
            .and_then(|n| n.get("resourceSubscriptions"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        UpstreamNote::Ack {
            kinds: KindSet {
                resources_changed: self.kinds.resources_changed && flag("resourcesListChanged"),
                prompts_changed: self.kinds.prompts_changed && flag("promptsListChanged"),
            },
            uris: self
                .uris
                .iter()
                .filter(|u| listed.contains(&u.as_str()))
                .cloned()
                .collect(),
        }
    }

    /// The full filter as an acknowledgement: what a peer that answers the
    /// listen with the compatible response shape (§3) is taken to honour.
    pub(crate) fn as_full_ack(&self) -> UpstreamNote {
        UpstreamNote::Ack {
            kinds: self.kinds,
            uris: self.uris.clone(),
        }
    }
}

/// A JSON-RPC response with the listen's id, seen as the stream's
/// `first` frame or later. The compatible acknowledgement (§3) is only the
/// first frame, with a result of exactly `{_meta: {SUBSCRIPTION_ID: id}}`
/// and no `resultType: "complete"`; every other response is the end.
pub(crate) fn classify_response(
    first: bool,
    listen_id: &Value,
    result: Option<&Value>,
    requested: &Requested,
) -> UpstreamNote {
    let compatible = first
        && result.and_then(Value::as_object).is_some_and(|r| {
            r.len() == 1
                && r.get("_meta")
                    .and_then(Value::as_object)
                    .is_some_and(|m| m.len() == 1 && m.get(SUBSCRIPTION_ID) == Some(listen_id))
        });
    if compatible {
        requested.as_full_ack()
    } else {
        UpstreamNote::End
    }
}

#[cfg(test)]
#[path = "upstream_tap_tests.rs"]
mod tests;
