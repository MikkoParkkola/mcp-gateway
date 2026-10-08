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
const TOOLS_CHANGED: &str = "notifications/tools/list_changed";
const ACKNOWLEDGED: &str = "notifications/subscriptions/acknowledged";

/// Which of the three upstream notifications a note stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum NoteKind {
    ResourceUpdated,
    ResourcesChanged,
    PromptsChanged,
    ToolsChanged,
}

/// The list-changed kinds a listen asked for or a peer honoured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KindSet {
    pub resources_changed: bool,
    pub prompts_changed: bool,
    pub tools_changed: bool,
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
    /// The peer answered the listen with `-32601`: it offers no listen, so
    /// the session backs off as for an HTTP 405 (MIK-7899).
    Unsupported,
}

impl UpstreamNote {
    /// The listen's last note: nothing of it follows.
    pub(crate) fn ends(&self) -> bool {
        matches!(self, Self::End | Self::Unsupported)
    }
}

/// JSON-RPC "method not found": the peer has no `subscriptions/listen`.
const METHOD_NOT_FOUND: i32 = -32601;

/// Why a frame was not turned into a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dropped {
    /// Not one of the three methods (or the acknowledgement).
    Other,
    /// A modern frame without the listen's tag, or with another one.
    Untagged,
    /// A `resources/updated` without a string `uri`, or one over the cap.
    Oversize,
    /// An acknowledgement after the listen's first frame (MIK-7898).
    Late,
}

/// The `notifications` filter a listen sends, from what it needs.
pub(crate) fn listen_filter(kinds: KindSet, uris: &[String]) -> Value {
    serde_json::json!({
        "notifications": {
            "toolsListChanged": kinds.tools_changed,
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
        TOOLS_CHANGED => NoteKind::ToolsChanged,
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

/// [`project`] for frame `first` of a modern listen: the acknowledgement
/// counts only as the first frame (§3); a later one is dropped.
pub(crate) fn project_listen(
    method: &str,
    params: Option<&Value>,
    listen_id: &Value,
    requested: &Requested,
    first: bool,
) -> Result<UpstreamNote, Dropped> {
    // The tag first: a frame of another listen, whatever its method, is not
    // this listen's frame at all (the tap never routes it here).
    if !tagged(params, listen_id) {
        return Err(Dropped::Untagged);
    }
    if method == ACKNOWLEDGED && !first {
        return Err(Dropped::Late);
    }
    project(method, params, Some((listen_id, requested)))
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
                tools_changed: self.kinds.tools_changed && flag("toolsListChanged"),
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
/// and no `resultType: "complete"`; a `-32601` error (`error_code`) is
/// `Unsupported`; every other response is the end.
pub(crate) fn classify_response(
    first: bool,
    listen_id: &Value,
    result: Option<&Value>,
    error_code: Option<i32>,
    requested: &Requested,
) -> UpstreamNote {
    if error_code == Some(METHOD_NOT_FOUND) {
        return UpstreamNote::Unsupported;
    }
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

/// One registered listen on a line-oriented transport (stdio, WebSocket).
struct Listen {
    tx: tokio::sync::mpsc::Sender<UpstreamNote>,
    requested: Requested,
    /// No frame of this listen has been routed yet.
    first: bool,
}

/// A filter over legacy `resources/updated` URIs.
type UriFilter = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Which legacy `resources/updated` URIs the session still watches (D5):
/// an update for any other is ignored before it can take a tap slot, so a
/// subscription that outlived its watcher never displaces a wanted notice.
#[derive(Clone, Default)]
pub(crate) struct Watched(Option<UriFilter>);

impl Watched {
    pub(crate) fn by(admits: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self(Some(std::sync::Arc::new(admits)))
    }

    /// Whether `note` may be delivered; every note but a URI update may.
    pub(crate) fn admits(&self, note: &UpstreamNote) -> bool {
        match (note, &self.0) {
            (
                UpstreamNote::Notice {
                    kind: NoteKind::ResourceUpdated,
                    uri: Some(uri),
                },
                Some(admits),
            ) => admits(uri),
            _ => true,
        }
    }
}

/// The reader loop's routing table for upstream notes (design §4). Every
/// send is `try_send`: the reader is the only reader of the peer's output
/// and must never park; a full channel drops and counts.
#[derive(Default)]
pub(crate) struct Taps {
    /// Listens by the canonical text of their JSON-RPC id.
    listens: parking_lot::Mutex<std::collections::HashMap<String, Listen>>,
    unsolicited: parking_lot::Mutex<Option<(tokio::sync::mpsc::Sender<UpstreamNote>, Watched)>>,
    /// Frames dropped: full tap, untagged, or oversize.
    pub drops: std::sync::atomic::AtomicU64,
}

impl Taps {
    /// Register listen `id`; its notes arrive on the returned receiver.
    pub(crate) fn listen(
        &self,
        id: &Value,
        requested: Requested,
    ) -> tokio::sync::mpsc::Receiver<UpstreamNote> {
        let (tx, rx) = tokio::sync::mpsc::channel(TAP_CAPACITY);
        self.listens.lock().insert(
            id.to_string(),
            Listen {
                tx,
                requested,
                first: true,
            },
        );
        rx
    }

    /// Stop routing to listen `id` (its receiver then sees `Closed`).
    pub(crate) fn forget(&self, id: &Value) {
        self.listens.lock().remove(&id.to_string());
    }

    /// Route the legacy peer's out-of-request notifications that `watched`
    /// admits to a receiver.
    pub(crate) fn unsolicited(
        &self,
        watched: Watched,
    ) -> tokio::sync::mpsc::Receiver<UpstreamNote> {
        let (tx, rx) = tokio::sync::mpsc::channel(TAP_CAPACITY);
        *self.unsolicited.lock() = Some((tx, watched));
        rx
    }

    /// The peer is gone: drop every sender so each receiver reports
    /// `Closed` instead of waiting for a frame that cannot come.
    pub(crate) fn clear(&self) {
        self.listens.lock().clear();
        *self.unsolicited.lock() = None;
    }

    fn drop_one(&self) {
        self.drops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Offer a peer notification. `true` when a tap consumed it (routed or
    /// dropped on its behalf); `false` leaves it to the existing routes.
    pub(crate) fn notification(&self, method: &str, params: Option<&Value>) -> bool {
        let tag = params
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(SUBSCRIPTION_ID));
        if let Some(tag) = tag {
            let mut listens = self.listens.lock();
            if let Some(listen) = listens.get_mut(&tag.to_string()) {
                let first = std::mem::replace(&mut listen.first, false);
                // The last slot stays free for the listen's terminal answer, so
                // a full tap still reports `Unsupported` rather than `Closed`.
                let routed = project_listen(method, params, tag, &listen.requested, first)
                    .is_ok_and(|note| listen.tx.capacity() > 1 && listen.tx.try_send(note).is_ok());
                if !routed {
                    self.drop_one();
                }
                return true;
            }
        }
        let guard = self.unsolicited.lock();
        let Some((tx, watched)) = guard.as_ref() else {
            return false;
        };
        match project(method, params, None) {
            Ok(note) => {
                if watched.admits(&note) && tx.try_send(note).is_err() {
                    self.drop_one();
                }
                true
            }
            Err(Dropped::Other) => false,
            Err(_) => {
                self.drop_one();
                true
            }
        }
    }

    /// [`Self::response`] for a transport's typed response.
    pub(crate) fn response_to(
        &self,
        id: &crate::protocol::RequestId,
        result: Option<&Value>,
        error: Option<&crate::protocol::JsonRpcError>,
    ) -> bool {
        serde_json::to_value(id).is_ok_and(|id| self.response(&id, result, error.map(|e| e.code)))
    }

    /// Offer a response (`result`, or an error's `error_code`). `true` when
    /// its id is a registered listen: the compatible first-frame
    /// acknowledgement is routed, anything else ends the listen, whose sender
    /// is removed whether or not the last note fit, so a full channel still
    /// reports the end as `Closed`.
    pub(crate) fn response(
        &self,
        id: &Value,
        result: Option<&Value>,
        error_code: Option<i32>,
    ) -> bool {
        let key = id.to_string();
        let mut listens = self.listens.lock();
        let Some(listen) = listens.get_mut(&key) else {
            return false;
        };
        let note = classify_response(listen.first, id, result, error_code, &listen.requested);
        listen.first = false;
        let end = note.ends();
        if listen.tx.try_send(note).is_err() {
            self.drop_one();
        }
        if end {
            listens.remove(&key);
        }
        true
    }
}

/// The notes of one open listen or unsolicited stream. Dropping it ends the
/// stream upstream: the guard cancels what the transport opened.
pub(crate) struct FrameStream {
    pub rx: tokio::sync::mpsc::Receiver<UpstreamNote>,
    _guard: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl FrameStream {
    pub(crate) fn new(rx: tokio::sync::mpsc::Receiver<UpstreamNote>) -> Self {
        Self { rx, _guard: None }
    }

    pub(crate) fn guarded(
        rx: tokio::sync::mpsc::Receiver<UpstreamNote>,
        guard: impl std::any::Any + Send + Sync,
    ) -> Self {
        Self {
            rx,
            _guard: Some(Box::new(guard)),
        }
    }
}

/// Why a transport could not open a stream.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The peer offers no such stream (405, or this era has none): not worth
    /// a fast retry.
    Unsupported,
    /// The session expired (404); the next attempt re-establishes it.
    Expired,
    Failed(crate::Error),
}

impl From<crate::Error> for Refused {
    fn from(error: crate::Error) -> Self {
        Self::Failed(error)
    }
}

/// What the events listener needs of a transport (design §4, ruling B): a
/// crate-private side trait, so the public `Transport` is unchanged.
/// `self: Arc<Self>` lets a stream's guard hold a `Weak` of the transport,
/// which never counts toward the strong count a restart waits on.
#[async_trait::async_trait]
pub(crate) trait UpstreamListen: Send + Sync {
    /// Open a modern `subscriptions/listen` for `requested`.
    async fn listen(
        self: std::sync::Arc<Self>,
        requested: Requested,
    ) -> Result<FrameStream, Refused>;

    /// The legacy peer's out-of-request notifications.
    async fn unsolicited(
        self: std::sync::Arc<Self>,
        watched: Watched,
    ) -> Result<FrameStream, Refused>;

    /// The HTTP transport this connection detected, read live: `Some(true)`
    /// for Streamable HTTP, `Some(false)` for the SSE handshake, `None`
    /// before it is known and for every other transport (MIK-7969).
    fn detected_streamable(&self) -> Option<bool> {
        None
    }

    /// Where a legacy `resources/subscribe` sent now would land (D5).
    /// The default names the transport instance alone as the holder.
    fn legacy_pin(&self) -> LegacyPin {
        LegacyPin::default()
    }

    /// `resources/subscribe` (or `unsubscribe`) of `uri` on exactly the
    /// holder `pin` names, on this transport: never re-sent on a healed
    /// session or another transport, so its answer is that holder's.
    async fn legacy_interest(
        self: std::sync::Arc<Self>,
        pin: LegacyPin,
        uri: &str,
        subscribe: bool,
    ) -> crate::Result<crate::protocol::JsonRpcResponse>;
}

/// The holder a legacy call is pinned to: beyond the transport instance,
/// an HTTP session, carried by the call and hashed for the ledger. The id
/// itself (replayable) stays in memory and is never logged.
#[derive(Clone, Default)]
pub(crate) struct LegacyPin {
    pub holder: u64,
    pub session: Option<String>,
}

/// `resources/subscribe` or `resources/unsubscribe`.
pub(crate) fn interest_method(subscribe: bool) -> &'static str {
    if subscribe {
        "resources/subscribe"
    } else {
        "resources/unsubscribe"
    }
}

#[cfg(test)]
#[path = "upstream_tap_tests.rs"]
mod tests;
