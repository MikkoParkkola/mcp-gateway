// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Request-scoped notifications (design §4.3, H5 and H6): judged at the one
//! funnel every backend notification passes, `send_or_count`, and written
//! as SSE frames by [`sse_message`], which commits each as it is framed.

use std::sync::{Arc, OnceLock};

use super::{
    Admission, Guard, OutboundFrame, Payload, RejectionAudit, admission, judges, raw_attribution,
};
use crate::protocol::JsonRpcNotification;
use crate::security::TransparencyLogger;
use crate::security::tenant_reads::ReadAttribution;

/// The judge of one POST stream's notifications: the firewall known when the
/// stream opens, the `caller_key` bound once the dispatch has resolved who is
/// asking, and the process's rejection auditor.
pub(crate) struct StreamJudge {
    guard: Option<Arc<Guard>>,
    key: OnceLock<String>,
    audit: Arc<RejectionAudit>,
    log: Option<Arc<TransparencyLogger>>,
}

impl std::fmt::Debug for StreamJudge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamJudge")
            .field("judging", &self.guard.is_some())
            .field("bound", &self.key.get().is_some())
            .finish_non_exhaustive()
    }
}

impl StreamJudge {
    /// A judge for one request's stream.
    pub(crate) fn new(
        guard: Option<Arc<Guard>>,
        audit: Arc<RejectionAudit>,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Self {
        Self {
            guard,
            key: OnceLock::new(),
            audit,
            log,
        }
    }

    /// Write `frame`'s `tenant_read` event before it is framed (§4.7).
    pub(crate) async fn record(&self, frame: OutboundFrame) -> OutboundFrame {
        super::recorded(frame, self.log.as_ref()).await
    }

    /// Write the stream's final answer's pending read record (after every
    /// late replacer), or replace the answer when it fails closed.
    pub(crate) async fn emit(
        &self,
        response: axum::response::Response,
    ) -> axum::response::Response {
        super::emit_http(response, self.log.as_ref()).await
    }

    /// Whether this stream judges at all; the default config does not.
    pub(crate) fn judges(&self) -> bool {
        judges(self.guard.as_deref())
    }

    /// Bind the caller this stream writes to. First binding wins: one
    /// request has one caller.
    pub(crate) fn bind(&self, key: String) {
        let _ = self.key.set(key);
    }

    /// Judge one document (a `subscriptions/listen` event) for this stream;
    /// `None` when it is withheld.
    pub(crate) fn judge_document(&self, document: serde_json::Value) -> Option<OutboundFrame> {
        self.admit(Payload::Request(document))
    }

    /// Judge one document that carries a stored task's output. The attribution
    /// kept beside a stored value is not persisted for a task, so with
    /// attribution on the read is not attributable, as a `tasks/get` of the
    /// same task treats it.
    pub(crate) fn judge_restored_document(
        &self,
        document: serde_json::Value,
    ) -> Option<OutboundFrame> {
        let hidden = self.unattributed_read();
        self.admit_hiding(Payload::Request(document), hidden.as_ref())
    }

    /// A read that cannot be attributed: `Some` only when this stream
    /// attributes reads.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    fn unattributed_read(&self) -> Option<ReadAttribution> {
        #[cfg(feature = "firewall")]
        {
            self.guard
                .as_deref()
                .filter(|guard| guard.tenant_guard().attributes())
                .map(|_| ReadAttribution::of(std::collections::BTreeSet::new(), true))
        }
        #[cfg(not(feature = "firewall"))]
        {
            None
        }
    }

    /// Judge the acknowledgement that opens a `subscriptions/listen` stream.
    /// The listen request's own params are a read by this caller too (they
    /// can name a tenant), though the acknowledgement does not echo them.
    pub(crate) fn judge_acknowledgement(
        &self,
        document: serde_json::Value,
        request_params: Option<&serde_json::Value>,
    ) -> Option<OutboundFrame> {
        let hidden = request_params.and_then(|p| raw_attribution(self.guard.as_deref(), p));
        self.admit_hiding(Payload::Request(document), hidden.as_ref())
    }

    fn admit(&self, payload: Payload) -> Option<OutboundFrame> {
        self.admit_hiding(payload, None)
    }

    fn admit_hiding(
        &self,
        payload: Payload,
        hidden: Option<&ReadAttribution>,
    ) -> Option<OutboundFrame> {
        let key = self.key.get().map(String::as_str);
        match admission(self.guard.as_deref(), key, payload, hidden) {
            Admission::Admitted(frame) => Some(frame),
            Admission::Blocked(evidence) => {
                self.audit.submit(evidence);
                None
            }
        }
    }

    /// Judge one notification for this stream. `None` when it is withheld;
    /// the rejection is then handed to the bounded detached audit. Before
    /// the caller is bound a tenant-bearing notification is unattributable.
    pub(crate) fn judge(&self, notification: JsonRpcNotification) -> Option<OutboundFrame> {
        self.admit(Payload::Notification(notification))
    }
}

/// Frame `frame` as one `event: message` SSE event and commit it. `None`
/// for a withheld frame or one that does not serialize.
pub(crate) fn sse_message(frame: &OutboundFrame) -> Option<String> {
    sse_data(frame).map(|data| format!("event: message\ndata: {data}\n\n"))
}

/// The `data` of `frame`'s SSE event, committed as it is handed over.
pub(crate) fn sse_data(frame: &OutboundFrame) -> Option<String> {
    let data = match &frame.payload {
        Payload::Notification(notification) => serde_json::to_string(notification),
        Payload::Response(response) => serde_json::to_string(response),
        Payload::Answer(value)
        | Payload::Request(value)
        | Payload::Event(value)
        | Payload::Callback(value) => serde_json::to_string(value),
        Payload::Batch(_) | Payload::Withheld => return None,
    }
    .ok()?;
    frame.written();
    Some(data)
}

/// The judge of the GET session streams (H7): installed on the multiplexer
/// once the router is built, so every fan-out judges each session's copy for
/// that session's caller at enqueue.
pub(crate) struct SessionJudge {
    guard: Arc<Guard>,
    audit: Arc<RejectionAudit>,
    log: Option<Arc<TransparencyLogger>>,
}

impl std::fmt::Debug for SessionJudge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionJudge").finish_non_exhaustive()
    }
}

/// One session-stream item's judgement: the reservation the stream commits
/// when it writes the item, and the evidence it records then. A clone is a
/// copy of the same item.
#[derive(Debug, Clone)]
pub(crate) struct StreamMark(OutboundFrame);

impl StreamMark {
    /// The stream is writing the item now: record the judgement, then
    /// commit. A record that fails under `FailClosed` withholds the item.
    pub(crate) async fn written(&self, judge: Option<&SessionJudge>) -> bool {
        let log = judge.and_then(|j| j.log.as_ref());
        if !super::audit::record(&self.0, log).await {
            return false;
        }
        self.0.written();
        true
    }
}

impl SessionJudge {
    /// A judge over `guard`'s tenant guard and read history, or `None` when
    /// it judges nothing (the default config).
    pub(crate) fn new(
        guard: Option<Arc<Guard>>,
        audit: Arc<RejectionAudit>,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Option<Self> {
        let guard = guard.filter(|g| judges(Some(g)))?;
        Some(Self { guard, audit, log })
    }

    /// The attribution of a raw inbound value before a transform drops
    /// fields (a webhook body, §4.4).
    pub(crate) fn raw(
        &self,
        value: &serde_json::Value,
    ) -> Option<crate::security::tenant_reads::ReadAttribution> {
        super::raw_attribution(Some(&self.guard), value)
    }

    /// Judge one session's copy of an item for that session's caller. `Err`
    /// when it is withheld; the rejection is then audited, bounded.
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unnecessary_wraps, clippy::unused_self)
    )]
    pub(crate) fn judge(
        &self,
        key: Option<&str>,
        data: &serde_json::Value,
        event_type: &str,
        hidden: Option<&crate::security::tenant_reads::ReadAttribution>,
    ) -> Result<Option<StreamMark>, ()> {
        #[cfg(feature = "firewall")]
        {
            match super::judge::admit_stream_item(&self.guard, key, data, event_type, hidden) {
                Admission::Admitted(frame) if frame.assessment.is_some() => {
                    Ok(Some(StreamMark(frame)))
                }
                Admission::Admitted(_) => Ok(None),
                Admission::Blocked(evidence) => {
                    self.audit.submit(evidence);
                    Err(())
                }
            }
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (key, data, event_type, hidden);
            Ok(None)
        }
    }
}
