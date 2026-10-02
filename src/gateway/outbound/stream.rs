// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Request-scoped notifications (design §4.3, H5 and H6): judged at the one
//! funnel every backend notification passes, `send_or_count`, and written
//! as SSE frames by [`sse_message`], which commits each as it is framed.

use std::sync::{Arc, OnceLock};

use super::{Admission, Guard, OutboundFrame, Payload, RejectionAudit, admission, judges};
use crate::protocol::JsonRpcNotification;
use crate::security::TransparencyLogger;

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

    /// Whether this stream judges at all; the default config does not.
    pub(crate) fn judges(&self) -> bool {
        judges(self.guard.as_deref())
    }

    /// Bind the caller this stream writes to. First binding wins: one
    /// request has one caller.
    pub(crate) fn bind(&self, key: String) {
        let _ = self.key.set(key);
    }

    /// Judge one notification for this stream. `None` when it is withheld;
    /// the rejection is then handed to the bounded detached audit. Before
    /// the caller is bound a tenant-bearing notification is unattributable.
    pub(crate) fn judge(&self, notification: JsonRpcNotification) -> Option<OutboundFrame> {
        let key = self.key.get().map(String::as_str);
        match admission(
            self.guard.as_deref(),
            key,
            Payload::Notification(notification),
            None,
        ) {
            Admission::Admitted(frame) => Some(frame),
            Admission::Blocked(evidence) => {
                self.audit.submit(evidence);
                None
            }
        }
    }
}

/// Frame `frame` as one `event: message` SSE event and commit it. `None`
/// for a withheld frame or one that does not serialize.
pub(crate) fn sse_message(frame: &OutboundFrame) -> Option<String> {
    let data = match &frame.payload {
        Payload::Notification(notification) => serde_json::to_string(notification),
        Payload::Response(response) => serde_json::to_string(response),
        Payload::Answer(value)
        | Payload::Request(value)
        | Payload::Event(value)
        | Payload::Callback(value) => serde_json::to_string(value),
        Payload::Withheld => return None,
    }
    .ok()?;
    frame.written();
    Some(format!("event: message\ndata: {data}\n\n"))
}
