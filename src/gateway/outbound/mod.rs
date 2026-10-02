// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The outbound writer (MIK-7116.MIN.2, design option C,
//! docs/design/2026-10-01-min2-min4-tenant-reads.md §4).
//!
//! Every frame the gateway sends a caller is an [`OutboundFrame`], and only
//! the judge in this module builds one. A frame is judged once, on its final
//! content, against the process's read history for the `caller_key` it is
//! bound to, and only a sink in this module writes it.
//!
//! SKELETON: the public shape the stream, stdio and callback writers build
//! against. The judge does not judge yet: every frame passes unassessed.

// The skeleton has no production caller until the writers are wired.
#![cfg_attr(not(test), allow(dead_code))]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::events::CallbackFailure;
use crate::protocol::{JsonRpcNotification, JsonRpcResponse};
use crate::security::TransparencyLogger;
use crate::security::firewall::Firewall;
use crate::security::firewall::tenant_reads::{ReadAttribution, ReadVerdict, RejectionEvidence};

/// The content of one frame, typed as it is built; never converted to a
/// `Value` tree on the fast path.
#[derive(Debug)]
pub(crate) enum Payload {
    /// An answer: result or error.
    Response(JsonRpcResponse),
    /// A notification.
    Notification(JsonRpcNotification),
    /// A server-to-client request, including proxy request envelopes.
    Request(Value),
    /// An SSE document that is not JSON-RPC (webhook bodies).
    Event(Value),
    /// A MIK-7630 event body for an HTTPS callback.
    Callback(Value),
    /// A stdio JSON-RPC array; items judged one by one.
    Batch(Vec<OutboundFrame>),
}

/// The judgement a frame carries: immutable once made, and kept as evidence
/// when a late replacer swaps the frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Assessment {
    /// `None` when the frame was within the rule.
    pub(crate) verdict: Option<ReadVerdict>,
    /// The tenants the frame named, hashed.
    pub(crate) attribution: ReadAttribution,
}

/// A judged frame. Private fields and no accessor to the payload: judged
/// content cannot be detached and changed, only written by a sink here.
#[derive(Debug)]
pub(crate) struct OutboundFrame {
    payload: Payload,
    assessment: Option<Assessment>,
    /// The `caller_key` the frame was judged for; a sink bound to another key
    /// drops it.
    key: Option<Arc<str>>,
}

impl OutboundFrame {
    /// The verdict, for records and tests; `None` when unassessed or within
    /// the rule.
    pub(crate) fn verdict(&self) -> Option<ReadVerdict> {
        self.assessment.as_ref().and_then(|a| a.verdict)
    }

    /// The judgement this frame carries, if it was assessed.
    pub(crate) fn assessment(&self) -> Option<&Assessment> {
        self.assessment.as_ref()
    }
}

/// The outcome of judging a frame that is withheld rather than replaced when
/// blocked: a notification, a server-to-client request, an event delivery.
#[derive(Debug)]
pub(crate) enum Admission {
    /// Write it through a sink.
    Admitted(OutboundFrame),
    /// Withhold it; audit the evidence (async producers await
    /// [`audit_rejection`]; sync producers hand it to [`RejectionAudit`]).
    Blocked(RejectionEvidence),
}

/// The attribution of a raw value under the firewall's `arg_keys`, taken
/// before a transform or a redaction can drop fields (§4.4). An outbox
/// record carries it to the delivery.
pub(crate) fn attribute(firewall: &Firewall, value: &Value) -> ReadAttribution {
    let _ = (firewall, value);
    ReadAttribution::default()
}

/// Judge a frame carrying backend-derived content for `key`. `request` is
/// the params of the request it answers; `hidden` is attribution the frame
/// no longer shows (pre-transform, cached, stored).
pub(crate) fn delivered(
    firewall: &Firewall,
    key: Option<&str>,
    payload: Payload,
    request: Option<&Value>,
    hidden: Option<&ReadAttribution>,
) -> OutboundFrame {
    let _ = (firewall, request, hidden);
    OutboundFrame {
        payload,
        assessment: None,
        key: key.map(Arc::from),
    }
}

/// Judge a frame that is withheld, not replaced, when blocked.
pub(crate) fn admit(
    firewall: &Firewall,
    key: Option<&str>,
    payload: Payload,
    hidden: Option<&ReadAttribution>,
) -> Admission {
    Admission::Admitted(delivered(firewall, key, payload, None, hidden))
}

/// E1: judge a MIK-7630 event delivery for the subscription principal.
/// `attribution` is what the outbox record carries from before the event
/// firewall's redaction; a record without it counts as unread.
pub(crate) fn callback_frame(
    firewall: &Firewall,
    principal: &str,
    body: Value,
    attribution: Option<&ReadAttribution>,
) -> Admission {
    admit(
        firewall,
        Some(principal),
        Payload::Callback(body),
        attribution,
    )
}

/// What the callback sender reports back to [`send_callback`].
#[derive(Debug)]
pub(crate) enum CallbackSend {
    /// Nothing left the process (a refused literal, DNS or connect failure
    /// before any byte): the frame's reservation is released.
    NotSent(CallbackFailure),
    /// The body was handed to the HTTP client: the frame commits, whatever
    /// the answer, because a recipient can read and then fail.
    Sent(Result<Vec<u8>, CallbackFailure>),
}

/// E1 sink: serialize `frame` and hand the bytes to `post` (the events
/// lane's signed `CallbackClient::post`). `principal` is the subscription's;
/// a frame judged for another key is dropped.
///
/// # Errors
/// The sender's failure, or `ConnectionRefused` for a frame bound to another
/// principal.
pub(crate) async fn send_callback<F, Fut>(
    frame: OutboundFrame,
    principal: &str,
    post: F,
) -> Result<Vec<u8>, CallbackFailure>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = CallbackSend>,
{
    let _ = principal;
    let body = match frame.payload {
        Payload::Callback(body) => serde_json::to_vec(&body).unwrap_or_default(),
        _ => return Err(CallbackFailure::ConnectionRefused),
    };
    match post(body).await {
        CallbackSend::NotSent(failure) => Err(failure),
        CallbackSend::Sent(result) => result,
    }
}

/// The rejection audit for an async producer: one `tenant_read` record of
/// `evidence`, through the bounded append. A failure is logged; the content
/// is withheld either way.
pub(crate) async fn audit_rejection(log: &Arc<TransparencyLogger>, evidence: &RejectionEvidence) {
    let _ = (log, evidence);
}

/// The rejection audit for sync producers (`send_or_count`): each rejection
/// is handed to one detached task, admitted by a bounded non-blocking permit
/// (F4). Saturation is counted as an audit failure.
pub(crate) struct RejectionAudit {
    log: Option<Arc<TransparencyLogger>>,
    saturated: AtomicU64,
}

impl RejectionAudit {
    /// An auditor writing to `log` with at most `permits` audits in flight.
    pub(crate) fn new(log: Option<Arc<TransparencyLogger>>, permits: usize) -> Self {
        let _ = permits;
        Self {
            log,
            saturated: AtomicU64::new(0),
        }
    }

    /// Hand `evidence` to a detached audit task. Never blocks. Returns whether
    /// a task was spawned; `false` means saturation, recorded.
    pub(crate) fn submit(&self, evidence: RejectionEvidence) -> bool {
        let log = self.log.clone();
        tokio::spawn(async move {
            if let Some(log) = log {
                audit_rejection(&log, &evidence).await;
            }
        });
        true
    }

    /// Rejections whose audit was refused for want of a permit.
    pub(crate) fn saturated(&self) -> u64 {
        self.saturated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
