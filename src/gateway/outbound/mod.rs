// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The outbound writer (MIK-7116.MIN.2, design option C,
//! docs/design/2026-10-01-min2-min4-tenant-reads.md §4).
//!
//! Every frame the gateway sends a caller is an [`OutboundFrame`], and only
//! the judge in this module builds one. A frame is judged once, on its final
//! content, against the process's read history for the `caller_key` it is
//! bound to, and only a sink in this module writes it. A sink commits the
//! frame's reservation when it writes; a frame dropped unwritten commits
//! nothing.

// Without the `firewall` feature nothing is judged: every frame takes the
// unjudged fast path and the judging half is unreachable.
#![cfg_attr(not(feature = "firewall"), allow(dead_code))]

mod audit;
mod callback;
mod http;
#[cfg(feature = "firewall")]
mod judge;
mod reply;
mod stdio;
mod stream;

use std::sync::Arc;

use serde_json::Value;

use crate::protocol::{JsonRpcNotification, JsonRpcResponse};
use crate::security::tenant_reads::{ReadAttribution, ReadTicket, ReadVerdict};

pub(crate) use audit::{REJECTION_AUDIT_PERMITS, RejectionAudit, audit_rejection, recorded};
pub(crate) use callback::{CallbackSend, callback_frame, send_callback};
pub(crate) use http::{HeldAnswerId, carry_record, emit_http, emit_http_checked, to_http};
#[cfg(all(test, feature = "firewall"))]
pub(crate) use judge::{admit, attribute, delivered};
pub(crate) use reply::{
    OutboundReply, gateway_reply, judged_reply, judged_reply_checked, stream_reply,
};
pub(crate) use stdio::StdioReads;
pub(crate) use stream::{SessionJudge, StreamJudge, StreamMark, sse_data, sse_message};

/// The firewall that carries the tenant guard and the read history. Without
/// the `firewall` feature nothing is judged, and this has no values.
#[cfg(feature = "firewall")]
pub(crate) use crate::security::firewall::Firewall as Guard;
/// The firewall that carries the tenant guard and the read history. Without
/// the `firewall` feature nothing is judged, and this has no values.
#[cfg(not(feature = "firewall"))]
#[derive(Debug)]
pub(crate) enum Guard {}

/// The content of one frame, typed as it is built; never converted to a
/// `Value` tree on the fast path.
#[derive(Debug, Clone)]
pub(crate) enum Payload {
    /// An answer: result or error.
    Response(JsonRpcResponse),
    /// A notification.
    Notification(JsonRpcNotification),
    /// An answer already rendered as a JSON value (the direct route).
    Answer(Value),
    /// A server-to-client request or a JSON-RPC document built as a value
    /// (bridged stdio requests, `subscriptions/listen` events).
    Request(Value),
    /// An SSE document that is not JSON-RPC (webhook bodies).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "session items are judged in place (StreamMark)")
    )]
    Event(Value),
    /// A MIK-7630 event body for an HTTPS callback.
    Callback(Value),
    /// A stdio JSON-RPC batch answer: items judged one by one, written as
    /// one array, each committed after the array is written (S1).
    Batch(Vec<OutboundFrame>),
    /// A blocked non-answer item: a sink writes nothing for it.
    Withheld,
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
/// A clone is a copy of the same frame (fan-out) and shares its ticket.
#[derive(Debug, Clone)]
pub(crate) struct OutboundFrame {
    payload: Payload,
    /// Boxed: most frames carry none, and inline it would push
    /// `Admission::Admitted` past the variant-size limit.
    assessment: Option<Box<Assessment>>,
    /// The history reservation; committed by the sink that writes the frame.
    ticket: Option<ReadTicket>,
    /// The `tenant_read` fields were taken by a record of the caller's own
    /// (MIK-7799): no standalone record is written for this frame.
    record_taken: bool,
    /// The `caller_key` the frame was judged for; a sink bound to another key
    /// drops it. `None` on the fast path, where nothing was judged.
    key: Option<Arc<str>>,
    /// Work committed once a sink writes this frame (MIK-7887.RECEIPT.3: a
    /// bridged prompt's relay receipt). Shared by fan-out clones and taken
    /// once; a replaced or withheld frame drops it uncommitted.
    delivery: Option<Arc<parking_lot::Mutex<Option<crate::gateway::input_bridge::DeliveryCommit>>>>,
    /// The continuation holds this answer carries (MIK-8176): handed off by
    /// the stdio writer as it takes the frame. A frame replaced, withheld or
    /// dropped before then carries none of them away, so they release.
    holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds,
}

impl OutboundFrame {
    /// The fast path: nothing to judge (attribution unconfigured, mode `off`,
    /// or no firewall). A move of the payload; no allocation, no lock.
    pub(crate) const fn unjudged(payload: Payload) -> Self {
        Self {
            payload,
            assessment: None,
            ticket: None,
            record_taken: false,
            key: None,
            delivery: None,
            holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
        }
    }

    /// The verdict; `None` when unassessed or within the rule.
    pub(crate) fn verdict(&self) -> Option<ReadVerdict> {
        self.assessment.as_ref().and_then(|a| a.verdict)
    }

    /// Whether the frame's content was withheld (an audit failure under
    /// fail-closed replaced it): nothing is left to write.
    pub(crate) const fn is_withheld(&self) -> bool {
        matches!(self.payload, Payload::Withheld)
    }

    /// Whether the frame, as it will be written, delivers a result: one the
    /// judge, an audit failure or a gate left in place, not a refusal that
    /// replaced it (a refusal carries no result). What a relay receipt may
    /// follow; a result beside an error is still delivered.
    pub(crate) fn delivers_result(&self) -> bool {
        match &self.payload {
            Payload::Response(response) => response.result.is_some() && !response.delivery_refusal,
            Payload::Answer(value) => value.get("result").is_some(),
            _ => false,
        }
    }

    /// The judgement this frame carries, if it was assessed.
    pub(crate) fn assessment(&self) -> Option<&Assessment> {
        self.assessment.as_deref()
    }

    /// Whether a sink bound to `destination` may write this frame. An
    /// unjudged frame carries no key and binds nowhere.
    fn bound_to(&self, destination: &str) -> bool {
        self.key.as_deref().is_none_or(|key| key == destination)
    }

    /// Commit as a sink would on writing it (tests only).
    #[cfg(test)]
    pub(crate) fn commit_for_test(&self) {
        self.written();
    }

    /// The sink wrote this frame: refresh its tenants' last-seen time. The
    /// pending reservation is released when the last copy goes.
    fn written(&self) {
        if let Some(ticket) = &self.ticket {
            ticket.emitted();
        }
    }

    /// A late replacer (an audit failure, a grant-slot failure) swaps this
    /// frame for a fixed gateway refusal. The refusal names no tenant, so it
    /// carries no ticket: the original reservation is dropped uncommitted,
    /// and its assessment stays as evidence.
    pub(crate) fn replaced_by(self, refusal: JsonRpcResponse) -> Self {
        Self {
            payload: Payload::Response(refusal),
            assessment: self.assessment,
            ticket: None,
            record_taken: self.record_taken,
            key: self.key,
            delivery: None,
            holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
        }
    }

    /// A non-answer frame that may not be written after all: nothing is
    /// sent, and its reservation is dropped uncommitted.
    pub(crate) fn withheld(self) -> Self {
        Self {
            payload: Payload::Withheld,
            assessment: self.assessment,
            ticket: None,
            record_taken: self.record_taken,
            key: self.key,
            delivery: None,
            holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
        }
    }

    /// This answer with the open request's holds it carries attached, for a
    /// sink that hands them off when it writes the frame (MIK-8176).
    pub(crate) fn carry_holds(mut self) -> Self {
        let result = match &self.payload {
            Payload::Response(answer) => answer.result.as_ref(),
            Payload::Answer(answer) => answer.get("result"),
            _ => None,
        };
        if let Some(result) = result {
            self.holds = crate::gateway::meta_mcp::sealed_hold::carried(result);
        }
        self
    }

    /// Hand off the holds this frame (and each frame a batch holds) carries:
    /// the sink is taking it to write.
    pub(crate) fn hand_off_holds(&self) {
        crate::gateway::meta_mcp::sealed_hold::hand_off(&self.holds);
        if let Payload::Batch(items) = &self.payload {
            for item in items {
                item.hand_off_holds();
            }
        }
    }

    /// The `tenant_read` fields of this judgement, for a caller that writes
    /// them inside a record of its own (the answer's delivery record,
    /// MIK-7799). Taken once: the sink then writes no standalone record.
    pub(crate) fn take_record_fields(&mut self) -> Option<serde_json::Map<String, Value>> {
        if self.record_taken {
            return None;
        }
        let fields = self
            .assessment
            .as_ref()
            .map(|a| a.record_fields(self.key.as_deref()))
            .filter(|fields| !fields.is_empty())?;
        self.record_taken = true;
        Some(fields)
    }

    /// The answer's id, for a replacement that must keep it.
    pub(crate) fn answer_id(&self) -> Option<crate::protocol::RequestId> {
        match &self.payload {
            Payload::Response(response) => response.id.clone(),
            Payload::Answer(value) => value
                .get("id")
                .and_then(|id| serde_json::from_value(id.clone()).ok()),
            _ => None,
        }
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
    Blocked(crate::security::tenant_reads::RejectionEvidence),
}

/// Whether `guard` judges frames at all: attribution configured and the mode
/// not `off`. Callers form a `caller_key` only when it does, so the default
/// deployment allocates nothing for the verdict.
pub(crate) fn judges(guard: Option<&Guard>) -> bool {
    #[cfg(feature = "firewall")]
    {
        guard.is_some_and(|g| judge::judging(g).is_some())
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = guard;
        false
    }
}

/// Judge an answer carrying backend-derived content for `key`. `request` is
/// the params of the request it answers; `hidden` is attribution the answer
/// no longer shows (pre-transform, cached, stored).
pub(crate) fn answer(
    guard: Option<&Guard>,
    key: Option<&str>,
    response: JsonRpcResponse,
    request: Option<&Value>,
    hidden: Option<&ReadAttribution>,
) -> OutboundFrame {
    #[cfg(feature = "firewall")]
    if let Some(guard) = guard {
        return judge::delivered(guard, key, Payload::Response(response), request, hidden);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (guard, key, request, hidden);
    OutboundFrame::unjudged(Payload::Response(response))
}

/// [`answer`] for an answer already rendered as a JSON value (the direct
/// route, H9).
pub(crate) fn answer_value(
    guard: Option<&Guard>,
    key: Option<&str>,
    body: Value,
    request: Option<&Value>,
    hidden: Option<&ReadAttribution>,
) -> OutboundFrame {
    #[cfg(feature = "firewall")]
    if let Some(guard) = guard {
        return judge::delivered(guard, key, Payload::Answer(body), request, hidden);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (guard, key, request, hidden);
    OutboundFrame::unjudged(Payload::Answer(body))
}

/// Judge a frame that is withheld, not replaced, when blocked.
pub(crate) fn admission(
    guard: Option<&Guard>,
    key: Option<&str>,
    payload: Payload,
    hidden: Option<&ReadAttribution>,
) -> Admission {
    #[cfg(feature = "firewall")]
    if let Some(guard) = guard {
        return judge::admit(guard, key, payload, hidden);
    }
    #[cfg(not(feature = "firewall"))]
    let _ = (guard, key, hidden);
    Admission::Admitted(OutboundFrame::unjudged(payload))
}

/// The attribution of a raw value before a transform or a redaction drops
/// fields (§4.4); `None` when nothing is judged.
pub(crate) fn raw_attribution(guard: Option<&Guard>, value: &Value) -> Option<ReadAttribution> {
    if !judges(guard) {
        return None;
    }
    #[cfg(feature = "firewall")]
    {
        guard.map(|g| judge::attribute(g, value))
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = value;
        None
    }
}

/// The `arg_keys` an attribution was taken under: an outbox record carries
/// them, and its attribution counts only while they are still the policy.
pub(crate) fn attribution_keys(guard: Option<&Guard>) -> Vec<String> {
    #[cfg(feature = "firewall")]
    {
        guard.map_or_else(Vec::new, |g| g.tenant_guard().config().arg_keys.clone())
    }
    #[cfg(not(feature = "firewall"))]
    {
        let _ = guard;
        Vec::new()
    }
}

/// Run `fut` inside a read scope when `guard` judges, so the inner
/// dispatches note what they read before any transform (§4.4). Returns what
/// was noted; a judge inside `fut` reads it so far with [`noted_reads`].
pub(crate) async fn read_scoped<F: std::future::Future>(
    guard: Option<Arc<Guard>>,
    fut: F,
) -> (F::Output, Option<ReadAttribution>) {
    #[cfg(feature = "firewall")]
    if let Some(guard) = guard.filter(|g| judges(Some(g))) {
        let (output, noted) = crate::security::tenant_reads::with_read_scope(guard, fut).await;
        return (output, Some(noted));
    }
    #[cfg(not(feature = "firewall"))]
    let _ = guard;
    (fut.await, None)
}

/// What the read scope around this task has noted so far.
pub(crate) fn noted_reads() -> Option<ReadAttribution> {
    crate::security::tenant_reads::noted()
}

#[cfg(all(test, feature = "firewall"))]
mod tests;
