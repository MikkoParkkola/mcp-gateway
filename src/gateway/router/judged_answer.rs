// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The delivery record of a judged answer on `POST /mcp` and stdio (MIK-7799,
//! MIK-7920): written after the outbound judge, with the answer's
//! `tenant_read` fields in it.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::response_security::DeliveryCredential;
use crate::gateway::outbound::OutboundFrame;
use crate::protocol::JsonRpcResponse;
use crate::security::response_policy::ResponseCorrelation;

/// Record the delivery attempt of the judged `frame`, with its `tenant_read`
/// fields in the same record. When the log refuses the record
/// the answer is withheld: the frame becomes the audit-unavailable refusal,
/// and so does `finalized`, the answer a stored delivery keeps (`None` when
/// no execution stores one).
pub(in crate::gateway) async fn record_delivery(
    meta: &MetaMcp,
    mut frame: OutboundFrame,
    correlation: &ResponseCorrelation<'_>,
    credential: DeliveryCredential,
    mut finalized: Option<JsonRpcResponse>,
) -> (OutboundFrame, Option<JsonRpcResponse>) {
    let read = frame.take_record_fields();
    // A1: the grant slot's decisions are written before this record, and the
    // slot sealed, so a failed write refuses the answer here, before it is
    // recorded, and the stored delivery keeps that refusal too.
    if crate::gateway::meta_mcp::grant_audit::seal_open_slot()
        .await
        .is_err()
    {
        let mut refusal = MetaMcp::audit_unavailable_refusal(frame.answer_id());
        refusal.invocation_trace = frame.response().and_then(|r| r.invocation_trace.clone());
        crate::gateway::delivery_facts::raise(
            crate::gateway::delivery_facts::ResponseEffect::Refused,
        );
        finalized = finalized.map(|_| refusal.clone());
        frame = frame.replaced_by(refusal);
    }
    let logged = meta
        .record_delivery_of(
            frame
                .response()
                .expect("an answer frame stays an answer through its replacements"),
            correlation,
            credential,
            read,
        )
        .await;
    if logged {
        return (frame, finalized);
    }
    let refusal = MetaMcp::audit_unavailable_refusal(frame.answer_id());
    let stored = finalized.map(|_| refusal.clone());
    (frame.replaced_by(refusal), stored)
}

/// Record the delivery of an error `tools/call` returned already rendered (a
/// refusal before dispatch), which skips the judged tail.
///
/// No scan saw it, so the record states only a refusal raised in the cell and
/// omits both fields otherwise (A2). When the record's own write fails, the
/// answer becomes the audit-unavailable refusal, sent with that refusal's
/// status. A response with no `ErrorFrame` is returned as it is.
pub(in crate::gateway) async fn record_error_exit(
    meta: &MetaMcp,
    response: axum::response::Response,
    correlation: &ResponseCorrelation<'_>,
    credential: DeliveryCredential,
    session_id: &str,
) -> axum::response::Response {
    let Some(super::helpers::ErrorFrame { frame: rpc, trace }) = response
        .extensions()
        .get::<super::helpers::ErrorFrame>()
        .cloned()
    else {
        return response;
    };
    crate::gateway::delivery_facts::unvouched();
    let sent = rpc.error.as_ref().map(|e| (e.code, e.message.clone()));
    let frame = OutboundFrame::unjudged(crate::gateway::outbound::Payload::Response(rpc));
    let correlation = ResponseCorrelation {
        trace_id: trace.as_deref(),
        ..*correlation
    };
    let (frame, _) = record_delivery(meta, frame, &correlation, credential, None).await;
    let recorded = frame
        .response()
        .and_then(|r| r.error.as_ref())
        .map(|e| (e.code, e.message.clone()));
    if recorded == sent {
        return response;
    }
    let status = frame
        .response()
        .and_then(super::handlers::refusal_status)
        .unwrap_or(response.status());
    crate::gateway::outbound::to_http(frame, status, session_id)
}
