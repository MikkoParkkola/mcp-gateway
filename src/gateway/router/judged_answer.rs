// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The delivery record of a judged POST answer (MIK-7799): written after the
//! outbound judge, with the answer's `tenant_read` fields in it.

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::outbound::OutboundFrame;
use crate::protocol::JsonRpcResponse;
use crate::security::response_policy::ResponseCorrelation;

/// Record the delivery attempt of the judged `frame`, with its `tenant_read`
/// fields in the same record. When the log refuses the record
/// the answer is withheld: the frame becomes the audit-unavailable refusal,
/// and so does `finalized`, the answer a stored delivery keeps (`None` when
/// no execution stores one).
pub(super) async fn record_delivery(
    meta: &MetaMcp,
    mut frame: OutboundFrame,
    correlation: &ResponseCorrelation<'_>,
    finalized: Option<JsonRpcResponse>,
) -> (OutboundFrame, Option<JsonRpcResponse>) {
    let read = frame.take_record_fields();
    let logged = meta
        .record_delivery_of(
            frame
                .response()
                .expect("an answer frame stays an answer through its replacements"),
            correlation,
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
