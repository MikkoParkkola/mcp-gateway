// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A stdio answer's delivery record follows the read judge (MIK-7920), as on
//! `POST /mcp`. The dispatch finalizes the content and hands the answer back
//! unrecorded; once the serve loop has judged it, the meta route's recorder
//! writes one record over the frame as served, with its `tenant_read` fields
//! (MIK-7799). Then the execution settles on what that record left, and the
//! relay receipts commit only when a result is delivered.

use serde_json::Value;

use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::admission::SyncLease;
use crate::gateway::meta_mcp::invoke::relay::StagedReceipts;
use crate::gateway::meta_mcp::signing::SigningInvocationContext;
use crate::gateway::outbound::{OutboundFrame, StdioReads};
use crate::protocol::JsonRpcResponse;
use crate::security::response_policy::ResponseCorrelation;
use crate::security::tenant_reads::ReadAttribution;

/// What a stdio dispatch answers with.
pub(super) enum StdioAnswer {
    /// Built by the gateway before anything ran (a bad signing envelope, a
    /// parse error): judged as it is, with no delivery record.
    Built(Value),
    /// Finalized content whose delivery record waits for the judge.
    Finalized(Box<Finalized>),
}

/// A finalized answer and what its delivery record and settlement need.
pub(super) struct Finalized {
    response: JsonRpcResponse,
    /// The correlation's `external_tool`.
    tool: String,
    execution: Option<SyncLease>,
    signing: Option<SigningInvocationContext>,
}

impl StdioAnswer {
    pub(super) fn finalized(
        response: JsonRpcResponse,
        tool: String,
        execution: Option<SyncLease>,
        signing: Option<SigningInvocationContext>,
    ) -> Self {
        Self::Finalized(Box::new(Finalized {
            response,
            tool,
            execution,
            signing,
        }))
    }

    /// The tail of `Gateway::judge_and_commit` with no judge, for a
    /// caller that judges no frame (a test): recorded and settled the same.
    #[cfg(test)]
    pub(super) async fn delivered_unjudged(
        self,
        meta: &MetaMcp,
        session_id: &str,
    ) -> OutboundFrame {
        match self {
            Self::Built(value) => OutboundFrame::gateway_stdio(value),
            Self::Finalized(answer) => {
                let (response, settle) = answer.split();
                let frame = crate::gateway::outbound::answer(None, None, response, None, None);
                deliver(meta, frame, session_id, settle, None).await
            }
        }
    }
}

impl Finalized {
    /// The response to judge, and what settles it: the stored delivery is a
    /// copy of it, taken only when an execution stores one.
    fn split(self) -> (JsonRpcResponse, Settle) {
        let stored = self.execution.as_ref().map(|_| self.response.clone());
        let settle = Settle {
            tool: self.tool,
            execution: self.execution,
            signing: self.signing,
            stored,
        };
        (self.response, settle)
    }
}

/// What a recorded answer settles with.
struct Settle {
    tool: String,
    execution: Option<SyncLease>,
    signing: Option<SigningInvocationContext>,
    stored: Option<JsonRpcResponse>,
}

impl super::Gateway {
    /// Judge one stdio answer, record its delivery over the frame the judge
    /// left, settle its execution, then record the receipts its dispatch
    /// staged, only when the frame as written delivers a result: a read the
    /// judge withholds, or an audit failure replaces, leaves none.
    pub(super) async fn judge_and_commit(
        meta: &MetaMcp,
        reads: &StdioReads,
        session_id: &str,
        (answer, params, hidden): (StdioAnswer, Option<&Value>, Option<&ReadAttribution>),
        staged: StagedReceipts,
    ) -> OutboundFrame {
        let frame = match answer {
            StdioAnswer::Built(value) => reads.answer(value, params, hidden).await,
            StdioAnswer::Finalized(answer) => {
                let (response, settle) = answer.split();
                let frame = reads.judge(response, params, hidden);
                // The read is what the dispatch's scope noted: settlement
                // runs past that scope now (`complete_delivery_read`).
                deliver(meta, frame, session_id, settle, hidden.cloned()).await
            }
        };
        staged.commit(frame.delivers_result());
        frame
    }
}

/// Record the delivery of the judged `frame` (`POST /mcp`'s recorder), then
/// settle the execution on the answer the record left: the finalized one, or
/// the audit-unavailable refusal when the log refused the record.
async fn deliver(
    meta: &MetaMcp,
    frame: OutboundFrame,
    session_id: &str,
    settle: Settle,
    read: Option<ReadAttribution>,
) -> OutboundFrame {
    let correlation = ResponseCorrelation {
        session_id,
        caller: "stdio",
        external_server: "gateway",
        external_tool: &settle.tool,
        subject: None,
    };
    let (frame, stored) =
        crate::gateway::router::record_judged_delivery(meta, frame, &correlation, settle.stored)
            .await;
    if let (Some(execution), Some(stored)) = (settle.execution, stored) {
        execution.complete_delivery_read(&stored, settle.signing.as_ref(), read);
    }
    frame
}
