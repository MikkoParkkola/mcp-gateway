// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A stdio answer's delivery record follows the read judge (MIK-7920), as on
//! `POST /mcp`. The dispatch finalizes the content and hands the answer back
//! unrecorded; once the serve loop has judged it, the meta route's recorder
//! writes one record over the frame as served, with its `tenant_read` fields
//! (MIK-7799). Then the execution settles on what that record left, and the
//! relay receipts commit only when a result is delivered.

use serde_json::Value;

use crate::gateway::gateway_writes::WriteRecord;
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
    /// What the gateway wrote into `response`, taken inside the dispatch's
    /// scope, which settlement outlives (MIK-7991).
    writes: WriteRecord,
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
            writes: crate::gateway::gateway_writes::recorded(),
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
                deliver(meta, frame, session_id, settle, None).await.0
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
            trace: self.response.invocation_trace.clone(),
            tool: self.tool,
            execution: self.execution,
            signing: self.signing,
            stored,
            writes: self.writes,
        };
        (self.response, settle)
    }
}

/// What a recorded answer settles with.
struct Settle {
    /// The invocation's trace, taken before the judge can replace the answer.
    trace: Option<std::sync::Arc<str>>,
    tool: String,
    execution: Option<SyncLease>,
    signing: Option<SigningInvocationContext>,
    stored: Option<JsonRpcResponse>,
    writes: WriteRecord,
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
        mut staged: StagedReceipts,
    ) -> OutboundFrame {
        let (frame, retained) = match answer {
            // Built by the gateway before anything ran: admission
            // retained no answer for it, so it captures nothing (E1).
            StdioAnswer::Built(value) => (reads.answer(value, params, hidden).await, false),
            StdioAnswer::Finalized(answer) => {
                let (response, settle) = answer.split();
                let frame = reads.judge(response, params, hidden);
                // The read is what the dispatch's scope noted: settlement
                // runs past that scope now (`complete_delivery_read`).
                deliver(meta, frame, session_id, settle, hidden.cloned()).await
            }
        };
        // `MIK-8408` E1: an answer admission did not retain captures no
        // replay receipts; its live receipts still record below.
        if !retained {
            staged.drop_replay_capture();
        }
        staged.commit(frame.delivers_result());
        frame
    }
}

/// Record the delivery of the judged `frame` (`POST /mcp`'s recorder), then
/// settle the execution on the answer the record left: the finalized one, or
/// the audit-unavailable refusal when the log refused the record. The second
/// value is whether admission retained the delivery — `true` only when a
/// lease settled `Retained` (E1: only a stored answer captures replay
/// receipts), never for a delivery with no execution to settle.
async fn deliver(
    meta: &MetaMcp,
    frame: OutboundFrame,
    session_id: &str,
    settle: Settle,
    read: Option<ReadAttribution>,
) -> (OutboundFrame, bool) {
    let correlation = ResponseCorrelation {
        session_id,
        caller: "stdio",
        external_server: "gateway",
        external_tool: &settle.tool,
        subject: None,
        trace_id: settle.trace.as_deref(),
        key: crate::security::response_policy::KeyOf::NoKey,
    };
    let (frame, stored) = crate::gateway::router::record_judged_delivery(
        meta,
        frame,
        &correlation,
        crate::gateway::meta_mcp::response_security::DeliveryCredential::stdio(meta.record_key()),
        settle.stored,
    )
    .await;
    let retained = match (settle.execution, stored) {
        (Some(execution), Some(stored)) => execution.complete_delivery_read(
            &stored,
            settle.signing.as_ref(),
            (read, settle.writes),
        ),
        _ => false,
    };
    (frame, retained)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::protocol::RequestId;

    /// D18 (`MIK-8408` E1): a stdio delivery with no execution to settle
    /// was retained by no admission, so `deliver` reports it unretained
    /// and `judge_and_commit` drops its replay capture: only an answer
    /// admission actually stored captures replay receipts.
    /// Mutant killed: `_ => true` (retained with no execution).
    #[tokio::test]
    async fn d18_a_delivery_with_no_execution_is_not_retained() {
        let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
        let response = JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "answer"}], "isError": false}),
        );
        let frame = crate::gateway::outbound::answer(None, None, response, None, None);
        let settle = Settle {
            trace: None,
            tool: "gateway_execute".to_owned(),
            execution: None,
            signing: None,
            stored: None,
            writes: WriteRecord::default(),
        };
        let (_frame, retained) = deliver(&meta, frame, "stdio-d18", settle, None).await;
        assert!(
            !retained,
            "a delivery admission did not retain must capture no replay entry"
        );
    }
}
