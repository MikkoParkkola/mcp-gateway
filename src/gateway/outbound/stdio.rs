// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The stdio sink (design §4.3, S1, S2). One process serves one client, so
//! every frame is judged for the constant caller `stdio`. The stdout queue
//! carries [`OutboundFrame`]s; the writer commits each after `stdout` took
//! it, so a frame still queued counts as pending against the next one.

use std::sync::Arc;

use serde_json::Value;

use super::{
    Admission, Guard, OutboundFrame, Payload, RejectionAudit, admission, answer_value, recorded,
};
use crate::protocol::JsonRpcNotification;
use crate::security::TransparencyLogger;
use crate::security::tenant_reads::ReadAttribution;

/// The caller every stdio frame is judged for (`stdio_nonce.rs`: one client).
pub(crate) const STDIO_KEY: &str = "stdio";

impl OutboundFrame {
    /// A gateway-built stdio frame (a parse error, the busy refusal): it
    /// carries no backend content and is never judged.
    pub(crate) const fn gateway_stdio(value: Value) -> Self {
        Self::unjudged(Payload::Answer(value))
    }

    /// The JSON value the stdio writer puts on `stdout`; `None` for a frame
    /// that writes nothing.
    pub(crate) fn stdio_value(&self) -> Option<Value> {
        match &self.payload {
            Payload::Answer(value) | Payload::Request(value) => Some(value.clone()),
            Payload::Response(response) => Some(response.to_value_lossy()),
            Payload::Notification(note) => serde_json::to_value(note).ok(),
            Payload::Batch(items) => Some(Value::Array(
                items.iter().filter_map(Self::stdio_value).collect(),
            )),
            Payload::Event(_) | Payload::Callback(_) | Payload::Withheld => None,
        }
    }

    /// `stdout` took this frame: commit it, and every item of a batch.
    pub(crate) fn stdio_written(&self) {
        self.written();
        if let Payload::Batch(items) = &self.payload {
            for item in items {
                item.written();
            }
        }
    }
}

/// The stdio transport's judge: the Meta-MCP's firewall, the rejection
/// auditor and the transparency log.
pub(crate) struct StdioReads {
    guard: Option<Arc<Guard>>,
    audit: Arc<RejectionAudit>,
    log: Option<Arc<TransparencyLogger>>,
}

impl std::fmt::Debug for StdioReads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioReads")
            .field("judging", &self.judges())
            .finish_non_exhaustive()
    }
}

impl StdioReads {
    /// A judge over `guard`; nothing is judged without one.
    pub(crate) fn new(
        guard: Option<Arc<Guard>>,
        audit: Arc<RejectionAudit>,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Self {
        Self { guard, audit, log }
    }

    /// The firewall a dispatch's read scope notes under.
    pub(crate) fn guard(&self) -> Option<Arc<Guard>> {
        self.guard.clone()
    }

    /// Whether frames are judged at all; the default config does not.
    pub(crate) fn judges(&self) -> bool {
        super::judges(self.guard.as_deref())
    }

    /// Judge and record one finalized answer. `request` is the params of
    /// the request it answers; `hidden` what its dispatch read before any
    /// transform.
    pub(crate) async fn answer(
        &self,
        value: Value,
        request: Option<&Value>,
        hidden: Option<&ReadAttribution>,
    ) -> OutboundFrame {
        let frame = answer_value(
            self.guard.as_deref(),
            Some(STDIO_KEY),
            value,
            request,
            hidden,
        );
        recorded(frame, self.log.as_ref()).await
    }

    /// Judge a batch's answers one by one, each with the params of the
    /// request it answers (matched by id in `requests`), into one frame.
    pub(crate) async fn batch(
        &self,
        answers: Vec<Value>,
        requests: Option<&Value>,
        hidden: Option<&ReadAttribution>,
    ) -> OutboundFrame {
        let mut items = Vec::with_capacity(answers.len());
        for answer in answers {
            let params = requests
                .and_then(Value::as_array)
                .and_then(|all| {
                    all.iter()
                        .find(|r| r.get("id").is_some() && r.get("id") == answer.get("id"))
                })
                .and_then(|r| r.get("params"));
            items.push(self.answer(answer, params, hidden).await);
        }
        OutboundFrame::unjudged(Payload::Batch(items))
    }

    /// Judge one backend notification for the stdio client; `None` when it
    /// is withheld (the rejection is audited, bounded and detached).
    pub(crate) async fn notification(&self, note: JsonRpcNotification) -> Option<OutboundFrame> {
        self.admitted(Payload::Notification(note)).await
    }

    /// Judge one bridged server-to-client request; `None` when it is
    /// withheld. An async producer: the rejection is audited before the
    /// caller answers its own waiter with a refusal (§4.7).
    pub(crate) async fn request(&self, frame: Value) -> Option<OutboundFrame> {
        match admission(
            self.guard.as_deref(),
            Some(STDIO_KEY),
            Payload::Request(frame),
            None,
        ) {
            Admission::Admitted(frame) => {
                let frame = recorded(frame, self.log.as_ref()).await;
                (!matches!(frame.payload, Payload::Withheld)).then_some(frame)
            }
            Admission::Blocked(evidence) => {
                if let Some(log) = &self.log {
                    super::audit::audit_rejection(log, &evidence).await;
                }
                None
            }
        }
    }

    async fn admitted(&self, payload: Payload) -> Option<OutboundFrame> {
        match admission(self.guard.as_deref(), Some(STDIO_KEY), payload, None) {
            Admission::Admitted(frame) => {
                let frame = recorded(frame, self.log.as_ref()).await;
                (!matches!(frame.payload, Payload::Withheld)).then_some(frame)
            }
            Admission::Blocked(evidence) => {
                self.audit.submit(evidence);
                None
            }
        }
    }
}
