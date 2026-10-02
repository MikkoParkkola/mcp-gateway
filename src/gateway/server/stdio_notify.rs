// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio dispatch's notifications, written as they arrive and each judged
//! for the stdio client (MIK-7116.MIN.2, design §4.3).

use std::future::Future;

use tokio::sync::mpsc::Sender;
use tracing::warn;

use super::Gateway;
use crate::gateway::outbound::{OutboundFrame, StdioReads};
use crate::security::tenant_reads::ReadAttribution;

/// One batch answer, the reading of its own dispatch, and its request's params.
pub(super) type BatchAnswer = (
    serde_json::Value,
    Option<ReadAttribution>,
    Option<serde_json::Value>,
);

impl Gateway {
    /// Run `fut` inside a notification scope, writing each notification the
    /// backend publishes as it arrives.
    ///
    /// Draining concurrently rather than afterwards is the whole point: a
    /// progress notification has to reach the client while the call that
    /// raised it is still running, so it must be written *before* the caller
    /// writes `fut`'s own response (`MIK-7272.SUB.2b`, S-02).
    ///
    /// Installing the scope is also what makes the mint reachable on stdio —
    /// `mint_progress_token` returns `None` outside one, and the client's own
    /// token would then travel to the backend unchanged.
    /// The dispatch also runs in a read scope, so the judge of its answer
    /// sees what it read before any transform; that is returned beside it.
    pub(super) async fn dispatch_streaming_notifications<F>(
        fut: F,
        writer: &Sender<OutboundFrame>,
        reads: &StdioReads,
    ) -> (F::Output, Option<ReadAttribution>)
    where
        F: Future,
    {
        let (scoped, mut notifications) = crate::transport::notification_sink::scope(
            crate::gateway::outbound::read_scoped(reads.guard(), fut),
        );
        tokio::pin!(scoped);
        let output = loop {
            tokio::select! {
                Some(notification) = notifications.recv() => {
                    Self::queue_notification(writer, reads, notification).await;
                }
                output = &mut scoped => break output,
            }
        };
        // The scope's sender drops with `scoped`, so anything still queued is
        // everything that will ever arrive; write it before the response.
        while let Ok(notification) = notifications.try_recv() {
            Self::queue_notification(writer, reads, notification).await;
        }
        output
    }

    /// Queue one notification for the client, judged first. A withheld one
    /// is not queued; its rejection is audited.
    async fn queue_notification(
        writer: &Sender<OutboundFrame>,
        reads: &StdioReads,
        notification: crate::protocol::JsonRpcNotification,
    ) {
        let method = notification.method.clone();
        if let Some(frame) = reads.notification(notification).await {
            drop(writer.send(frame).await);
        } else {
            warn!(%method, "stdio: notification withheld");
        }
    }

    /// A JSON-RPC batch, each answer beside what its own dispatch read before
    /// any transform (MIN.2: judged one by one, design S1).
    pub(super) async fn dispatch_batch_read(
        meta_mcp: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
        tool_policy: &std::sync::Arc<crate::security::ToolPolicy>,
        mtls_policy: &std::sync::Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
        protocol_telemetry_sink: &super::StdioTelemetry,
        guard: Option<std::sync::Arc<crate::gateway::outbound::Guard>>,
    ) -> Vec<BatchAnswer> {
        let serde_json::Value::Array(requests) = batch else {
            return vec![(
                crate::protocol::JsonRpcResponse::error(None, -32600, "Invalid Request")
                    .to_value_lossy(),
                None,
                None,
            )];
        };

        if requests.is_empty() {
            return vec![(
                crate::protocol::JsonRpcResponse::error(None, -32600, "Invalid Request")
                    .to_value_lossy(),
                None,
                None,
            )];
        }

        let mut responses = Vec::new();
        let judging = crate::gateway::outbound::judges(guard.as_deref());
        for req in requests {
            // Each answer keeps its own request's params: ids may repeat.
            let params = judging.then(|| req.get("params").cloned()).flatten();
            let (resp, read) = crate::gateway::outbound::read_scoped(
                guard.clone(),
                Box::pin(Self::dispatch_single_with_sink(
                    meta_mcp,
                    tool_policy,
                    mtls_policy,
                    req,
                    super::StdioClient {
                        session_id,
                        // A batch is dispatched sequentially inside the serve
                        // loop's own task, so there is no reader to deliver a
                        // reply: batch concurrency is out of scope for MIK-7387 by
                        // design. Nothing to declare to either — a retained
                        // handshake would widen a channel that cannot ask.
                        channel: &crate::gateway::input_bridge::NoClientChannel,
                        handshake_capabilities: crate::protocol::meta::Declared::NONE,
                        // A batch is a legacy shape; it serves no `tasks/*`.
                        tasks: None,
                        modern: false,
                    },
                    protocol_telemetry_sink,
                )),
            )
            .await;
            if let Some(resp) = resp {
                responses.push((resp, read, params));
            }
        }
        responses
    }

    /// [`Self::dispatch_batch_read`] without the readings.
    #[cfg(test)]
    pub(super) async fn dispatch_batch_with_sink(
        meta_mcp: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
        tool_policy: &std::sync::Arc<crate::security::ToolPolicy>,
        mtls_policy: &std::sync::Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
        protocol_telemetry_sink: &super::StdioTelemetry,
    ) -> Vec<serde_json::Value> {
        Self::dispatch_batch_read(
            meta_mcp,
            tool_policy,
            mtls_policy,
            batch,
            session_id,
            protocol_telemetry_sink,
            None,
        )
        .await
        .into_iter()
        .map(|(answer, ..)| answer)
        .collect()
    }
}
