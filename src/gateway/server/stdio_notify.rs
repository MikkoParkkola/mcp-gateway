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
        screen: crate::transport::notification_sink::Screen,
    ) -> (F::Output, Option<ReadAttribution>)
    where
        F: Future,
    {
        let (scoped, mut notifications) = crate::transport::notification_sink::scope(
            screen,
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

    /// A JSON-RPC batch: each answer judged right after its own dispatch
    /// (MIN.2: one by one, design S1), and its relay receipts recorded then,
    /// so a later item's relay check sees what an earlier item delivered.
    pub(super) async fn dispatch_batch_read(
        meta_mcp: &std::sync::Arc<crate::gateway::meta_mcp::MetaMcp>,
        tool_policy: &std::sync::Arc<crate::security::ToolPolicy>,
        mtls_policy: &std::sync::Arc<crate::mtls::MtlsPolicy>,
        batch: serde_json::Value,
        session_id: &str,
        protocol_telemetry_sink: &super::StdioTelemetry,
        reads: &StdioReads,
    ) -> Vec<OutboundFrame> {
        let invalid = || {
            crate::protocol::JsonRpcResponse::error(None, -32600, "Invalid Request")
                .to_value_lossy()
        };
        let requests = match batch {
            serde_json::Value::Array(requests) if !requests.is_empty() => requests,
            _ => return vec![reads.answer(invalid(), None, None).await],
        };

        let mut frames = Vec::new();
        let judging = reads.judges();
        for req in requests {
            // Each answer keeps its own request's params: ids may repeat.
            let params = judging.then(|| req.get("params").cloned()).flatten();
            let ((resp, staged), read) = crate::gateway::outbound::read_scoped(
                reads.guard(),
                Box::pin(Self::dispatch_single_staged(
                    meta_mcp,
                    tool_policy,
                    mtls_policy,
                    req,
                    super::StdioClient {
                        session_id,
                        // A batch's items run one by one in the batch's own
                        // task (MIK-7684), with no client channel: a batched
                        // call cannot hold for input, so nothing would deliver
                        // a reply. Nothing to declare to either — a retained
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
            match resp {
                Some(resp) => frames.push(
                    Self::judge_and_commit(
                        meta_mcp,
                        reads,
                        session_id,
                        (resp, params.as_ref(), read.as_ref()),
                        staged,
                    )
                    .await,
                ),
                None => staged.commit(false),
            }
        }
        frames
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
        let reads = meta_mcp.stdio_reads();
        Self::dispatch_batch_read(
            meta_mcp,
            tool_policy,
            mtls_policy,
            batch,
            session_id,
            protocol_telemetry_sink,
            &reads,
        )
        .await
        .into_iter()
        .filter_map(|frame| frame.stdio_value().map(std::borrow::Cow::into_owned))
        .collect()
    }
}
