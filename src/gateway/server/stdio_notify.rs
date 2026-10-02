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
}
