// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task notification's frame for one reader (MIK-7778 PAYLOAD.1).
//!
//! The tasks extension says each `notifications/tasks` carries the full task
//! state. The publisher sends only the task id and status on a broadcast every
//! listener shares, so the full state is built here, per reader, at delivery,
//! under the same rules a `tasks/get` by that reader would meet: the stored
//! output is re-authorized against the reader (`refuse_stored_delivery`), the
//! grant decisions it makes are flushed in a grant-decision slot, relay
//! receipts are collected and recorded only if the frame is delivered, and the
//! frame is written to the transparency log as it will be sent.
//!
//! A full frame carries the task as it is when the frame is built, not as it
//! was when the notification was published (MIK-7858). The broadcast names no
//! revision, so a notification that waited behind a later transition is sent
//! with the later state, whole: status and content come from one read of the
//! store, never mixed. A reader who cannot have the stored task (a
//! status-only stream, a refused output, or a task no longer stored) gets the
//! notification as published instead, so its status can be older than one an
//! earlier full frame showed. `tasks/get` is the authority for the current
//! state; a frame is a prompt to read it.

use serde_json::{Value, json};

use super::MetaMcp;
use super::response_security::ResponseCorrelation;
use crate::gateway::task_service::CommittedTask;
use crate::protocol::subscriptions::SubscriptionId;

/// Who a frame is for, as the delivery log names it.
pub(crate) struct Reader<'a> {
    pub caller: &'a str,
    pub session_id: &'a str,
    /// The reader's verified grant subject, when one resolved (MIK-7938).
    pub subject: Option<&'a crate::identity_grants::GrantSubject>,
}

/// A frame built for one reader, not yet delivered. Nothing about its delivery
/// is on record: [`MetaMcp::finish_task_frame`] writes the delivery entry and
/// records the relay receipts once the stream's own gates have let it out.
pub(crate) struct PendingTaskFrame {
    /// The tagged frame.
    pub frame: Value,
    /// It carries a stored task's output, so it is a read of stored data.
    pub restored_output: bool,
    withheld: bool,
    staged: super::invoke::relay::StagedReceipts,
}

impl MetaMcp {
    /// The tagged frame to send this reader for `notification`, or `None` when
    /// a grant decision made on the way could not be written.
    ///
    /// `stored` is the reader's own owner-scoped read of the task, `None` when
    /// it cannot be read (the minimal notification is sent). `refused` is the
    /// reader's re-authorization of the stored output, run inside the
    /// collectors this function opens. A refused reader, or one without the
    /// stored task, gets `notification` as published: the task id and status,
    /// never output.
    pub(crate) async fn task_notification_frame(
        &self,
        notification: &Value,
        stored: Option<&CommittedTask>,
        refused: impl FnOnce(&CommittedTask) -> bool + Send,
        subscription: &SubscriptionId,
    ) -> Option<PendingTaskFrame> {
        // The collector is outside the slot, so receipts outlive the slot's
        // own write (grant decisions); they are handed back, recorded or
        // dropped by `finish_task_frame`.
        let (decided, staged) = self
            .collecting_staged(async {
                super::grant_audit::slot_result(self.transparency_logger.as_ref(), async {
                    let withheld = stored.is_none_or(refused);
                    let mut params = match stored {
                        Some(task) if !withheld => serde_json::to_value(task.task.wire()).ok(),
                        _ => None,
                    };
                    // The stored output meets the egress scan again at send, as
                    // `tasks/get` does: a policy tightened since settlement
                    // covers both reads. A refusal sends the minimal frame, so
                    // the subscriber still hears the task ended.
                    let outcome = match (stored, params.as_mut()) {
                        (Some(task), Some(value)) => self.scan_stored_task(task, value),
                        _ => super::invoke::egress::EgressOutcome::Delivered,
                    };
                    if outcome == super::invoke::egress::EgressOutcome::Refused {
                        params = None;
                    }
                    // The receipts collected here describe the stored text: a
                    // frame that no longer carries it (refused or redacted)
                    // commits none.
                    let withheld =
                        withheld || outcome != super::invoke::egress::EgressOutcome::Delivered;
                    // A read of stored backend output only when the task serves
                    // some, as `tasks/get` counts it: a working or cancelled
                    // task read nothing.
                    let restored_output = params.is_some()
                        && stored.is_some_and(CommittedTask::serves_backend_output);
                    let frame = match params {
                        Some(params) => json!({
                            "jsonrpc": "2.0",
                            "method": notification["method"],
                            "params": params,
                        }),
                        None => notification.clone(),
                    };
                    Ok((subscription.tag(frame), withheld, restored_output))
                })
                .await
                .ok()
            })
            .await;
        let (frame, withheld, restored_output) = decided?;
        Some(PendingTaskFrame {
            frame,
            restored_output,
            withheld,
            staged,
        })
    }

    /// Record the delivery of `pending`, now that the stream's gates have
    /// passed and `sent` is what goes out: the delivery entry first, then, if
    /// it is on record and the frame carried no refused output, the relay
    /// receipts. `false` withholds the frame (a fail-closed log that could not
    /// record it).
    pub(crate) async fn finish_task_frame(
        &self,
        pending: PendingTaskFrame,
        sent: &Value,
        reader: &Reader<'_>,
    ) -> bool {
        let correlation = ResponseCorrelation {
            session_id: reader.session_id,
            caller: reader.caller,
            external_server: "gateway",
            external_tool: "notifications/tasks",
            subject: reader.subject,
        };
        let delivered = self
            .record_notification_delivery_attempt(sent, &correlation)
            .await;
        pending.staged.commit(delivered && !pending.withheld);
        delivered
    }
}
