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

use serde_json::{Value, json};

use super::MetaMcp;
use super::response_security::ResponseCorrelation;
use crate::gateway::task_service::CommittedTask;
use crate::protocol::subscriptions::SubscriptionId;

/// Who a frame is for, as the delivery log names it.
pub(crate) struct Reader<'a> {
    pub caller: &'a str,
    pub session_id: &'a str,
}

impl MetaMcp {
    /// The tagged frame to send this reader for `notification`, or `None` when
    /// the frame must be withheld (the delivery could not be audited under a
    /// fail-closed policy, or the grant-decision write failed).
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
        reader: &Reader<'_>,
    ) -> Option<Value> {
        let delivery = super::invoke::relay::collecting(async {
            let withheld = stored.is_none_or(refused);
            let params = match stored {
                Some(task) if !withheld => serde_json::to_value(task.task.wire()).ok(),
                _ => None,
            };
            let frame = match params {
                Some(params) => json!({
                    "jsonrpc": "2.0",
                    "method": notification["method"],
                    "params": params,
                }),
                None => notification.clone(),
            };
            let frame = subscription.tag(frame);
            let correlation = ResponseCorrelation {
                session_id: reader.session_id,
                caller: reader.caller,
                external_server: "gateway",
                external_tool: "notifications/tasks",
            };
            let delivered = self
                .record_notification_delivery_attempt(&frame, &correlation)
                .await;
            // Receipts a refused or withheld frame staged are dropped.
            self.commit_staged_relay(delivered && !withheld);
            Ok(delivered.then_some(frame))
        });
        super::grant_audit::slot_result(self.transparency_logger.as_ref(), delivery)
            .await
            .ok()
            .flatten()
    }
}
