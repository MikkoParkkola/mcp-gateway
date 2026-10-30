// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The receipts a stored task read renews, moved out of the parent to keep it
//! under the file-size ceiling (MIK-8387). A pure move: bodies and visibility
//! are unchanged.

use super::super::MetaMcp;
use crate::gateway::task_service::CommittedTask;
use crate::protocol::tasks::TaskStatus;

impl MetaMcp {
    /// Stage the receipt a read of `stored` renews: its result, its pending
    /// input requests, or (MIK-7887) the peer's own error of a failed task.
    /// A completed multi-target task, and a completed plan task on one
    /// distinct target, stage their stored plan receipts (`MIK-8408`); an
    /// error the gateway wrote or whose author is not established, and a
    /// working or cancelled task stage nothing.
    pub(crate) fn stage_stored_receipt(
        &self,
        who: super::super::invoke::relay::RelayKey<'_>,
        api_key_name: Option<&str>,
        stored: &CommittedTask,
    ) {
        if !self.relay_active() || !stored.serves_backend_output() {
            return;
        }
        let [target] = stored.targets.as_slice() else {
            if stored.task.status() == TaskStatus::Completed {
                // As the single-target arm: the stored result's gateway
                // members are restored, so the final pass keeps each
                // replayed receipt to the backend text only.
                super::super::invoke::gateway_writes::restore(&stored.gateway_writes);
                super::super::invoke::relay::stage_task_replay(self, who, stored);
            }
            return;
        };
        let to = (target.server.as_str(), target.tool.as_str());
        match stored.task.status() {
            TaskStatus::Completed => {
                if crate::gateway::meta_mcp::is_composite_meta_tool(stored.task.tool()) {
                    // A plan whose steps all ran on one distinct target:
                    // the deduplicated targets record a single target, but
                    // the task is still a plan, so it takes the plan replay
                    // as the multi-target arm does. Only a missing replay
                    // entry (a restart, an eviction, a detection-off
                    // delivery) falls back to the single-target receipt,
                    // which the writes restored above it already serve, so
                    // it renews exactly what it renewed before.
                    super::super::invoke::gateway_writes::restore(&stored.gateway_writes);
                    if super::super::invoke::relay::stage_task_replay(self, who, stored) {
                        return;
                    }
                    if let Some(result) = stored.backend_result() {
                        self.stage_relay_receipt(who, to, result);
                    }
                } else if let Some(result) = stored.backend_result() {
                    // MIK-7993.STORE.1: the members the gateway wrote into the
                    // stored result are its own text; restored into this
                    // read's record, the receipt (and its rebuild from what
                    // is delivered) leaves exactly those out.
                    super::super::invoke::gateway_writes::restore(&stored.gateway_writes);
                    self.stage_relay_receipt(who, to, result);
                }
            }
            TaskStatus::InputRequired => {
                if let Some(requests) = stored.task.input_requests() {
                    let prompt = serde_json::Value::Object(requests.clone());
                    let recorded = self.recorded_prompt(to, api_key_name, "tasks/get", &prompt);
                    self.stage_relay_receipt(who, to, &recorded);
                }
            }
            TaskStatus::Failed => {
                // Only an error the gateway established as the peer's is the
                // backend's text; its own errors receipt nothing (MIK-7887.RECEIPT.1).
                if let Some(error) = stored.backend_error()
                    && let Ok(error) = serde_json::to_value(error)
                {
                    // Classified like a pending prompt, so a sensitive error
                    // is recorded as sensitive without a `sources` rule.
                    let recorded = self.recorded_prompt(to, api_key_name, "tasks/get", &error);
                    self.stage_relay_receipt(who, to, &recorded);
                }
            }
            _ => {}
        }
    }
}

impl MetaMcp {
    /// MIK-7887.RECEIPT.1: a followed task's failure at settlement. A peer's
    /// own error replaces the working stub with its receipt, classified like a
    /// pending prompt as a read classifies it; any other error is the
    /// gateway's and drops the stub, so nothing it wrote is receipted.
    pub(crate) fn stage_followed_error(
        &self,
        who: super::super::invoke::relay::RelayKey<'_>,
        target: (&str, &str),
        error: &crate::protocol::JsonRpcError,
        author: crate::gateway::task_service::ErrorAuthor,
    ) {
        if !self.relay_active() {
            return;
        }
        if author == crate::gateway::task_service::ErrorAuthor::Peer
            && let Ok(error) = serde_json::to_value(error)
        {
            let recorded = self.recorded_prompt(target, None, "tasks/settle", &error);
            self.stage_upstream_result(who, target, &recorded);
        } else {
            super::super::invoke::relay::discard_staged();
        }
    }
}
