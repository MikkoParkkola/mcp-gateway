// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The records of the verdict (design §4.7): one `tenant_read` event per
//! judged frame that names a tenant, is unread or has a verdict, and the
//! rejection audit of frames that are withheld rather than written.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value, json};
use tokio::sync::Semaphore;

use super::{Assessment, OutboundFrame};
use crate::security::TransparencyLogger;
use crate::security::audit::{AuditEnvelope, AuditFailurePolicy};
use crate::security::tenant_reads::RejectionEvidence;

impl Assessment {
    /// The audit fields of this judgement; empty when it named nothing.
    pub(crate) fn record_fields(&self, key: Option<&str>) -> Map<String, Value> {
        let mut fields = Map::new();
        if self.attribution.is_empty() && self.verdict.is_none() {
            return fields;
        }
        fields.insert("event".into(), "tenant_read".into());
        if let Some(key) = key {
            fields.insert("caller_key".into(), key.into());
        }
        if !self.attribution.tenants.is_empty() {
            let tenants: Vec<Value> = self
                .attribution
                .tenants
                .iter()
                .map(|t| Value::String(t.clone()))
                .collect();
            fields.insert("tenants".into(), tenants.into());
        }
        if self.attribution.uninspected {
            fields.insert("attribution".into(), "uninspected".into());
        }
        if let Some(verdict) = self.verdict {
            fields.insert("cross_tenant_read".into(), json!(verdict));
        }
        fields
    }
}

/// Write `frame`'s `tenant_read` event, if its judgement names anything.
/// `false` only when the write failed under `FailClosed`: the frame must
/// not be written then.
pub(super) async fn record(frame: &OutboundFrame, log: Option<&Arc<TransparencyLogger>>) -> bool {
    let (Some(log), Some(assessment)) = (log, frame.assessment()) else {
        return true;
    };
    let fields = assessment.record_fields(frame.key.as_deref());
    if fields.is_empty() {
        return true;
    }
    let envelope = AuditEnvelope::gateway();
    let written = log
        .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
        .await;
    match written {
        Ok(()) => true,
        Err(error) if log.failure_policy() == AuditFailurePolicy::FailClosed => {
            tracing::warn!(%error, "tenant_read audit failed; the frame is withheld");
            false
        }
        Err(error) => {
            tracing::warn!(%error, "tenant_read audit failed; best effort, delivered");
            true
        }
    }
}

/// [`record`] `frame` before a sink writes it. Under `FailClosed` a failed
/// write turns an answer into the audit-unavailable refusal and withholds
/// anything else; either drops the reservation. The refusal itself is not
/// audited again, so this always terminates.
pub(crate) async fn recorded(
    frame: OutboundFrame,
    log: Option<&Arc<TransparencyLogger>>,
) -> OutboundFrame {
    if record(&frame, log).await {
        return frame;
    }
    if !frame.is_answer() {
        return frame.withheld();
    }
    let refusal = frame.answer_id().map_or_else(
        || {
            let error = crate::Error::AuditUnavailable;
            crate::protocol::JsonRpcResponse::error(None, error.to_rpc_code(), error.to_string())
        },
        |id| {
            crate::gateway::meta_mcp::error_response_preserving_status(
                id,
                &crate::Error::AuditUnavailable,
            )
        },
    );
    frame.replaced_by(refusal)
}

/// The fields of one `tenant_read` rejection record.
fn rejection_fields(evidence: &RejectionEvidence) -> Map<String, Value> {
    let assessment = Assessment {
        verdict: Some(evidence.verdict),
        attribution: evidence.attribution.clone(),
    };
    assessment.record_fields(evidence.caller_key.as_deref())
}

/// The rejection audit for an async producer: one `tenant_read` record of
/// `evidence`, through the bounded append. A failure is logged; the content
/// is withheld either way.
pub(crate) async fn audit_rejection(log: &Arc<TransparencyLogger>, evidence: &RejectionEvidence) {
    let fields = rejection_fields(evidence);
    let envelope = AuditEnvelope::gateway();
    let written = log
        .append_bounded(move |log| log.append_event(fields, &envelope).map(|_| ()))
        .await;
    if let Err(error) = written {
        tracing::warn!(%error, "tenant_read rejection audit failed; the frame stays withheld");
    }
}

/// Audit tasks one process may have in flight for withheld frames.
pub(crate) const REJECTION_AUDIT_PERMITS: usize = 64;

/// The rejection audit for sync producers (`send_or_count`): each rejection
/// is handed to one detached task, admitted by a bounded non-blocking permit
/// (F4). Saturation is counted as an audit failure; the content stays
/// withheld either way.
pub(crate) struct RejectionAudit {
    log: Option<Arc<TransparencyLogger>>,
    permits: Arc<Semaphore>,
    saturated: AtomicU64,
}

impl std::fmt::Debug for RejectionAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectionAudit")
            .field("logged", &self.log.is_some())
            .field("saturated", &self.saturated)
            .finish_non_exhaustive()
    }
}

impl RejectionAudit {
    /// An auditor writing to `log` with at most `permits` audits in flight.
    pub(crate) fn new(log: Option<Arc<TransparencyLogger>>, permits: usize) -> Self {
        Self {
            log,
            permits: Arc::new(Semaphore::new(permits)),
            saturated: AtomicU64::new(0),
        }
    }

    /// Hand `evidence` to a detached audit task. Never blocks. Returns whether
    /// a task was spawned; `false` means saturation, recorded.
    pub(crate) fn submit(&self, evidence: RejectionEvidence) -> bool {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            self.saturated.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("tenant_read rejection audit saturated; the frame stays withheld");
            return false;
        };
        let log = self.log.clone();
        tokio::spawn(async move {
            if let Some(log) = log {
                audit_rejection(&log, &evidence).await;
            }
            drop(permit);
        });
        true
    }

    /// Rejections whose audit was refused for want of a permit.
    #[cfg(test)]
    pub(crate) fn saturated(&self) -> u64 {
        self.saturated.load(Ordering::Relaxed)
    }
}
