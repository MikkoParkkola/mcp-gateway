// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Delivery-attempt records for finalized responses and notifications.

use super::ResponseCorrelation;

impl super::super::MetaMcp {
    /// Record the delivery attempt of the finalized `response`, with `read`
    /// (the answer's `tenant_read` fields) in the same record. With auth on, a
    /// response whose delivery cannot be audited is withheld: it is replaced
    /// by the audit-unavailable refusal. Test-only since stdio records after
    /// its judge (MIK-7920).
    #[cfg(test)]
    pub(crate) async fn record_delivery(
        &self,
        response: crate::protocol::JsonRpcResponse,
        correlation: &ResponseCorrelation<'_>,
        read: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> crate::protocol::JsonRpcResponse {
        if self.record_delivery_of(&response, correlation, read).await {
            return response;
        }
        Self::audit_unavailable_refusal(response.id)
    }

    /// [`Self::record_delivery`] without taking the response: `false` when
    /// the log refused the record and the answer must be withheld.
    pub(crate) async fn record_delivery_of(
        &self,
        response: &crate::protocol::JsonRpcResponse,
        correlation: &ResponseCorrelation<'_>,
        read: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> bool {
        // Logging applies to every actual response, including unscanned methods.
        self.record_response_delivery_attempt(response, correlation, read)
            .await
    }

    /// The refusal that replaces an answer whose record the log refused.
    pub(crate) fn audit_unavailable_refusal(
        id: Option<crate::protocol::RequestId>,
    ) -> crate::protocol::JsonRpcResponse {
        let error = crate::Error::AuditUnavailable;
        match id {
            Some(id) => super::error_response_preserving_status(id, &error),
            None => crate::protocol::JsonRpcResponse::error(
                None,
                error.to_rpc_code(),
                error.to_string(),
            ),
        }
    }

    /// Append evidence of the final output attempt; never a client receipt.
    ///
    /// Returns `false` only when the append failed under
    /// [`AuditFailurePolicy::FailClosed`](crate::security::audit::AuditFailurePolicy),
    /// meaning the response must not be delivered.
    pub(super) async fn record_response_delivery_attempt(
        &self,
        response: &crate::protocol::JsonRpcResponse,
        correlation: &ResponseCorrelation<'_>,
        read: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> bool {
        use crate::security::audit::AuditOutcome;

        let outcome = response
            .error
            .as_ref()
            .map_or(AuditOutcome::Ok, |e| AuditOutcome::Error(e.code));
        self.record_delivery_attempt(
            serde_json::to_value(response),
            outcome,
            "transport_finalized",
            correlation,
            read,
        )
        .await
    }

    /// The delivery evidence for one pushed notification frame, hashed as it
    /// is about to be sent. Same event, same failure policy as a response.
    pub(in crate::gateway::meta_mcp) async fn record_notification_delivery_attempt(
        &self,
        frame: &serde_json::Value,
        correlation: &ResponseCorrelation<'_>,
    ) -> bool {
        self.record_delivery_attempt(
            Ok(frame.clone()),
            crate::security::audit::AuditOutcome::Ok,
            "notification_delivered",
            correlation,
            None,
        )
        .await
    }

    pub(super) async fn record_delivery_attempt(
        &self,
        value: serde_json::Result<serde_json::Value>,
        outcome: crate::security::audit::AuditOutcome,
        stage: &str,
        correlation: &ResponseCorrelation<'_>,
        read: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> bool {
        append_delivery_attempt(
            self.transparency_logger.as_ref(),
            value,
            outcome,
            stage,
            correlation,
            read,
        )
        .await
    }
}

/// `MetaMcp::record_response_delivery_attempt` for an answer
/// already rendered as a JSON value, into `logger` (the direct route,
/// MIK-7669): same event, stage, hash and failure policy. `outcome` is the
/// route's own classification, which reads the HTTP status as well as the
/// body (L1254). `false` means the answer must be withheld.
pub(crate) async fn record_answer_delivery(
    logger: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
    answer: serde_json::Result<serde_json::Value>,
    outcome: crate::security::audit::AuditOutcome,
    correlation: &ResponseCorrelation<'_>,
    read: Option<serde_json::Map<String, serde_json::Value>>,
) -> bool {
    append_delivery_attempt(
        logger,
        answer,
        outcome,
        "transport_finalized",
        correlation,
        read,
    )
    .await
}

/// Append one delivery-attempt record to `logger`; `true` when there is no
/// log. `false` only when the append failed under `FailClosed`.
async fn append_delivery_attempt(
    logger: Option<&std::sync::Arc<crate::security::TransparencyLogger>>,
    value: serde_json::Result<serde_json::Value>,
    outcome: crate::security::audit::AuditOutcome,
    stage: &str,
    correlation: &ResponseCorrelation<'_>,
    read: Option<serde_json::Map<String, serde_json::Value>>,
) -> bool {
    use crate::security::audit::{AuditEnvelope, AuditFailurePolicy, AuditWho};

    use sha2::{Digest, Sha256};

    let Some(logger) = logger else {
        return true;
    };
    let fail_closed = logger.failure_policy() == AuditFailurePolicy::FailClosed;
    let encoded = value.and_then(|value| serde_json::to_vec(&value));
    let Ok(encoded) = encoded else {
        tracing::warn!("Failed to encode response delivery attempt for transparency log");
        return !fail_closed;
    };
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(encoded)));
    let mut fields = serde_json::Map::new();
    fields.insert("event".into(), "response_delivery_attempt".into());
    fields.insert("response_stage".into(), stage.into());
    fields.insert("response_hash_encoding".into(), "sorted-json-v1".into());
    fields.insert("response_hash".into(), hash.into());
    fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
    // A fingerprint: the id is its anonymous holder's credential (F9).
    let session_id = crate::gateway::session_id::session_fp(correlation.session_id);
    fields.insert("session_id".into(), session_id.into());
    fields.insert("caller".into(), correlation.caller.into());
    fields.insert("server".into(), correlation.external_server.into());
    fields.insert("tool".into(), correlation.external_tool.into());
    // The answer's read verdict rides this record instead of a second one
    // (MIK-7799); its own `event` and `caller_key` stay the delivery's.
    if let Some(read) = read {
        for (name, value) in read {
            if name != "event" {
                fields.entry(name).or_insert(value);
            }
        }
    }
    // Named as the invocation record names the same call (MIK-7938): a
    // certificate or agent caller is the client `anonymous` or `public`, so
    // only its verified grant subject says who it was.
    let mut who = AuditWho::from_actor_id(correlation.caller);
    if let Some(grant) = correlation.subject {
        who.authority = Some(grant.authority.clone());
        who.subject = Some(grant.subject.clone());
    }
    let envelope = AuditEnvelope {
        outcome,
        ..AuditEnvelope::ok(who)
    };
    // F20: bounded on the blocking pool; a stalled disk withholds the
    // response (FailClosed) instead of pinning a runtime worker.
    let logger = std::sync::Arc::clone(logger);
    if let Err(error) = logger
        .append_bounded(move |l| l.append_event(fields, &envelope))
        .await
    {
        tracing::warn!(
            error_kind = ?error.kind(),
            "Failed to append response delivery attempt to transparency log"
        );
        return !fail_closed;
    }
    true
}
