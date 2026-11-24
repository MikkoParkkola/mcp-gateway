// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The mint's audit row: written through the logger's one issuance helper
//! and judged by the log's failure policy.

use axum::http::StatusCode;
use tracing::warn;

use super::KeyServer;
use super::audit::AuditEvent;
use super::handler::error_response;
use crate::security::transparency_log::issuance::IssuanceRow;

/// What the row records about the token's lifetime: the configured ttl, and
/// the latest moment the token can expire (activation must happen before the
/// pending deadline, so deadline plus ttl bounds every expiry).
pub(super) struct RowExpiry {
    pub(super) ttl_secs: u64,
    pub(super) expires_by: u64,
}

impl RowExpiry {
    /// The bound for a slot whose pending deadline is `deadline`; `None` when
    /// the sum overflows, which the caller refuses like an unreadable clock.
    pub(super) fn after(deadline: u64, ttl_secs: u64) -> Option<Self> {
        let expires_by = deadline.checked_add(ttl_secs)?;
        Some(Self {
            ttl_secs,
            expires_by,
        })
    }
}

/// Write the mint's `token.issued` row and apply the log's failure policy to
/// how that came out. An `Err` carries the refusal the caller answers with;
/// `Ok` holds the confirmed row when there is one, for the token to point at.
/// Under `FailClosed` any outcome but a confirmed row refuses (a late row may still
/// land; the slot is released and no bearer exists). Under `BestEffort` the
/// mint goes on with a fixed-label warning and counter. Neither policy skips
/// the reservation or identity checks that follow.
pub(super) async fn record_issuance(
    ks: &KeyServer,
    event: &AuditEvent,
    expiry: RowExpiry,
) -> Result<Option<IssuanceRow>, Box<axum::response::Response>> {
    use crate::security::audit::{AuditEnvelope, AuditFailurePolicy};
    use crate::security::transparency_log::issuance::IssuanceWrite;
    let Some(log) = ks.issuance_log.as_ref() else {
        return Ok(None);
    };
    // An event that cannot become a row is a row never attempted, so the
    // policy still applies to it.
    let write = match serde_json::to_value(event) {
        Ok(serde_json::Value::Object(mut fields)) => {
            // Kept off the public event type: only the row carries them.
            fields.insert("ttl_secs".into(), expiry.ttl_secs.into());
            fields.insert("expires_by".into(), expiry.expires_by.into());
            log.append_issuance_row(fields, AuditEnvelope::gateway())
                .await
        }
        _ => IssuanceWrite::NotAttempted(std::io::Error::other("the event is not a record")),
    };
    let status = write.label();
    let error_kind = write.error_kind();
    telemetry_metrics::counter!("mcp_key_server_issuance_rows_total", "status" => status)
        .increment(1);
    if let IssuanceWrite::Confirmed(row) = write {
        return Ok(Some(row));
    }
    if log.failure_policy() == AuditFailurePolicy::FailClosed {
        warn!(
            status,
            ?error_kind,
            "key server: the issuance row was not confirmed; no token issued"
        );
        let mut refusal = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "the token could not be recorded in the audit log; retry",
        );
        refusal.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
        return Err(Box::new(refusal));
    }
    warn!(
        status,
        ?error_kind,
        "key server: the issuance row was not confirmed; the mint goes on (best effort)"
    );
    Ok(None)
}
