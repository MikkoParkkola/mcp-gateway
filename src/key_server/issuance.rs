// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The mint's audit row: written through the logger's one issuance helper
//! and judged by the log's failure policy.

use axum::http::StatusCode;
use tracing::warn;

use super::KeyServer;
use super::audit::AuditEvent;
use super::handler::error_response;

/// Write the mint's `token.issued` row and apply the log's failure policy to
/// how that came out. `Some` is the refusal to answer with: under
/// `FailClosed` any outcome but a confirmed row refuses (a late row may still
/// land; the slot is released and no bearer exists). Under `BestEffort` the
/// mint goes on with a fixed-label warning and counter. Neither policy skips
/// the reservation or identity checks that follow.
pub(super) async fn record_issuance(
    ks: &KeyServer,
    event: &AuditEvent,
) -> Option<axum::response::Response> {
    use crate::security::audit::{AuditEnvelope, AuditFailurePolicy};
    use crate::security::transparency_log::issuance::IssuanceWrite;
    let log = ks.issuance_log.as_ref()?;
    // An event that cannot become a row is a row never attempted, so the
    // policy still applies to it.
    let write = match serde_json::to_value(event) {
        Ok(serde_json::Value::Object(fields)) => {
            log.append_issuance_row(fields, AuditEnvelope::gateway())
                .await
        }
        _ => IssuanceWrite::NotAttempted(std::io::Error::other("the event is not a record")),
    };
    let status = write.label();
    let error_kind = write.error_kind();
    telemetry_metrics::counter!("mcp_key_server_issuance_rows_total", "status" => status)
        .increment(1);
    if matches!(write, IssuanceWrite::Confirmed) {
        return None;
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
        return Some(refusal);
    }
    warn!(
        status,
        ?error_kind,
        "key server: the issuance row was not confirmed; token issued anyway"
    );
    None
}
