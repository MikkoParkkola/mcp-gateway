// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record a sync admission stores beside its secured response, and how a replay decodes it.

use serde_json::Value;

use crate::protocol::JsonRpcResponse;
use crate::security::audit::AuditOutcome;

/// What a sync admission stores: the secured response plus its server-owned
/// chain eligibility, which the response's own serialization never carries.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct StoredDelivery {
    pub(super) response: Value,
    /// Absent in records written before the chain existed: never eligible.
    #[serde(default)]
    pub(super) chain: StoredChain,
    /// Absent in records written before #2472, and for calls that wrote no
    /// invocation record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) audit: Option<ReplayAudit>,
    /// MIK-7116.MIN.2: what the first execution read before any transform,
    /// restored into a replay's read scope; absent, a replay is unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) read: Option<crate::security::tenant_reads::ReadAttribution>,
    /// MIK-7991: the members the gateway wrote into `response`, restored
    /// into a replay's record so its receipt leaves them out; absent, none.
    #[serde(
        default,
        skip_serializing_if = "crate::gateway::gateway_writes::WriteRecord::is_empty"
    )]
    pub(super) writes: crate::gateway::gateway_writes::WriteRecord,
}

/// #2472: the first execution's invocation-record outcome and response hash,
/// stored server-side beside its secured response. The response a replay
/// delivers is the wrapped, post-delivery form, so neither can be derived
/// from it: a wrapped tool error reads as a success.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReplayAudit {
    outcome: StoredOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_hash: Option<String>,
    /// MIK-7641: the request hash the first record carried. A retry admitted
    /// as the same operation may send an equivalent but different envelope
    /// (`arguments` as a JSON string), so it is never re-derived from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredOutcome {
    Ok,
    ToolError,
    Denied(i32),
    Invalid(i32),
    Error(i32),
}

impl ReplayAudit {
    pub(crate) fn new(outcome: AuditOutcome, response_hash: Option<String>) -> Self {
        let outcome = match outcome {
            AuditOutcome::Ok => StoredOutcome::Ok,
            AuditOutcome::ToolError => StoredOutcome::ToolError,
            AuditOutcome::Denied(code) => StoredOutcome::Denied(code),
            AuditOutcome::Invalid(code) => StoredOutcome::Invalid(code),
            AuditOutcome::Error(code) => StoredOutcome::Error(code),
        };
        Self {
            outcome,
            response_hash,
            request_hash: None,
        }
    }

    /// These facts with the request hash their record was written under.
    pub(crate) fn with_request_hash(mut self, request_hash: String) -> Self {
        self.request_hash = Some(request_hash);
        self
    }

    pub(crate) fn request_hash(&self) -> Option<&str> {
        self.request_hash.as_deref()
    }

    pub(crate) fn outcome(&self) -> AuditOutcome {
        match self.outcome {
            StoredOutcome::Ok => AuditOutcome::Ok,
            StoredOutcome::ToolError => AuditOutcome::ToolError,
            StoredOutcome::Denied(code) => AuditOutcome::Denied(code),
            StoredOutcome::Invalid(code) => AuditOutcome::Invalid(code),
            StoredOutcome::Error(code) => AuditOutcome::Error(code),
        }
    }

    pub(crate) fn response_hash(&self) -> Option<&str> {
        self.response_hash.as_deref()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum StoredChain {
    Backend,
    /// A chained backend's result (inc3 R8): its upstream links answered
    /// another request's nonce, so a replay is never linked.
    ChainedBackend,
    #[default]
    NotEligible,
}

/// Decode a stored delivery; a bare response is a record from before the
/// envelope and replays without a link.
pub(super) fn stored_response(bytes: &[u8]) -> Option<(JsonRpcResponse, Option<ReplayAudit>)> {
    if let Ok(stored) = serde_json::from_slice::<StoredDelivery>(bytes) {
        crate::security::tenant_reads::note_restored(stored.read.as_ref());
        crate::gateway::gateway_writes::restore(&stored.writes);
        let mut response: JsonRpcResponse = serde_json::from_value(stored.response).ok()?;
        if stored.chain == StoredChain::Backend {
            response.chain_source = crate::protocol::ChainSource::Replay;
        }
        return Some((response, stored.audit));
    }
    crate::security::tenant_reads::note_restored(None);
    serde_json::from_slice(bytes)
        .ok()
        .map(|response| (response, None))
}
