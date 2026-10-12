// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-scoped capability grants for personal MCP tools.
//!
//! This module is the MIK-6553 grant contract. It models who may use a
//! capability, which agent may act for that subject, how long the permission is
//! live, and why each decision was made. Gateway dispatch uses this contract
//! to fail closed for explicitly personal capabilities while existing shared
//! and public tools keep their backward-compatible behavior.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::security::OwnedProvenAgentId;

/// Stable local grant-file schema version.
pub const IDENTITY_GRANTS_FILE_SCHEMA_VERSION: &str = "identity_grants.v1";

/// Default recommendation lease duration for local grants.
pub const DEFAULT_GRANT_LEASE_SECONDS: i64 = 60 * 60;

/// Maximum recommendation lease duration for local grants.
pub const MAX_GRANT_LEASE_SECONDS: i64 = 24 * 60 * 60;

/// Stable subject identity used by grant evaluation.
///
/// Equality is `(authority, subject)` only; see `identity_grants_matching.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSubject {
    /// Identity authority, such as an issuer URL or local authority name.
    pub authority: String,
    /// Stable subject identifier inside the authority namespace.
    pub subject: String,
    /// Optional operator-facing label. Display only: never part of identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl GrantSubject {
    /// Create a new grant subject.
    #[must_use]
    pub fn new(
        authority: impl Into<String>,
        subject: impl Into<String>,
        label: Option<String>,
    ) -> Self {
        Self {
            authority: authority.into(),
            subject: subject.into(),
            label,
        }
    }

    /// The only way production code builds a CALLER's grant subject
    /// (MIK-8286): `None` when the authority or the subject is empty, since
    /// such a subject names nobody and every key built from it would merge
    /// all such callers. Grant-file rule targets are not caller identities
    /// and keep [`GrantSubject::new`]; `scripts/release/check_identity_sources.py`
    /// counts every production `new` call outside this one.
    pub(crate) fn checked(
        authority: impl Into<String>,
        subject: impl Into<String>,
        label: Option<String>,
    ) -> Option<Self> {
        let (authority, subject) = (authority.into(), subject.into());
        names_someone(&authority, &subject).then(|| Self::new(authority, subject, label))
    }
}

/// Whether an (authority, subject) pair names someone: both non-empty,
/// compared raw (verified bytes are never trimmed). The one predicate every
/// caller-identity source applies (MIK-8286). It does not judge names: a
/// subject literally spelled like a placeholder still names someone, so the
/// certificate refusal is its own check (`CertIdentity::subject_id`).
pub(crate) fn names_someone(authority: &str, subject: &str) -> bool {
    !authority.is_empty() && !subject.is_empty()
}

/// Agent binding for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAgent {
    /// Grant applies to any agent acting for the subject.
    Any,
    /// Grant applies only to this exact proven agent: source and id.
    Exact(GrantAgentKey),
}

/// Capability exposure class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityExposure {
    /// No caller identity is required. This preserves public-tool behavior.
    Public,
    /// Shared team or gateway capability.
    #[default]
    Shared,
    /// Personal capability. Caller identity, matching ownership, and a live grant are required.
    Personal,
}

impl CapabilityExposure {
    /// Whether this is the backward-compatible default exposure.
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        matches!(self, Self::Shared)
    }
}

/// Action scope granted for a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// Calls to capabilities that declare `metadata.read_only: true`.
    Read,
    /// Any call to the capability, read-only or not.
    Execute,
    /// Any operation.
    Any,
}

#[doc(hidden)]
pub mod journal;
#[cfg(test)]
mod journal_tests;
#[path = "identity_grants_matching.rs"]
mod matching;
pub use matching::GrantAgentKey;
mod store;

/// One durable grant row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrant {
    /// Stable grant identifier.
    pub grant_id: String,
    /// Subject that owns the grant.
    pub subject: GrantSubject,
    /// Agent binding.
    pub agent: GrantAgent,
    /// Capability identifier, usually the gateway capability id.
    pub capability: String,
    /// Optional concrete tool name under the capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Granted action scope.
    pub scope: GrantScope,
    /// Optional owner that must match the caller for personal tools.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<GrantSubject>,
    /// Optional expiry timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional revocation timestamp. Any value means the grant is denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Provenance for why the grant exists.
    pub provenance: String,
    /// Operator-visible reason.
    pub reason: String,
}

/// Local JSON/YAML grant file loaded by free/core deployments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantFile {
    /// Grant-file schema version.
    #[serde(default = "default_identity_grants_file_schema_version")]
    pub schema_version: String,
    /// Durable local grant rows.
    #[serde(default)]
    pub grants: Vec<IdentityGrant>,
}

impl IdentityGrantFile {
    /// Build a grant file from rows.
    #[must_use]
    pub fn new(grants: Vec<IdentityGrant>) -> Self {
        Self {
            schema_version: IDENTITY_GRANTS_FILE_SCHEMA_VERSION.to_string(),
            grants,
        }
    }
}

fn default_identity_grants_file_schema_version() -> String {
    IDENTITY_GRANTS_FILE_SCHEMA_VERSION.to_string()
}

/// Run a blocking file read off the async workers, on a detached thread and
/// not `spawn_blocking`: dropping a Tokio runtime waits for its blocking
/// tasks, so a read stalled on NFS or FUSE would hold shutdown for as long as
/// the mount stalls (#1808, MIK-7693).
async fn read_off_runtime(
    read: impl FnOnce() -> std::io::Result<String> + Send + 'static,
) -> std::io::Result<String> {
    let (done, result) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("identity-grants-read".into())
        .spawn(move || {
            // The reader may be gone (reload cancelled); nothing to tell it.
            let _ = done.send(read());
        })?;
    result
        .await
        .map_err(|_| std::io::Error::other("identity grants read thread ended without a result"))?
}

/// The read `read_identity_grants_file` performs.
type GrantsReader = fn(&Path, crate::config::CheckedFile) -> std::io::Result<String>;

#[cfg(test)]
thread_local! {
    /// A stand-in read for the calling thread, so a test drives the public
    /// reader itself and not only its helper (`MIK-8052.AC2`).
    static TEST_READER: std::cell::Cell<Option<GrantsReader>> = const { std::cell::Cell::new(None) };
}

/// The checked file read; under test, a stand-in installed on the calling
/// thread. Taken BEFORE the read moves to its own thread.
fn grants_reader() -> GrantsReader {
    #[cfg(test)]
    if let Some(read) = TEST_READER.with(std::cell::Cell::get) {
        return read;
    }
    crate::config::read_checked_file
}

/// Read a local identity-grants file as persisted rows.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or uses an unsupported
/// schema version.
pub async fn read_identity_grants_file(path: &Path) -> Result<IdentityGrantFile, String> {
    // Mode-checked off the runtime (F18 I3): readable, not writable, by others.
    let (owned, what) = (
        path.to_path_buf(),
        crate::config::CheckedFile::IdentityGrants,
    );
    let read = grants_reader();
    let content = read_off_runtime(move || read(&owned, what))
        .await
        .map_err(|e| {
            format!(
                "failed to read identity grants file {}: {e}",
                path.display()
            )
        })?;
    let file = serde_json::from_str::<IdentityGrantFile>(&content)
        .or_else(|_| serde_yaml::from_str::<IdentityGrantFile>(&content))
        .map_err(|e| matching::parse_refusal(path, &content, &e))?;

    if file.schema_version != IDENTITY_GRANTS_FILE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported identity grants schema version '{}' in {}; expected '{}'",
            file.schema_version,
            path.display(),
            IDENTITY_GRANTS_FILE_SCHEMA_VERSION
        ));
    }

    Ok(file)
}

/// Replace the identity-grants file at `path` atomically.
///
/// LIVES BESIDE ITS READER ON PURPOSE. It used to sit in the CLI's own module,
/// which put the reader and the writer of one file format in two different
/// crates and left the writer untestable from the library. The format's two
/// halves belong together.
///
/// NOT `tokio::fs::write`, and that is a correctness requirement rather than
/// hygiene. A truncating write is observable mid-flight, and a grants file
/// truncated after its header still PARSES — as zero grants, because
/// [`IdentityGrantFile`] defaults both fields and the schema check compares
/// against the very constant it defaults to. Those are bit-for-bit the
/// deliberate revoke-everything file, so an interrupted `identity grant add`
/// would revoke every grant, through the SUCCESS path, where neither the
/// fail-open ruling nor any parser can see it. Only the writer can prevent
/// it, by never publishing a prefix.
///
/// `write_text_atomic` is sync `std::fs` while this is async, so it goes
/// through `spawn_blocking` rather than blocking the runtime: the CLI is
/// one-shot, but this is a shared helper now, and a blocking call inside an
/// async fn is exactly what gets reused somewhere it stalls a reactor.
///
/// # Errors
///
/// Returns an error if the directory cannot be created, the grants cannot be
/// serialized, or the file cannot be replaced.
pub async fn write_identity_grants_file(
    path: &Path,
    grant_file: &IdentityGrantFile,
) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            format!(
                "failed to create identity grants directory {}: {error}",
                parent.display()
            )
        })?;
    }

    // JSON or YAML by extension, matching what the reader accepts. The atomic
    // replace below is byte-agnostic, so one writer covers both.
    let content = if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        serde_json::to_string_pretty(grant_file)
            .map_err(|error| format!("failed to serialize identity grants JSON: {error}"))?
    } else {
        serde_yaml::to_string(grant_file)
            .map_err(|error| format!("failed to serialize identity grants YAML: {error}"))?
    };

    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::config_persistence::write_text_atomic(&target, &content)
    })
    .await
    .map_err(|error| format!("identity grants writer did not run: {error}"))?
    .map_err(|error| {
        format!(
            "failed to write identity grants file {}: {error}",
            path.display()
        )
    })
}

/// Load local identity grants from a JSON or YAML file.
///
/// # Errors
///
/// Returns an error if the file cannot be read, parsed, or uses an unsupported
/// schema version.
pub async fn load_identity_grants_file(path: &Path) -> Result<LocalIdentityGrantStore, String> {
    let file = read_identity_grants_file(path).await?;
    Ok(LocalIdentityGrantStore::from_grants(file.grants))
}

impl IdentityGrant {
    fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }

    fn covers(
        &self,
        identity: &GrantSubject,
        agent_id: Option<&OwnedProvenAgentId>,
        capability: &str,
        tool: Option<&str>,
        scope: &GrantScope,
        now: DateTime<Utc>,
    ) -> bool {
        self.is_active_at(now)
            && &self.subject == identity
            && self.agent.matches(agent_id)
            && self.capability == capability
            && self
                .tool
                .as_deref()
                .is_none_or(|expected| Some(expected) == tool)
            && self.scope.grants(scope)
    }
}

/// Grant evaluation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityGrantRequest {
    /// Caller identity, when the transport authenticated one.
    pub identity: Option<GrantSubject>,
    /// Calling agent, with the source that proved it, when one was proven.
    pub agent_id: Option<OwnedProvenAgentId>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    pub tool: Option<String>,
    /// Requested action scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Owner for personal tools.
    pub owner: Option<GrantSubject>,
    /// Evaluation timestamp.
    pub now: DateTime<Utc>,
}

/// Result of evaluating a grant request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantEvaluation {
    /// Whether dispatch is allowed by this grant decision.
    pub allowed: bool,
    /// Stable reason code.
    pub reason: IdentityGrantDecisionReason,
    /// Matching grant id when one was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Audit event for durable logs.
    pub audit: IdentityGrantAuditEvent,
}

/// Stable reason code for grant decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityGrantDecisionReason {
    /// Public capability is allowed without a personal grant.
    PublicCapability,
    /// Shared capability is allowed by backward-compatible behavior.
    SharedCapability,
    /// Personal capability request has no authenticated subject.
    MissingIdentity,
    /// Personal capability request has no ownership evidence.
    MissingOwner,
    /// Personal capability belongs to a different subject.
    OwnerMismatch,
    /// No live matching grant was found.
    MissingGrant,
    /// A live matching grant allowed the request.
    GrantMatched,
}

/// Data class used when recommending least-privilege grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantDataClass {
    /// Public data.
    Public,
    /// Internal project or team data.
    Internal,
    /// Personal user data.
    Personal,
    /// Sensitive business, regulated, or private data.
    Sensitive,
}

/// Tool risk used when recommending least-privilege grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantToolRisk {
    /// Low-risk read or lookup workflow.
    Low,
    /// Medium-risk workflow that may need review.
    Medium,
    /// High-risk workflow that must be confirmed.
    High,
    /// Destructive workflow that must be confirmed.
    Destructive,
}

/// Request for a grant recommendation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecommendationRequest {
    /// Caller identity, when the transport authenticated one.
    pub identity: Option<GrantSubject>,
    /// Calling agent, with the source that proved it, when one was proven.
    pub agent_id: Option<OwnedProvenAgentId>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    pub tool: Option<String>,
    /// Requested action scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Owner for personal tools.
    pub owner: Option<GrantSubject>,
    /// Data class touched by the requested workflow.
    pub data_class: GrantDataClass,
    /// Tool risk for the requested workflow.
    pub tool_risk: GrantToolRisk,
    /// Requested lease duration in seconds.
    pub requested_lease_seconds: Option<i64>,
    /// Human-readable reason for the request.
    pub reason: String,
    /// Recommendation timestamp.
    pub now: DateTime<Utc>,
}

/// Recommendation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRecommendationDecision {
    /// Public or shared capability can proceed under existing compatibility behavior.
    AllowPublicOrShared,
    /// An existing live grant already covers this request.
    UseExistingGrant,
    /// A short least-privilege lease can be proposed for human approval.
    RecommendLease,
    /// Human confirmation is required before a lease can be used.
    RequireConfirmation,
    /// Delegated administrator review is required.
    RequestAdmin,
    /// The request cannot be recommended.
    Deny,
}

/// Stable reason code for grant recommendations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRecommendationReason {
    /// Public or shared capability does not need a personal grant.
    PublicOrSharedCapability,
    /// A live grant already covers the request.
    ExistingGrant,
    /// No caller identity was present.
    MissingIdentity,
    /// No owner evidence was present.
    MissingOwner,
    /// The request crosses user boundaries.
    CrossUserAccess,
    /// Tool risk requires explicit confirmation.
    HighRiskTool,
    /// Scope or data class requires explicit confirmation.
    SensitiveOrBroadScope,
    /// A short least-privilege lease is recommended.
    LeastPrivilegeLease,
}

/// Time-bound lease proposal emitted by the recommendation engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLeaseProposal {
    /// Subject that would own the grant.
    pub subject: GrantSubject,
    /// Agent binding for the proposed grant.
    pub agent: GrantAgent,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Proposed action scope.
    pub scope: GrantScope,
    /// Optional owner subject for personal capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<GrantSubject>,
    /// Proposed expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Human-readable reason.
    pub reason: String,
    /// Provenance for the recommendation.
    pub provenance: String,
}

/// Result of generating a grant recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecommendation {
    /// Recommendation decision.
    pub decision: GrantRecommendationDecision,
    /// Stable reason code.
    pub reason: GrantRecommendationReason,
    /// Operator-facing explanation.
    pub explanation: String,
    /// True when a human must approve before dispatch or grant creation.
    pub confirmation_required: bool,
    /// Proposed short lease, when one is safe to present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<GrantLeaseProposal>,
    /// Revoke or rollback guidance.
    pub revoke_path: String,
    /// Audit event for recommendation logs.
    pub audit: GrantRecommendationAuditEvent,
}

/// Audit event emitted for each recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecommendationAuditEvent {
    /// Event name.
    pub event: String,
    /// Recommendation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Recommendation decision.
    pub decision: GrantRecommendationDecision,
    /// Stable reason code.
    pub reason: GrantRecommendationReason,
    /// Caller subject, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<GrantSubject>,
    /// Proven agent rendered `source:id` (for example `mtls:runner`), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Requested scope.
    pub scope: GrantScope,
    /// Capability exposure class.
    pub exposure: CapabilityExposure,
    /// Whether human confirmation is required.
    pub confirmation_required: bool,
    /// Proposed lease expiry, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
}

/// Audit event emitted for every grant evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityGrantAuditEvent {
    /// Event name.
    pub event: String,
    /// Evaluation timestamp.
    pub timestamp: DateTime<Utc>,
    /// Whether the request was allowed.
    pub allowed: bool,
    /// Stable reason code.
    pub reason: IdentityGrantDecisionReason,
    /// Caller subject, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<GrantSubject>,
    /// Proven agent rendered `source:id` (for example `mtls:runner`), when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Capability identifier.
    pub capability: String,
    /// Optional concrete tool name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Requested scope.
    pub scope: GrantScope,
    /// Matching grant id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

/// Local in-memory implementation of the grant store contract.
#[derive(Debug, Default, Clone)]
pub struct LocalIdentityGrantStore {
    grants: BTreeMap<String, IdentityGrant>,
}

#[cfg(test)]
#[path = "identity_grants_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "identity_grants_agent_key_tests.rs"]
mod agent_key_tests;
