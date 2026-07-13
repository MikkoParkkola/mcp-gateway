// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway-side attestation validation (MIK-5223 AC.3–AC.5, AC.9).
//!
//! The [`AttestationValidator`] is the single validation point: every
//! cross-boundary call presents its token here.  Rejections — including
//! forgery attempts — are recorded in the [`AuditRingBuffer`] with the
//! measured detection latency, and emitted as `attestation_audit` tracing
//! events (a name distinct from the existing `agent_tool_audit` signal so the
//! two streams are independently attributable, B1-IDENT).
//!
//! Rotation: when a long-running task rotates its token, the predecessor
//! enters a grace window during which in-flight syscalls that still carry it
//! keep validating; after the window it is rejected as `RotatedOut`.  The
//! rotation state serializes to a [`RotationCheckpoint`] so it survives
//! checkpoint/restore (B3-DURABLE, ties to RUNTIME-C).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use super::signer::BnautAttestationSigner;
use super::token::{AttestationToken, BNAUT_ISSUER, TokenClaims};

/// Default capacity of the audit ring buffer.
pub const DEFAULT_AUDIT_CAPACITY: usize = 1024;

/// Default grace window during which a rotated-out token still validates.
pub const DEFAULT_ROTATION_GRACE_SECS: i64 = 30;

/// How a wired attestation boundary treats a rejected token.
///
/// Distinct from the boot-time [`crate::attestation::AttestationEnforcement`]
/// rollback flag: this governs an already-wired call boundary (e.g.
/// `gateway_invoke`), not whether the boot gate is bypassed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationMode {
    /// Validate and audit every presented token, but never block a call.
    /// The safe rollout position — enabling the validator on live traffic
    /// cannot break unattested or mis-attested calls.
    #[default]
    Observe,
    /// Fail closed: a missing or invalid token rejects the call.
    Enforce,
}

// ── Rejection reasons ────────────────────────────────────────────────────────

/// Why a token failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttestationRejection {
    /// No token was presented at all (fail-closed boots hit this).
    MissingToken,
    /// The token is structurally invalid (bad base64, bad JSON, no separator).
    MalformedToken {
        /// Description of the structural defect.
        detail: String,
    },
    /// The signature does not verify — forgery or tampering.
    BadSignature,
    /// The token claims an issuer other than bnaut-attestation.
    UnknownIssuer {
        /// The issuer the token claimed.
        issuer: String,
    },
    /// The `expires_at` claim is not valid RFC-3339.
    InvalidExpiry {
        /// The raw claim value.
        value: String,
    },
    /// The token has expired.
    Expired {
        /// The RFC-3339 expiration that has passed.
        expires_at: String,
    },
    /// The token was rotated out and its grace window has closed.
    RotatedOut {
        /// `token_id` of the rejected predecessor token.
        token_id: String,
    },
    /// The token is authentic and unexpired, but its capability allow-list
    /// does not grant the requested action (MIK-6163, fail-closed).
    CapabilityNotGranted {
        /// The capability/action the call required.
        required: String,
        /// The capabilities the token actually carries.
        granted: Vec<String>,
    },
}

impl std::fmt::Display for AttestationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingToken => write!(f, "no attestation token presented"),
            Self::MalformedToken { detail } => write!(f, "malformed attestation token: {detail}"),
            Self::BadSignature => write!(f, "attestation signature verification failed"),
            Self::UnknownIssuer { issuer } => write!(f, "unknown attestation issuer: {issuer}"),
            Self::InvalidExpiry { value } => write!(f, "invalid expiry timestamp: {value}"),
            Self::Expired { expires_at } => write!(f, "attestation token expired at {expires_at}"),
            Self::RotatedOut { token_id } => {
                write!(f, "token {token_id} rotated out and past its grace window")
            }
            Self::CapabilityNotGranted { required, granted } => write!(
                f,
                "token capabilities {granted:?} do not grant required action {required:?}"
            ),
        }
    }
}

// ── Audit ring buffer ────────────────────────────────────────────────────────

/// One audit record for a rejected attestation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationAuditRecord {
    /// Monotonic sequence number — unique per record (B1-IDENT attribution).
    pub seq: u64,
    /// RFC-3339 timestamp of the rejection.
    pub timestamp: String,
    /// The boundary at which the call was rejected (e.g. `sandbox_boot`,
    /// `gateway_invoke`).
    pub boundary: String,
    /// `token_id` when the payload was parseable; `None` for forged or
    /// malformed tokens whose claims cannot be trusted.
    pub token_id: Option<String>,
    /// Claimed agent identity when parseable (untrusted for forgeries).
    pub agent_identity: Option<String>,
    /// Why the token was rejected.
    pub rejection: AttestationRejection,
    /// Microseconds between the validation starting and the rejection being
    /// detected (AC.5: detection within 100ms).
    pub detection_micros: u64,
}

/// Fixed-capacity ring buffer of attestation rejections (MIK-NEW.RUNTIME-A.3).
///
/// When full, the oldest record is evicted.  Thread-safe.
#[derive(Debug)]
pub struct AuditRingBuffer {
    entries: Mutex<VecDeque<AttestationAuditRecord>>,
    capacity: usize,
    sequence: AtomicU64,
}

impl AuditRingBuffer {
    /// Create a ring buffer holding at most `capacity` records.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(
                capacity.min(DEFAULT_AUDIT_CAPACITY),
            )),
            capacity: capacity.max(1),
            sequence: AtomicU64::new(0),
        }
    }

    /// Append a record, evicting the oldest when at capacity.  Returns the
    /// assigned sequence number.
    pub fn push(&self, mut record: AttestationAuditRecord) -> u64 {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        record.seq = seq;
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entries.len() == self.capacity {
            entries.pop_front();
        }
        entries.push_back(record);
        seq
    }

    /// Snapshot of the current records, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AttestationAuditRecord> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Number of records currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the buffer holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total records ever pushed (monotonic, survives eviction).
    #[must_use]
    pub fn total_pushed(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }
}

// ── Rotation checkpoint ──────────────────────────────────────────────────────

/// A rotated-out token still inside its grace window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetiringToken {
    /// `token_id` of the predecessor token.
    pub token_id: String,
    /// RFC-3339 instant after which the token is rejected.
    pub reject_after: String,
}

/// Serializable rotation state (MIK-NEW.RUNTIME-A.4 / B3-DURABLE).
///
/// Persisting this across a checkpoint keeps in-flight grace windows intact
/// when the validator is restored in a new process.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationCheckpoint {
    /// Tokens rotated out but still within their grace window.
    pub retiring: Vec<RetiringToken>,
}

// ── Capability matching ──────────────────────────────────────────────────────

/// Whether a token's capability allow-list grants the requested action.
///
/// Fail-closed: the empty allow-list grants nothing. A capability grants the
/// requested action when it is the `"*"` wildcard (a deliberately broad,
/// operator-minted grant) or an exact match for the action. Matching is exact
/// otherwise — no prefix/substring coercion that could widen a narrow grant.
#[must_use]
fn capabilities_grant(capabilities: &[String], required: &str) -> bool {
    capabilities.iter().any(|cap| cap == "*" || cap == required)
}

// ── Validator ────────────────────────────────────────────────────────────────

/// Gateway-side validator — the single point every cross-boundary call goes
/// through (MIK-NEW.RUNTIME-A.3).
#[derive(Debug)]
pub struct AttestationValidator {
    signer: BnautAttestationSigner,
    audit: AuditRingBuffer,
    /// `token_id` → instant after which the rotated-out token is rejected.
    retiring: Mutex<HashMap<String, DateTime<Utc>>>,
    rotation_grace: TimeDelta,
    validations_total: AtomicU64,
    rejections_total: AtomicU64,
    rotations_total: AtomicU64,
}

impl AttestationValidator {
    /// Create a validator that verifies with `signer`'s key material.
    #[must_use]
    pub fn new(signer: BnautAttestationSigner) -> Self {
        Self::with_settings(
            signer,
            DEFAULT_AUDIT_CAPACITY,
            TimeDelta::seconds(DEFAULT_ROTATION_GRACE_SECS),
        )
    }

    /// Create a validator with explicit audit capacity and rotation grace.
    #[must_use]
    pub fn with_settings(
        signer: BnautAttestationSigner,
        audit_capacity: usize,
        rotation_grace: TimeDelta,
    ) -> Self {
        Self {
            signer,
            audit: AuditRingBuffer::new(audit_capacity),
            retiring: Mutex::new(HashMap::new()),
            rotation_grace,
            validations_total: AtomicU64::new(0),
            rejections_total: AtomicU64::new(0),
            rotations_total: AtomicU64::new(0),
        }
    }

    /// Validate the token presented by a cross-boundary call.
    ///
    /// On success returns the verified claims.  On failure the rejection is
    /// recorded in the audit ring buffer with its detection latency and
    /// emitted as an `attestation_audit` tracing event, then returned.
    ///
    /// `required_capability` is the action/tool the call is requesting. When
    /// `Some`, the token's capability allow-list MUST grant it (an exact match,
    /// or the `"*"` wildcard) or the call is rejected with
    /// [`AttestationRejection::CapabilityNotGranted`] — authenticity alone never
    /// authorizes an out-of-scope action (MIK-6163, fail-closed). `None` is for
    /// capability-agnostic boundaries (e.g. `sandbox_boot`), which validate
    /// authenticity only.
    ///
    /// # Errors
    ///
    /// Returns the [`AttestationRejection`] describing why the token was
    /// refused.
    pub fn validate_boundary_call(
        &self,
        encoded: Option<&str>,
        boundary: &str,
        required_capability: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<TokenClaims, AttestationRejection> {
        let started = Instant::now();
        match self.check(encoded, required_capability, now) {
            Ok(claims) => {
                self.validations_total.fetch_add(1, Ordering::Relaxed);
                Ok(claims)
            }
            Err((rejection, claims)) => {
                self.rejections_total.fetch_add(1, Ordering::Relaxed);
                let detection_micros =
                    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                let record = AttestationAuditRecord {
                    seq: 0, // assigned by the ring buffer
                    timestamp: now.to_rfc3339(),
                    boundary: boundary.to_string(),
                    token_id: claims.as_ref().map(|c| c.token_id.clone()),
                    agent_identity: claims.as_ref().map(|c| c.agent_identity.clone()),
                    rejection: rejection.clone(),
                    detection_micros,
                };
                let seq = self.audit.push(record);
                tracing::warn!(
                    seq,
                    boundary,
                    rejection = %rejection,
                    detection_micros,
                    "attestation_audit"
                );
                Err(rejection)
            }
        }
    }

    /// Signature → structure → issuer → expiry → rotation → capability, in that
    /// order. Returns parsed claims alongside the rejection when they were
    /// readable (for audit attribution; never trusted for authorization).
    #[allow(clippy::result_large_err)]
    fn check(
        &self,
        encoded: Option<&str>,
        required_capability: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<TokenClaims, (AttestationRejection, Option<TokenClaims>)> {
        let Some(encoded) = encoded else {
            return Err((AttestationRejection::MissingToken, None));
        };
        let (payload, signature) = AttestationToken::split_unverified(encoded)
            .map_err(|detail| (AttestationRejection::MalformedToken { detail }, None))?;
        if !self.signer.verify_bytes(&payload, &signature) {
            // Claims from a forged token are attribution hints at best.
            let claims = serde_json::from_slice::<TokenClaims>(&payload).ok();
            return Err((AttestationRejection::BadSignature, claims));
        }
        let claims: TokenClaims = serde_json::from_slice(&payload).map_err(|e| {
            (
                AttestationRejection::MalformedToken {
                    detail: format!("claims JSON: {e}"),
                },
                None,
            )
        })?;
        if claims.issuer != BNAUT_ISSUER {
            let issuer = claims.issuer.clone();
            return Err((AttestationRejection::UnknownIssuer { issuer }, Some(claims)));
        }
        let expires_at = match claims.expires_at_utc() {
            Ok(t) => t,
            Err(value) => {
                return Err((AttestationRejection::InvalidExpiry { value }, Some(claims)));
            }
        };
        if now > expires_at {
            let expires_at = claims.expires_at.clone();
            return Err((AttestationRejection::Expired { expires_at }, Some(claims)));
        }
        let rotated_out = {
            let retiring = self
                .retiring
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            retiring
                .get(&claims.token_id)
                .is_some_and(|reject_after| now > *reject_after)
        };
        if rotated_out {
            let token_id = claims.token_id.clone();
            return Err((AttestationRejection::RotatedOut { token_id }, Some(claims)));
        }
        // Capability allow-list check — the token is authentic and live, but it
        // must still be scoped for the requested action (MIK-6163, fail-closed).
        // Authenticity answers WHO; this answers WHAT they may do. A `None`
        // requirement is a capability-agnostic boundary (e.g. sandbox_boot).
        if let Some(required) = required_capability
            && !capabilities_grant(&claims.capabilities, required)
        {
            let rejection = AttestationRejection::CapabilityNotGranted {
                required: required.to_string(),
                granted: claims.capabilities.clone(),
            };
            return Err((rejection, Some(claims)));
        }
        Ok(claims)
    }

    /// Rotate `current` for a long-running task (MIK-NEW.RUNTIME-A.4).
    ///
    /// The successor is signed immediately; `current` enters the grace window
    /// (`now + rotation_grace`) so in-flight syscalls that still carry it are
    /// not disrupted.
    #[must_use]
    pub fn rotate(
        &self,
        current: &TokenClaims,
        now: DateTime<Utc>,
        ttl: TimeDelta,
    ) -> AttestationToken {
        let successor = self.signer.rotate(current, now, ttl);
        {
            let mut retiring = self
                .retiring
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            retiring.insert(current.token_id.clone(), now + self.rotation_grace);
        }
        self.rotations_total.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            predecessor = %current.token_id,
            successor = %successor.claims().token_id,
            "attestation_rotation"
        );
        successor
    }

    /// Serialize rotation state for a checkpoint (B3-DURABLE).
    #[must_use]
    pub fn checkpoint(&self) -> RotationCheckpoint {
        let retiring = self
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries: Vec<RetiringToken> = retiring
            .iter()
            .map(|(token_id, reject_after)| RetiringToken {
                token_id: token_id.clone(),
                reject_after: reject_after.to_rfc3339(),
            })
            .collect();
        entries.sort_by(|a, b| a.token_id.cmp(&b.token_id));
        RotationCheckpoint { retiring: entries }
    }

    /// Restore rotation state from a checkpoint, replacing current state.
    /// Entries with unparseable timestamps are dropped (fail-closed: a token
    /// absent from the retiring map validates only on its own merits).
    pub fn restore(&self, checkpoint: &RotationCheckpoint) {
        let mut restored = HashMap::with_capacity(checkpoint.retiring.len());
        for entry in &checkpoint.retiring {
            if let Ok(reject_after) = DateTime::parse_from_rfc3339(&entry.reject_after) {
                restored.insert(entry.token_id.clone(), reject_after.with_timezone(&Utc));
            }
        }
        let mut retiring = self
            .retiring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *retiring = restored;
    }

    /// The audit ring buffer holding rejection records.
    #[must_use]
    pub fn audit(&self) -> &AuditRingBuffer {
        &self.audit
    }

    /// Count of successful boundary validations.
    #[must_use]
    pub fn validations_total(&self) -> u64 {
        self.validations_total.load(Ordering::Relaxed)
    }

    /// Count of rejected boundary validations — observably distinct from the
    /// success counter and from pre-existing gateway metrics (B1-IDENT).
    #[must_use]
    pub fn rejections_total(&self) -> u64 {
        self.rejections_total.load(Ordering::Relaxed)
    }

    /// Count of token rotations performed.
    #[must_use]
    pub fn rotations_total(&self) -> u64 {
        self.rotations_total.load(Ordering::Relaxed)
    }

    /// Verify a signed runtime provenance receipt against this validator's key
    /// material (MIK-6905, rung 1.3).
    ///
    /// Provenance receipts are not attestation tokens — they carry no expiry,
    /// rotation, or capability semantics — so they do not flow through
    /// [`Self::validate_boundary_call`]. This method is the validation authority
    /// for the `_meta.provenance` channel: it re-derives the receipt's canonical
    /// bytes and constant-time-compares the detached HMAC. Returns `true` only
    /// when the signature is well-formed and matches.
    #[must_use]
    pub fn verify_result_provenance(&self, signed: &crate::trust::SignedResultProvenance) -> bool {
        let Some(signature) = signed.signature_bytes() else {
            return false;
        };
        // `signed.key_id` is unauthenticated metadata: it is not part of
        // `canonical_bytes()` and so is not covered by this HMAC. Any future
        // multi-key/rotation-aware verification must not trust `key_id` to
        // select a key without additional signed binding.
        self.signer
            .verify_bytes(&signed.receipt.canonical_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::signer::TokenRequest;
    use uuid::Uuid;

    fn validator() -> AttestationValidator {
        AttestationValidator::with_settings(
            BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit"),
            8,
            TimeDelta::seconds(30),
        )
    }

    fn sample_receipt() -> crate::trust::RuntimeProvenanceReceipt {
        crate::trust::RuntimeProvenanceReceipt::observed(
            "github",
            "search_issues",
            "2026-07-13T10:15:30Z",
            crate::trust::CacheOutcome::Miss,
            true,
        )
    }

    #[test]
    fn result_provenance_round_trips_sign_then_verify() {
        let v = validator();
        // Twin signer sharing the validator's key material.
        let twin = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit");
        let signed = sample_receipt().sign(&twin);
        assert_eq!(signed.algorithm, crate::attestation::SIGNING_ALGORITHM);
        assert_eq!(signed.key_id, "bnaut/unit");
        assert!(v.verify_result_provenance(&signed));
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let v = validator();
        let twin = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit");
        let mut signed = sample_receipt().sign(&twin);
        // Flip a fact after signing — the HMAC must no longer match.
        signed.receipt.backend_ok = false;
        assert!(!v.verify_result_provenance(&signed));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let v = validator();
        let other = BnautAttestationSigner::new(b"a-different-key".to_vec(), "unit");
        let signed = sample_receipt().sign(&other);
        assert!(!v.verify_result_provenance(&signed));
    }

    #[test]
    fn malformed_signature_encoding_fails_verification() {
        let v = validator();
        let twin = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit");
        let mut signed = sample_receipt().sign(&twin);
        signed.signature = "not valid base64url!!".to_string();
        assert!(!v.verify_result_provenance(&signed));
    }

    fn issue(now: DateTime<Utc>) -> AttestationToken {
        // Twin signer sharing the validator's key material.
        let signer = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit");
        signer.issue(
            &TokenRequest {
                agent_identity: "agent".to_string(),
                task_uuid: Uuid::new_v4(),
                capabilities: vec!["cap".to_string()],
            },
            now,
            TimeDelta::minutes(10),
        )
    }

    #[test]
    fn valid_token_passes_and_counts() {
        let v = validator();
        let now = Utc::now();
        let token = issue(now);
        let claims = v
            .validate_boundary_call(Some(token.encoded()), "test", None, now)
            .unwrap();
        assert_eq!(claims.agent_identity, "agent");
        assert_eq!(v.validations_total(), 1);
        assert_eq!(v.rejections_total(), 0);
        assert!(v.audit().is_empty());
    }

    #[test]
    fn missing_token_rejected_and_audited() {
        let v = validator();
        let err = v
            .validate_boundary_call(None, "boot", None, Utc::now())
            .unwrap_err();
        assert_eq!(err, AttestationRejection::MissingToken);
        assert_eq!(v.rejections_total(), 1);
        let records = v.audit().snapshot();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].boundary, "boot");
    }

    #[test]
    fn mik_5223_caps_1_rejects_token_lacking_required_capability() {
        // MIK-5223.CAPS.1 — fail-closed: an authentic, unexpired token whose
        // capability allow-list does NOT include the requested action is
        // rejected. Authenticity alone must not authorize an out-of-scope call.
        let v = validator();
        let now = Utc::now();
        let token = issue(now); // minted with capabilities = ["cap"]

        // Requesting an action the token was not scoped for → rejected.
        let err = v
            .validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("write"), now)
            .unwrap_err();
        assert!(
            matches!(err, AttestationRejection::CapabilityNotGranted { .. }),
            "expected CapabilityNotGranted, got: {err:?}"
        );
        assert_eq!(v.rejections_total(), 1);

        // The same token IS admitted for the capability it actually holds.
        let granted = v
            .validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("cap"), now)
            .unwrap();
        assert_eq!(granted.agent_identity, "agent");

        // A capability-agnostic boundary (None, e.g. sandbox_boot) still passes.
        v.validate_boundary_call(Some(token.encoded()), "boot", None, now)
            .unwrap();
    }

    #[test]
    fn wildcard_capability_grants_any_action() {
        // A token holding the "*" wildcard authorizes any requested action.
        let signer = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit");
        let now = Utc::now();
        let token = signer.issue(
            &TokenRequest {
                agent_identity: "agent".to_string(),
                task_uuid: Uuid::new_v4(),
                capabilities: vec!["*".to_string()],
            },
            now,
            TimeDelta::minutes(10),
        );
        let v = validator();
        v.validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("write"), now)
            .unwrap();
    }

    #[test]
    fn expired_token_rejected() {
        let v = validator();
        let issued = Utc::now();
        let token = issue(issued);
        let later = issued + TimeDelta::minutes(11);
        let err = v
            .validate_boundary_call(Some(token.encoded()), "call", None, later)
            .unwrap_err();
        assert!(matches!(err, AttestationRejection::Expired { .. }));
    }

    #[test]
    fn ring_buffer_evicts_oldest_at_capacity() {
        let buffer = AuditRingBuffer::new(2);
        for i in 0..3 {
            buffer.push(AttestationAuditRecord {
                seq: 0,
                timestamp: String::new(),
                boundary: format!("b{i}"),
                token_id: None,
                agent_identity: None,
                rejection: AttestationRejection::MissingToken,
                detection_micros: 0,
            });
        }
        let records = buffer.snapshot();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].boundary, "b1");
        assert_eq!(records[1].boundary, "b2");
        assert_eq!(buffer.total_pushed(), 3);
    }

    #[test]
    fn checkpoint_round_trips_rotation_state() {
        let v = validator();
        let now = Utc::now();
        let token = issue(now);
        let _successor = v.rotate(token.claims(), now, TimeDelta::minutes(10));
        let checkpoint = v.checkpoint();
        assert_eq!(checkpoint.retiring.len(), 1);
        assert_eq!(checkpoint.retiring[0].token_id, token.claims().token_id);

        let fresh = validator();
        fresh.restore(&checkpoint);
        assert_eq!(fresh.checkpoint(), checkpoint);
    }

    #[test]
    fn restore_drops_unparseable_timestamps() {
        let v = validator();
        v.restore(&RotationCheckpoint {
            retiring: vec![RetiringToken {
                token_id: "t".to_string(),
                reject_after: "not-a-time".to_string(),
            }],
        });
        assert!(v.checkpoint().retiring.is_empty());
    }
}
