//! Symphony+ attestation token injection at sandbox creation (B1-IDENT).
//!
//! Every sandbox boot receives a signed attestation token via bnaut-attestation.
//! The token is the **first** sequence position — other runtime primitives depend
//! on token signing for auth scoping.
//!
//! # Feature flag
//!
//! Set `SYMPHONY_PLUS_ATTESTATION=0` to disable attestation (sandbox starts
//! without token, still isolated, loses identity guarantees).
//!
//! # Token format
//!
//! The token is a base64-encoded JSON object signed with HMAC-SHA256.
//! Claims:
//! - `agent_id` — agent identity (client_id / sub)
//! - `task_uuid` — task UUID
//! - `capability_allowlist` — list of permitted capabilities
//! - `exp` — RFC-3339 expiration timestamp
//! - `iat` — issued-at RFC-3339 timestamp
//! - `sig` — HMAC-SHA256 signature over the claim bytes
//!
//! # Design
//!
//! ```text
//! AttestationClaims        (serde, the payload)
//!   └── AttestationToken   (signs/validates with HMAC-SHA256)
//!
//! AttestationSigner        (holds the shared secret)
//!   ├── sign(claims) → AttestationToken
//!   └── verify(token) → Result<AttestationClaims>
//!
//! AuditRingBuffer          (fixed-size ring buffer for forgery detection)
//!   ├── record(entry)
//!   └── recent_forgeries() → Vec<AuditEntry>
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ── Feature flag ──────────────────────────────────────────────────────────────

/// Return `true` when Symphony+ attestation is enabled.
///
/// Controlled by `SYMPHONY_PLUS_ATTESTATION` env var:
/// - unset or `"1"` → enabled (default)
/// - `"0"` → disabled
pub fn attestation_enabled() -> bool {
    match std::env::var("SYMPHONY_PLUS_ATTESTATION") {
        Ok(val) if val == "0" => false,
        _ => true,
    }
}

// ── AttestationClaims ─────────────────────────────────────────────────────────

/// Claims carried in an attestation token.
///
/// # Acceptance Criteria Mapping
///
/// AC.2: Token carries agent identity, task UUID, capability allow-list,
/// RFC-3339 expiration; signed by bnaut-attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationClaims {
    /// Agent identity (maps to `client_id` / `sub`).
    pub agent_id: String,
    /// Task UUID (v4).
    pub task_uuid: String,
    /// Capability allow-list — names of permitted capabilities.
    pub capability_allowlist: Vec<String>,
    /// RFC-3339 expiration timestamp.
    pub exp: String,
    /// RFC-3339 issued-at timestamp.
    pub iat: String,
}

impl AttestationClaims {
    /// Create new claims with an expiration offset from now.
    pub fn new(
        agent_id: String,
        task_uuid: String,
        capability_allowlist: Vec<String>,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(ttl).unwrap_or_default();
        Self {
            agent_id,
            task_uuid,
            capability_allowlist,
            exp: exp.to_rfc3339(),
            iat: now.to_rfc3339(),
        }
    }

    /// Check whether the token is expired.
    pub fn is_expired(&self) -> bool {
        DateTime::parse_from_rfc3339(&self.exp)
            .map(|exp| Utc::now() > exp)
            .unwrap_or(true) // unparseable exp → treat as expired (fail-closed)
    }

    /// Time until expiration. `None` if already expired.
    pub fn time_to_expiry(&self) -> Option<Duration> {
        DateTime::parse_from_rfc3339(&self.exp)
            .ok()
            .and_then(|exp| {
                let remaining = exp.signed_duration_since(Utc::now());
                remaining.to_std().ok()
            })
    }
}

// ── AttestationToken ──────────────────────────────────────────────────────────

/// A signed attestation token.
///
/// Serialized as a base64-encoded JSON object with an HMAC-SHA256 signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationToken {
    /// The claims body.
    #[serde(flatten)]
    pub claims: AttestationClaims,
    /// HMAC-SHA256 signature over the canonical JSON of claims (base64).
    pub sig: String,
}

impl AttestationToken {
    /// Serialize claims to canonical JSON for signing.
    fn claims_bytes(claims: &AttestationClaims) -> Vec<u8> {
        // Use a deterministic JSON representation for signing.
        serde_json::to_vec(claims).unwrap_or_default()
    }

    /// Sign claims with the given HMAC key.
    pub fn sign(claims: AttestationClaims, secret: &[u8]) -> Self {
        let bytes = Self::claims_bytes(&claims);
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
        mac.update(&bytes);
        let sig_bytes = mac.finalize().into_bytes();
        let sig = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig_bytes);
        Self { claims, sig }
    }

    /// Verify the token signature against the given secret.
    ///
    /// Returns `Ok(&AttestationClaims)` on success, `Err(AttestationError)` on failure.
    pub fn verify(&self, secret: &[u8]) -> Result<&AttestationClaims, AttestationError> {
        let bytes = Self::claims_bytes(&self.claims);
        let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| {
            AttestationError::Crypto("HMAC key rejection".to_string())
        })?;
        mac.update(&bytes);

        let expected_sig = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &mac.finalize().into_bytes(),
        );

        if self.sig != expected_sig {
            return Err(AttestationError::InvalidSignature);
        }

        if self.claims.is_expired() {
            return Err(AttestationError::Expired);
        }

        Ok(&self.claims)
    }

    /// Check if the token signature is valid (without checking expiry).
    ///
    /// Used in forgery detection — we want to measure detection time even
    /// for non-expired forged tokens.
    pub fn signature_valid(&self, secret: &[u8]) -> bool {
        let bytes = Self::claims_bytes(&self.claims);
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            return false;
        };
        mac.update(&bytes);
        let expected_sig = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &mac.finalize().into_bytes(),
        );
        self.sig == expected_sig
    }
}

// ── AttestationSigner ─────────────────────────────────────────────────────────

/// HMAC-SHA256 signer for attestation tokens.
///
/// Holds the shared secret used to sign and verify tokens.
/// Thread-safe via `Arc`.
#[derive(Debug, Clone)]
pub struct AttestationSigner {
    /// HMAC shared secret.
    secret: Arc<Vec<u8>>,
    /// Whether attestation is enabled.
    enabled: bool,
}

impl AttestationSigner {
    /// Create a new signer with the given secret.
    ///
    /// Returns `None` when attestation is disabled (feature flag).
    pub fn new(secret: Vec<u8>) -> Option<Self> {
        if !attestation_enabled() {
            return None;
        }
        Some(Self {
            secret: Arc::new(secret),
            enabled: true,
        })
    }

    /// Create a signer for testing (always enabled, regardless of env var).
    #[must_use]
    pub fn new_always(secret: Vec<u8>) -> Self {
        Self {
            secret: Arc::new(secret),
            enabled: true,
        }
    }

    /// Whether attestation is enabled for this signer.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Sign claims into an attestation token.
    pub fn sign(&self, claims: AttestationClaims) -> AttestationToken {
        AttestationToken::sign(claims, &self.secret)
    }

    /// Verify a token and return its claims.
    pub fn verify(&self, token: &AttestationToken) -> Result<&AttestationClaims, AttestationError> {
        token.verify(&self.secret)
    }

    /// Return the secret bytes (for downstream token rotation).
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

// ── AttestationError ──────────────────────────────────────────────────────────

/// Errors that can occur during attestation token validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// Token signature is invalid (forged or corrupted).
    InvalidSignature,
    /// Token has expired.
    Expired,
    /// Token is missing claims.
    MissingClaims,
    /// Cryptographic operation failed.
    Crypto(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "attestation token signature invalid"),
            Self::Expired => write!(f, "attestation token expired"),
            Self::MissingClaims => write!(f, "attestation token missing required claims"),
            Self::Crypto(msg) => write!(f, "attestation crypto error: {msg}"),
        }
    }
}

// ── AuditRingBuffer ───────────────────────────────────────────────────────────

/// An audit entry recorded on token validation failure.
///
/// AC.3: Token validates against gateway on every cross-boundary call;
/// rejection logs to audit ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC-3339 timestamp of the rejection.
    pub timestamp: String,
    /// The error that occurred.
    pub error: String,
    /// Agent identity from the token (if extractable).
    pub agent_id: Option<String>,
    /// Task UUID from the token (if extractable).
    pub task_uuid: Option<String>,
    /// Operation being attempted when the rejection occurred.
    pub operation: String,
    /// Time from token presentation to rejection decision (milliseconds).
    pub decision_time_ms: u64,
}

/// Fixed-size ring buffer for audit entries.
///
/// AC.3: Rejection logs to audit ring buffer.
/// AC.5: Token forgery attempt detected and logged within 100ms.
#[derive(Debug)]
pub struct AuditRingBuffer {
    /// Ring buffer of audit entries.
    entries: RwLock<Vec<AuditEntry>>,
    /// Maximum number of entries.
    capacity: usize,
    /// Write position (oldest entry is overwritten when full).
    position: RwLock<usize>,
    /// Whether the buffer has wrapped (is full).
    wrapped: AtomicBool,
}

impl AuditRingBuffer {
    /// Create a new audit ring buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: RwLock::new(Vec::with_capacity(capacity)),
            capacity,
            position: RwLock::new(0),
            wrapped: AtomicBool::new(false),
        }
    }

    /// Record an audit entry.
    pub fn record(&self, entry: AuditEntry) {
        let mut entries = self.entries.write();
        let mut pos = self.position.write();

        if entries.len() < self.capacity {
            entries.push(entry);
        } else {
            entries[*pos] = entry;
            *pos = (*pos + 1) % self.capacity;
            if *pos == 0 {
                self.wrapped.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Return all entries in insertion order (oldest first).
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        let entries = self.entries.read();
        if !self.wrapped.load(Ordering::Relaxed) || entries.len() < self.capacity {
            return entries.clone();
        }

        let pos = *self.position.read();
        let mut out = Vec::with_capacity(entries.len());
        out.extend_from_slice(&entries[pos..]);
        out.extend_from_slice(&entries[..pos]);
        out
    }

    /// Return the most recent `n` entries.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        let all = self.entries();
        let start = all.len().saturating_sub(n);
        all[start..].to_vec()
    }

    /// Count of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

impl Default for AuditRingBuffer {
    fn default() -> Self {
        Self::new(1024)
    }
}

// ── AttestationValidator ──────────────────────────────────────────────────────

/// Thread-safe attestation token validator with integrated audit.
///
/// Used by `SandboxEnforcer` to validate tokens on every cross-boundary call
/// (AC.3) and detect forgery within 100ms (AC.5).
#[derive(Debug, Clone)]
pub struct AttestationValidator {
    /// The HMAC signer for token verification.
    signer: Option<AttestationSigner>,
    /// Audit ring buffer for rejection logging.
    audit: Arc<AuditRingBuffer>,
    /// Whether to require attestation (fail-closed when `true`).
    require_attestation: bool,
}

impl AttestationValidator {
    /// Create a new validator.
    pub fn new(signer: Option<AttestationSigner>, require_attestation: bool) -> Self {
        Self {
            signer,
            audit: Arc::new(AuditRingBuffer::default()),
            require_attestation,
        }
    }

    /// Create a validator with a custom audit buffer capacity.
    pub fn with_audit_capacity(
        signer: Option<AttestationSigner>,
        require_attestation: bool,
        audit_capacity: usize,
    ) -> Self {
        Self {
            signer,
            audit: Arc::new(AuditRingBuffer::new(audit_capacity)),
            require_attestation,
        }
    }

    /// Whether attestation is required for this validator.
    #[must_use]
    pub fn requires_attestation(&self) -> bool {
        self.require_attestation
    }

    /// Validate a token and return its claims.
    ///
    /// Records audit entries for all rejection paths (AC.3).
    /// Guarantees forgery detection and logging within 100ms (AC.5).
    pub fn validate(
        &self,
        token: Option<&AttestationToken>,
        operation: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        let start = Instant::now();

        let result = self.validate_inner(token);

        let decision_time_ms = start.elapsed().as_millis() as u64;

        if let Err(ref err) = result {
            let agent_id = token.and_then(|t| Some(t.claims.agent_id.clone()));
            let task_uuid = token.and_then(|t| Some(t.claims.task_uuid.clone()));

            self.audit.record(AuditEntry {
                timestamp: Utc::now().to_rfc3339(),
                error: err.to_string(),
                agent_id,
                task_uuid,
                operation: operation.to_string(),
                decision_time_ms,
            });
        }

        result
    }

    fn validate_inner(
        &self,
        token: Option<&AttestationToken>,
    ) -> Result<AttestationClaims, AttestationError> {
        let signer = match &self.signer {
            Some(s) => s,
            None => {
                if self.require_attestation {
                    // AC.1: Sandbox boot fails closed without a valid attestation token.
                    return Err(AttestationError::Crypto(
                        "attestation is required but no signer configured".to_string(),
                    ));
                }
                // Attestation not required and no signer → pass through.
                return Ok(AttestationClaims {
                    agent_id: "anonymous".to_string(),
                    task_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                    capability_allowlist: vec![],
                    exp: Utc::now().to_rfc3339(),
                    iat: Utc::now().to_rfc3339(),
                });
            }
        };

        let token = match token {
            Some(t) => t,
            None => {
                if self.require_attestation {
                    // AC.1: No token provided, attestation required → fail closed.
                    return Err(AttestationError::MissingClaims);
                }
                // Attestation not required, no token → pass through.
                return Ok(AttestationClaims {
                    agent_id: "anonymous".to_string(),
                    task_uuid: "00000000-0000-0000-0000-000000000000".to_string(),
                    capability_allowlist: vec![],
                    exp: Utc::now().to_rfc3339(),
                    iat: Utc::now().to_rfc3339(),
                });
            }
        };

        if self.require_attestation {
            // Fail-closed: full validation.
            signer.verify(token).map(|c| c.clone())
        } else {
            // Attestation not required but token present — verify signature only.
            if token.signature_valid(signer.secret_bytes()) {
                Ok(token.claims.clone())
            } else {
                Err(AttestationError::InvalidSignature)
            }
        }
    }

    /// Get a reference to the audit ring buffer.
    #[must_use]
    pub fn audit(&self) -> &Arc<AuditRingBuffer> {
        &self.audit
    }

    /// Get the signer (if any).
    #[must_use]
    pub fn signer(&self) -> Option<&AttestationSigner> {
        self.signer.as_ref()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;
