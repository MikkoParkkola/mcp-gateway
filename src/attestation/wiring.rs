// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env-driven wiring of the gateway attestation validator (MIK-6163 rollout).
//!
//! The validator and the [`MetaMcp::with_attestation`] builder already exist
//! (MIK-5223 / #259, #261); this module is the missing seam that decides — from
//! operator config — *whether* to attach a validator on a live gateway and in
//! which [`AttestationMode`].
//!
//! Modes (MIK-7570 ATTEST.1):
//! - Default is **off**: unset, empty or `off` attaches no validator at all —
//!   a pure no-op, byte-identical to the pre-wiring gateway.
//! - `observe` audits every presented token but never blocks a call.
//! - `enforce` is a load error in this build. The direct `/mcp/{name}` route
//!   and synthesized envelopes carry no token yet, so an enforce that only
//!   guarded `gateway_invoke` would claim more than it refuses.
//! - Any other value is a load error, never a silent downgrade.
//!
//! [`MetaMcp::with_attestation`]: crate::gateway::meta_mcp::MetaMcp::with_attestation
//! [`AttestationMode`]: super::validator::AttestationMode

use std::sync::Arc;

use super::signer::BnautAttestationSigner;
use super::validator::{AttestationMode, AttestationValidator};

/// Env var selecting the wired attestation mode at the `gateway_invoke`
/// boundary: `off` (default) or `observe`.
///
/// `enforce` is refused at load in this build — see the module docs.
pub const ATTESTATION_MODE_ENV: &str = "GATEWAY_ATTESTATION_MODE";

/// Env var carrying the HMAC-SHA256 signing key shared with bnaut-attestation.
///
/// When unset/empty/whitespace-only the validator still initialises; in
/// observe mode every presented token simply fails signature verification
/// and is audit-logged (the call is never blocked). A whitespace-only value
/// is normalized to the same empty-key posture rather than used verbatim as
/// low-entropy HMAC key material (MIK-6909 item 1).
pub const ATTESTATION_SIGNING_KEY_ENV: &str = "GATEWAY_ATTESTATION_SIGNING_KEY";

/// Env var for the signing key id (namespaced under `bnaut/` by the signer).
/// Defaults to [`DEFAULT_KEY_ID`].
pub const ATTESTATION_KEY_ID_ENV: &str = "GATEWAY_ATTESTATION_KEY_ID";

/// Default signing key id when [`ATTESTATION_KEY_ID_ENV`] is unset.
pub const DEFAULT_KEY_ID: &str = "gateway";

/// Resolve the attestation wiring from explicit settings — the unit-testable
/// core that performs no process-environment reads.
///
/// The mode is matched case-insensitively after trimming. Unset, empty or
/// `off` returns `Ok(None)` (attach no validator — the default). `observe`
/// returns `Ok(Some((validator, Observe)))`. `enforce`, which is not wired in
/// this build, and any unrecognised value return `Err` for startup to report.
pub fn resolve_attestation_wiring(
    mode: Option<&str>,
    signing_key: Option<&[u8]>,
    key_id: Option<&str>,
) -> Result<Option<(Arc<AttestationValidator>, AttestationMode)>, String> {
    let normalized = mode.map(|m| m.trim().to_ascii_lowercase());
    let mode = match normalized.as_deref() {
        None | Some("" | "off") => return Ok(None),
        Some("observe") => AttestationMode::Observe,
        Some(other) => {
            return Err(format!(
                "{ATTESTATION_MODE_ENV}={other:?} is not a valid mode; \
                 use `observe` or `off`"
            ));
        }
    };

    let key = signing_key.unwrap_or_default();
    // Whitespace-only key material is exactly as low-entropy as an empty
    // key (MIK-6909 item 1) — normalize both to the same "no key" posture
    // rather than using the whitespace bytes verbatim as the HMAC key.
    // Decode as UTF-8 and reuse `str::trim`, so this gate uses the exact
    // Unicode-whitespace set as `resolve_provenance_signer` /
    // `validator_from_env` (parity, MIK-6909 item 1). The empty slice trims
    // to empty, subsuming the pre-existing empty-key check. Non-UTF-8 bytes
    // are treated as *not* whitespace and used verbatim — the correct
    // fail-open-to-use posture for an opaque binary key.
    let key = if std::str::from_utf8(key).is_ok_and(|s| s.trim().is_empty()) {
        tracing::warn!(
            env = ATTESTATION_SIGNING_KEY_ENV,
            "attestation observe mode enabled without a signing key; presented tokens \
             will fail verification and be audit-logged only (never blocked)"
        );
        Vec::new()
    } else {
        key.to_vec()
    };
    let key_id = key_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_KEY_ID);

    let signer = BnautAttestationSigner::new(key, key_id);
    let validator = Arc::new(AttestationValidator::new(signer));
    Ok(Some((validator, mode)))
}

/// Resolve the attestation wiring from an env overlay.
///
/// Thin wrapper over [`resolve_attestation_wiring`] reading
/// [`ATTESTATION_MODE_ENV`], [`ATTESTATION_SIGNING_KEY_ENV`], and
/// [`ATTESTATION_KEY_ID_ENV`]. With nothing set the default is off.
///
/// Reads the overlay, not `std::env`: env files load into an in-memory overlay
/// rather than into the process environment, so a process-environment read
/// cannot see a mode or a signing key an env file assigns.
pub fn attestation_wiring_from_overlay(
    env: &crate::config::EnvOverlay,
) -> Result<Option<(Arc<AttestationValidator>, AttestationMode)>, String> {
    let mode = env.resolve(ATTESTATION_MODE_ENV);
    let key = env.resolve(ATTESTATION_SIGNING_KEY_ENV);
    let key_id = env.resolve(ATTESTATION_KEY_ID_ENV);
    resolve_attestation_wiring(
        mode.as_deref(),
        key.as_deref().map(str::as_bytes),
        key_id.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(raw: Option<&str>) -> Result<Option<AttestationMode>, String> {
        resolve_attestation_wiring(raw, Some(b"k"), None).map(|w| w.map(|(_, mode)| mode))
    }

    #[test]
    fn mode_from_an_env_file_reaches_the_wiring() {
        let dir = tempfile::tempdir().unwrap();
        let env_file = dir.path().join(".env");
        std::fs::write(&env_file, "GATEWAY_ATTESTATION_MODE=observe\n").unwrap();
        let overlay = crate::config::EnvOverlay::from_paths(&[env_file]);

        assert!(
            matches!(attestation_wiring_from_overlay(&overlay), Ok(Some(_))),
            "`observe` in an env file must attach a validator"
        );
        assert!(std::env::var(ATTESTATION_MODE_ENV).is_err());
    }

    /// MIK-7570.ATTEST.1: with nothing set, no validator is built.
    #[test]
    fn unset_mode_attaches_no_validator() {
        assert!(
            matches!(
                attestation_wiring_from_overlay(&crate::config::EnvOverlay::none()),
                Ok(None)
            ),
            "with nothing set, attestation is off"
        );
        for raw in [None, Some(""), Some("   ")] {
            assert_eq!(mode_of(raw), Ok(None), "mode={raw:?}");
        }
    }

    #[test]
    fn explicit_observe_attaches_validator() {
        let (_, mode) = resolve_attestation_wiring(Some("observe"), Some(b"k"), Some("kid"))
            .expect("observe must parse")
            .expect("observe must attach a validator");
        assert_eq!(mode, AttestationMode::Observe);
    }

    #[test]
    fn mode_parsing_is_case_and_whitespace_insensitive() {
        for raw in ["  ObSeRvE  ", "OBSERVE", "\tobserve\n"] {
            assert_eq!(
                mode_of(Some(raw)),
                Ok(Some(AttestationMode::Observe)),
                "{raw:?}"
            );
        }
        for raw in ["OFF", "  Off ", "\toff\n"] {
            assert_eq!(mode_of(Some(raw)), Ok(None), "{raw:?}");
        }
        for raw in ["ENFORCE", " Enforce ", "\tenforce\n"] {
            assert!(mode_of(Some(raw)).is_err(), "{raw:?} must be refused");
        }
    }

    #[test]
    fn off_is_a_pure_no_op_returning_none() {
        // off → no validator attached at all (byte-identical to pre-wiring).
        assert_eq!(mode_of(Some("off")), Ok(None));
        assert!(matches!(
            resolve_attestation_wiring(Some("  OFF "), None, None),
            Ok(None)
        ));
    }

    /// `enforce` is not wired in this build, so it is refused at load rather
    /// than downgraded to observe. The message says so and names the values
    /// that do work.
    #[test]
    fn enforce_is_refused_at_load() {
        let err = mode_of(Some("enforce")).expect_err("enforce must be a load error");
        assert!(err.contains("not available in this build"), "{err}");
        assert!(err.contains("observe") && err.contains("off"), "{err}");
    }

    #[test]
    fn unknown_mode_is_refused() {
        for raw in ["enforcee", "block", "true", "1"] {
            let err = mode_of(Some(raw)).expect_err("an unknown mode must be a load error");
            assert!(err.contains(raw), "error must name the value: {err}");
            assert!(err.contains("observe") && err.contains("off"), "{err}");
            assert!(!err.contains("not available in this build"), "{err}");
        }
    }

    #[test]
    fn missing_signing_key_still_initialises_validator() {
        // No key configured → validator still inits (observe will audit-only).
        let wiring = resolve_attestation_wiring(Some("observe"), None, None).unwrap();
        assert!(wiring.is_some(), "validator must init even without a key");
        let (validator, _) = wiring.unwrap();
        // A token cannot verify against the empty key, so observe would audit it;
        // assert the validator is live and starts with an empty audit buffer.
        assert!(validator.audit().is_empty());
    }

    #[test]
    fn whitespace_only_signing_key_normalizes_to_empty_not_used_verbatim() {
        // MIK-6909 item 1: a whitespace-only key must not be used verbatim as
        // HMAC key material (that would install a low-entropy signer). It is
        // normalized to the same "no signing key" posture as an absent key —
        // the validator still initialises (observe mode audits, never
        // blocks), matching `missing_signing_key_still_initialises_validator`
        // above.
        use super::super::signer::TokenRequest;
        use super::super::validator::AttestationRejection;
        use chrono::{TimeDelta, Utc};

        let (validator, _) = resolve_attestation_wiring(Some("observe"), Some(b"   "), Some("kid"))
            .unwrap()
            .expect("whitespace-only key must still attach an observe validator");

        let request = TokenRequest {
            agent_identity: "agent".to_string(),
            task_uuid: uuid::Uuid::new_v4(),
            capabilities: vec![],
        };
        let now = Utc::now();

        // A token signed with the literal whitespace bytes must NOT verify —
        // proving the wired validator did not use those bytes as key material.
        let literal_signer = BnautAttestationSigner::new(b"   ".to_vec(), "kid");
        let literal_token = literal_signer.issue(&request, now, TimeDelta::minutes(5));
        let err = validator
            .validate_boundary_call(Some(literal_token.encoded()), "test", None, now)
            .expect_err("token signed with the literal whitespace key must be rejected");
        assert_eq!(err, AttestationRejection::BadSignature);

        // A token signed with a truly empty key DOES verify — the posture
        // whitespace-only normalizes to.
        let empty_signer = BnautAttestationSigner::new(Vec::new(), "kid");
        let empty_token = empty_signer.issue(&request, now, TimeDelta::minutes(5));
        validator
            .validate_boundary_call(Some(empty_token.encoded()), "test", None, now)
            .expect("whitespace-only key normalizes to empty key material");
    }
}
