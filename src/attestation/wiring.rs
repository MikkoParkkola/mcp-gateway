// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env-driven wiring of the gateway attestation validator (MIK-6163 rollout).
//!
//! The validator and the [`MetaMcp::with_attestation`] builder already exist
//! (MIK-5223 / #259, #261); this module is the missing seam that decides — from
//! operator config — *whether* to attach a validator on a live gateway and in
//! which [`AttestationMode`].
//!
//! Rollout posture (operator directive 2026-06-19):
//! - Default is **observe**: the validator audits every presented token but
//!   never blocks a call, so enabling it on live traffic cannot break
//!   unattested or mis-attested calls.
//! - `off` attaches no validator at all — a pure no-op, byte-identical to the
//!   pre-wiring gateway.
//! - `enforce` is *intentionally not yet a recognised value*. Flipping to
//!   fail-closed is a future one-liner here (add the `Some("enforce")` arm),
//!   which is why an unrecognised mode falls back to observe rather than
//!   silently enforcing.
//!
//! [`MetaMcp::with_attestation`]: crate::gateway::meta_mcp::MetaMcp::with_attestation
//! [`AttestationMode`]: super::validator::AttestationMode

use std::sync::Arc;

use super::signer::BnautAttestationSigner;
use super::validator::{AttestationMode, AttestationValidator};

/// Env var selecting the wired attestation mode at the `gateway_invoke`
/// boundary: `observe` (default) or `off`.
///
/// `enforce` is deliberately NOT recognised yet — see the module docs.
pub const ATTESTATION_MODE_ENV: &str = "GATEWAY_ATTESTATION_MODE";

/// Env var carrying the HMAC-SHA256 signing key shared with bnaut-attestation.
///
/// When unset/empty the validator still initialises; in observe mode every
/// presented token simply fails signature verification and is audit-logged
/// (the call is never blocked).
pub const ATTESTATION_SIGNING_KEY_ENV: &str = "GATEWAY_ATTESTATION_SIGNING_KEY";

/// Env var for the signing key id (namespaced under `bnaut/` by the signer).
/// Defaults to [`DEFAULT_KEY_ID`].
pub const ATTESTATION_KEY_ID_ENV: &str = "GATEWAY_ATTESTATION_KEY_ID";

/// Default signing key id when [`ATTESTATION_KEY_ID_ENV`] is unset.
pub const DEFAULT_KEY_ID: &str = "gateway";

/// Resolve the attestation wiring from explicit settings — the unit-testable
/// core that performs no process-environment reads.
///
/// Returns `None` when the mode is `off` (attach no validator — a pure no-op).
/// Returns `Some((validator, mode))` otherwise. The mode is matched
/// case-insensitively after trimming; unset/empty resolves to
/// [`AttestationMode::Observe`] (the default rollout posture), and any
/// unrecognised value — including `enforce`, which is not yet wired — also
/// falls back to observe with a warning.
#[must_use]
pub fn resolve_attestation_wiring(
    mode: Option<&str>,
    signing_key: Option<&[u8]>,
    key_id: Option<&str>,
) -> Option<(Arc<AttestationValidator>, AttestationMode)> {
    let normalized = mode.map(|m| m.trim().to_ascii_lowercase());
    let mode = match normalized.as_deref() {
        Some("off") => return None,
        None | Some("" | "observe") => AttestationMode::Observe,
        Some(other) => {
            tracing::warn!(
                requested = other,
                "GATEWAY_ATTESTATION_MODE unrecognised (enforce is not yet wired); \
                 defaulting to observe"
            );
            AttestationMode::Observe
        }
    };

    let key = signing_key.unwrap_or_default().to_vec();
    if key.is_empty() {
        tracing::warn!(
            env = ATTESTATION_SIGNING_KEY_ENV,
            "attestation observe mode enabled without a signing key; presented tokens \
             will fail verification and be audit-logged only (never blocked)"
        );
    }
    let key_id = key_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_KEY_ID);

    let signer = BnautAttestationSigner::new(key, key_id);
    let validator = Arc::new(AttestationValidator::new(signer));
    Some((validator, mode))
}

/// Read the attestation wiring from the process environment.
///
/// Thin wrapper over [`resolve_attestation_wiring`] reading
/// [`ATTESTATION_MODE_ENV`], [`ATTESTATION_SIGNING_KEY_ENV`], and
/// [`ATTESTATION_KEY_ID_ENV`]. With no env set the default is observe.
#[must_use]
pub fn attestation_wiring_from_env() -> Option<(Arc<AttestationValidator>, AttestationMode)> {
    let mode = std::env::var(ATTESTATION_MODE_ENV).ok();
    let key = std::env::var(ATTESTATION_SIGNING_KEY_ENV).ok();
    let key_id = std::env::var(ATTESTATION_KEY_ID_ENV).ok();
    resolve_attestation_wiring(
        mode.as_deref(),
        key.as_deref().map(str::as_bytes),
        key_id.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_unset_is_observe_with_validator() {
        // Unset mode → default rollout posture: validator attached, observe.
        let (_, mode) = resolve_attestation_wiring(None, Some(b"k"), None)
            .expect("default must attach a validator");
        assert_eq!(mode, AttestationMode::Observe);
    }

    #[test]
    fn explicit_observe_attaches_validator() {
        let (_, mode) = resolve_attestation_wiring(Some("observe"), Some(b"k"), Some("kid"))
            .expect("observe must attach a validator");
        assert_eq!(mode, AttestationMode::Observe);
    }

    #[test]
    fn mode_parsing_is_case_and_whitespace_insensitive() {
        let (_, mode) = resolve_attestation_wiring(Some("  ObSeRvE  "), Some(b"k"), None)
            .expect("trimmed/cased observe must attach a validator");
        assert_eq!(mode, AttestationMode::Observe);
    }

    #[test]
    fn off_is_a_pure_no_op_returning_none() {
        // off → no validator attached at all (byte-identical to pre-wiring).
        assert!(resolve_attestation_wiring(Some("off"), Some(b"k"), None).is_none());
        assert!(resolve_attestation_wiring(Some("  OFF "), None, None).is_none());
    }

    #[test]
    fn unrecognised_mode_falls_back_to_observe_not_enforce() {
        // enforce (and any unknown value) must NOT silently enable fail-closed;
        // it falls back to the safe observe posture.
        for raw in ["enforce", "block", "true", "1"] {
            let (_, mode) = resolve_attestation_wiring(Some(raw), Some(b"k"), None)
                .unwrap_or_else(|| panic!("{raw} should still attach an observe validator"));
            assert_eq!(mode, AttestationMode::Observe, "mode={raw}");
        }
    }

    #[test]
    fn missing_signing_key_still_initialises_validator() {
        // No key configured → validator still inits (observe will audit-only).
        let wiring = resolve_attestation_wiring(Some("observe"), None, None);
        assert!(wiring.is_some(), "validator must init even without a key");
        let (validator, _) = wiring.unwrap();
        // A token cannot verify against the empty key, so observe would audit it;
        // assert the validator is live and starts with an empty audit buffer.
        assert!(validator.audit().is_empty());
    }
}
