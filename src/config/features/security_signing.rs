// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Resolving and validating message-signing settings: the key references,
//! and which change to them needs a restart.

use super::MessageSigningConfig;

impl MessageSigningConfig {
    /// Resolve and validate signing settings without changing the literal config.
    ///
    /// Disabled settings are dormant. Errors identify only the field: neither
    /// a secret nor its environment reference belongs in a diagnostic.
    pub(crate) fn resolve_with_env(
        &self,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Self> {
        if !self.enabled {
            return Ok(self.clone());
        }
        if self.key_id.trim().is_empty() {
            return Err(Self::signing_config_error("key_id", "must not be blank"));
        }
        if self.replay_window == 0 {
            return Err(Self::signing_config_error(
                "replay_window",
                "must be greater than zero",
            ));
        }
        let mut resolved = self.clone();
        if self.resolved_shared_secret != Some(Self::key_identity(&self.shared_secret)) {
            resolved.configured_shared_secret = Some(Self::key_identity(&self.shared_secret));
            resolved.shared_secret =
                Self::resolve_key(&self.shared_secret, "shared_secret", overlay)?;
            resolved.resolved_shared_secret = Some(Self::key_identity(&resolved.shared_secret));
        }
        if self.previous_secret.is_empty() {
            resolved.resolved_previous_secret = None;
            resolved.configured_previous_secret = None;
        } else if self.resolved_previous_secret != Some(Self::key_identity(&self.previous_secret)) {
            resolved.configured_previous_secret = Some(Self::key_identity(&self.previous_secret));
            resolved.previous_secret =
                Self::resolve_key(&self.previous_secret, "previous_secret", overlay)?;
            resolved.resolved_previous_secret = Some(Self::key_identity(&resolved.previous_secret));
        }
        Ok(resolved)
    }

    /// A signer and its replay state retain startup settings. Compare both the
    /// configured key source and effective bytes, including equal-byte reference
    /// edits that the ordinary effective-config diff cannot see.
    pub(crate) fn restart_changed_field(
        &self,
        candidate: &Self,
        startup_overlay: &crate::config::EnvOverlay,
        candidate_overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<Option<&'static str>> {
        let running = self.resolve_with_env(startup_overlay)?;
        let proposed = candidate.resolve_with_env(candidate_overlay)?;
        let field = if running.enabled != proposed.enabled {
            Some("enabled")
        } else if running.shared_secret != proposed.shared_secret
            || running
                .configured_shared_secret
                .unwrap_or_else(|| Self::key_identity(&running.shared_secret))
                != proposed
                    .configured_shared_secret
                    .unwrap_or_else(|| Self::key_identity(&proposed.shared_secret))
        {
            Some("shared_secret")
        } else if running.previous_secret != proposed.previous_secret
            || running
                .configured_previous_secret
                .unwrap_or_else(|| Self::key_identity(&running.previous_secret))
                != proposed
                    .configured_previous_secret
                    .unwrap_or_else(|| Self::key_identity(&proposed.previous_secret))
        {
            Some("previous_secret")
        } else if running.key_id != proposed.key_id {
            Some("key_id")
        } else if running.require_nonce != proposed.require_nonce {
            Some("require_nonce")
        } else if running.replay_window != proposed.replay_window {
            Some("replay_window")
        } else {
            None
        };
        Ok(field)
    }

    fn key_identity(value: &str) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(value.as_bytes()).into()
    }

    fn resolve_key(
        literal: &str,
        field: &str,
        overlay: &crate::config::EnvOverlay,
    ) -> crate::Result<String> {
        let missing =
            || Self::signing_config_error(field, "requires an available environment value");
        let resolved = match crate::config::secret_ref::SecretRef::parse(literal) {
            crate::config::secret_ref::SecretRef::Literal(text) => {
                crate::config::secret_ref::expand_template(text, overlay).map_err(|_| missing())?
            }
            reference @ crate::config::secret_ref::SecretRef::Env(_) => {
                reference.resolve(field, overlay).map_err(|_| missing())?
            }
            // The file's own reason (mode, size, missing) is the diagnostic;
            // "requires an available environment value" would mislead.
            reference @ crate::config::secret_ref::SecretRef::File(_) => {
                reference.resolve(&format!("security.message_signing.{field}"), overlay)?
            }
        };
        crate::security::message_signing::validate_key(
            &format!("security.message_signing.{field}"),
            &resolved,
        )?;
        Ok(resolved)
    }

    fn signing_config_error(field: &str, reason: &str) -> crate::Error {
        crate::Error::ConfigValidation(format!("security.message_signing.{field} {reason}"))
    }
}
