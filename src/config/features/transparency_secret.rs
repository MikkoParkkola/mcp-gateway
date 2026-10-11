// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365: the transparency-log HMAC key is resolved once at load, like
//! message signing's key, and never parsed again.

use super::TransparencyLogConfig;
use crate::config::env_overlay::{EnvOverlay, SecretRefsRead, digest};
use crate::config::secret_ref::{self, SecretRef};
use crate::security::message_signing::MIN_SECRET_BYTES;
use crate::{Error, Result};

const FIELD: &str = "security.transparency_log.shared_secret";

impl TransparencyLogConfig {
    /// Why the key did not resolve, when the log is off and it did not
    /// (MIK-8365). `audit verify` refuses on it: an empty key would verify a
    /// signed log hash-only, and the reference text is public.
    #[must_use]
    pub fn unresolved_secret(&self) -> Option<&str> {
        self.unresolved_secret.as_deref()
    }

    /// Resolve `shared_secret` as written: `${VAR}` templates, `env:NAME`,
    /// `file:PATH`, or a literal. One read: the first failure is the answer,
    /// and the resolved bytes are the key even when they look like a reference.
    ///
    /// With the log on, a failure refuses the load and a non-empty key under
    /// [`MIN_SECRET_BYTES`] is refused. With it off, a failure leaves the key
    /// empty and records why, so `audit verify` refuses rather than verify with
    /// the reference's public text. Messages name the field, never a value.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] when the log is on and the key does not
    /// resolve or is too short.
    pub(crate) fn resolve_secret(
        &mut self,
        auth_enabled: bool,
        overlay: &EnvOverlay,
        refs: &mut SecretRefsRead,
    ) -> Result<()> {
        let enabled = self.is_enabled(auth_enabled);
        let resolved = if self.shared_secret.contains("${") {
            secret_ref::expand_field(FIELD, &self.shared_secret, overlay)
                .map_err(|why| Error::ConfigValidation(format!("{why}{}", overlay.absent_files_hint())))
        } else {
            match SecretRef::parse(&self.shared_secret) {
                // An empty literal stays empty: entries are unsigned.
                SecretRef::Literal(_) => return self.check_length(enabled),
                reference @ SecretRef::Env(name) => {
                    refs.0.insert(name.to_owned());
                    reference.resolve(FIELD, overlay)
                }
                SecretRef::File(path) => secret_ref::read_file_ref(FIELD, path).inspect(|key| {
                    refs.1.insert(path.to_path_buf(), Some(digest(key)));
                }),
            }
        };
        match resolved {
            Ok(key) => {
                self.shared_secret = key;
                self.check_length(enabled)
            }
            Err(error) if enabled => Err(error),
            Err(error) => {
                let reason = match error {
                    Error::ConfigValidation(message) => message,
                    other => other.to_string(),
                };
                tracing::warn!(
                    "{reason}; the transparency log is off, so the gateway starts, but `audit \
                     verify` refuses until the key resolves"
                );
                self.shared_secret.clear();
                self.unresolved_secret = Some(reason);
                Ok(())
            }
        }
    }

    fn check_length(&self, enabled: bool) -> Result<()> {
        if enabled && !self.shared_secret.is_empty() && self.shared_secret.len() < MIN_SECRET_BYTES
        {
            return Err(Error::ConfigValidation(format!(
                "{FIELD} must be at least {MIN_SECRET_BYTES} bytes"
            )));
        }
        Ok(())
    }
}
