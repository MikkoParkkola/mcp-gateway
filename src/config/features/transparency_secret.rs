// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8365: the transparency-log HMAC key is resolved once at load, like
//! message signing's key, and never parsed again.

use std::path::Path;

use super::TransparencyLogConfig;
use crate::config::env_overlay::{EnvOverlay, SecretRefsRead, digest};
use crate::config::secret_ref::{self, SecretRef};
use crate::{Error, Result};

const FIELD: &str = "security.transparency_log.shared_secret";
/// The refusal while the key is unresolved. The detailed reason (which
/// variable or file) is logged once, at load.
const UNRESOLVED: &str = "security.transparency_log.shared_secret did not resolve (an unset or \
                          empty variable, or an unreadable file; the load warning names it)";

impl TransparencyLogConfig {
    /// Why the key did not resolve while the log was off (MIK-8365): a
    /// field-named reason, never a value. Every reader that verifies with the
    /// key (`audit verify`, SIEM export) refuses while it is set, since the key
    /// is then empty and would verify a signed log hash-only.
    pub(crate) fn unresolved_secret(&self) -> Option<&'static str> {
        self.unresolved_secret.then_some(UNRESOLVED)
    }

    /// Resolve `shared_secret` as written: `${VAR}` templates, `env:NAME`,
    /// `file:PATH`, or a literal. One read: the first failure is the answer,
    /// and the resolved bytes are the key even when they look like a reference.
    ///
    /// With the log on, a failure refuses the load and a non-empty key under
    /// 32 bytes, or all zero, is refused. With it off, a failure leaves the key
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
            secret_ref::expand_field(FIELD, &self.shared_secret, overlay).map_err(|why| {
                Error::ConfigValidation(format!("{why}{}", overlay.absent_files_hint()))
            })
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
                self.unresolved_secret = true;
                Ok(())
            }
        }
    }

    /// Message signing's weak-key rule, applied to a key the log will use.
    fn check_length(&self, enabled: bool) -> Result<()> {
        if enabled && !self.shared_secret.is_empty() {
            crate::security::message_signing::validate_key(FIELD, &self.shared_secret)?;
        }
        Ok(())
    }
}

impl crate::config::Config {
    /// The key and key id `audit verify` checks a log with, read from the
    /// gateway config at `path` (MIK-6700 HMAC.3). Fails closed: a config that
    /// does not load, or whose key did not resolve while the log was off
    /// (MIK-8365), is an error, never an empty key (that would verify a signed
    /// log hash-only) and never the reference's public text.
    ///
    /// # Errors
    ///
    /// As [`Self::load`], and [`Error::ConfigValidation`] naming the field
    /// when the key did not resolve.
    pub fn audit_verify_config(
        path: Option<&Path>,
    ) -> Result<crate::security::transparency_log::TransparencyLogConfig> {
        let config = Self::load(path)?;
        let log = &config.security.transparency_log;
        if let Some(reason) = log.unresolved_secret() {
            return Err(Error::ConfigValidation(reason.to_owned()));
        }
        Ok(crate::security::transparency_log::TransparencyLogConfig {
            key_id: log.key_id.clone(),
            shared_secret: log.shared_secret.clone(),
            ..crate::security::transparency_log::TransparencyLogConfig::default()
        })
    }
}
