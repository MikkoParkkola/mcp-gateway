// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which of a backend's `headers:` and `env:` values are credentials, as the
//! config wrote them. Load overwrites each value with what it resolves to,
//! so this record is the only place that still knows which ones came from a
//! secret source; the backend's redaction set is seeded from it.

use super::EnvOverlay;
use super::secret_ref::{SecretRef, literal_outside_templates, template_names};

/// How sure the gateway is that a configured value is a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SecretOrigin {
    /// The config said so: a whole-value `env:`, `file:` or `keychain:`
    /// reference, or a variable substituted into a header. Redacted at any
    /// length.
    Explicit,
    /// Guessed from an `env:` value written as nothing but `${VAR}`
    /// references. Redacted only when long enough not to damage ordinary
    /// text.
    Inferred,
}

/// One configured credential: the field it was written in and its value.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConfiguredSecret {
    /// `headers.<key>` or `env.<key>`, for warnings.
    pub(crate) field: String,
    pub(crate) value: String,
    pub(crate) origin: SecretOrigin,
}

/// A backend's configured credentials. Never printed: `Debug` names the
/// count.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfiguredSecrets(Vec<ConfiguredSecret>);

impl std::fmt::Debug for ConfiguredSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{} configured secrets>", self.0.len())
    }
}

impl ConfiguredSecrets {
    pub(crate) fn iter(&self) -> impl Iterator<Item = &ConfiguredSecret> {
        self.0.iter()
    }

    /// In a fixed order: `headers:` and `env:` are maps, so two loads of the
    /// same file can record in different orders, and a reload compares
    /// records to tell whether a marking changed.
    pub(super) fn sorted(mut self) -> Self {
        self.0.sort();
        self.0.dedup();
        self
    }

    /// A record holding exactly `secrets`, for rows that seed a set directly.
    #[cfg(test)]
    pub(crate) fn of(secrets: Vec<ConfiguredSecret>) -> Self {
        Self(secrets)
    }
}

/// Each enabled backend's configured credentials, by backend name, as one
/// load recorded them. Kept beside the config, never on it: the config's
/// public structs carry no field for it.
pub(crate) type ConfiguredByBackend = std::collections::HashMap<String, ConfiguredSecrets>;

/// Which kind of slot a value was written in.
#[derive(Clone, Copy)]
pub(super) enum Slot {
    Header,
    Env,
}

/// Records the credentials in one `headers:` or `env:` value, from the text
/// as written, before load overwrites it. `resolved` is what a whole-value
/// reference resolved to.
pub(super) fn record(
    secrets: &mut ConfiguredSecrets,
    slot: Slot,
    key: &str,
    written: &str,
    resolved: &str,
    overlay: &EnvOverlay,
) {
    let field = match slot {
        Slot::Header => format!("headers.{key}"),
        Slot::Env => format!("env.{key}"),
    };
    let mut push = |value: String, origin| {
        if !value.is_empty() {
            secrets.0.push(ConfiguredSecret {
                field: field.clone(),
                value,
                origin,
            });
        }
    };
    if !matches!(SecretRef::parse(written), SecretRef::Literal(_)) {
        push(resolved.to_owned(), SecretOrigin::Explicit);
        return;
    }
    let origin = match slot {
        Slot::Header => SecretOrigin::Explicit,
        // A mixed template such as `${HOME}/bin` is a path, not a credential.
        Slot::Env if literal_outside_templates(written).is_empty() => SecretOrigin::Inferred,
        Slot::Env => return,
    };
    // Only values the environment supplied: a `:-default` is config text.
    for name in template_names(written) {
        if let Some(value) = overlay.resolve(name) {
            push(value, origin);
        }
    }
}

#[cfg(test)]
#[path = "configured_secrets_tests.rs"]
mod tests;
