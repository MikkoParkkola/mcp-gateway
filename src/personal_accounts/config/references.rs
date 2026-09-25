// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `env:` and `file:` secret references in the `accounts` block (C9). The
//! grammar is `config::secret_ref`'s; this is the text-level view the accounts
//! checks need, plus key resolution through [`SecretOverlay`].

use super::{AccountsConfigError, SecretOverlay, decode_key};

/// Whether `reference` is `env:` or `file:` rather than a literal secret.
/// Text only; reads nothing.
pub(super) fn is_reference(reference: &str) -> bool {
    reference.starts_with("env:") || reference.starts_with("file:")
}

/// The name a resolved reference is reported under: the variable for `env:`,
/// the whole `file:PATH` text for a file.
pub(super) fn reference_name(reference: &str) -> &str {
    reference.strip_prefix("env:").unwrap_or(reference)
}

/// One `accounts.keys` entry: an `env:` or `file:` reference, resolved and
/// decoded. The value never appears in an error.
pub(super) fn resolve_key(
    key_id: &str,
    reference: &str,
    overlay: &dyn SecretOverlay,
) -> Result<Vec<u8>, AccountsConfigError> {
    if !is_reference(reference) {
        return Err(AccountsConfigError::KeyNotAReference {
            key_id: key_id.to_string(),
        });
    }
    let encoded = overlay
        .resolve_reference(&format!("accounts.keys[{key_id}]"), reference)
        .map_err(AccountsConfigError::SecretFile)?
        .ok_or_else(|| AccountsConfigError::KeyReferenceUnresolved {
            key_id: key_id.to_string(),
            variable: reference_name(reference).to_string(),
        })?;
    decode_key(key_id, &encoded)
}

/// A reference compared by identity for the structural alias check: an
/// `env:` variable, or a `file:` path with symlinks and `.` resolved where the
/// file exists (a Kubernetes mount reaches one file through `..data` links).
/// Reads no secret.
#[derive(PartialEq, Eq)]
pub(super) enum ReferenceKey {
    Env(String),
    File(std::path::PathBuf),
}

impl ReferenceKey {
    pub(super) fn of(spec: &str) -> Option<Self> {
        if let Some(variable) = spec.strip_prefix("env:") {
            return Some(Self::Env(variable.to_string()));
        }
        let path = std::path::Path::new(spec.strip_prefix("file:")?);
        Some(Self::File(
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
        ))
    }
}
