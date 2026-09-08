// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Deployment `accounts` block -> `StoreConfig`. Refusing scaffold.
//!
//! Field names and rules are the approved configuration table (design doc rows
//! 414-432). Nothing here is invented, and no knob is added that the table does
//! not name.
//!
//! SECRETS FOLLOW THE EXISTING PATTERN, not an assumed one. `accounts.keys` maps
//! a key id to an `env:VARIABLE` reference, exactly like `auth.bearer_token` and
//! `agent_auth.agents[].hs256_secret`, and is resolved through the same
//! `EnvOverlay` that `Config::resolve_secret_refs` uses -- which also returns the
//! set of names it looked up, so a caller can assert WHICH variables were read.
//! An unresolvable name is left verbatim and reported as a missing reference, not
//! silently emptied. The scoped scan found no `SecretString`/`Zeroize` type in
//! this codebase, so none is assumed here.
//!
//! An inline literal key is a configuration error, not a convenience: it would
//! put 32 bytes of key material in a file that gets copied, diffed and pasted.
//!
//! Omitted `accounts` preserves existing behaviour and enables no managed
//! custody -- `resolve` answers `Ok(None)`, never a default store.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::StoreConfig;

/// The `accounts` block as configured. Unknown fields reject startup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountsConfig {
    /// Required literal `accounts.v1`.
    pub(crate) schema_version: String,
    /// Default false; required true for any `personal_managed` descriptor.
    pub(crate) enabled: bool,
    /// Literal `single_process` for managed custody, explicitly set.
    pub(crate) deployment: String,
    pub(crate) instance_id: String,
    pub(crate) store_dir: PathBuf,
    pub(crate) authority_dir: PathBuf,
    /// Nonempty key id, required present in `keys`.
    pub(crate) current_key_id: String,
    /// key id -> `env:VARIABLE` reference resolving to base64 of exactly 32 bytes.
    pub(crate) keys: BTreeMap<String, String>,
    pub(crate) limits: AccountsLimits,
}

/// Only the two bounds this slice maps onto `StoreConfig`. The other limit
/// fields in the approved table belong to journeys and catalogues and are not
/// invented here.
///
/// BOTH ARE "reject zero/overflow" (approved configuration table, design doc
/// row 432). The overflow half is not an invented ceiling: `storage.rs`'s
/// `validate_config` refuses a store whose
/// `max_authority_bytes.checked_add(16).and_then(|size| size.checked_mul(4))`
/// overflows, so the largest accepted `authority_bytes` is `(usize::MAX/4)-16`.
/// The numbers named on each field below are the approved DEFAULTS, not bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AccountsLimits {
    /// Default 10000 -> `StoreConfig::max_entries`. Zero and overflow reject.
    pub(crate) store_entries: usize,
    /// Default 16777216 -> `StoreConfig::max_authority_bytes`. Zero rejects, and
    /// so does any value the storage sealing arithmetic above cannot carry.
    pub(crate) authority_bytes: usize,
}

/// Why a configuration is refused. Carries no secret material: a variant that
/// echoed a resolved key would put it in every log line that renders the error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AccountsConfigError {
    #[error("accounts configuration resolution is not implemented")]
    RuntimeNotImplemented,
    #[error("accounts.schema_version must be the literal accounts.v1")]
    SchemaVersion,
    #[error("accounts.deployment must be the literal single_process for managed custody")]
    Deployment,
    #[error("accounts.enabled must be true for a personal_managed descriptor")]
    NotEnabled,
    #[error("accounts.instance_id must be nonempty")]
    InstanceId,
    #[error("accounts.{field} must be an absolute path with no symlink alias")]
    Directory { field: &'static str },
    #[error("accounts.store_dir and accounts.authority_dir must resolve to disjoint paths")]
    DirectoriesNotDisjoint,
    #[error("accounts.current_key_id is absent from accounts.keys")]
    CurrentKeyMissing,
    /// Named by key id only. The value is never part of the message.
    #[error("accounts.keys[{key_id}] must be an env: reference")]
    KeyNotAReference { key_id: String },
    #[error("accounts.keys[{key_id}] reference {variable} is unresolved")]
    KeyReferenceUnresolved { key_id: String, variable: String },
    #[error("accounts.keys[{key_id}] must decode to exactly 32 bytes")]
    KeyMaterial { key_id: String },
    #[error("accounts.limits.{field} must be a positive integer within bounds")]
    Limit { field: &'static str },
    #[error("accounts contains unknown field {field}")]
    UnknownField { field: String },
}

/// `StoreConfig` itself carries raw key bytes and deliberately has no `Debug`,
/// so this wrapper cannot derive one either: it renders key IDs and never
/// values. Anything that reaches a log line goes through here.
#[derive(Clone)]
pub(crate) struct ResolvedAccounts {
    pub(crate) store: StoreConfig,
    /// Environment variable names looked up, in sorted order. Names only.
    pub(crate) secret_refs_read: Vec<String>,
}

impl std::fmt::Debug for ResolvedAccounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedAccounts")
            .field("instance_id", &self.store.instance_id)
            .field("current_key_id", &self.store.current_key_id)
            .field("key_ids", &self.store.keys.keys().collect::<Vec<_>>())
            .field("secret_refs_read", &self.secret_refs_read)
            .finish_non_exhaustive()
    }
}

/// Resolve the block into a `StoreConfig`, or `Ok(None)` when `accounts` is
/// omitted.
///
/// Structure is validated BEFORE any secret is read, so a malformed block never
/// causes an environment lookup. Key material is read last, once per declared
/// reference, in key-id order.
pub(crate) fn resolve(
    accounts: Option<&AccountsConfig>,
    overlay: &dyn SecretOverlay,
) -> Result<Option<ResolvedAccounts>, AccountsConfigError> {
    // Omitted `accounts` preserves existing behaviour and enables no managed
    // custody. Nothing is read, because nothing is configured.
    let Some(accounts) = accounts else {
        return Ok(None);
    };

    if accounts.schema_version != SCHEMA_VERSION {
        return Err(AccountsConfigError::SchemaVersion);
    }
    if accounts.deployment != DEPLOYMENT {
        return Err(AccountsConfigError::Deployment);
    }
    if !accounts.enabled {
        return Err(AccountsConfigError::NotEnabled);
    }
    if accounts.instance_id.is_empty() {
        return Err(AccountsConfigError::InstanceId);
    }

    validate_directory("store_dir", &accounts.store_dir)?;
    validate_directory("authority_dir", &accounts.authority_dir)?;
    // Same volume is allowed; the resolved paths must be neither equal nor
    // nested either way, so a token snapshot replacement cannot reach the
    // manifest and lock directory.
    if accounts.store_dir.starts_with(&accounts.authority_dir)
        || accounts.authority_dir.starts_with(&accounts.store_dir)
    {
        return Err(AccountsConfigError::DirectoriesNotDisjoint);
    }

    validate_limit("store_entries", accounts.limits.store_entries)?;
    validate_limit("authority_bytes", accounts.limits.authority_bytes)?;
    // The approved storage bound: `storage::validate_config` refuses a store
    // whose sealed-manifest arithmetic overflows, so a value that cannot carry
    // it is rejected here rather than at open time.
    if accounts
        .limits
        .authority_bytes
        .checked_add(16)
        .and_then(|size| size.checked_mul(4))
        .is_none()
    {
        return Err(AccountsConfigError::Limit {
            field: "authority_bytes",
        });
    }

    if !accounts.keys.contains_key(&accounts.current_key_id) {
        return Err(AccountsConfigError::CurrentKeyMissing);
    }

    // Reject malformed references anywhere in the block before resolving any
    // secret. A later invalid key must not cause an earlier environment read.
    for (key_id, reference) in &accounts.keys {
        if !reference.starts_with("env:") {
            return Err(AccountsConfigError::KeyNotAReference {
                key_id: key_id.clone(),
            });
        }
    }

    let mut keys = BTreeMap::new();
    let mut secret_refs_read = Vec::new();
    for (key_id, reference) in &accounts.keys {
        let variable = reference.strip_prefix("env:").ok_or_else(|| {
            AccountsConfigError::KeyNotAReference {
                key_id: key_id.clone(),
            }
        })?;
        secret_refs_read.push(variable.to_string());
        let encoded = overlay.resolve(variable).ok_or_else(|| {
            AccountsConfigError::KeyReferenceUnresolved {
                key_id: key_id.clone(),
                variable: variable.to_string(),
            }
        })?;
        let material = decode_key(key_id, &encoded)?;
        keys.insert(key_id.clone(), material);
    }
    secret_refs_read.sort();

    Ok(Some(ResolvedAccounts {
        store: StoreConfig {
            instance_id: accounts.instance_id.clone(),
            store_dir: accounts.store_dir.clone(),
            authority_dir: accounts.authority_dir.clone(),
            current_key_id: accounts.current_key_id.clone(),
            keys,
            max_entries: accounts.limits.store_entries,
            max_authority_bytes: accounts.limits.authority_bytes,
        },
        secret_refs_read,
    }))
}

const SCHEMA_VERSION: &str = "accounts.v1";
const DEPLOYMENT: &str = "single_process";
const KEY_BYTES: usize = 32;

fn validate_directory(
    field: &'static str,
    path: &std::path::Path,
) -> Result<(), AccountsConfigError> {
    if !path.is_absolute() {
        return Err(AccountsConfigError::Directory { field });
    }
    // A `..` component can alias out of the configured tree even when the
    // string is absolute, so it is refused with the same category.
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(AccountsConfigError::Directory { field });
    }
    Ok(())
}

fn validate_limit(field: &'static str, value: usize) -> Result<(), AccountsConfigError> {
    if value == 0 {
        return Err(AccountsConfigError::Limit { field });
    }
    Ok(())
}

/// Decode one reference's material. The value never appears in the error: a
/// message that echoed it would put a live key in the log line reporting the
/// failure.
fn decode_key(key_id: &str, encoded: &str) -> Result<Vec<u8>, AccountsConfigError> {
    use base64::Engine as _;

    let material = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AccountsConfigError::KeyMaterial {
            key_id: key_id.to_string(),
        })?;
    if material.len() != KEY_BYTES {
        return Err(AccountsConfigError::KeyMaterial {
            key_id: key_id.to_string(),
        });
    }
    Ok(material)
}

/// The existing overlay contract, narrowed to what this slice needs: a name in,
/// an optional value out. Implemented by `config::EnvOverlay` in production and
/// by a counting fake in tests.
pub(crate) trait SecretOverlay {
    fn resolve(&self, name: &str) -> Option<String>;
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
