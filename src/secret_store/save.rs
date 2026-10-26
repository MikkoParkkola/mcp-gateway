// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ADR-024's all-or-nothing save over a [`SecretStore`] (ADR-028 rules 2, 3
//! and 6).
//!
//! Under the per-user vault lock: every value is checked and the store
//! probed before anything is written; each fresh name is indexed durably,
//! confirmed absent, then created; the caller's commit runs only once every
//! entry exists. Any failure deletes only the entries this save created.
//! An old entry is never deleted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::index::Index;
use super::{SecretStore, StoreError, fresh_name, random_suffix};
use crate::fs_lock::ExclusiveFileLock;

/// The per-user vault lock and the index of one config directory.
pub(crate) struct Vault {
    lock_path: PathBuf,
    index: Index,
}

impl Vault {
    /// The vault for a config in `config_dir`. The lock is per user,
    /// `<home>/.mcp-gateway-secrets.lock`, whatever the data or config dir,
    /// so two gateways sharing a keychain share it (ADR-028 rule 3).
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] when there is no home directory.
    pub(crate) fn for_config_dir(config_dir: &Path) -> Result<Self, StoreError> {
        let home = crate::home_dir::home_dir().ok_or_else(|| {
            StoreError::Unavailable("there is no home directory for the vault lock".to_owned())
        })?;
        Ok(Self::with_lock(
            config_dir,
            home.join(".mcp-gateway-secrets.lock"),
        ))
    }

    /// The vault lock's path.
    #[cfg(test)]
    pub(crate) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// A vault whose lock is at `lock_path`, for tests that own a home.
    pub(crate) fn with_lock(config_dir: &Path, lock_path: PathBuf) -> Self {
        Self {
            lock_path,
            index: Index::at(config_dir),
        }
    }
}

/// One secret a save writes: the field it is for and its value.
#[derive(Clone, Copy)]
pub(crate) struct NewSecret<'a> {
    pub(crate) field: &'a str,
    pub(crate) value: &'a [u8],
}

/// Why a save did not commit.
#[derive(Debug)]
pub(crate) enum SaveError<E> {
    /// Refused before anything was written.
    Refused(StoreError),
    /// A store or index write failed; this save's entries were removed.
    Store(StoreError),
    /// The caller's commit failed; this save's entries were removed.
    Commit(E),
}

/// Milliseconds since the epoch; 0 for a clock set before it, which the
/// random part of a name still keeps unique.
fn now_ms() -> u64 {
    crate::clock::unix_millis().unwrap_or(0)
}

/// Writes `secrets` to fresh entries in `store`, then runs `commit` with
/// their reference texts, in order. All or nothing (ADR-024).
///
/// # Errors
///
/// [`SaveError::Refused`] before any write: no home or lock, an empty,
/// non-UTF-8 or oversized value, or a failed probe. [`SaveError::Store`] or
/// [`SaveError::Commit`] after rollback.
pub(crate) fn save_secrets<T, E>(
    vault: &Vault,
    store: &dyn SecretStore,
    secrets: &[NewSecret<'_>],
    commit: impl FnOnce(&[String]) -> Result<T, E>,
) -> Result<T, SaveError<E>> {
    // Held from the first absence check through commit or rollback.
    let _lock = ExclusiveFileLock::acquire(&vault.lock_path).map_err(|e| {
        SaveError::Refused(StoreError::Failed(format!(
            "cannot take the vault lock: {e}"
        )))
    })?;
    for secret in secrets {
        let refusal = if secret.value.is_empty() {
            Some(StoreError::Empty)
        } else if secret.value.len() > store.limit() {
            Some(StoreError::TooLarge {
                limit: store.limit(),
            })
        } else if std::str::from_utf8(secret.value).is_err() {
            Some(StoreError::NotUtf8)
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return Err(SaveError::Refused(refusal));
        }
    }
    store.probe().map_err(SaveError::Refused)?;

    let mut written = Written::default();
    let refs = match write_all(vault, store, secrets, &mut written) {
        Ok(refs) => refs,
        Err(error) => {
            written.roll_back(vault, store);
            return Err(SaveError::Store(error));
        }
    };
    match commit(&refs) {
        Ok(saved) => Ok(saved),
        Err(error) => {
            written.roll_back(vault, store);
            Err(SaveError::Commit(error))
        }
    }
}

/// What this save has indexed and what it may have created.
#[derive(Default)]
struct Written {
    indexed: Vec<String>,
    created: Vec<String>,
}

impl Written {
    /// Deletes what this save created, newest first, and marks each name it
    /// indexed as removed. A name whose delete failed stays live in the
    /// index, so the unused listing still finds it.
    fn roll_back(&self, vault: &Vault, store: &dyn SecretStore) {
        let mut kept = BTreeSet::new();
        for name in self.created.iter().rev() {
            if let Err(error) = store.delete(name) {
                tracing::warn!(entry = %name, %error, "a rolled-back secret entry could not be removed");
                kept.insert(name.as_str());
            }
        }
        for name in self.indexed.iter().filter(|n| !kept.contains(n.as_str())) {
            if let Err(error) = vault.index.append_removed(name) {
                tracing::warn!(entry = %name, %error, "a rolled-back secret entry stays in the index");
            }
        }
    }
}

fn write_all(
    vault: &Vault,
    store: &dyn SecretStore,
    secrets: &[NewSecret<'_>],
    written: &mut Written,
) -> Result<Vec<String>, StoreError> {
    let mut refs = Vec::with_capacity(secrets.len());
    for secret in secrets {
        let name = fresh_name(secret.field, now_ms(), random_suffix()?);
        vault.index.append_created(&name, store.kind())?;
        written.indexed.push(name.clone());
        // Create-only: a taken name is someone else's entry, never replaced.
        if store.exists(&name)? {
            return Err(StoreError::Exists);
        }
        match store.create(&name, secret.value) {
            Ok(reference) => {
                written.created.push(name);
                refs.push(reference);
            }
            Err(StoreError::Exists) => return Err(StoreError::Exists),
            Err(error) => {
                // A failed or timed-out create may still have written.
                if store.exists(&name).unwrap_or(true) {
                    written.created.push(name);
                }
                return Err(error);
            }
        }
    }
    Ok(refs)
}

/// Names in the index that still exist in their store and that no loaded
/// config references, oldest first (ADR-028 rule 6).
///
/// # Errors
///
/// The index read failing, or an `exists` check failing.
pub(crate) fn unused_entries(
    vault: &Vault,
    stores: &[&dyn SecretStore],
    referenced: &BTreeSet<String>,
) -> Result<Vec<String>, StoreError> {
    let mut unused = Vec::new();
    for (name, kind) in vault.index.live()? {
        if referenced.contains(&name) {
            continue;
        }
        let Some(store) = stores.iter().find(|s| s.kind().as_str() == kind) else {
            continue;
        };
        if store.exists(&name)? {
            unused.push(name);
        }
    }
    Ok(unused)
}
