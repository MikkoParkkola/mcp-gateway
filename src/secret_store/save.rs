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
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::index::Index;
use super::{SecretStore, StoreError, StoreKind, fresh_name, now_ms, random_suffix};
use crate::config_persistence::lock::{NotLocked, lock_file_blocking};
use crate::fs_lock::ExclusiveFileLock;

/// How long a synchronous save waits for another save holding the vault lock.
pub(crate) const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// The vault lock, through the config lock's owner-only sidecar, waiting no
/// later than `deadline`.
fn take_lock(lock_path: &Path, deadline: Instant) -> Result<ExclusiveFileLock, StoreError> {
    lock_file_blocking(lock_path, deadline).map_err(|e| match e {
        NotLocked::Busy => StoreError::Failed(
            "another save held the vault lock until the deadline; nothing was written".to_owned(),
        ),
        NotLocked::Failed(why) => StoreError::Failed(format!("cannot take the vault lock: {why}")),
    })
}

/// The per-user vault lock and the index of one config directory. Cheap to
/// clone: two paths.
#[derive(Clone)]
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
    /// [`StoreError::Failed`] when there is no home directory.
    pub(crate) fn for_config_dir(config_dir: &Path) -> Result<Self, StoreError> {
        let home = crate::home_dir::home_dir().ok_or_else(|| {
            StoreError::Failed("there is no home directory for the vault lock".to_owned())
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

/// Why a save did not commit. `create_secrets` returns
/// `SaveError<Infallible>`: it has no commit of its own.
#[derive(Debug)]
pub(crate) enum SaveError<E> {
    /// Refused before anything was written.
    Refused(StoreError),
    /// A store or index write failed; this save's entries were removed.
    Store(StoreError),
    /// The caller's commit failed; this save's entries were removed.
    Commit(E),
}

/// Writes `secrets` to fresh entries in `store`, then runs `commit` with
/// their reference texts, in order. All or nothing (ADR-024).
///
/// `commit` writes the config. It must leave the old config in force when it
/// returns `Err`, since every new entry is then removed; a panic inside it
/// removes them too. The lock order is reload, then config sidecar, then
/// vault: a caller holding either of the first two takes it before this.
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
    let (_lock, written, refs) =
        begin(vault, store, secrets, Instant::now() + LOCK_WAIT).map_err(widen)?;
    // Removes this save's entries on an error return and on a panic alike.
    let mut undo = Undo {
        written: &written,
        vault,
        store,
        armed: true,
    };
    let saved = commit(&refs).map_err(SaveError::Commit)?;
    undo.armed = false;
    Ok(saved)
}

/// A phase-one error as a `save_secrets` error.
fn widen<E>(error: SaveError<Infallible>) -> SaveError<E> {
    match error {
        SaveError::Refused(e) => SaveError::Refused(e),
        SaveError::Store(e) => SaveError::Store(e),
        SaveError::Commit(never) => match never {},
    }
}

/// Rolls a save back when dropped armed.
struct Undo<'a> {
    written: &'a Written,
    vault: &'a Vault,
    store: &'a dyn SecretStore,
    armed: bool,
}

impl Drop for Undo<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _kept = self.written.roll_back(self.vault, self.store);
        }
    }
}

/// Phase one, shared by `save_secrets` and `create_secrets`, in B1's order:
/// the vault lock (waiting no later than `deadline`), the value checks, the
/// probe, then per secret: index the fresh name durably, confirm it absent,
/// create it. A failure rolls this save back before it returns. On success
/// the caller owns the lock and the rollback record.
pub(super) fn begin(
    vault: &Vault,
    store: &dyn SecretStore,
    secrets: &[NewSecret<'_>],
    deadline: Instant,
) -> Result<(ExclusiveFileLock, Written, Vec<String>), SaveError<Infallible>> {
    // Held from the first absence check through commit or rollback.
    let lock = take_lock(&vault.lock_path, deadline).map_err(SaveError::Refused)?;
    for secret in secrets {
        let refusal = if secret.value.is_empty() {
            Some(StoreError::Empty)
        } else if secret.value.len() > store.limit() {
            Some(StoreError::TooLarge {
                limit: store.limit(),
                store: store.kind(),
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

    // Rolls back on an error return and on a panic inside a store or index
    // call alike; disarmed only once every entry exists.
    let mut undo = Rollback {
        written: Written::default(),
        vault,
        store,
        armed: true,
    };
    let refs = write_all(vault, store, secrets, &mut undo.written).map_err(SaveError::Store)?;
    undo.armed = false;
    Ok((lock, std::mem::take(&mut undo.written), refs))
}

/// Phase one's own rollback record, rolled back when dropped armed.
struct Rollback<'a> {
    written: Written,
    vault: &'a Vault,
    store: &'a dyn SecretStore,
    armed: bool,
}

impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _kept = self.written.roll_back(self.vault, self.store);
        }
    }
}

/// What this save has indexed and what it may have created.
#[derive(Default)]
pub(super) struct Written {
    indexed: Vec<String>,
    created: Vec<String>,
    /// Creates that timed out: still in flight, so never deleted.
    timed_out: Vec<String>,
    /// Names taken by an entry this save did not make.
    collided: Vec<String>,
}

impl Written {
    /// Deletes what this save created, newest first, then marks as removed
    /// each indexed name that is gone. A name whose delete failed stays live
    /// in the index, so the unused listing still finds it. A timed-out create
    /// is never deleted nor marked removed, whatever `exists` reads: the
    /// abandoned call may land after this returns. A collided name is marked
    /// removed: its entry is not ours (the name's random part makes that
    /// certain), so the listing must never offer it. Returns the names this
    /// save created, or may yet create, and could not remove.
    pub(super) fn roll_back(&self, vault: &Vault, store: &dyn SecretStore) -> Vec<String> {
        let mut removed = BTreeSet::new();
        let mut kept = Vec::new();
        for name in self.created.iter().rev() {
            match store.delete(name) {
                Ok(()) => {
                    removed.insert(name.as_str());
                }
                Err(error) => {
                    tracing::warn!(entry = %name, %error, "a rolled-back secret entry could not be removed");
                    kept.push(name.clone());
                }
            }
        }
        kept.extend(self.timed_out.iter().cloned());
        // Gone: deleted durably here, never created and not there, or someone
        // else's. A timed-out name is never gone.
        let gone = |name: &String| {
            !self.timed_out.contains(name)
                && (removed.contains(name.as_str())
                    || self.collided.contains(name)
                    || (!self.created.contains(name) && matches!(store.exists(name), Ok(false))))
        };
        for name in self.indexed.iter().filter(|n| gone(n)) {
            if let Err(error) = vault.index.append_removed(name) {
                tracing::warn!(entry = %name, %error, "a rolled-back secret entry stays in the index");
            }
        }
        kept
    }

    /// How many entries this save created.
    pub(super) fn created_count(&self) -> usize {
        self.created.len()
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
            written.collided.push(name);
            return Err(StoreError::Exists);
        }
        match store.create(&name, secret.value) {
            Ok(reference) => {
                written.created.push(name);
                refs.push(reference);
            }
            Err(StoreError::Exists) => {
                written.collided.push(name);
                return Err(StoreError::Exists);
            }
            Err(StoreError::TimedOut) => {
                written.timed_out.push(name);
                return Err(StoreError::TimedOut);
            }
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

/// An entry in the index that still exists and that no config on disk names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnusedEntry {
    pub(crate) name: String,
    pub(crate) store: StoreKind,
    /// When the save that created it indexed it; 0 for a clock set before
    /// the epoch. Never a sort key: the listing keeps index order.
    pub(crate) created_at_ms: u64,
}

/// Entries in the index that still exist in their store and that no config
/// on disk names, in index order (ADR-028 rule 6).
///
/// `referenced` is the entry names the on-disk `gateway.yaml` names: a
/// `keychain:` name, or the basename of a `file:` path under `secrets/`. A
/// caller holds the config sidecar from reading that file until this
/// returns, so a concurrent save cannot make an active secret look unused.
///
/// # Errors
///
/// The vault lock, the index read or an `exists` check failing.
pub(crate) fn unused_entries(
    vault: &Vault,
    stores: &[&dyn SecretStore],
    referenced: &BTreeSet<String>,
) -> Result<Vec<UnusedEntry>, StoreError> {
    unused_entries_until(vault, stores, referenced, Instant::now() + LOCK_WAIT)
}

/// [`unused_entries`], waiting for the vault lock no later than `deadline`.
pub(crate) fn unused_entries_until(
    vault: &Vault,
    stores: &[&dyn SecretStore],
    referenced: &BTreeSet<String>,
    deadline: Instant,
) -> Result<Vec<UnusedEntry>, StoreError> {
    // A save holding the lock may have created entries it has not committed.
    let _lock = take_lock(&vault.lock_path, deadline)?;
    let mut unused = Vec::new();
    for live in vault.index.live()? {
        if referenced.contains(&live.name) {
            continue;
        }
        // An index row is a candidate: the store is asked whether it exists.
        let Some(store) = stores.iter().find(|s| s.kind().as_str() == live.store) else {
            continue;
        };
        if store.exists(&live.name)? {
            unused.push(UnusedEntry {
                name: live.name,
                store: store.kind(),
                created_at_ms: live.created_at_ms,
            });
        }
    }
    Ok(unused)
}
