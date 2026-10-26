// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The two-phase save, for a caller whose commit is async (ADR-024 under
//! ADR-028): phase one writes the entries and returns them pending; the
//! caller writes its config, then keeps, discards or abandons them.
//!
//! The vault lock is held from phase one until that decision. A pending save
//! dropped without one discards: a panicking or cancelled save must not leave
//! entries no config names. `abandon` is the deliberate exception, for a file
//! rollback that failed or is unconfirmed, where the file on disk may name
//! them.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use super::save::{Written, begin};
use super::{NewSecret, SaveError, SecretStore, Vault};
use crate::fs_lock::ExclusiveFileLock;
use crate::wiped_bytes::WipedBytes;

/// One secret to write, owned, so phase one can run on another thread.
pub(crate) struct NewSecretOwned {
    pub(crate) field: String,
    pub(crate) value: WipedBytes,
}

/// Entries phase one created, held under the vault lock until the caller
/// decides. Owns everything it needs: it crosses `spawn_blocking`.
pub(crate) struct PendingSecrets {
    vault: Vault,
    store: Arc<dyn SecretStore + Send + Sync>,
    written: Written,
    refs: Vec<String>,
    /// Released after the rollback in `Drop`: fields drop after its body.
    _lock: ExclusiveFileLock,
    settled: bool,
}

const _: () = {
    const fn sendable<T: Send + 'static>() {}
    sendable::<PendingSecrets>();
};

/// Phase one: writes `secrets` to fresh entries in `store` and returns them
/// pending. The vault lock is waited for no later than `deadline`: an async
/// caller passes what is left of its own budget.
///
/// # Errors
///
/// [`SaveError::Refused`] before any write; [`SaveError::Store`] after this
/// call has removed what it wrote.
pub(crate) fn create_secrets(
    vault: Vault,
    store: Arc<dyn SecretStore + Send + Sync>,
    secrets: &[NewSecretOwned],
    deadline: Instant,
) -> Result<PendingSecrets, SaveError<Infallible>> {
    let borrowed: Vec<NewSecret<'_>> = secrets
        .iter()
        .map(|secret| NewSecret {
            field: &secret.field,
            value: secret.value.as_bytes(),
        })
        .collect();
    let (lock, written, refs) = begin(&vault, store.as_ref(), &borrowed, deadline)?;
    Ok(PendingSecrets {
        vault,
        store,
        written,
        refs,
        _lock: lock,
        settled: false,
    })
}

impl PendingSecrets {
    /// The reference texts the config points at, in input order.
    pub(crate) fn refs(&self) -> &[String] {
        &self.refs
    }

    /// The config naming these entries is in force: keep them.
    pub(crate) fn keep(mut self) {
        self.settled = true;
    }

    /// The config was rolled back durably: delete only this save's entries.
    /// Returns the names it could not remove; they stay live in the index,
    /// so the unused listing shows them.
    pub(crate) fn discard(mut self) -> Vec<String> {
        self.settled = true;
        self.written.roll_back(&self.vault, self.store.as_ref())
    }

    /// The file rollback failed or is unconfirmed, so the file on disk may
    /// name these entries: keep them. Ones no config names show as unused.
    pub(crate) fn abandon(mut self) {
        self.settled = true;
        tracing::warn!(
            entries = self.written.created_count(),
            "secret entries kept after an unconfirmed config rollback"
        );
    }
}

impl Drop for PendingSecrets {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // A panic or a cancel: no config is known to name these entries.
        let kept = self.written.roll_back(&self.vault, self.store.as_ref());
        tracing::warn!(
            entries = self.written.created_count(),
            not_removed = kept.len(),
            "a pending secret save was dropped undecided; its entries were discarded"
        );
    }
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;
