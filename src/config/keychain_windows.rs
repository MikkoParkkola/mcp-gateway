// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows keychain: Credential Manager through `crate::win_cred`, each
//! call bounded at 2 s on its own thread (ADR-028 rules 2 and 7).

use std::time::Duration;

use super::keychain::{
    BOUND, CONFIRM_ATTEMPTS, CONFIRM_GAP, KeychainError, KeychainRead, WipedBytes, bounded,
    delete_confirmed,
};
use crate::secret_store::{SecretStore, StoreError, StoreKind};
use crate::win_cred::{self, CredError};

/// The largest blob Credential Manager keeps (ADR-028 rule 2).
const LIMIT: usize = 2_560;

/// A name no entry is ever created under, for the read-only probe.
const PROBE_NAME: &str = "mcp-gateway.probe.absent";

/// The Credential Manager delete a store delete makes; rows swap in a fake.
type CredDelete = fn(&str) -> Result<(), CredError>;
/// The existence ask a store delete makes after it; rows swap in a fake.
type CredExists = fn(&str) -> Result<bool, CredError>;

/// Credential Manager's generic credentials.
pub(crate) struct WindowsKeychain {
    bound: Duration,
    /// Test seam: how long each call waits before it starts.
    delay: Duration,
    /// Test seam: the delete and the ask behind [`SecretStore::delete`].
    cred_delete: CredDelete,
    cred_exists: CredExists,
}

impl WindowsKeychain {
    pub(crate) fn new() -> Self {
        Self {
            bound: BOUND,
            delay: Duration::ZERO,
            cred_delete: win_cred::delete,
            cred_exists: win_cred::exists,
        }
    }

    /// A bound and a delay before each call, for timeout tests.
    #[cfg(test)]
    pub(crate) fn with_timing(bound: Duration, delay: Duration) -> Self {
        Self {
            bound,
            delay,
            cred_delete: win_cred::delete,
            cred_exists: win_cred::exists,
        }
    }

    /// Fake Credential Manager calls behind the store's delete, for the rows
    /// that drive the call site.
    #[cfg(test)]
    pub(crate) fn with_cred(cred_delete: CredDelete, cred_exists: CredExists) -> Self {
        Self {
            bound: BOUND,
            delay: Duration::ZERO,
            cred_delete,
            cred_exists,
        }
    }
}

impl KeychainRead for WindowsKeychain {
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError> {
        let name = name.to_owned();
        bounded(self.bound, self.delay, move || {
            win_cred::read(&name).map_err(|e| match e {
                CredError::NotFound => KeychainError::Missing,
                other => KeychainError::Unavailable(format!("Credential Manager: {other:?}")),
            })
        })
    }
}

impl SecretStore for WindowsKeychain {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn limit(&self) -> usize {
        LIMIT
    }

    /// A lookup of a name that never exists: "not found" means Credential
    /// Manager answers for this logon session.
    fn probe(&self) -> Result<(), StoreError> {
        match self.exists(PROBE_NAME) {
            Ok(false) => Ok(()),
            Ok(true) => Err(StoreError::Unavailable(
                "Credential Manager holds the probe's reserved name".into(),
            )),
            // A probe writes nothing, so its timeout is plain unavailability.
            Err(StoreError::TimedOut) => Err(StoreError::Unavailable(
                "Credential Manager did not answer in time".into(),
            )),
            Err(error) => Err(error),
        }
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        let name = name.to_owned();
        bounded(self.bound, self.delay, move || {
            win_cred::exists(&name).map_err(|e| unavailable(&e))
        })
        .map_err(store_error)
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        // The thread owns a wiped copy, so a call that outlives the bound
        // still wipes it when it ends.
        let (name, value) = (name.to_owned(), WipedBytes::new(value.to_vec()));
        let reference = format!("keychain:{name}");
        let written = bounded(self.bound, self.delay, move || {
            Ok(win_cred::create(&name, value.as_bytes()))
        })
        .map_err(store_error)?;
        match written {
            Ok(()) => Ok(reference),
            Err(CredError::Exists) => Err(StoreError::Exists),
            Err(other) => Err(store_error(unavailable(&other))),
        }
    }

    /// Removed means seen gone: Credential Manager can keep answering for an
    /// entry whose delete succeeded, so the entry is asked for again, within
    /// the call's bound. One that is still readable fails the delete.
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        let name = name.to_owned();
        let (cred_delete, cred_exists) = (self.cred_delete, self.cred_exists);
        bounded(self.bound, self.delay, move || {
            delete_confirmed(
                CONFIRM_ATTEMPTS,
                CONFIRM_GAP,
                std::thread::sleep,
                || match cred_delete(&name) {
                    // Already gone is durably gone.
                    Ok(()) | Err(CredError::NotFound) => Ok(()),
                    Err(other) => Err(unavailable(&other)),
                },
                || cred_exists(&name).map_err(|e| unavailable(&e)),
            )
        })
        .map_err(store_error)
    }
}

fn unavailable(error: &CredError) -> KeychainError {
    KeychainError::Unavailable(format!("Credential Manager: {error:?}"))
}

/// A reader error as a writer error. A timeout stays a timeout: the call is
/// still running and may yet write.
fn store_error(error: KeychainError) -> StoreError {
    match error {
        KeychainError::Timeout => StoreError::TimedOut,
        KeychainError::Unavailable(why) => StoreError::Unavailable(why),
        KeychainError::Locked => StoreError::Unavailable("Credential Manager is locked".into()),
        KeychainError::Missing => StoreError::Failed("the entry vanished mid-call".into()),
    }
}
