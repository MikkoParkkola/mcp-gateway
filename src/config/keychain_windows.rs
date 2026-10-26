// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows keychain: Credential Manager through `crate::win_cred`, each
//! call bounded at 2 s on its own thread (ADR-028 rules 2 and 7).

use std::time::Duration;

use super::keychain::{BOUND, KeychainError, KeychainRead, WipedBytes, bounded};
use crate::secret_store::{SecretStore, StoreError, StoreKind};
use crate::win_cred::{self, CredError};

/// The largest blob Credential Manager keeps (ADR-028 rule 2).
const LIMIT: usize = 2_560;

/// A name no entry is ever created under, for the read-only probe.
const PROBE_NAME: &str = "mcp-gateway.probe.absent";

/// Credential Manager's generic credentials.
pub(crate) struct WindowsKeychain {
    bound: Duration,
    /// Test seam: how long each call waits before it starts.
    delay: Duration,
}

impl WindowsKeychain {
    pub(crate) fn new() -> Self {
        Self {
            bound: BOUND,
            delay: Duration::ZERO,
        }
    }

    /// A bound and a delay before each call, for timeout tests.
    #[cfg(test)]
    pub(crate) fn with_timing(bound: Duration, delay: Duration) -> Self {
        Self { bound, delay }
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

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        let name = name.to_owned();
        bounded(self.bound, self.delay, move || {
            match win_cred::delete(&name) {
                // Already gone is durably gone.
                Ok(()) | Err(CredError::NotFound) => Ok(()),
                Err(other) => Err(unavailable(&other)),
            }
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
