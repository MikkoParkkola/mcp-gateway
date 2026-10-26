// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Windows keychain: Credential Manager through `crate::win_cred`, each
//! call bounded at 2 s on its own thread (ADR-028 rules 2 and 7).

use std::time::Duration;

use super::keychain::{BOUND, KeychainError, KeychainRead, WipedBytes, bounded};
use crate::win_cred::{self, CredError};

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
