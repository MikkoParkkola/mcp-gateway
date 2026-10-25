// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The OS keychain behind `keychain:NAME` references (ADR-028).
//!
//! Only reads live here. Values cross this module as [`WipedBytes`], and no
//! error carries one: an error names a reason, and the caller names the entry.

use std::sync::Arc;

/// Why a keychain read did not return a value. Never holds the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeychainError {
    /// No entry has that name.
    Missing,
    /// The store holding the entry is locked, and the gateway never prompts.
    Locked,
    /// The store cannot be reached: no tool, no session bus, or a refusal.
    Unavailable(String),
    /// The entry's bytes are not UTF-8.
    NotUtf8,
    /// The store did not answer within the bound (ADR-028 rule 7).
    Timeout,
}

impl KeychainError {
    /// A short reason for an operator-facing message.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Missing => "it does not exist".to_owned(),
            Self::Locked => "the keychain is locked".to_owned(),
            Self::Unavailable(why) => format!("the keychain is unavailable: {why}"),
            Self::NotUtf8 => "it is not UTF-8".to_owned(),
            Self::Timeout => "the keychain timed out".to_owned(),
        }
    }
}

/// Reads keychain entries by name.
pub(crate) trait KeychainRead: Send + Sync {
    /// The entry's exact bytes.
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError>;
}

/// Secret bytes overwritten on drop. `Debug` shows only the length.
pub(crate) struct WipedBytes(Vec<u8>);

impl WipedBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        // No `zeroize` crate in the tree; `black_box` keeps the stores from
        // being elided as writes to memory about to be freed (as `WipedToken`).
        self.0.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&self.0);
    }
}

impl std::fmt::Debug for WipedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WipedBytes({} bytes)", self.0.len())
    }
}

/// The reader an [`EnvOverlay`](super::EnvOverlay) resolves through. The
/// default is the OS keychain.
#[derive(Clone)]
pub(crate) struct KeychainReader(Arc<dyn KeychainRead>);

impl KeychainReader {
    pub(crate) fn new(reader: Arc<dyn KeychainRead>) -> Self {
        Self(reader)
    }

    pub(crate) fn get(&self) -> &dyn KeychainRead {
        self.0.as_ref()
    }
}

impl Default for KeychainReader {
    fn default() -> Self {
        Self(Arc::new(OsKeychain))
    }
}

/// The platform keychain.
struct OsKeychain;

impl KeychainRead for OsKeychain {
    fn read(&self, _name: &str) -> Result<WipedBytes, KeychainError> {
        Err(KeychainError::Unavailable("not implemented".to_owned()))
    }
}

/// An in-memory keychain for tests: entries, forced failures, and every name
/// asked for.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FakeKeychain {
    entries: std::sync::Mutex<std::collections::BTreeMap<String, Result<Vec<u8>, KeychainError>>>,
    asked: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FakeKeychain {
    pub(crate) fn insert(&self, name: &str, bytes: &[u8]) {
        self.entries
            .lock()
            .unwrap()
            .insert(name.to_owned(), Ok(bytes.to_vec()));
    }

    pub(crate) fn fail(&self, name: &str, error: KeychainError) {
        self.entries
            .lock()
            .unwrap()
            .insert(name.to_owned(), Err(error));
    }

    pub(crate) fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }

    fn lookup(&self, name: &str) -> Option<Result<Vec<u8>, KeychainError>> {
        self.asked.lock().unwrap().push(name.to_owned());
        self.entries.lock().unwrap().get(name).cloned()
    }
}

#[cfg(test)]
impl KeychainRead for FakeKeychain {
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError> {
        match self.lookup(name) {
            None => Err(KeychainError::Missing),
            Some(entry) => entry.map(WipedBytes::new),
        }
    }
}
