// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The OS keychain behind `keychain:NAME` references (ADR-028).
//!
//! Only reads live here. Values cross this module as [`WipedBytes`], and no
//! error carries one: an error names a reason, and the caller names the entry.

use std::sync::Arc;

pub(crate) use crate::wiped_bytes::WipedBytes;

/// Why a keychain read did not return a value. Never holds the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeychainError {
    /// No entry has that name.
    Missing,
    /// The store holding the entry is locked, and the gateway never prompts.
    #[cfg_attr(
        all(not(test), windows),
        expect(dead_code, reason = "Credential Manager has no locked state")
    )]
    Locked,
    /// The store cannot be reached: no tool, no session bus, or a refusal.
    Unavailable(String),
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
            Self::Timeout => "the keychain timed out".to_owned(),
        }
    }
}

/// Reads keychain entries by name.
pub(crate) trait KeychainRead: Send + Sync {
    /// The entry's exact bytes.
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError>;
}

/// How long one keychain call may take (ADR-028 rule 7).
#[cfg(any(target_os = "macos", windows))]
pub(crate) const BOUND: std::time::Duration = std::time::Duration::from_secs(2);

/// Runs a native keychain `call` on its own thread, after `delay` (a test
/// seam), and waits at most `bound`. A late answer is dropped unread, and its
/// value wiped; the thread itself is left to finish.
#[cfg(any(target_os = "macos", windows))]
pub(crate) fn bounded(
    bound: std::time::Duration,
    delay: std::time::Duration,
    call: impl FnOnce() -> Result<WipedBytes, KeychainError> + Send + 'static,
) -> Result<WipedBytes, KeychainError> {
    use std::sync::mpsc;
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("keychain-read".into())
        .spawn(move || {
            std::thread::sleep(delay);
            // A receiver that timed out is gone; the value is wiped on drop.
            let _ = send.send(call());
        })
        .map_err(|_| KeychainError::Unavailable("no thread for the keychain call".into()))?;
    match receive.recv_timeout(bound) {
        Ok(found) => found,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KeychainError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KeychainError::Unavailable(
            "the keychain call ended without an answer".into(),
        )),
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
        #[cfg(test)]
        if let Some(reader) = TEST_READER.with(|slot| slot.borrow().clone()) {
            return Self(reader);
        }
        Self::new(os_keychain())
    }
}

/// The platform keychain, once per process.
fn os_keychain() -> Arc<dyn KeychainRead> {
    static OS: std::sync::OnceLock<Arc<dyn KeychainRead>> = std::sync::OnceLock::new();
    OS.get_or_init(|| {
        #[cfg(target_os = "linux")]
        let os: Arc<dyn KeychainRead> = Arc::new(super::keychain_linux::LinuxKeychain::from_path());
        #[cfg(target_os = "macos")]
        let os: Arc<dyn KeychainRead> = Arc::new(super::keychain_macos::MacKeychain::search_list());
        #[cfg(windows)]
        let os: Arc<dyn KeychainRead> = Arc::new(super::keychain_windows::WindowsKeychain::new());
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let os: Arc<dyn KeychainRead> = Arc::new(Unsupported);
        os
    })
    .clone()
}

#[cfg(test)]
thread_local! {
    /// The reader every overlay built on this thread gets, so a test can load
    /// a whole config against a fake (`Config::load` builds its own overlay).
    static TEST_READER: std::cell::RefCell<Option<Arc<dyn KeychainRead>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `body` with every overlay built on this thread reading from `reader`.
#[cfg(test)]
pub(crate) fn with_test_keychain<T>(reader: Arc<dyn KeychainRead>, body: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<dyn KeychainRead>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            TEST_READER.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let previous = TEST_READER.with(|slot| slot.borrow_mut().replace(reader));
    let _restore = Restore(previous);
    body()
}

/// A target with no keychain reader yet: every read is refused by name.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
struct Unsupported;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl KeychainRead for Unsupported {
    fn read(&self, _name: &str) -> Result<WipedBytes, KeychainError> {
        Err(KeychainError::Unavailable(
            "no keychain reader on this platform yet".to_owned(),
        ))
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
