// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The macOS keychain through `security-framework`, never the `security` CLI
//! (ADR-028 rules 2 and 7).
//!
//! Prompts are switched off for the whole process the first time a backend
//! starts, and stay off: a call that would show a dialog fails with
//! `errSecInteractionNotAllowed` instead. Each call runs on its own thread,
//! bounded at 2 s; a late answer is dropped, and wiped, unread.

use std::sync::OnceLock;
use std::time::Duration;

use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use security_framework::os::macos::passwords::find_generic_password;

use super::keychain::{KeychainError, KeychainRead, WipedBytes, bounded};

/// The account every gateway entry is stored under (ADR-028 rule 1).
const ACCOUNT: &str = "mcp-gateway";

/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecInteractionNotAllowed`: the call needed a prompt.
const INTERACTION_NOT_ALLOWED: i32 = -25308;

/// The keychain search list, or the given keychains.
pub(crate) struct MacKeychain {
    keychains: Option<Vec<SecKeychain>>,
    bound: Duration,
    /// Test seam: how long each call waits before it starts.
    delay: Duration,
}

impl MacKeychain {
    /// The default search list.
    pub(crate) fn search_list() -> Self {
        Self::build(None, super::keychain::BOUND, Duration::ZERO)
    }

    /// These keychains only, with a bound and a delay before each call, for
    /// tests that cannot rely on the runner's login keychain.
    #[cfg(test)]
    pub(crate) fn with_keychains(
        keychains: Vec<SecKeychain>,
        bound: Duration,
        delay: Duration,
    ) -> Self {
        Self::build(Some(keychains), bound, delay)
    }

    fn build(keychains: Option<Vec<SecKeychain>>, bound: Duration, delay: Duration) -> Self {
        let _ = no_prompts();
        Self {
            keychains,
            bound,
            delay,
        }
    }
}

/// Switches keychain prompts off for the process, once. The lock is held for
/// the process lifetime: the flag is process-wide, dropping the lock turns
/// prompts back on, and a gateway never wants a dialog.
fn no_prompts() -> Result<(), KeychainError> {
    static NO_PROMPTS: OnceLock<Result<KeychainUserInteractionLock, i32>> = OnceLock::new();
    match NO_PROMPTS.get_or_init(|| SecKeychain::disable_user_interaction().map_err(|e| e.code())) {
        Ok(_) => Ok(()),
        Err(code) => Err(KeychainError::Unavailable(format!(
            "keychain prompts could not be switched off (status {code})"
        ))),
    }
}

impl KeychainRead for MacKeychain {
    fn read(&self, name: &str) -> Result<WipedBytes, KeychainError> {
        // Never call the keychain while it could still prompt.
        no_prompts()?;
        let (keychains, name) = (self.keychains.clone(), name.to_owned());
        bounded(self.bound, self.delay, move || {
            find_generic_password(keychains.as_deref(), &name, ACCOUNT)
                // ponytail: the framework frees its copy without zeroing it;
                // wiping that needs `unsafe`, which ADR-028 rules out on macOS.
                .map(|(password, _item)| WipedBytes::new(password.to_vec()))
                .map_err(|e| classify(e.code()))
        })
    }
}

/// An `OSStatus` as a reason. Only the code is kept: the framework's message
/// is not ours to vouch for.
fn classify(code: i32) -> KeychainError {
    match code {
        ITEM_NOT_FOUND => KeychainError::Missing,
        INTERACTION_NOT_ALLOWED => KeychainError::Locked,
        other => KeychainError::Unavailable(format!("macOS keychain status {other}")),
    }
}
