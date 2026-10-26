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

use core_foundation::data::CFData;
use security_framework::item::{
    ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Location,
};
use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
use security_framework::os::macos::passwords::find_generic_password;

use super::keychain::{KeychainError, KeychainRead, WipedBytes, bounded};
use crate::secret_store::{SecretStore, StoreError, StoreKind};

/// The account every gateway entry is stored under (ADR-028 rule 1).
const ACCOUNT: &str = "mcp-gateway";

/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25300;
/// `errSecInteractionNotAllowed`: the call needed a prompt.
const INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecDuplicateItem`.
const DUPLICATE_ITEM: i32 = -25299;

/// The largest value written, in bytes. ADR-028 states no macOS limit; this
/// matches `files`, so a secret always fits a later switch to files.
const LIMIT: usize = 65_535;

/// A name no entry is ever created under, for the read-only probe.
const PROBE_NAME: &str = "mcp-gateway.probe.absent";

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

impl MacKeychain {
    /// A search for the gateway's generic-password item `name`, in this
    /// keychain list: the same service and account the reader uses.
    fn query(keychains: Option<&[SecKeychain]>, name: &str) -> ItemSearchOptions {
        let mut query = ItemSearchOptions::new();
        query
            .class(ItemClass::generic_password())
            .service(name)
            .account(ACCOUNT);
        if let Some(keychains) = keychains {
            query.keychains(keychains);
        }
        query
    }
}

impl SecretStore for MacKeychain {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn limit(&self) -> usize {
        LIMIT
    }

    /// A query for a name that never exists: "not found" means the keychain
    /// answers without a prompt. A locked keychain can still pass, and then
    /// fails at the first create, which the store core rolls back.
    fn probe(&self) -> Result<(), StoreError> {
        // Attributes only, like `exists`: never the reserved name's data.
        match self.exists(PROBE_NAME) {
            Ok(false) => Ok(()),
            Ok(true) => Err(StoreError::Unavailable(
                "the keychain holds the probe's reserved name".into(),
            )),
            // A probe writes nothing, so its timeout is plain unavailability.
            Err(StoreError::TimedOut) => Err(StoreError::Unavailable(
                "the keychain did not answer in time".into(),
            )),
            Err(error) => Err(error),
        }
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        no_prompts().map_err(store_error)?;
        let (keychains, name) = (self.keychains.clone(), name.to_owned());
        bounded(self.bound, self.delay, move || {
            // Attributes only: no secret data is returned.
            let mut query = Self::query(keychains.as_deref(), &name);
            query.load_attributes(true).limit(Limit::Max(1));
            match query.search() {
                Ok(found) => Ok(!found.is_empty()),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(false),
                Err(e) => Err(classify(e.code())),
            }
        })
        .map_err(store_error)
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        no_prompts().map_err(store_error)?;
        let location = match self.keychains.as_deref() {
            Some([first, ..]) => Location::FileKeychain(first.clone()),
            _ => Location::DefaultFileKeychain,
        };
        // The thread owns a wiped copy, so a call that outlives the bound
        // still wipes it when it ends.
        let (name, value) = (name.to_owned(), WipedBytes::new(value.to_vec()));
        let reference = format!("keychain:{name}");
        let added = bounded(self.bound, self.delay, move || {
            // ponytail: CFData's copy is freed unzeroed; wiping it needs
            // `unsafe`, which ADR-028 rules out on macOS.
            let mut add = ItemAddOptions::new(ItemAddValue::Data {
                class: ItemClass::generic_password(),
                data: CFData::from_buffer(value.as_bytes()),
            });
            add.set_service(&name)
                .set_account_name(ACCOUNT)
                .set_label(&name)
                .set_location(location);
            // SecItemAdd refuses a duplicate itself: create-only.
            Ok(add.add().map_err(|e| e.code()))
        })
        .map_err(store_error)?;
        match added {
            Ok(()) => Ok(reference),
            Err(DUPLICATE_ITEM) => Err(StoreError::Exists),
            Err(code) => Err(store_error(classify(code))),
        }
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        no_prompts().map_err(store_error)?;
        let (keychains, name) = (self.keychains.clone(), name.to_owned());
        bounded(self.bound, self.delay, move || {
            match Self::query(keychains.as_deref(), &name).delete() {
                Ok(()) => Ok(()),
                // Already gone is durably gone.
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(()),
                Err(e) => Err(classify(e.code())),
            }
        })
        .map_err(store_error)
    }
}

/// A reader error as a writer error. A timeout stays a timeout: the call is
/// still running and may yet write.
fn store_error(error: KeychainError) -> StoreError {
    match error {
        KeychainError::Timeout => StoreError::TimedOut,
        KeychainError::Locked => {
            StoreError::Unavailable("the keychain is locked, and the gateway never prompts".into())
        }
        KeychainError::Unavailable(why) => StoreError::Unavailable(why),
        KeychainError::Missing => StoreError::Failed("the entry vanished mid-call".into()),
    }
}
