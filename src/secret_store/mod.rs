// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where secrets saved through the gateway are written (ADR-028).
//!
//! A save never edits a stored secret: each value goes to a fresh entry, the
//! config is pointed at it, and the old entry stays until an admin removes
//! it. [`save::save_secrets`] is ADR-024's all-or-nothing sequence over any
//! [`SecretStore`]; the stores are the OS keychain and owner-only files.
//! Nothing here ever holds a value in an error.

mod files;
mod index;
mod pending;
mod report;
mod save;

use std::path::Path;
use std::sync::Arc;

use crate::config::SecretStoreChoice;

pub(crate) use files::FilesStore;
pub(crate) use pending::{NewSecretOwned, PendingSecrets, create_secrets};
pub use report::{SecretStoreReport, doctor_report};
pub(crate) use save::{
    LOCK_WAIT, NewSecret, SaveError, UnusedEntry, Vault, save_secrets, unused_entries,
    unused_entries_until,
};

/// A store new secrets are written to. Every call is bounded and never
/// prompts; no method returns or logs a value.
pub(crate) trait SecretStore {
    /// Which store this is, as the index records it.
    fn kind(&self) -> StoreKind;
    /// The largest value this store keeps intact, in bytes (ADR-028 rule 2).
    fn limit(&self) -> usize;
    /// Whether the store can take a write now (ADR-028 rule 7).
    fn probe(&self) -> Result<(), StoreError>;
    /// Whether an entry `name` exists.
    fn exists(&self, name: &str) -> Result<bool, StoreError>;
    /// Stores `value` under `name`, refusing a name already taken, and returns
    /// the reference text the config points at.
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError>;
    /// Removes the entry `name`. `Ok` means the removal is durable: the
    /// index marks the name removed only after this returns `Ok`.
    fn delete(&self, name: &str) -> Result<(), StoreError>;
}

/// The store an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreKind {
    Keychain,
    Files,
}

impl StoreKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Keychain => "keychain",
            Self::Files => "files",
        }
    }
}

/// Why a store call did not succeed. Names a reason, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreError {
    /// The name is taken; the entry under it is left unchanged.
    Exists,
    /// The store cannot take a write: the reason, for the operator.
    Unavailable(String),
    /// An empty value; refused on every store.
    Empty,
    /// The value is not UTF-8, which every reader requires.
    NotUtf8,
    /// The value is longer than `store` keeps intact.
    TooLarge { limit: usize, store: StoreKind },
    /// The store failed: the operation and the OS reason, never a value.
    Failed(String),
    /// The store did not answer within its bound. The abandoned call may
    /// still write, so its entry is never deleted and stays indexed.
    TimedOut,
}

impl StoreError {
    /// The operator-facing reason, with the switch to `files` where it helps.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::Exists => "an entry with that name already exists".to_owned(),
            Self::Unavailable(why) => format!("the secret store is unavailable: {why}; {SWITCH}"),
            Self::Empty => "the value is empty; empty secrets are refused".to_owned(),
            Self::NotUtf8 => "the value is not UTF-8".to_owned(),
            Self::TooLarge { limit, store } => {
                let base = format!("the value is longer than this store's limit of {limit} bytes");
                match store {
                    StoreKind::Keychain => format!("{base}; {SWITCH}"),
                    StoreKind::Files => base,
                }
            }
            Self::Failed(why) => why.clone(),
            Self::TimedOut => "the secret store did not answer in time; an entry it may \
                still write is kept and listed as unused"
                .to_owned(),
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason())
    }
}

/// A store failure: what was being done, and the OS reason.
fn failed(what: &str, error: &std::io::Error) -> StoreError {
    StoreError::Failed(format!("{what}: {error}"))
}

/// Milliseconds since the epoch; 0 for a clock set before it, which only
/// dates an index line (a name's random part keeps it unique).
fn now_ms() -> u64 {
    crate::clock::unix_millis().unwrap_or(0)
}

/// The longest reference text any store returns: `file:` and a path (a
/// Windows long path runs to 32,767 characters), or `keychain:` and a
/// name. The byte writer bounds a filled file by it before any entry exists.
pub(crate) const MAX_REFERENCE_LEN: usize = 32 * 1024;

const SWITCH: &str = "set `secrets.store: files`, or unlock or install the keychain";

/// The store a save writes to, and why it was chosen.
pub(crate) struct Chosen {
    pub(crate) store: Arc<dyn SecretStore + Send + Sync>,
    /// The operator-facing reason: the setting, or the probe's answer.
    /// Never a value, an entry name or a path under `secrets/`.
    pub(crate) reason: String,
    /// `auto` fell back to files because the keychain did not answer.
    pub(crate) fell_back: bool,
}

/// The store a save with `choice` writes to, for a config in `config_dir`,
/// logged once per call so a fallback to files is never silent.
///
/// `auto` probes the OS keychain now and takes files when it fails;
/// `keychain` is probed again by every save, which refuses rather than
/// switching (ADR-028 rule 7).
///
/// # Errors
///
/// [`StoreError::Unavailable`] for `keychain` on a target without one.
pub(crate) fn choose_store(
    choice: SecretStoreChoice,
    config_dir: &Path,
) -> Result<Chosen, StoreError> {
    let chosen = choose_with(
        choice,
        config_dir,
        crate::config::keychain::os_secret_store(),
    )?;
    log_choice(choice, &chosen);
    Ok(chosen)
}

/// One line per choice: `warn` when `auto` fell back to files, else `info`.
pub(crate) fn log_choice(choice: SecretStoreChoice, chosen: &Chosen) {
    let (setting, store) = (choice_str(choice), chosen.store.kind().as_str());
    if chosen.fell_back {
        tracing::warn!(setting, store, reason = %chosen.reason, "secrets go to files");
    } else {
        tracing::info!(setting, store, reason = %chosen.reason, "secret store chosen");
    }
}

/// [`choose_store`] over a given OS store, `None` where the target has none.
pub(crate) fn choose_with(
    choice: SecretStoreChoice,
    config_dir: &Path,
    os: Option<Arc<dyn SecretStore + Send + Sync>>,
) -> Result<Chosen, StoreError> {
    let files = |reason: String, fell_back: bool| Chosen {
        store: Arc::new(FilesStore::new(config_dir)),
        reason,
        fell_back,
    };
    match (choice, os) {
        (SecretStoreChoice::Files, _) => Ok(files("set to files".to_owned(), false)),
        (SecretStoreChoice::Keychain, None) => Err(StoreError::Unavailable(
            "this platform has no keychain store".to_owned(),
        )),
        (SecretStoreChoice::Keychain, Some(store)) => Ok(Chosen {
            store,
            reason: "set to keychain; every save probes it first".to_owned(),
            fell_back: false,
        }),
        (SecretStoreChoice::Auto, None) => Ok(files(
            "auto: this platform has no keychain store".to_owned(),
            true,
        )),
        (SecretStoreChoice::Auto, Some(store)) => match store.probe() {
            Ok(()) => Ok(Chosen {
                store,
                reason: "auto: the keychain probe passed".to_owned(),
                fell_back: false,
            }),
            Err(error) => Ok(files(
                format!("auto: the keychain probe failed: {error}"),
                true,
            )),
        },
    }
}

/// The setting as written in `gateway.yaml`.
pub(crate) fn choice_str(choice: SecretStoreChoice) -> &'static str {
    match choice {
        SecretStoreChoice::Auto => "auto",
        SecretStoreChoice::Keychain => "keychain",
        SecretStoreChoice::Files => "files",
    }
}

/// A fresh entry name for a secret of `field`: `mcp-gateway.<slug>.<ms>.<16
/// hex>` (ADR-028 rule 1). The slug is the field path with every byte outside
/// `[A-Za-z0-9-]` mapped to `-`, runs collapsed, capped at 40.
pub(crate) fn fresh_name(field: &str, unix_ms: u64, random: u64) -> String {
    let mut slug = String::with_capacity(40);
    for byte in field.bytes() {
        if slug.len() == 40 {
            break;
        }
        let keep = byte.is_ascii_alphanumeric() || byte == b'-';
        if keep {
            slug.push(char::from(byte));
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    if slug.is_empty() {
        slug.push_str("secret");
    }
    format!("mcp-gateway.{slug}.{unix_ms}.{random:016x}")
}

/// 64 bits from the OS random source, for [`fresh_name`].
///
/// # Errors
///
/// [`StoreError::Failed`] when the OS source fails; no name is made up.
pub(crate) fn random_suffix() -> Result<u64, StoreError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StoreError::Failed("the OS random source failed".to_owned()))?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod choose_tests;
#[cfg(test)]
mod rollback_tests;
