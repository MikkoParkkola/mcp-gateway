// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What `mcp-gateway doctor` shows about the secret store: the setting, the
//! store it resolves to and why, and how many unused entries are waiting for
//! an admin. Read-only: the probe never writes, and nothing in the config
//! directory is created or changed.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{
    FilesStore, SecretStore, StoreError, StoreKind, Vault, choice_str, choose_with,
    unused_entries_until,
};
use crate::config::SecretStoreChoice;

/// How long doctor waits for a save holding the vault lock.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The secret store as doctor reports it. Owned text and a count: never a
/// store handle, an entry name or a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretStoreReport {
    /// `secrets.store` as written: `auto`, `keychain` or `files`.
    pub setting: &'static str,
    /// The store saves write to, or `None` when the setting is refused here.
    pub chosen: Option<&'static str>,
    /// Why: the setting, the probe's answer, or the refusal.
    pub reason: String,
    /// `auto` fell back to files because the keychain did not answer.
    pub fell_back: bool,
    /// Entries the index lists that still exist and that `gateway.yaml` does
    /// not name; `None` when they could not be counted.
    pub unused: Option<usize>,
    /// Why the count is missing.
    pub unused_error: Option<String>,
}

/// The report for the config at `config_path` with `choice`.
///
/// ponytail: the count does not hold the config sidecar, which would create
/// it, so a save committing at that moment can count its new entry once.
/// The count is advisory; removal (a later change) must hold both locks.
#[must_use]
pub fn doctor_report(config_path: &Path, choice: SecretStoreChoice) -> SecretStoreReport {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let vault = Vault::for_config_dir(config_dir);
    report_with(
        config_path,
        choice,
        vault,
        crate::config::keychain::os_secret_store().as_ref(),
    )
}

/// [`doctor_report`] over a given vault and OS store.
pub(super) fn report_with(
    config_path: &Path,
    choice: SecretStoreChoice,
    vault: Result<Vault, StoreError>,
    os: Option<&Arc<dyn SecretStore + Send + Sync>>,
) -> SecretStoreReport {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let (chosen, reason, fell_back) = match choose_with(choice, config_dir, os.cloned()) {
        Ok(chosen) => {
            // No choice log line here: that line belongs to saves, and doctor
            // shows the same fields in its row.
            let kind = chosen.store.kind();
            // Explicit `keychain` is probed by every save; doctor runs the
            // same probe now. A locked macOS keychain can still pass it and
            // refuse at the first create (ADR-028 §7).
            match (choice, kind) {
                (SecretStoreChoice::Keychain, StoreKind::Keychain) => match chosen.store.probe() {
                    Ok(()) => (
                        Some(kind.as_str()),
                        "set to keychain; the probe passed".to_owned(),
                        false,
                    ),
                    Err(error) => (
                        None,
                        format!("set to keychain; saves are refused: {error}"),
                        false,
                    ),
                },
                _ => (Some(kind.as_str()), chosen.reason, chosen.fell_back),
            }
        }
        Err(error) => (None, error.reason(), false),
    };
    let counted = vault
        .map_err(|e| e.reason())
        .and_then(|vault| count_unused(config_path, config_dir, &vault, os.map(|os| &**os)));
    let (unused, unused_error) = match counted {
        Ok(count) => (Some(count), None),
        Err(why) => (None, Some(why)),
    };
    SecretStoreReport {
        setting: choice_str(choice),
        chosen,
        reason,
        fell_back,
        unused,
        unused_error,
    }
}

/// Entries in either store count, whichever the setting now picks: an
/// entry made before a switch is still waiting for an admin.
fn count_unused(
    config_path: &Path,
    config_dir: &Path,
    vault: &Vault,
    os: Option<&(dyn SecretStore + Send + Sync)>,
) -> Result<usize, String> {
    // The same mode-checked read the loader uses: no FIFO, no wide modes.
    let text = crate::config::read_checked_file(config_path, crate::config::CheckedFile::Config)
        .map_err(|e| e.to_string())?;
    let named = named_in_yaml(&text)?;
    // No lock file means no save ever ran, so nothing is indexed; taking the
    // lock would create the file, and the report writes nothing.
    if !vault.lock_exists() {
        return Ok(0);
    }
    let files = FilesStore::new(config_dir);
    let mut stores: Vec<&dyn SecretStore> = vec![&files];
    if let Some(os) = os {
        stores.push(os);
    }
    let unused = unused_entries_until(vault, &stores, &named, Instant::now() + LOCK_WAIT)
        .map_err(|e| e.reason())?;
    Ok(unused.len())
}

/// The entry names in every string of the parsed config, so a YAML escape
/// cannot hide a live reference. A config that does not parse is not counted.
fn named_in_yaml(text: &str) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value = crate::yaml::from_str(text)
        .map_err(|_| "gateway.yaml did not parse, so references were not read".to_owned())?;
    let mut names = BTreeSet::new();
    let mut pending = vec![&value];
    while let Some(next) = pending.pop() {
        match next {
            serde_json::Value::String(s) => names.extend(named(s)),
            serde_json::Value::Array(items) => pending.extend(items),
            serde_json::Value::Object(map) => pending.extend(map.values()),
            _ => {}
        }
    }
    Ok(names)
}

/// Every entry name `text` mentions, as a `keychain:` reference or a
/// `file:secrets/` path alike: each maximal run of name characters that
/// starts with the fresh-name prefix (ADR-028 rule 1). A name in a comment
/// counts as named, so the count errs low, never high.
fn named(text: &str) -> BTreeSet<String> {
    const PREFIX: &str = "mcp-gateway.";
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
    let mut names = BTreeSet::new();
    let mut rest = text;
    while let Some(at) = rest.find(PREFIX) {
        let tail = &rest[at..];
        let len = tail.find(|c: char| !is_name(c)).unwrap_or(tail.len());
        names.insert(tail[..len].trim_end_matches('.').to_owned());
        rest = &tail[len.max(PREFIX.len())..];
    }
    names
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
