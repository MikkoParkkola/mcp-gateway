// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What `mcp-gateway doctor` shows about the secret store: the setting, the
//! store it resolves to and why, and how many unused entries are waiting for
//! an admin. Read-only: the probe never writes, and nothing in the config
//! directory is created or changed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::unused::{NamingSources, listing_within};
use super::{FilesStore, SecretStore, StoreError, StoreKind, Vault, choice_str, choose_with};
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
    let process_env: Vec<OsString> = std::env::vars_os().map(|(_, value)| value).collect();
    report_with(
        config_path,
        choice,
        vault,
        crate::config::keychain::os_secret_store().as_ref(),
        &process_env,
    )
}

/// [`doctor_report`] over a given vault and OS store.
pub(super) fn report_with(
    config_path: &Path,
    choice: SecretStoreChoice,
    vault: Result<Vault, StoreError>,
    os: Option<&Arc<dyn SecretStore + Send + Sync>>,
    process_env: &[OsString],
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
    let counted = vault.map_err(|e| e.reason()).and_then(|vault| {
        count_unused(
            config_path,
            config_dir,
            &vault,
            os.map(|os| &**os),
            process_env,
        )
    });
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
/// entry made before a switch is still waiting for an admin. Named or not is
/// the Settings listing's own check, over every source doctor can see.
fn count_unused(
    config_path: &Path,
    config_dir: &Path,
    vault: &Vault,
    os: Option<&(dyn SecretStore + Send + Sync)>,
    process_env: &[OsString],
) -> Result<usize, String> {
    let sources = offline_sources(config_path, config_dir, process_env)?;
    // No lock file means no save ever ran, so nothing is indexed; taking the
    // lock would create the file, and the report writes nothing. An index
    // with no lock beside it is not counted rather than reported as zero.
    if !vault.lock_exists() {
        return if vault.index_exists() {
            Err(
                "the index exists but the vault lock does not, so entries were not counted"
                    .to_owned(),
            )
        } else {
            Ok(0)
        };
    }
    let files = FilesStore::new(config_dir);
    let mut stores: Vec<&dyn SecretStore> = vec![&files];
    if let Some(os) = os {
        stores.push(os);
    }
    let listed = listing_within(vault, &stores, &sources, LOCK_WAIT);
    if let Some((_, reason)) = listed.errors.into_iter().next() {
        return Err(reason);
    }
    Ok(listed.entries.len())
}

/// Every naming source doctor can see, read as startup reads them: the config,
/// the env files its `env_files` name and the values they assign, this
/// process's environment, and the config's capability directories. A running
/// gateway's listing also reads its live config's directories, which offline
/// doctor cannot. A config that does not load is not counted, with a fixed
/// sentence: a loader error can quote config text that holds a literal secret.
fn offline_sources(
    config_path: &Path,
    config_dir: &Path,
    process_env: &[OsString],
) -> Result<NamingSources, String> {
    let loaded = crate::config::Config::load_evaluated(Some(config_path))
        .map_err(|_| "gateway.yaml did not load, so references were not read".to_owned())?;
    Ok(NamingSources {
        config: config_path.to_path_buf(),
        entries_dir: FilesStore::new(config_dir).entries_dir().to_path_buf(),
        env_files: loaded.env_paths.as_paths().to_vec(),
        env_values: loaded
            .overlay
            .assigned_values()
            .map(str::to_owned)
            .collect(),
        process_env: process_env.to_vec(),
        capability_dirs: loaded
            .config
            .capabilities
            .directories
            .iter()
            .map(PathBuf::from)
            .collect(),
    })
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
