// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unused secret entries, listed and deleted one at a time (ADR-028 rule 6).
//!
//! An entry is named, and never deleted, while its generated suffix occurs in any
//! source a load or a capability call reads, or a `file:` value reaches its file.
//! The delete re-checks under the vault lock and writes its index line only after
//! the store delete succeeded.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

use super::{SecretStore, Vault};

/// Every source that can name an entry, read fresh for each check.
pub(crate) struct NamingSources {
    /// The selected `gateway.yaml`.
    pub(crate) config: PathBuf,
    /// Every env file the live overlay was built from.
    pub(crate) env_files: Vec<PathBuf>,
    /// The values the live overlay parsed from those env files.
    pub(crate) env_values: Vec<String>,
    /// Process environment values (the overlay falls through to them).
    pub(crate) process_env: Vec<OsString>,
    /// Capability directories, walked recursively.
    pub(crate) capability_dirs: Vec<PathBuf>,
}

/// Whether an entry is named, with the digest of every source read when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Naming {
    Named,
    NotNamed { digest: String },
}

/// Why a delete did nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeleteRefused {
    BadName,
    NotListed,
    StoreMismatch,
    Named,
    Pending,
    Busy,
    TimedOut,
    Failed(String),
}

/// What a delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deleted {
    Removed,
    AlreadyGone,
}

/// Whether `name` has the shape `fresh_name` makes:
/// `mcp-gateway.<slug>.<unix_ms>.<16 lowercase hex>`.
pub(crate) fn is_generated_name(_name: &str) -> bool {
    true
}

/// The generated 16-hex suffix of a well-shaped name.
pub(crate) fn suffix_of(_name: &str) -> Option<&str> {
    None
}

/// Whether any source names `name`. An unreadable source is an error, never "not named".
pub(crate) fn naming(_sources: &NamingSources, _name: &str) -> Result<Naming, String> {
    Ok(Naming::NotNamed {
        digest: String::new(),
    })
}

/// Delete one unused entry from `store`, re-checking everything under the vault lock.
pub(crate) fn delete_unused(
    _vault: &Vault,
    _store: &dyn SecretStore,
    _name: &str,
    _sources: &NamingSources,
    _deadline: Instant,
) -> Result<Deleted, DeleteRefused> {
    Err(DeleteRefused::Failed("not built".to_owned()))
}

#[cfg(test)]
#[path = "unused_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "unused_delete_tests.rs"]
mod delete_tests;
