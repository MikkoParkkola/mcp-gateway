// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — `oauth migrate-legacy`: carry one ordinary backend's 3.x
//! OAuth credential to its 4.0 per-issuer key, offline, on the operator's
//! assertion of the issuer (design 2026-10-05, §§13-15).
//!
//! A 3.x credential file records no issuer, so nothing in the file can say
//! which authorization server issued the grant. The operator says so with
//! `--issuer`. The copy is written under `storage_key(backend, issuer)`, which
//! the running gateway reads only when discovery returns exactly that issuer:
//! a wrong assertion that does not match discovery is never used and costs one
//! re-authorization. A wrong assertion that DOES match discovery sends the 3.x
//! refresh token to that issuer; matching discovery does not prove the grant's
//! provenance, and the command says so. This is the same trust as
//! `accounts migrate-credentials --legacy-issuer`.
//!
//! The 3.x files are only ever read. Nothing here writes, renames or deletes
//! them, so a rollback to 3.x finds them as they were.

use std::path::Path;

use crate::config::Config;
use crate::oauth::TokenStorage;

/// What to migrate.
#[derive(Clone, Debug)]
pub struct LegacyOAuthMigration<'a> {
    /// The 4.0 backend registry name.
    pub backend: &'a str,
    /// The authorization server the operator asserts issued the 3.x grant,
    /// spelled exactly as that server's discovery document spells `issuer`.
    pub issuer: &'a str,
    /// The 3.x backend name, when the backend was renamed since.
    pub legacy_backend_name: Option<&'a str>,
    /// The 3.x `http_url`, when it changed since.
    pub legacy_resource_url: Option<&'a str>,
    /// Report the plan and write nothing.
    pub dry_run: bool,
}

/// What one migration did. Names and booleans only: no credential material.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct LegacyOAuthMigrated {
    /// The 3.x client id was published under the 4.0 key.
    pub wrote_client: bool,
    /// The 3.x token was published under the 4.0 key. False when an entry was
    /// already there (nothing to do) or on a dry run.
    pub wrote_token: bool,
    /// An entry already existed under the 4.0 key; nothing was written.
    pub already_present: bool,
    /// Nothing was written because this was a dry run.
    pub dry_run: bool,
    /// Operator-facing cautions that do not stop the migration.
    pub warnings: Vec<String>,
}

/// Why a migration was refused. A refusal writes nothing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum LegacyOAuthMigrateError {
    /// No backend by that name in the configuration.
    #[error("no backend named `{0}` in the configuration")]
    NoSuchBackend(String),
    /// The backend has no enabled `oauth` block or no `http_url`.
    #[error(
        "backend `{0}` has no enabled `oauth` block over HTTP; nothing reads a migrated credential"
    )]
    NotOAuth(String),
    /// The backend is bound to a personal account, whose store this command does not write.
    #[error("backend `{0}` is bound to a personal account; use `accounts migrate-credentials`")]
    AccountBound(String),
    /// A gateway holds the token directory.
    #[error("a gateway is running against this token directory; stop it first")]
    GatewayRunning,
    /// The 3.x source could not be read.
    #[error("the 3.x credential cannot be read: {0}")]
    Source(String),
    /// The 3.x client id disagrees with one the 4.0 side already uses.
    #[error("the 3.x client id differs from {0}; a token without its client cannot refresh")]
    ClientMismatch(&'static str),
    /// A filesystem or configuration failure.
    #[error("{0}")]
    Io(String),
}

/// Migrate one backend's 3.x credential in the default token directory.
///
/// # Errors
///
/// Every refusal in [`LegacyOAuthMigrateError`]; a refusal writes nothing.
pub fn migrate_legacy_oauth_offline(
    config: &Config,
    request: &LegacyOAuthMigration<'_>,
) -> Result<LegacyOAuthMigrated, LegacyOAuthMigrateError> {
    let storage = TokenStorage::default_location()
        .map_err(|error| LegacyOAuthMigrateError::Io(error.to_string()))?;
    migrate_in(&storage, config, request)
}

/// [`migrate_legacy_oauth_offline`] against an explicit token directory.
pub(crate) fn migrate_in(
    storage: &TokenStorage,
    config: &Config,
    request: &LegacyOAuthMigration<'_>,
) -> Result<LegacyOAuthMigrated, LegacyOAuthMigrateError> {
    let _ = (storage, config, request, Path::new(""));
    Err(LegacyOAuthMigrateError::Io("not implemented".to_owned()))
}

/// The token directory's instance lock, held SHARED by a running gateway for
/// its lifetime so `oauth migrate-legacy` can tell it is running.
pub(crate) fn hold_instance_lock(storage: &TokenStorage) -> std::io::Result<std::fs::File> {
    let _ = storage;
    Err(std::io::Error::other("not implemented"))
}

#[cfg(test)]
#[path = "legacy_migrate_tests.rs"]
mod legacy_migrate_tests;
