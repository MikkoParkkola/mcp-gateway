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
    use LegacyOAuthMigrateError as E;
    let name = request.backend;
    let backend = config
        .backends
        .get(name)
        .ok_or_else(|| E::NoSuchBackend(name.to_owned()))?;
    let crate::config::TransportConfig::Http { http_url, .. } = &backend.transport else {
        return Err(E::NotOAuth(name.to_owned()));
    };
    let Some(oauth) = backend.oauth.as_ref().filter(|oauth| oauth.enabled) else {
        return Err(E::NotOAuth(name.to_owned()));
    };
    // An account-bound backend reads the personal-account store, never this
    // directory: a copy here would be a credential nothing reads.
    let bound = crate::config::account_bindings::compile(config)
        .map_err(|error| E::Io(error.to_string()))?;
    if bound.contains_key(name) {
        return Err(E::AccountBound(name.to_owned()));
    }

    // Exclusive: a running gateway holds it shared for its whole life.
    let _quiet = take_exclusive(storage)?;

    let legacy_name = request.legacy_backend_name.unwrap_or(name);
    let legacy_url = request.legacy_resource_url.unwrap_or(http_url);
    let token = crate::oauth::legacy_source::read_legacy_source(
        &storage.token_path(legacy_name, legacy_url),
    )
    .map_err(|refusal| E::Source(refusal.to_string()))?;
    let legacy_client = storage.load_client_id(legacy_name, legacy_url);

    let key = crate::oauth::client::storage_key(name, request.issuer);
    if storage.token_path(&key, http_url).exists() {
        return Ok(LegacyOAuthMigrated {
            already_present: true,
            ..LegacyOAuthMigrated::default()
        });
    }
    // A token without its client cannot refresh: refuse before any write.
    if let (Some(configured), Some(legacy)) = (oauth.client_id.as_deref(), legacy_client.as_deref())
        && configured != legacy
    {
        return Err(E::ClientMismatch("the configured client_id"));
    }
    let existing_client = storage.load_client_id(&key, http_url);
    if let (Some(existing), Some(legacy)) = (existing_client.as_deref(), legacy_client.as_deref())
        && existing != legacy
    {
        return Err(E::ClientMismatch(
            "the client already registered under this issuer",
        ));
    }
    let mut warnings = Vec::new();
    if legacy_client.is_none() && oauth.client_id.is_none() && existing_client.is_none() {
        warnings.push(
            "no 3.x client id and no configured client_id: the copied refresh token will likely \
             fail against a fresh registration, which then costs one re-authorization"
                .to_owned(),
        );
    }
    if request.dry_run {
        return Ok(LegacyOAuthMigrated {
            dry_run: true,
            warnings,
            ..LegacyOAuthMigrated::default()
        });
    }

    // Client first: an interrupted run leaves a client and no token, and a
    // re-run publishes the token against the same client.
    let mut wrote_client = false;
    if let (Some(legacy), None) = (legacy_client.as_deref(), existing_client.as_deref()) {
        let adopted = storage
            .save_client_id(&key, http_url, legacy)
            .map_err(|error| E::Io(error.to_string()))?;
        if adopted != legacy {
            return Err(E::ClientMismatch("a client another writer just registered"));
        }
        wrote_client = true;
    }
    let wrote_token = storage
        .publish_new(&key, http_url, &token)
        .map_err(|error| E::Io(error.to_string()))?;
    Ok(LegacyOAuthMigrated {
        wrote_client,
        wrote_token,
        already_present: !wrote_token,
        warnings,
        ..LegacyOAuthMigrated::default()
    })
}

/// The instance lock inside a token directory.
fn open_instance_lock(storage: &TokenStorage) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(storage.dir().join(".instance.lock"))
}

fn take_exclusive(storage: &TokenStorage) -> Result<std::fs::File, LegacyOAuthMigrateError> {
    let file = open_instance_lock(storage)
        .map_err(|error| LegacyOAuthMigrateError::Io(error.to_string()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(LegacyOAuthMigrateError::GatewayRunning),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(LegacyOAuthMigrateError::Io(error.to_string()))
        }
    }
}

/// The token directory's instance lock, held SHARED by a running gateway for
/// its lifetime so `oauth migrate-legacy` can tell it is running. Blocks only
/// while a migration holds it exclusive, which takes milliseconds.
///
/// # Errors
///
/// Returns the I/O error when the lock file cannot be opened or locked.
pub(crate) fn hold_instance_lock(storage: &TokenStorage) -> std::io::Result<std::fs::File> {
    let file = open_instance_lock(storage)?;
    file.lock_shared()?;
    Ok(file)
}

#[cfg(test)]
#[path = "legacy_migrate_tests.rs"]
mod legacy_migrate_tests;
