// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — the migration entry point.
//!
//! One offline function per declared backend. It reaches no network, starts no
//! worker and needs no provider: it opens an already-initialized store, reads
//! one 3.x file, and commits one guarded write. `serve` never reaches it.
//!
//! WHAT IT REFUSES, AND WHY EVERY REFUSAL IS LOUD. Each precondition exists
//! because the alternative is a migration that SUCCEEDS and leaves the user
//! worse off than not migrating: a dead grant, a grant that cannot refresh, a
//! credential re-homed to the wrong authorization server, or — the quietest of
//! them — nothing at all, reported as nothing to do.
//!
//! THE 3.X SOURCE IS NEVER WRITTEN. Not re-keyed, not truncated, not deleted.
//! A failed migration leaves the user exactly where they started.

use std::path::PathBuf;

use super::super::consent::GuardedCommit;
use super::super::identity::{self, Principal};
use super::super::service::ConsentExpectation;
use super::super::{AccountKey, PersonalAccountStore};
use super::migration::{RecordRefusal, grant_from_legacy};
use super::migration_precondition::{PreconditionRefusal, check_issuer, recover_client_id};
use super::migration_revision::descriptor_revision;
use super::migration_source::{SourceRefusal, read_legacy_source};
use crate::oauth::TokenStorage;
use crate::personal_accounts::config::AccountDescriptor;

/// One backend the caller asked to migrate.
///
/// `legacy_backend_name` is an OVERRIDE, not a declaration. The 3.x file is
/// hashed over the backend registry name, which the compiled binding already
/// carries, so asking for it again would create a second source of truth for
/// one fact where the restatement can disagree with reality and the
/// disagreement is silent. It survives for the one case nothing records: a
/// backend renamed between 3.x and 4.0.0, whose file is hashed under the old
/// name.
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 command caller not yet landed")
)]
pub(in crate::personal_accounts) struct MigrationRequest<'a> {
    /// The four-field descriptor the account key is built from.
    pub(in crate::personal_accounts) key_descriptor: &'a identity::AccountDescriptor,
    /// The full declared descriptor, for the rules the key descriptor cannot
    /// answer: scopes and `client_id`.
    pub(in crate::personal_accounts) descriptor: &'a AccountDescriptor,
    /// The backend registry name from the compiled binding.
    pub(in crate::personal_accounts) bound_backend: &'a str,
    /// `--legacy-backend-name`, for a backend renamed since 3.x.
    pub(in crate::personal_accounts) legacy_backend_name: Option<&'a str>,
    /// `--legacy-issuer`: the authorization server the caller asserts issued
    /// this credential. Never defaulted from the descriptor.
    pub(in crate::personal_accounts) legacy_issuer: &'a str,
    /// A prior Dynamic Client Registration, if one is on disk.
    pub(in crate::personal_accounts) registered_client_id: Option<&'a str>,
}

/// What happened to one declared backend.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 command caller not yet landed")
)]
pub(in crate::personal_accounts) enum MigrationOutcome {
    /// The grant was written. The 3.x file is untouched.
    Migrated,
    /// The account already held a grant, or a revoked one, so the guarded
    /// commit fenced without writing.
    ///
    /// This is what makes a re-run safe: idempotency is a property of the
    /// `Absent` guard, not of a bookkeeping file this would otherwise invent.
    /// It is also what stops a credential a user deliberately revoked from
    /// being resurrected.
    AlreadyPresent,
}

/// Why one backend was not migrated.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::personal_accounts) enum MigrationRefusal {
    #[error(transparent)]
    Source(#[from] SourceRefusal),
    #[error(transparent)]
    Precondition(#[from] PreconditionRefusal),
    #[error(transparent)]
    Record(#[from] RecordRefusal),
    /// The store refused the write, or the key could not be built.
    #[error("the account store refused the migrated grant")]
    Store,
}

/// Migrate one declared backend into the per-principal store.
///
/// The order is: resolve, read, check, build, commit. Preconditions that need
/// no credential material run before the file is read where they can, and the
/// issuer contradiction check runs immediately after, so the window in which
/// plaintext exists is as short as the checks allow.
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 command caller not yet landed")
)]
pub(in crate::personal_accounts) fn migrate_backend(
    store: &PersonalAccountStore,
    legacy: &TokenStorage,
    request: &MigrationRequest<'_>,
) -> Result<MigrationOutcome, MigrationRefusal> {
    let backend_name = request.legacy_backend_name.unwrap_or(request.bound_backend);
    let path: PathBuf = legacy.token_path(backend_name, &request.key_descriptor.resource);

    // Loud, per design 5.3c.1: a resolved path that does not exist must not
    // read as "nothing to migrate".
    let token = read_legacy_source(&path)?;

    check_issuer(
        request.legacy_issuer,
        &request.key_descriptor.issuer,
        token.token_endpoint.as_deref(),
    )?;
    let client_id = recover_client_id(
        request.descriptor,
        request.registered_client_id,
        token.client_id.as_deref(),
    )?;

    let generation = super::random_hex().map_err(|_| MigrationRefusal::Store)?;
    let revision = descriptor_revision(request.descriptor).map_err(|_| MigrationRefusal::Store)?;
    let record = grant_from_legacy(
        &token,
        request.descriptor.scopes.as_deref(),
        client_id,
        generation,
        revision,
    )?;

    let account = account_key(request)?;
    // The provenance marker: the 3.x file this grant came from. Only migration
    // sets it, which is what lets an auditor tell a grant the user consented to
    // from one written on their behalf.
    let provenance = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned);
    match store.commit_grant_if_unchanged(
        &account,
        &ConsentExpectation::Absent,
        &record,
        provenance.as_deref(),
    ) {
        Ok(GuardedCommit::Committed) => Ok(MigrationOutcome::Migrated),
        Ok(GuardedCommit::Fenced) => Ok(MigrationOutcome::AlreadyPresent),
        Err(_) => Err(MigrationRefusal::Store),
    }
}

/// The account key, built by the SAME function the lease path uses.
///
/// Not a restatement of the five fields. `Principal::SoleOperator` needs no
/// verified identity, so migration calls the one constructor rather than
/// assembling a key from values copied out of another module — which means the
/// two cannot disagree about where a migrated grant lands, rather than agreeing
/// because two documents say the same thing today.
fn account_key(request: &MigrationRequest<'_>) -> Result<AccountKey, MigrationRefusal> {
    identity::account_key(Some(Principal::SoleOperator), request.key_descriptor)
        .map_err(|_| MigrationRefusal::Store)
}

#[cfg(test)]
#[path = "migration_entry_tests.rs"]
mod migration_entry_tests;
