// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — building a `GrantRecord` from a 3.x credential record.
//!
//! Design: `docs/internal/design/2026-09-21-store-1-3x-credential-migration.md`
//! §7.2 (field construction) and §7.2a (the two seeds that could make a working
//! 3.x grant stop working).
//!
//! WHY THIS IS A PURE FUNCTION. It takes no store, no filesystem, no RNG and no
//! clock: `generation` and `descriptor_revision` arrive as arguments. That keeps
//! the two data-loss rules testable on their own, before the entry point, the
//! operator declaration or the guarded commit exist — and it means this slice
//! needs no API visibility widening (design §8.2/O2 stays at one item, still
//! unapproved and still not taken here).
//!
//! WHY REFUSAL RATHER THAN A BEST EFFORT. A migration that fails is
//! recoverable: the 3.x file is untouched and the operator re-authenticates
//! once, which is the behaviour 4.0.0 already promised them. A migration that
//! SUCCEEDS and leaves a credential that worked before the upgrade and does not
//! work after it is worse than never migrating, because it consumes the one
//! outcome and delivers the other. Both refusals below exist for that reason,
//! and each was a silent default in the first draft of the design.

use super::super::GrantRecord;
use crate::oauth::TokenInfo;

/// Why one backend's 3.x record cannot become a `GrantRecord`.
///
/// Per-backend and carries no credential material: a run refuses this backend,
/// reports why, and continues with the others (design §7.2a). Secret-free by
/// construction, like `AccountError` (`mod.rs:83-103`) — no variant carries a
/// token, a scope string or a file path.
///
/// MIK-6744.STORE.1: built and unit-tested ahead of the entry point that calls
/// it, so the two data-loss rules are settled before the plumbing around them
/// exists. `expect` (not `allow`) so this self-deletes the moment the entry
/// point lands; `cfg_attr(not(test), ..)` keeps the expectation out of the
/// `lib test` compile unit, where the test-tree caller already makes
/// `dead_code` not fire -- a bare `expect` would itself become an
/// `unfulfilled_lint_expectations` error under `--all-targets`.
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 entry point not yet landed")
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(in crate::personal_accounts) enum RecordRefusal {
    /// The record carries no access token, so there is nothing to migrate.
    #[error("the 3.x record carries no access token")]
    EmptyAccessToken,
    /// Neither an expiry nor a refresh token: every possible seed is wrong.
    ///
    /// `0` would make the grant permanently expired AND permanently
    /// unrefreshable — `AccountService` refreshes anything expired
    /// (`service.rs:272-277`) and the provider refuses without a refresh token
    /// (`provider.rs:307-311`). Any positive value would be a lifetime the
    /// gateway invented for a live credential. So the backend is refused and
    /// the user re-authenticates once (design §7.2a(a)).
    #[error(
        "the 3.x record carries neither an expiry nor a refresh token, so no expiry seed is honest"
    )]
    NoHonestExpiry,
    /// The record names no scopes and the destination descriptor declares none.
    ///
    /// An empty scope set is not a neutral default: `AccountService::apply`
    /// reads every scope in a refresh response as broadening when the stored
    /// set is empty (`service.rs:393-400`), so the grant would refuse its own
    /// first refresh (design §7.2a(b)).
    #[error("neither the 3.x record nor the destination descriptor names any scope")]
    UndeclaredScopes,
}

/// Build the grant a 3.x record migrates into, or refuse this backend.
///
/// `generation` and `descriptor_revision` are supplied by the caller because
/// minting them is not this function's business — see the module note. Every
/// seed is chosen to satisfy `validate_record` (`storage.rs:127-145`), and the
/// two rules that are decisions rather than copies are `expires_at` and
/// `scopes`.
#[cfg_attr(
    all(not(test), not(kani)),
    expect(dead_code, reason = "MIK-6744.STORE.1 entry point not yet landed")
)]
pub(in crate::personal_accounts) fn grant_from_legacy(
    token: &TokenInfo,
    descriptor_scopes: Option<&[String]>,
    client_id: String,
    generation: String,
    descriptor_revision: String,
) -> Result<GrantRecord, RecordRefusal> {
    if token.access_token.is_empty() {
        return Err(RecordRefusal::EmptyAccessToken);
    }
    Ok(GrantRecord {
        generation,
        // A migrated grant is the FIRST revision of a NEW authorization in this
        // store, never a continuation of one: nothing here replaces an existing
        // entry, because the commit is `Absent`-guarded. `validate_record`
        // refuses zero for both (`storage.rs:136-137`).
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision,
        scopes: seed_scopes(token, descriptor_scopes)?,
        access_token: token.access_token.clone(),
        refresh_token: token.refresh_token.clone(),
        token_type: token.token_type.clone(),
        expires_at: seed_expiry(token)?,
        // The 3.x record has no field for it and nothing may be invented.
        provider_account_id: None,
        client_id,
    })
}

/// Design §7.2a(a). Preserve, seed expired, or refuse — never `unwrap_or(0)`.
fn seed_expiry(token: &TokenInfo) -> Result<u64, RecordRefusal> {
    match (token.expires_at, token.refresh_token.as_deref()) {
        // The record states the real lifetime. Nothing is invented and nothing
        // is discarded.
        (Some(expires_at), _) => Ok(expires_at),
        // Expired on arrival, deliberately: one refresh before first use beats
        // handing out a token whose remaining life the record never stated. The
        // refresh can succeed, so nothing is lost.
        (None, Some(_)) => Ok(0),
        // Fail-dead, not fail-closed. Refuse.
        (None, None) => Err(RecordRefusal::NoHonestExpiry),
    }
}

/// Design §7.2a(b). The record's scopes, else the descriptor's, else refuse.
///
/// Sorted and deduped either way: `validate_record` demands STRICTLY ascending
/// (`storage.rs:138`), and `AccountDescriptor.scopes` carries no ordering
/// contract, so a descriptor declaring two scopes in declaration order — or the
/// same scope twice — would otherwise build a record that cannot be stored.
fn seed_scopes(
    token: &TokenInfo,
    descriptor_scopes: Option<&[String]>,
) -> Result<Vec<String>, RecordRefusal> {
    // Whitespace-only is absent, not empty: `scope: "   "` splits to nothing,
    // and treating that as "the user granted no scopes" is the defect this
    // function exists to prevent.
    let from_record = token
        .scope
        .as_deref()
        .map(ascending)
        .filter(|scopes| !scopes.is_empty());
    if let Some(scopes) = from_record {
        return Ok(scopes);
    }
    // The operator has already declared what this backend is authorized for,
    // and §5.3a requires the legacy and destination issuers to be equal, so the
    // declaration describes the same authorization server the credential came
    // from. This is an ATTRIBUTION, not a recovery: the scopes were not in the
    // record.
    let from_descriptor = descriptor_scopes
        .map(|scopes| ascending(&scopes.join(" ")))
        .filter(|scopes| !scopes.is_empty());
    from_descriptor.ok_or(RecordRefusal::UndeclaredScopes)
}

/// Whitespace-split, sorted, deduped — the shape `validate_record` accepts.
fn ascending(scope: &str) -> Vec<String> {
    let mut scopes: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
    scopes.sort();
    scopes.dedup();
    scopes
}

#[cfg(test)]
#[path = "migration_record_tests.rs"]
mod migration_record_tests;
