// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §7.2a — the two seeds that could make a working 3.x grant
//! stop working, and the refusals that stop them.
//!
//! EVERY CASE HERE IS TWO-DIRECTIONAL, and the positive legs are not decoration.
//! A suite that only proved "the bad record is refused" passes for an
//! implementation that refuses everything, which would satisfy the letter of
//! §7.2a and migrate nothing at all. So each refusal is paired with the nearest
//! record that MUST still migrate, differing in exactly one field.

use super::{RecordRefusal, grant_from_legacy};
use crate::oauth::TokenInfo;

const GENERATION: &str = "fedcba9876543210fedcba9876543210";
const CLIENT: &str = "synthetic-migration-client";
/// 2100-01-01, so a seeded expiry is unambiguously in the future.
const FAR_FUTURE: u64 = 4_102_444_800;

fn revision() -> String {
    "0".repeat(64)
}

/// A 3.x record with every optional field absent, to be narrowed per case.
fn legacy(access_token: &str) -> TokenInfo {
    TokenInfo {
        access_token: access_token.to_owned(),
        token_type: "Bearer".to_owned(),
        refresh_token: None,
        expires_at: None,
        scope: None,
        token_endpoint: None,
        client_id: None,
        client_secret: None,
    }
}

fn build(
    token: &TokenInfo,
    descriptor_scopes: Option<&[String]>,
) -> Result<crate::personal_accounts::GrantRecord, RecordRefusal> {
    grant_from_legacy(
        token,
        descriptor_scopes,
        CLIENT.to_owned(),
        GENERATION.to_owned(),
        revision(),
    )
}

fn declared(scopes: &[&str]) -> Vec<String> {
    scopes.iter().map(|s| (*s).to_owned()).collect()
}

// ── §7.2a(a) expiry ──────────────────────────────────────────────────────────

/// A record with neither an expiry nor a refresh token is REFUSED.
///
/// `unwrap_or(0)` would have committed it: permanently expired, because
/// `AccountService` refreshes anything expired (`service.rs:272-277`), and
/// permanently unrefreshable, because the provider needs a refresh token
/// (`provider.rs:307-311`). That access token worked in 3.x until its real
/// expiry, so the migration would have KILLED a working grant.
#[test]
fn a_record_with_neither_expiry_nor_refresh_token_is_refused() {
    let token = legacy("live-3x-access-token");
    assert_eq!(
        build(&token, Some(&declared(&["read"]))),
        Err(RecordRefusal::NoHonestExpiry),
        "no expiry and no refresh token: every seed is wrong, so refuse rather \
         than commit a grant that cannot work"
    );
}

/// POSITIVE CONTROL for the case above: one field different, and it migrates.
///
/// Without this, the refusal test passes for an implementation that refuses
/// every record — which is why it is here and not in a follow-up.
#[test]
fn a_record_with_no_expiry_but_a_refresh_token_migrates_expired_on_arrival() {
    let mut token = legacy("live-3x-access-token");
    token.refresh_token = Some("live-3x-refresh-token".to_owned());
    let record = build(&token, Some(&declared(&["read"]))).expect("must migrate");
    assert_eq!(
        record.expires_at, 0,
        "expired on arrival is right HERE: the refresh token can redeem it, so \
         one refresh before first use costs nothing and beats handing out a \
         token whose remaining life the record never stated"
    );
    assert_eq!(
        record.refresh_token.as_deref(),
        Some("live-3x-refresh-token")
    );
}

/// A real expiry is preserved verbatim, never overwritten with `0`.
///
/// The other direction of the same rule: `0` is a seed for a record that has no
/// expiry, not a policy applied to every migrated grant.
#[test]
fn a_record_with_a_real_expiry_keeps_it() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    let record = build(&token, Some(&declared(&["read"]))).expect("must migrate");
    assert_eq!(
        record.expires_at, FAR_FUTURE,
        "the record states the real lifetime; discarding it would force a \
         needless refresh and lose the only expiry anyone knows"
    );
}

/// An expiry with no refresh token is still migratable — the refusal is about
/// having NEITHER.
#[test]
fn a_record_with_an_expiry_but_no_refresh_token_still_migrates() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    let record = build(&token, Some(&declared(&["read"]))).expect("must migrate");
    assert_eq!(record.expires_at, FAR_FUTURE);
    assert_eq!(
        record.refresh_token, None,
        "an access-only grant with a known lifetime is usable until it expires, \
         which is exactly what 3.x did with it"
    );
}

// ── §7.2a(b) scopes ──────────────────────────────────────────────────────────

/// No scope in the record and none on the descriptor is REFUSED.
///
/// The empty set is not neutral: `AccountService::apply` reads every scope in a
/// refresh response as broadening when the stored set is empty
/// (`service.rs:393-400`), so the grant would refuse its own first refresh.
#[test]
fn a_record_with_no_scope_against_a_descriptor_declaring_none_is_refused() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    assert_eq!(
        build(&token, None),
        Err(RecordRefusal::UndeclaredScopes),
        "nothing names the grant's scopes, and the empty set is actively harmful"
    );
}

/// POSITIVE CONTROL: the same record migrates when the descriptor declares scopes.
#[test]
fn a_record_with_no_scope_takes_the_descriptor_scopes() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    let record = build(&token, Some(&declared(&["write", "read"]))).expect("must migrate");
    assert_eq!(
        record.scopes,
        vec!["read".to_owned(), "write".to_owned()],
        "the operator already declared what this backend is authorized for, and \
         it is sorted on the way in because validate_record demands strictly \
         ascending"
    );
}

/// The record's own scopes win over the descriptor's, and are normalized.
///
/// `"write read read"` is the shape that catches both defects at once: out of
/// order, and duplicated. `validate_record` rejects either (`storage.rs:138`).
#[test]
fn record_scopes_win_over_the_descriptor_and_land_strictly_ascending() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    token.scope = Some("write read read".to_owned());
    let record = build(&token, Some(&declared(&["something-else"]))).expect("must migrate");
    assert_eq!(
        record.scopes,
        vec!["read".to_owned(), "write".to_owned()],
        "what the server actually granted beats what config declares, and the \
         duplicate is dropped rather than committed"
    );
}

/// A whitespace-only scope is ABSENT, not empty.
///
/// The distinction is the whole point: treating `"   "` as "the user granted no
/// scopes" commits the empty set the refusal above exists to prevent.
#[test]
fn a_whitespace_only_scope_falls_through_to_the_descriptor() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    token.scope = Some("   ".to_owned());
    let record = build(&token, Some(&declared(&["read"]))).expect("must migrate");
    assert_eq!(record.scopes, vec!["read".to_owned()]);

    token.scope = Some("   ".to_owned());
    assert_eq!(
        build(&token, None),
        Err(RecordRefusal::UndeclaredScopes),
        "and with nothing to fall through to, it refuses rather than committing \
         an empty set"
    );
}

/// A descriptor declaring only whitespace names no scopes either.
#[test]
fn a_descriptor_declaring_only_blank_scopes_is_refused() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    assert_eq!(
        build(&token, Some(&declared(&["", "  "]))),
        Err(RecordRefusal::UndeclaredScopes),
        "a declaration that names nothing is not a declaration"
    );
}

// ── the rest of §7.2, held to the same standard ──────────────────────────────

/// An empty access token is refused: there is nothing to migrate.
#[test]
fn a_record_with_no_access_token_is_refused() {
    let mut token = legacy("");
    token.expires_at = Some(FAR_FUTURE);
    assert_eq!(
        build(&token, Some(&declared(&["read"]))),
        Err(RecordRefusal::EmptyAccessToken)
    );
}

/// The version fields a migrated grant lands with, and why they are not copies.
///
/// A migrated grant is the FIRST revision of a NEW authorization in this store,
/// never a continuation: the commit is `Absent`-guarded, so nothing it writes
/// replaces an existing entry. `validate_record` refuses zero for both
/// (`storage.rs:136-137`), so the seeds are also the minimum legal values.
#[test]
fn a_migrated_grant_is_the_first_revision_of_a_new_authorization() {
    let mut token = legacy("live-3x-access-token");
    token.expires_at = Some(FAR_FUTURE);
    token.scope = Some("read".to_owned());
    let record = build(&token, None).expect("must migrate");
    assert_eq!(record.token_revision, 1);
    assert_eq!(record.authorization_epoch, 1);
    assert_eq!(record.generation, GENERATION);
    assert_eq!(record.descriptor_revision, revision());
    assert_eq!(
        record.provider_account_id, None,
        "the 3.x record has no field for it, and nothing may be invented"
    );
    assert_eq!(record.client_id, CLIENT);
    assert_eq!(record.token_type, "Bearer");
    assert_eq!(record.access_token, "live-3x-access-token");
}
