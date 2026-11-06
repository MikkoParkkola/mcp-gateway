// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A keyed grant store holds each row's keyed id beside the row: the same
//! rows under the same key give the same ids, an edited row or another key
//! another id, and upsert and revoke keep the table in step.

use super::journal::grant_digest;
use super::{GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore};
use crate::security::rule_id::{RuleId, RuleKey};

fn row(grant_id: &str, reason: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::for_test("api_key", "alice", None),
        agent: GrantAgent::Any,
        capability: "cap".to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "p".to_string(),
        reason: reason.to_string(),
    }
}

/// The id a keyed store is expected to hold for `grant` under `key`.
pub(crate) fn grant_id_of(key: &RuleKey, grant: &IdentityGrant) -> RuleId {
    RuleId::of(
        "grant",
        key,
        &serde_json::to_vec(grant).expect("serialises"),
    )
}

/// `store`'s id for each of `rows`, beside the id expected under `key`.
fn ids(
    store: &LocalIdentityGrantStore,
    key: &RuleKey,
    rows: &[&IdentityGrant],
) -> (Vec<Option<RuleId>>, Vec<Option<RuleId>>) {
    let got = rows
        .iter()
        .map(|g| store.rule_id(&g.grant_id).cloned())
        .collect();
    let want = rows.iter().map(|g| Some(grant_id_of(key, g))).collect();
    (got, want)
}

fn keyed(rows: &[IdentityGrant], key: &RuleKey) -> LocalIdentityGrantStore {
    LocalIdentityGrantStore::from_grants(rows.to_vec()).with_rule_ids(key)
}

#[test]
fn grant_ids_are_keyed_and_stable_across_loads() {
    let (one, two) = (
        RuleKey::from_derived([1; 32]),
        RuleKey::from_derived([2; 32]),
    );
    let (g1, g2) = (row("g1", "r"), row("g2", "r"));
    let rows = [g1.clone(), g2.clone()];
    for load in ["first load", "second load"] {
        let (got, want) = ids(&keyed(&rows, &one), &one, &[&g1, &g2]);
        assert_eq!(got, want, "{load}: expected rule_ids {want:?}, got {got:?}");
    }
    let (got, want) = ids(&keyed(&rows, &two), &two, &[&g1, &g2]);
    assert_ne!(grant_id_of(&one, &g1), grant_id_of(&two, &g1), "premise");
    assert_eq!(
        got, want,
        "another key: expected rule_ids {want:?}, got {got:?}"
    );
    // A reason edit is a changed row: a new id for it, none for the other.
    let edited = row("g1", "edited");
    assert_ne!(
        grant_id_of(&one, &edited),
        grant_id_of(&one, &g1),
        "premise"
    );
    let store = keyed(&[edited.clone(), g2.clone()], &one);
    let (got, want) = ids(&store, &one, &[&edited, &g2]);
    assert_eq!(
        got, want,
        "edited g1: expected rule_ids {want:?}, got {got:?}"
    );
}

#[test]
fn a_keyed_grant_store_keeps_ids_in_step_through_upsert_and_revoke() {
    let key = RuleKey::from_derived([3; 32]);
    let mut store = LocalIdentityGrantStore::new().with_rule_ids(&key);
    let (g1, g2) = (row("g1", "r"), row("g2", "r"));
    store.upsert(g1.clone());
    store.upsert(g2.clone());
    let (got, want) = ids(&store, &key, &[&g1, &g2]);
    assert_eq!(
        got, want,
        "into an empty store: expected {want:?}, got {got:?}"
    );
    let replaced = row("g1", "replaced");
    store.upsert(replaced.clone());
    let (got, want) = ids(&store, &key, &[&replaced, &g2]);
    assert_eq!(got, want, "replaced g1: expected {want:?}, got {got:?}");
    let at = chrono::Utc::now();
    assert!(store.revoke("g1", at), "premise: g1 is held");
    let mut revoked = replaced;
    revoked.revoked_at = Some(at);
    let (got, want) = ids(&store, &key, &[&revoked, &g2]);
    assert_eq!(got, want, "revoked g1: expected {want:?}, got {got:?}");
}

/// Computed once from `RuleId::of` on Spark and pasted, so a change to the grant
/// row's serde form, which would rotate every grant's id, is seen.
const GOLDEN_ID: &str = "grant:3102953d0b22447af1fa5ea2789ac63601706c7b81811258bc20e762b73e563e";

#[test]
fn a_grant_rule_id_hashes_the_whole_row() {
    let key = RuleKey::from_derived([7; 32]);
    let g1 = row("g1", "r");
    assert_eq!(grant_id_of(&key, &g1).as_str(), GOLDEN_ID, "the row's id");
    let store = keyed(std::slice::from_ref(&g1), &key);
    let got = store.rule_id("g1");
    assert_eq!(
        got.map(RuleId::as_str),
        Some(GOLDEN_ID),
        "expected rule_id {GOLDEN_ID}, got {got:?}"
    );
}

#[test]
fn keying_a_grant_store_leaves_grant_digest_unchanged() {
    let rows = [row("g1", "r"), row("g2", "r")];
    let digests = |store: &LocalIdentityGrantStore| -> Vec<String> {
        store.values().map(grant_digest).collect()
    };
    let plain = LocalIdentityGrantStore::from_grants(rows.to_vec());
    let store = keyed(&rows, &RuleKey::from_derived([4; 32]));
    assert_eq!(digests(&store), digests(&plain));
}

#[test]
fn a_keyed_grant_store_debug_holds_no_key_bytes() {
    let store = keyed(&[row("g1", "r")], &RuleKey::from_derived([0xAB; 32]));
    let shown = format!("{store:?}");
    let hex = "ab".repeat(32);
    let decimal = ["171"; 32].join(", ");
    for form in [
        hex.as_str(),
        &hex.to_uppercase(),
        &decimal,
        "q6urq6urq6urq6ur",
    ] {
        assert!(!shown.contains(form), "key bytes as {form}: {shown}");
    }
}
