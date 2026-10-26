// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The events fence binding through the REAL store: every rotation the fence
//! relies on moves it, and an ordinary token refresh does not (VFENCE.5).
//!
//! The rotations are the store's own journeys, not a hand-bumped field, so a
//! journey that only moved `token_revision` would show here as an unmoved
//! fence.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use super::{
    ALICE_TOKEN, AccountCustody, AccountKey, CustodyHandle, GrantRecord, PersonalAccountStore,
    Principal, ProviderRefreshError, RefreshProvider, SilentObserver, TokenRefresh, VaultStrategy,
    ViewBinding, block_on, custody, descriptor, identity, key_for, seed, seeded_revision,
    store_config, unexpired_grant,
};

const DRIVE: &str = "https://www.googleapis.com/auth/drive.readonly";
const GMAIL: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// Rotates every refresh to a new access token and `scopes`.
struct Rotating {
    scopes: Vec<String>,
}

impl RefreshProvider for Rotating {
    fn refresh(
        &self,
        _account: &AccountKey,
        _current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        let rotated = TokenRefresh {
            access_token: "synthetic-rotated-access-private-material-5e1c".into(),
            refresh_token: None,
            scopes: Some(self.scopes.clone()),
            token_type: "Bearer".into(),
            expires_at: u64::MAX,
        };
        async move { Ok(rotated) }
    }
}

fn alice() -> AccountKey {
    key_for(Principal::Verified(&identity()))
}

fn expired_with(scopes: &[&str]) -> GrantRecord {
    GrantRecord {
        expires_at: 1,
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        ..unexpired_grant(ALICE_TOKEN)
    }
}

fn bound(binding: ViewBinding) -> String {
    match binding {
        ViewBinding::Bound(binding) => binding,
        other => panic!("expected a bound fence, got {other:?}"),
    }
}

/// The fence and the call binding before and after one refresh by a provider
/// answering `scopes`.
fn across_refresh(seeded: &[&str], scopes: &[&str]) -> [(String, String); 2] {
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(alice(), expired_with(seeded))]);
    block_on(async {
        let custody: Arc<dyn AccountCustody> = Arc::new(
            CustodyHandle::start(
                store_config(tmp.path()),
                Rotating {
                    scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                },
                SilentObserver,
                4,
            )
            .expect("custody starts"),
        );
        let vault =
            VaultStrategy::new(Arc::clone(&custody), descriptor(), seeded_revision(), false);
        let id = identity();
        let read = || async {
            (
                bound(vault.fence_binding(Principal::Verified(&id)).await),
                bound(
                    vault
                        .view_binding_classified(Principal::Verified(&id))
                        .await,
                ),
            )
        };
        let before = read().await;
        custody
            .refresh_if_expired(&alice())
            .await
            .expect("the expired grant refreshes");
        [before, read().await]
    })
}

/// The fence as a fresh strategy over the store at `root` reads it now.
fn fence_now(root: &std::path::Path) -> ViewBinding {
    block_on(async {
        let (custody, _) = custody(root);
        VaultStrategy::new(custody, descriptor(), seeded_revision(), false)
            .fence_binding(Principal::Verified(&identity()))
            .await
    })
}

/// Apply one store journey with no custody running over the store.
fn journey(root: &std::path::Path, step: impl FnOnce(&PersonalAccountStore)) {
    let store = PersonalAccountStore::open(store_config(root)).expect("open");
    step(&store);
}

fn regrant(generation: &str) -> GrantRecord {
    GrantRecord {
        generation: generation.into(),
        ..unexpired_grant(ALICE_TOKEN)
    }
}

#[test]
fn a_plain_refresh_keeps_the_fence() {
    let [(fence_before, call_before), (fence_after, call_after)] =
        across_refresh(&[DRIVE], &[DRIVE]);
    assert_ne!(call_before, call_after, "the refresh happened");
    assert_eq!(
        fence_before, fence_after,
        "a refresh must not end a listener run"
    );
}

#[test]
fn a_narrowing_refresh_moves_the_fence() {
    let [(before, _), (after, _)] = across_refresh(&[DRIVE, GMAIL], &[DRIVE]);
    assert_ne!(before, after, "narrower scopes are a new authorization");
}

#[test]
fn a_regrant_moves_the_fence() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(alice(), unexpired_grant(ALICE_TOKEN))]);
    let before = bound(fence_now(tmp.path()));
    journey(tmp.path(), |store| {
        store
            .commit_grant(&alice(), &regrant("0123456789abcdef0123456789abcdef"))
            .expect("re-grant");
    });
    assert_ne!(before, bound(fence_now(tmp.path())));
}

#[test]
fn a_revoke_then_reconnect_moves_the_fence() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(alice(), unexpired_grant(ALICE_TOKEN))]);
    let before = bound(fence_now(tmp.path()));
    journey(tmp.path(), |store| store.revoke(&alice()).expect("revoke"));
    assert!(
        matches!(fence_now(tmp.path()), ViewBinding::NoView(_)),
        "a revoked grant fences closed"
    );
    journey(tmp.path(), |store| {
        store
            .commit_grant(&alice(), &regrant("00112233445566778899aabbccddeeff"))
            .expect("reconnect");
    });
    assert_ne!(before, bound(fence_now(tmp.path())));
}

#[test]
fn a_reconnect_required_grant_fences_closed() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(alice(), unexpired_grant(ALICE_TOKEN))]);
    journey(tmp.path(), |store| {
        store
            .mark_reconnect_required(&alice(), &"1".repeat(64))
            .expect("a descriptor move marks the grant");
    });
    assert!(matches!(fence_now(tmp.path()), ViewBinding::NoView(_)));
}

#[test]
fn the_fence_counts_no_refresh() {
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(alice(), unexpired_grant(ALICE_TOKEN))]);
    let calls: Arc<AtomicUsize> = block_on(async {
        let (custody, calls) = custody(tmp.path());
        let vault = VaultStrategy::new(custody, descriptor(), seeded_revision(), false);
        bound(vault.fence_binding(Principal::Verified(&identity())).await);
        calls
    });
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}
