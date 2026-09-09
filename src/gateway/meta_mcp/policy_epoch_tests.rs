// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! CACHE.4b — a policy change must ADVANCE the epoch that keys the response
//! cache, so an answer computed under the old grants cannot be served under
//! the new ones.
//!
//! These drive the PRODUCTION key builder (`response_cache_key_for`, the same
//! function both `invoke` call sites use) against the PRODUCTION epoch field
//! and the PRODUCTION mutation site (`MetaMcp::set_identity_grants`). Hashing
//! two hand-built `KeyContext`s and comparing them would prove nothing about
//! either.
//!
//! Honest limit: the full `invoke` path is not driven, because registering a
//! backend that answers a tool call needs a live MCP transport and no test
//! harness in this repo provides one. The observable here is therefore a
//! CACHE MISS on a real `ResponseCache`, not a backend call counter.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::json;

use super::BackendRegistry;
use super::MetaMcp;
use super::support::response_cache_key_for;
use crate::cache::{KeyContext, ResponseCache};
use crate::identity_grants::LocalIdentityGrantStore;
use crate::protocol::mrtr::RetryFields;

/// Builds a cache key exactly as `invoke` does: read the epoch once into a
/// local, then hand that local to the key builder.
fn key_now(meta: &MetaMcp, retry: &RetryFields) -> String {
    let policy_epoch = meta.policy_epoch().load(Ordering::Acquire);
    response_cache_key_for(
        "srv",
        "tool",
        &json!({"a": 1}),
        "",
        Some("alice"),
        retry,
        KeyContext {
            routing_profile: "default",
            protocol_revision: None,
            policy_epoch,
        },
    )
}

#[test]
fn set_identity_grants_advances_the_epoch_so_a_pre_change_entry_cannot_be_served() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let retry = RetryFields::default();
    let cache = ResponseCache::new();

    let before = key_now(&meta, &retry);
    assert!(
        cache.set(
            &before,
            json!({"answer": "allowed"}),
            Duration::from_secs(60)
        ),
        "the pre-change answer must actually be cached, or the miss below is vacuous"
    );
    assert!(
        cache.get(&before).is_some(),
        "sanity: the entry is retrievable under the key it was stored with"
    );

    // The production mutation site. A revoked grant arrives this way.
    meta.set_identity_grants(LocalIdentityGrantStore::new());

    let after = key_now(&meta, &retry);
    assert_ne!(
        before, after,
        "a grant change must move the cache key; unchanged means the epoch never advanced"
    );
    assert!(
        cache.get(&after).is_none(),
        "CACHE.4b: a post-change reader must NOT be served the answer computed \
         under the previous grants"
    );
}

#[test]
fn the_epoch_the_accessor_hands_out_is_the_one_the_mutation_site_bumps() {
    // Guards the "two epochs" failure: a second allocation would leave the
    // criterion silently unmet with every test above still green.
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let observed = meta.policy_epoch();
    let start = observed.load(Ordering::Acquire);

    meta.set_identity_grants(LocalIdentityGrantStore::new());

    assert_eq!(
        observed.load(Ordering::Acquire),
        start + 1,
        "the Arc handed to external mutation sites must be the same allocation \
         the key builder reads"
    );
}
