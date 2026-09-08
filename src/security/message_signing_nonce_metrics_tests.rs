// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5: nonce occupancy/rejection telemetry and opaque-principal redaction.
//!
//! Every case observes what the production nonce path emits, through a recorder
//! scoped to the calling thread only — never the global one. The gauge cases are
//! about the SAME guarded state admission, reclamation and eviction hold:
//! publication has to happen inside that lock, or a reader can see an aggregate
//! a concurrent operation has already moved.
//!
//! Harness: `message_signing_nonce_metrics_support.rs`.

use super::NonceStore;
use super::nonce_metrics_support::{
    CAPACITY_REFUSAL, INVALID_REFUSAL, REPLAY_REFUSAL, assert_no_occupancy, assert_no_rejections,
    assert_occupancy, assert_refusal, assert_single_rejection, observe, principal_key,
    witness_publication_under_guard,
};
use crate::gateway::auth::{AuthenticatedClient, QuotaPrincipal, principal_of};

const OUTSIDE_GUARD: &str = "occupancy was published outside the store guard; a reader can see an \
                             aggregate a concurrent operation has already moved";

// ── Occupancy ────────────────────────────────────────────────────────────────

#[test]
fn first_admission_publishes_aggregate_occupancy_without_labels() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("occupancy-a");

    let (result, events) = observe(|| store.check_and_register_for_principal("n-1", &principal));

    result.expect("first admission");
    assert_occupancy(&events, 1);
    assert_no_rejections(&events);
}

#[test]
fn second_admission_publishes_the_new_aggregate() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("occupancy-b");
    store
        .check_and_register_for_principal("n-1", &principal)
        .expect("first admission");

    let (result, events) = observe(|| store.check_and_register_for_principal("n-2", &principal));

    result.expect("second admission");
    assert_occupancy(&events, 2);
    assert_eq!(store.len(), 2);
}

#[test]
fn expiry_cleanup_publishes_zero_occupancy() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("occupancy-c");
    for nonce in ["n-1", "n-2"] {
        store
            .check_and_register_for_principal(nonce, &principal)
            .expect("admission");
    }
    store.advance_for_test(301);

    let ((), events) = observe(|| store.evict_expired());

    assert_occupancy(&events, 0);
    assert!(store.is_empty(), "expired entries must be gone");
}

#[test]
fn admission_reclamation_publishes_the_post_reclaim_aggregate() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("occupancy-d");
    store
        .check_and_register_for_principal("old", &principal)
        .expect("first admission");
    store.advance_for_test(301);

    // The admission reclaims `old` under the same lock before inserting `new`,
    // so the only correct publication is the aggregate AFTER both.
    let (result, events) = observe(|| store.check_and_register_for_principal("new", &principal));

    result.expect("admission after expiry");
    assert_occupancy(&events, 1);
    assert_eq!(store.len(), 1);
}

// ── Bounded rejection reasons + untouched refusal shapes ─────────────────────

#[test]
fn replay_refusal_keeps_its_error_and_counts_reason_replay() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("reject-replay");
    store
        .check_and_register_for_principal("dup", &principal)
        .expect("first admission");

    let (result, events) = observe(|| store.check_and_register_for_principal("dup", &principal));

    assert_refusal(result, -32001, REPLAY_REFUSAL);
    assert_single_rejection(&events, "replay");
    assert_eq!(store.len(), 1, "a refusal must not disturb live entries");
}

#[test]
fn empty_nonce_refusal_keeps_its_error_and_counts_reason_invalid() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("reject-invalid");

    let (result, events) = observe(|| store.check_and_register_for_principal("", &principal));

    assert_refusal(result, -32602, INVALID_REFUSAL);
    assert_single_rejection(&events, "invalid");
}

#[test]
fn oversized_nonce_is_refused_as_invalid_before_the_store_is_touched() {
    let store = NonceStore::with_clock_for_test(1, 1);
    let principal = principal_key("reject-invalid-first");
    store
        .check_and_register_for_principal("fills-the-store", &principal)
        .expect("first admission");

    // The store is at both limits, so a capacity reason would also be true —
    // validation runs before the lock, so `invalid` is the only correct answer
    // and no occupancy is published at all.
    let oversized = "x".repeat(257);
    let (result, events) =
        observe(|| store.check_and_register_for_principal(&oversized, &principal));

    assert_refusal(result, -32602, INVALID_REFUSAL);
    assert_single_rejection(&events, "invalid");
    assert_no_occupancy(&events);
}

#[test]
fn per_principal_capacity_refusal_counts_reason_principal_capacity() {
    let store = NonceStore::with_clock_for_test(64, 2);
    let principal = principal_key("reject-principal-cap");
    for nonce in ["n-1", "n-2"] {
        store
            .check_and_register_for_principal(nonce, &principal)
            .expect("admission");
    }

    let (result, events) = observe(|| store.check_and_register_for_principal("n-3", &principal));

    assert_refusal(result, -32001, CAPACITY_REFUSAL);
    assert_single_rejection(&events, "principal_capacity");
    assert_eq!(store.len(), 2, "a capacity refusal must not evict");
}

#[test]
fn global_capacity_refusal_counts_reason_global_capacity() {
    let store = NonceStore::with_clock_for_test(2, 64);
    let a = principal_key("reject-global-a");
    let b = principal_key("reject-global-b");
    store
        .check_and_register_for_principal("n-1", &a)
        .expect("admission");
    store
        .check_and_register_for_principal("n-2", &b)
        .expect("admission");

    let (result, events) = observe(|| store.check_and_register_for_principal("n-3", &a));

    assert_refusal(result, -32001, CAPACITY_REFUSAL);
    assert_single_rejection(&events, "global_capacity");
}

#[test]
fn both_capacities_full_reports_global_capacity() {
    // Source order is `global || principal`; the reason must be deterministic
    // rather than whichever branch a future edit happens to evaluate first.
    let store = NonceStore::with_clock_for_test(2, 2);
    let principal = principal_key("reject-both-caps");
    for nonce in ["n-1", "n-2"] {
        store
            .check_and_register_for_principal(nonce, &principal)
            .expect("admission");
    }

    let (result, events) = observe(|| store.check_and_register_for_principal("n-3", &principal));

    assert_refusal(result, -32001, CAPACITY_REFUSAL);
    assert_single_rejection(&events, "global_capacity");
}

#[test]
fn replay_is_counted_before_capacity_when_the_store_is_full() {
    let store = NonceStore::with_clock_for_test(2, 2);
    let principal = principal_key("reject-replay-first");
    for nonce in ["n-1", "n-2"] {
        store
            .check_and_register_for_principal(nonce, &principal)
            .expect("admission");
    }

    let (result, events) = observe(|| store.check_and_register_for_principal("n-1", &principal));

    assert_refusal(result, -32001, REPLAY_REFUSAL);
    assert_single_rejection(&events, "replay");
    assert_eq!(store.len(), 2, "a replay refusal must not evict protection");
}

// ── Publication happens under the store's own guard ──────────────────────────
//
// Three witnesses, because the store publishes from three places and a hook
// wired into one of them says nothing about the other two. Each blocks a REAL
// publication in the recorder callback and probes `state.try_lock` — the same
// guard the operation holds — then releases and lets the operation finish.

#[test]
fn admission_publishes_occupancy_while_the_store_guard_is_held() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("lock-witness");

    // Warm-up first: with no occupancy gauge in production yet, this fails with
    // a semantic message instead of waiting out a gate nothing will trip.
    let (first, warmup) = observe(|| store.check_and_register_for_principal("lock-1", &principal));
    first.expect("first admission");
    assert_occupancy(&warmup, 1);

    let (admitted, witness) = witness_publication_under_guard(&store, || {
        store.check_and_register_for_principal("lock-2", &principal)
    });

    admitted.expect("second admission");
    assert!(witness.guard_held, "{OUTSIDE_GUARD}");
    assert_occupancy(&witness.events, 2);

    let (third, events) = observe(|| store.check_and_register_for_principal("lock-3", &principal));
    third.expect("third admission");
    assert_occupancy(&events, 3);
    assert_eq!(store.len(), 3, "the final gauge must agree with the length");
}

#[test]
fn eviction_publishes_occupancy_while_the_store_guard_is_held() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("evict-witness");
    let (older, warmup) = observe(|| store.check_and_register_for_principal("older", &principal));
    older.expect("first admission");
    assert_occupancy(&warmup, 1);

    // `older` ages past the 300s window; `fresh`, admitted 200s later, does not.
    store.advance_for_test(200);
    store
        .check_and_register_for_principal("fresh", &principal)
        .expect("second admission");
    store.advance_for_test(101);

    let ((), witness) = witness_publication_under_guard(&store, || store.evict_expired());

    assert!(witness.guard_held, "{OUTSIDE_GUARD}");
    assert_occupancy(&witness.events, 1);
    assert_eq!(store.len(), 1);

    // Eviction must take the expired entry and nothing else: the survivor is
    // still protecting against its own replay.
    let (replay, events) = observe(|| store.check_and_register_for_principal("fresh", &principal));
    assert_refusal(replay, -32001, REPLAY_REFUSAL);
    assert_single_rejection(&events, "replay");

    let (next, events) = observe(|| store.check_and_register_for_principal("next", &principal));
    next.expect("admission after eviction");
    assert_occupancy(&events, 2);
    assert_eq!(store.len(), 2, "the final gauge must agree with the length");
}

#[test]
fn admission_reclamation_publishes_occupancy_while_the_store_guard_is_held() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let principal = principal_key("reclaim-witness");
    let (older, warmup) = observe(|| store.check_and_register_for_principal("older", &principal));
    older.expect("first admission");
    assert_occupancy(&warmup, 1);

    store.advance_for_test(200);
    store
        .check_and_register_for_principal("fresh", &principal)
        .expect("second admission");
    store.advance_for_test(101);

    // This admission reclaims `older` and inserts `new` under ONE guard, so the
    // only aggregate a reader may end up seeing is the one after both.
    let (admitted, witness) = witness_publication_under_guard(&store, || {
        store.check_and_register_for_principal("new", &principal)
    });

    admitted.expect("admission after expiry");
    assert!(witness.guard_held, "{OUTSIDE_GUARD}");
    assert_occupancy(&witness.events, 2);
    assert_eq!(store.len(), 2);

    let (replay, events) = observe(|| store.check_and_register_for_principal("fresh", &principal));
    assert_refusal(replay, -32001, REPLAY_REFUSAL);
    assert_single_rejection(&events, "replay");

    let (next, events) = observe(|| store.check_and_register_for_principal("next", &principal));
    next.expect("admission after reclamation");
    assert_occupancy(&events, 3);
    assert_eq!(store.len(), 3, "the final gauge must agree with the length");
}

// ── Opaque principal structure and redaction ─────────────────────────────────

#[test]
fn quota_key_is_a_full_sha256_not_the_audit_fingerprint() {
    let key = QuotaPrincipal::api_key("fixture-secret")
        .as_store_key()
        .to_owned();

    assert_eq!(key.len(), 64, "quota buckets use the whole digest");
    assert!(
        key.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // The audit fingerprint is a truncated digest of the same secret. A quota
    // bucket is neither it nor an extension of it — same input, separate domain.
    let fingerprint = principal_of("fixture-secret");
    assert_ne!(key, fingerprint);
    assert!(
        !key.starts_with(&fingerprint),
        "bucket is not the audit prefix"
    );
    assert_eq!(
        key,
        QuotaPrincipal::api_key("fixture-secret").as_store_key(),
        "the same validated input must resolve to the same bucket"
    );
}

#[test]
fn quota_kinds_are_domain_separated_for_identical_bytes() {
    let same = "identical-bytes";
    let mut keys = vec![
        QuotaPrincipal::configured_bearer(same)
            .as_store_key()
            .to_owned(),
        QuotaPrincipal::api_key(same).as_store_key().to_owned(),
        QuotaPrincipal::oidc_identity(same)
            .as_store_key()
            .to_owned(),
        QuotaPrincipal::oauth_client(same).as_store_key().to_owned(),
        QuotaPrincipal::client_certificate(same.as_bytes())
            .as_store_key()
            .to_owned(),
        QuotaPrincipal::dashboard_session()
            .as_store_key()
            .to_owned(),
    ];
    let distinct = keys.len();
    keys.sort_unstable();
    keys.dedup();

    assert_eq!(
        keys.len(),
        distinct,
        "one credential's bytes must not span kinds"
    );
    // Length-prefixed components: neighbouring splits of the same bytes cannot
    // collide either.
    assert_ne!(
        QuotaPrincipal::oidc_identity("ab").as_store_key(),
        QuotaPrincipal::oidc_identity("a\u{0}b").as_store_key()
    );
}

#[test]
fn quota_principal_debug_hides_the_credential_and_its_digest() {
    let secret = "synthetic-fixture-secret";
    let principal = QuotaPrincipal::api_key(secret);
    let key = principal.as_store_key().to_owned();

    let rendered = format!("{principal:?}");

    assert_eq!(rendered, "QuotaPrincipal(<redacted>)");
    assert!(!rendered.contains(secret), "credential must not be printed");
    assert!(
        !rendered.contains(&key),
        "bucket digest must not be printed"
    );
}

#[test]
fn nonce_store_debug_hides_the_admitted_nonce_and_principal() {
    let store = NonceStore::with_clock_for_test(64, 64);
    let secret = "synthetic-debug-secret";
    let principal = principal_key(secret);
    store
        .check_and_register_for_principal("secret-nonce-value", &principal)
        .expect("admission");

    let rendered = format!("{store:?}");

    assert!(
        !rendered.contains("secret-nonce-value"),
        "nonce leaked: {rendered}"
    );
    assert!(
        !rendered.contains(&principal),
        "bucket digest leaked: {rendered}"
    );
    assert!(!rendered.contains(secret), "credential leaked: {rendered}");
    assert!(
        rendered.contains("live_entries: 1"),
        "occupancy is the safe part"
    );
}

#[test]
fn authenticated_client_debug_redacts_the_nested_quota_principal() {
    let secret = "synthetic-client-secret";
    let quota = QuotaPrincipal::api_key(secret);
    let key = quota.as_store_key().to_owned();
    let client = AuthenticatedClient {
        name: "fixture-client".to_string(),
        rate_limit: 0,
        backends: Vec::new(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: "0123456789ab".to_string(),
        quota_principal: Some(quota),
        authenticated: true,
    };

    let rendered = format!("{client:?}");

    assert!(
        rendered.contains("<redacted>"),
        "the nested quota must be redacted"
    );
    assert!(!rendered.contains(&key), "bucket digest leaked: {rendered}");
    assert!(!rendered.contains(secret), "credential leaked: {rendered}");
}
