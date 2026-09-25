// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — what else follows once a `stateless` backend slots
//! per caller.
//!
//! The arm is one expression in `pool_key_for`; these are the consequences it
//! is supposed to carry for free, each pinned so "for free" is a test rather
//! than an argument: the cache really is per caller and really is a cache
//! (T-S2, T-S3), the retry set derived from it moves with it (T-S8), the
//! revocation path reaches the new slots on the prefix production actually
//! passes (T-S9), the key itself stays bound to the binding (T-S7), and the
//! schema mirror reads the slot the catalogue was listed from (LIST/INVOKE).
//!
//! EVERY CELL HERE USES A `stateless` FIXTURE. The original defect in this area
//! survived a complete mutation table because every fixture was `per_user`, so
//! no mutation could reach the broken arm. The fixture is the coverage.

use super::{
    ALPHA_TOOL, BETA_TOOL, PerIdentityTools, STATIC_TOOL, bind, minted, names, prefix, wired,
};
use crate::backend::PoolKey;
use std::sync::Arc;

/// GIVEN the widened `pool_key_for` arm
/// WHEN it is asked for a `stateless` backend with and without a binding, and
/// for a backend carrying no identity-propagation config at all
/// THEN only `(Some(session_mode), Some(binding))` gets a private slot.
///
/// T-S7 — THE INVERSE MISTAKE. `(Some(_), Some(binding))` is deliberately wide
/// on the session mode so no mode added later silently collapses to `Shared`.
/// The risk it creates is keying on the mode ALONE and forgetting the binding,
/// which would mint a slot named after nobody. Row 1 is the only assertion that
/// fails against that arm.
///
/// Rows 2 and 3 are the actual pinned IDP.5 surface, restated here because
/// `pool_tests.rs` sits on its file-size baseline and may not take a line:
/// ADR-007 scopes IDP.5 to ABSENT propagation config, and the executable pin
/// asserts exactly `pool_key_for(None) == Shared` and
/// `plain.pool_key_for(Some(..)) == Shared`. The widened arm moves neither.
#[test]
fn the_widened_arm_still_needs_a_binding_and_still_spares_unconfigured_backends() {
    let stateless = super::stateless_backend();

    // ROW 1 — a mode without a caller is not a slot.
    assert_eq!(
        stateless.pool_key_for(None),
        PoolKey::Shared,
        "a `stateless` backend with no resolved binding was given a private \
         slot, so the arm keys on the session mode alone and the slot is named \
         after nobody"
    );

    // ROW 2 — the arm being delivered.
    assert_eq!(
        stateless.pool_key_for(Some("alpha@ledger")),
        PoolKey::PerUser {
            binding: "alpha@ledger".to_string()
        },
        "a `stateless` backend with a resolved binding must get that caller's \
         own slot"
    );

    // ROW 3 — IDP.5 as ADR-007 scopes it: absent propagation config is
    // untouched however well the caller identifies itself.
    let plain = Arc::new(crate::backend::Backend::new(
        "plain",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(300),
    ));
    assert_eq!(
        plain.pool_key_for(Some("alpha@ledger")),
        PoolKey::Shared,
        "a backend with no identity-propagation config was slotted per caller, \
         which is the byte-for-byte single-tenant guarantee IDP.5 pins"
    );
    assert_eq!(
        plain.pool_key_for(None),
        PoolKey::Shared,
        "an unconfigured backend with no binding must stay on the shared slot"
    );
}

/// GIVEN a `stateless` backend whose upstream discriminates on the credential
/// WHEN one caller lists the same family twice
/// THEN exactly ONE fill ran, on that caller's own slot.
///
/// T-S2 — THE NEVER-CACHE DISCRIMINATOR. An implementation that fetches per
/// caller and stores nothing satisfies "beta does not see alpha's tools"
/// perfectly, and is the option ADR-007 IDP.8 names. It fails here: two reads
/// would appear as two identical keyed entries in the transcript. Compared
/// unsorted and undeduplicated, because deduplicating is precisely what would
/// hide the refetch this cell exists to catch.
#[tokio::test]
async fn a_stateless_slot_caches_so_one_caller_reading_twice_fills_once() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    let first = backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha fills its own slot");
    let second = backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha reads its own slot again");

    // THE DISCRIMINATOR, FIRST. One entry, not two.
    assert_eq!(
        wire.slots(),
        vec![Some("alpha@ledger".to_string())],
        "one caller reading twice went upstream twice, so the `stateless` \
         catalogue is refetched per read rather than cached on the caller's slot"
    );
    assert_eq!(
        names(&first),
        names(&second),
        "the second read answered a different catalogue from the first"
    );
    assert_eq!(
        names(&second),
        vec![ALPHA_TOOL.to_string()],
        "alpha was not served its own catalogue, so the single-fill assertion \
         above measures an empty answer rather than a cache"
    );
}

/// GIVEN a `stateless` backend whose upstream discriminates on the credential
/// WHEN alpha lists, beta lists, and alpha lists again
/// THEN there are exactly TWO fills and alpha still reads its own catalogue.
///
/// T-S3 — THE OVERWRITE-CACHE DISCRIMINATOR. A mechanism that keys storage
/// without moving the fetch — a binding-keyed map inside one shared slot, or a
/// single entry each caller clobbers — still answers whoever filled LAST
/// correctly. So beta's re-read proves nothing and alpha is the one who must be
/// asked again: under overwrite, alpha's third read either refetches (a third
/// transcript entry) or comes back holding beta's catalogue.
#[tokio::test]
async fn a_second_identitys_fill_does_not_evict_the_first_on_a_stateless_backend() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha fills");
    backend
        .get_tools_for_binding(Some("beta@ledger"), &minted("beta"))
        .await
        .expect("beta fills");
    let alpha_again = backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha reads again");

    // THE DISCRIMINATOR, FIRST. No third fill: alpha's entry survived beta's.
    assert_eq!(
        wire.slots(),
        vec![
            Some("alpha@ledger".to_string()),
            Some("beta@ledger".to_string()),
        ],
        "re-reading the FIRST caller after a second one filled went upstream \
         again, so one entry is being overwritten rather than one per caller"
    );
    assert_eq!(
        names(&alpha_again),
        vec![ALPHA_TOOL.to_string()],
        "after another identity filled its own slot, the first caller no longer \
         reads its own catalogue: one cache is being overwritten"
    );
    assert!(
        !names(&alpha_again).contains(&BETA_TOOL.to_string())
            && !names(&alpha_again).contains(&STATIC_TOOL.to_string()),
        "alpha's re-read returned another slot's catalogue: {:?}",
        names(&alpha_again)
    );
}

/// The set `binding`'s slot currently grants resend permission to.
fn permitted_on(backend: &crate::backend::Backend, binding: Option<&str>) -> Vec<String> {
    let key = binding.map_or(PoolKey::Shared, |b| PoolKey::PerUser {
        binding: b.to_string(),
    });
    let mut permitted: Vec<String> = backend
        .pooled_entry(&key)
        .resend_permitted
        .read()
        .iter()
        .cloned()
        .collect();
    permitted.sort_unstable();
    permitted
}

/// GIVEN a `stateless` backend whose upstream declares every tool resend-safe
/// WHEN alpha and beta each list tools
/// THEN each slot's resend set holds ONLY that caller's own tools.
///
/// T-S8 — THE FIFTH FIELD. `resend_permitted` is derived from `tools_cache`, so
/// it must live where `tools_cache` lives or it is a set coarser than its own
/// source: one identity's catalogue fill would decide another identity's retry
/// policy, and membership is the only thing that grants a `tools/call`
/// permission to be resent (ADR-012 A1). Before the arm widened both fills
/// wrote through `tools_slot(binding)` — the SHARED slot on a `stateless`
/// backend — so alpha's fill set beta's retry policy.
///
/// Sorted ONLY inside `permitted_on`, because the thing under test is a
/// `HashSet` whose iteration order is not a fact about the product. The
/// transcripts elsewhere in this file stay raw.
#[tokio::test]
async fn resend_permission_follows_the_stateless_slot_that_derived_it() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha fills");
    backend
        .get_tools_for_binding(Some("beta@ledger"), &minted("beta"))
        .await
        .expect("beta fills");

    // THE DISCRIMINATOR, FIRST. Each slot holds its own caller's set.
    assert_eq!(
        permitted_on(&backend, Some("alpha@ledger")),
        vec![ALPHA_TOOL.to_string()],
        "alpha's slot does not hold the resend set derived from alpha's own \
         catalogue, so the retry policy came off some other slot"
    );
    assert_eq!(
        permitted_on(&backend, Some("beta@ledger")),
        vec![BETA_TOOL.to_string()],
        "beta's slot inherited a resend set it never listed: one identity's \
         catalogue is deciding another identity's retry policy"
    );

    // THE SHARED SLOT NEVER SAW EITHER FILL. Absent means deny, the safe
    // direction, and it is what proves the writes were not merely duplicated
    // onto the slot every caller reads.
    assert!(
        permitted_on(&backend, None).is_empty(),
        "an identified caller's resend set was written to the SHARED slot, \
         where every caller reads it: {:?}",
        permitted_on(&backend, None)
    );
}

/// GIVEN a `stateless` backend with two identified callers' slots filled
/// WHEN a grant revocation evicts on the PRODUCTION binding prefix
/// THEN alpha's slot is removed and refills on the next read, while beta's slot
/// and transcript are untouched.
///
/// T-S9 — REVOCATION REACHES THE NEW SLOTS (C4). `evict_identity_slots` skips
/// `PoolKey::Shared`, so before the arm widened a `stateless` backend had
/// nothing for a revocation to evict and the whole path was a silent no-op.
///
/// THE PREFIX IS THE PRODUCTION ONE, and that is the point of this cell rather
/// than a detail of it. `config_reload` passes what `identity_binding_prefix`
/// builds — `idp:{len}:{subject}:` — never a test string. So the binding here
/// is DERIVED from that same function plus `cache_binding`'s audience half,
/// because restating either formula would let the two drift and pin a person
/// the gateway never authenticated.
#[tokio::test]
async fn revocation_evicts_a_stateless_backends_per_identity_slot() {
    let wire = PerIdentityTools::new();
    let backend = super::stateless_backend();
    let clone = || Arc::clone(&wire) as Arc<dyn crate::transport::Transport>;
    backend.set_transport_for_test(clone());
    for who in ["alpha", "beta"] {
        backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding: bind(who) }, clone());
    }

    backend
        .get_tools_for_binding(Some(&bind("alpha")), &minted("alpha"))
        .await
        .expect("alpha fills");
    backend
        .get_tools_for_binding(Some(&bind("beta")), &minted("beta"))
        .await
        .expect("beta fills");

    let evicted = backend.evict_identity_slots(&prefix("alpha")).await;

    // THE DISCRIMINATOR, FIRST. Beta's slot is what holds beta's catalogue and
    // the revocation named alpha, so beta's must survive it. Before the arm
    // widened neither caller's slot ever held anything — both fills landed on
    // `Shared` — so this row is empty and the whole path is a no-op.
    assert!(
        !backend
            .get_cached_tool_names_for(Some(&bind("beta")))
            .is_empty(),
        "beta's slot holds no catalogue of its own, so a revocation of alpha \
         has nothing on this backend it could have spared"
    );
    assert!(
        backend
            .get_cached_tool_names_for(Some(&bind("alpha")))
            .is_empty(),
        "the revoked identity's catalogue survived its own slot's eviction: {:?}",
        backend.get_cached_tool_names_for(Some(&bind("alpha")))
    );

    // COUNT, as corroboration only. `set_pooled_transport_for_test` creates the
    // slot it seeds, so a count of 1 holds whether or not a fill ever reached
    // it — which is why it is not the leading row.
    assert_eq!(
        evicted,
        1,
        "the revocation prefix `{}` matched no slot on a `stateless` backend",
        prefix("alpha")
    );

    // Alpha's next read must go upstream again; beta's must not.
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: bind("alpha"),
        },
        clone(),
    );
    backend
        .get_tools_for_binding(Some(&bind("alpha")), &minted("alpha"))
        .await
        .expect("alpha refills after revocation");
    backend
        .get_tools_for_binding(Some(&bind("beta")), &minted("beta"))
        .await
        .expect("beta reads its untouched slot");

    assert_eq!(
        wire.slots(),
        vec![Some(bind("alpha")), Some(bind("beta")), Some(bind("alpha"))],
        "after revocation alpha must refetch and beta must not: a third entry \
         for beta means the eviction reached past its prefix, and a missing \
         third entry for alpha means the revoked catalogue survived"
    );
}

/// GIVEN a `stateless` backend where an identified caller's slot is filled
/// WHEN the schema lookup the invoke path uses asks for that caller's tool
/// THEN it reads THIS caller's slot, not the shared one.
///
/// LIST AND INVOKE MUST NOT DISAGREE. Once `stateless` lists per caller, a
/// caller-only tool is listed from the caller's slot while the schema behind it
/// was read from the shared one — so the `Mcp-Param-*` mirror
/// (`Backend::param_header_set`), the output-schema check and the "did you
/// mean" hint all consulted a catalogue the caller was never shown. This is the
/// accessor all three route through; the two invoke-path readers take the same
/// binding `dispatch_to_backend` already carries.
#[tokio::test]
async fn the_schema_lookup_reads_the_callers_own_stateless_slot() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha fills its own slot");

    // THE DISCRIMINATOR, FIRST. Alpha's own tool is visible from alpha's slot.
    assert!(
        backend
            .get_cached_tool_for(Some("alpha@ledger"), ALPHA_TOOL)
            .is_some(),
        "a tool alpha listed is invisible to the schema lookup on alpha's own \
         slot, so every mirror and schema check for alpha reads a catalogue \
         alpha was never shown: {:?}",
        backend.get_cached_tool_names_for(Some("alpha@ledger"))
    );
    assert_eq!(
        backend.get_cached_tool_names_for(Some("alpha@ledger")),
        vec![ALPHA_TOOL.to_string()],
        "alpha's slot holds a catalogue that is not alpha's"
    );

    // AND THE SHARED SLOT STAYS EMPTY, which is what makes the row above a
    // statement about WHICH slot was read rather than about a warm cache.
    assert!(
        backend.get_cached_tool_for(None, ALPHA_TOOL).is_none(),
        "alpha's private tool is readable from the shared slot, where every \
         caller reads it: {:?}",
        backend.get_cached_tool_names_for(None)
    );
    assert!(
        backend.get_cached_tool_names_for(None).is_empty(),
        "the shared slot was filled by an identified caller's read: {:?}",
        backend.get_cached_tool_names_for(None)
    );
}
