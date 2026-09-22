// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — the `stateless` cells that need the families fixture.
//!
//! Own file because `catalogue_families_per_caller_tests.rs` would cross the
//! 800-line ceiling, and declared from inside it with `#[path]` rather than
//! from `meta_mcp::mod` so `super::` reaches its fixture: `stateless_gateway`,
//! `listed_for`, `serves` and `identity` are private to that module, and a
//! sibling declared anywhere else could not see them. An undeclared
//! `*_tests.rs` is invisible to `cargo test`, to coverage and to grep, which
//! has bitten this criterion before.

use super::{ALPHA_ITEM, BETA_ITEM, FAMILIES, STATIC_ITEM, identity, listed_for, serves};

/// GIVEN a `stateless` backend with identity propagation configured
/// WHEN a caller with NO verified identity lists each family
/// THEN the fill runs unkeyed on the shared slot with empty headers, and the
/// caller is served the static-credential catalogue.
///
/// T-S5 — THE ANONYMOUS CONTROL, ON ITS OWN CALLER. Without it, T-S1 can be
/// bought by dropping the identity-free shared path entirely: every absence
/// assertion there passes against a gateway that stopped answering
/// unidentified callers, which is the failure the prior design's T6 exists to
/// catch and is what ADR-007 scopes IDP.5 to.
///
/// ITS OWN GATEWAY, DELIBERATELY. An earlier draft cited the identified alpha's
/// `STATIC_ITEM` rows for this — the very rows T-S1 inverts — so the control
/// and the case under test were the same caller and the control proved nothing.
#[tokio::test]
async fn an_unidentified_caller_still_reads_a_stateless_backends_shared_slot() {
    for method in FAMILIES {
        let (meta, wire) = super::stateless_gateway();

        let anonymous = listed_for(&meta, method, None).await;

        // THE DISCRIMINATOR, FIRST. One fill, unkeyed, with no headers at all.
        assert_eq!(
            wire.fills_for(method),
            vec![None],
            "{method}: an identity-free caller did not fill the shared slot, so \
             the single-tenant path IDP.5 pins has moved"
        );
        assert_eq!(
            wire.headers_for(method),
            vec![Vec::<(String, String)>::new()],
            "{method}: the identity-free fill carried headers it has no caller \
             to have minted"
        );

        // ANTI-VACUITY. It really was answered, and with the gateway's own
        // catalogue rather than somebody's private one.
        assert!(
            serves(&anonymous, STATIC_ITEM),
            "{method}: the identity-free caller lost the static-credential \
             catalogue, so isolation was bought by blanking the shared path: \
             {anonymous:?}"
        );
        assert!(
            !serves(&anonymous, ALPHA_ITEM) && !serves(&anonymous, BETA_ITEM),
            "{method}: an unidentified caller was served an identity's private \
             catalogue: {anonymous:?}"
        );
    }
}

/// GIVEN a `stateless` backend serving a different catalogue per credential
/// WHEN alpha lists, beta lists, and alpha lists again
/// THEN there are exactly TWO fills and alpha still reads its own catalogue.
///
/// T-S2 AND T-S3 IN ONE PASS — the two mutants the brief requires every cell to
/// survive. Under **never-cache** the third read appears as a third transcript
/// entry. Under **overwrite-cache** — a binding-keyed map inside one shared
/// slot, or one entry each caller clobbers — whoever filled LAST is still
/// answered correctly, so beta's re-read would prove nothing and alpha is the
/// one who must be asked again: alpha either refetches or comes back holding
/// beta's catalogue.
#[tokio::test]
async fn a_stateless_catalogue_is_cached_per_caller_and_not_overwritten() {
    let alpha_id = identity("alpha");
    let beta_id = identity("beta");

    for method in FAMILIES {
        let (meta, wire) = super::stateless_gateway();

        listed_for(&meta, method, Some(&alpha_id)).await;
        listed_for(&meta, method, Some(&beta_id)).await;
        let alpha_again = listed_for(&meta, method, Some(&alpha_id)).await;

        // THE DISCRIMINATOR, FIRST. Three reads, two fills.
        assert_eq!(
            wire.fills_for(method),
            vec![
                Some("alpha@ledger".to_string()),
                Some("beta@ledger".to_string()),
            ],
            "{method}: re-reading the FIRST caller after a second one filled \
             went upstream again, so the `stateless` catalogue is refetched per \
             read rather than cached on each caller's own slot"
        );
        assert!(
            serves(&alpha_again, ALPHA_ITEM),
            "{method}: after another identity filled its own slot, the first \
             caller no longer reads its own catalogue — one cache is being \
             overwritten rather than one cache per caller: {alpha_again:?}"
        );
        assert!(
            !serves(&alpha_again, BETA_ITEM) && !serves(&alpha_again, STATIC_ITEM),
            "{method}: alpha's re-read returned another slot's catalogue: \
             {alpha_again:?}"
        );
    }
}
