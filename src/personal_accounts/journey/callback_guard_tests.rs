// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The callback's admission guards that run before or beside the store: the
//! oversize cap on the secrets it carries, and a record with no owner.

use super::super::tests::{fresh, limits, maximal_record, refused};
use super::{CALLBACK_SECRET_MAX, JourneyError, JourneyRefusal, admitted, within_cap};

/// Mutant: an oversized state or binding reaches the store, or either side of
/// the cap is off by one.
#[test]
fn an_oversized_state_or_binding_is_refused_before_any_store_access() {
    let at_cap = "s".repeat(CALLBACK_SECRET_MAX);
    let over = "s".repeat(CALLBACK_SECRET_MAX + 1);
    assert!(within_cap(&at_cap, Some(&at_cap)).is_ok(), "control");
    assert!(within_cap(&at_cap, None).is_ok());
    for (state, binding) in [(&over, None), (&at_cap, Some(&over)), (&over, Some(&over))] {
        let refused = within_cap(state, binding.map(String::as_str));
        assert!(
            matches!(
                refused,
                Err(JourneyError::Refused(JourneyRefusal::InvalidRequest))
            ),
            "{refused:?}"
        );
    }
}

/// Mutant: a journey written before owners were recorded is admitted, so a
/// callback could complete it for no one in particular.
#[test]
fn a_journey_record_without_its_owner_is_not_admitted() {
    let whole = maximal_record();
    assert!(admitted("j".to_owned(), &whole).is_ok(), "control");
    let mut no_authority = maximal_record();
    no_authority.owner_authority = None;
    let mut no_subject = maximal_record();
    no_subject.owner_subject = None;
    for record in [no_authority, no_subject] {
        assert!(matches!(
            admitted("j".to_owned(), &record),
            Err(JourneyRefusal::UnknownState)
        ));
    }
}

fn is_storage<T>(result: &Result<T, JourneyError>) -> bool {
    matches!(result, Err(JourneyError::Storage(_)))
}

/// Mutant: a callback entry point drops (or runs after) its cap check. The
/// control is a short absent state, which only a store lookup refuses as
/// `UnknownState`; an oversized one must be refused as `InvalidRequest`.
#[test]
fn every_callback_entry_point_refuses_an_oversized_secret_before_the_store() {
    let (_root, _config, store) = fresh();
    let limits = limits();
    let over = "s".repeat(CALLBACK_SECRET_MAX + 1);
    let absent = "absent";
    let reached = JourneyRefusal::UnknownState;
    let capped = JourneyRefusal::InvalidRequest;

    assert_eq!(
        refused(store.callback_journey(1_000, &limits, absent)),
        reached,
        "control: a short absent state reaches the store"
    );
    assert_eq!(
        refused(store.callback_journey(1_000, &limits, &over)),
        capped
    );
    for binding in [Some("b"), None] {
        assert_eq!(
            refused(store.admit_callback(1_000, &limits, absent, binding)),
            reached,
            "control: admit reaches the store"
        );
        assert_eq!(
            refused(store.consume_callback(1_000, &limits, absent, binding)),
            reached,
            "control: consume reaches the store"
        );
        assert_eq!(
            refused(store.admit_callback(1_000, &limits, &over, binding)),
            capped
        );
        assert_eq!(
            refused(store.consume_callback(1_000, &limits, &over, binding)),
            capped
        );
    }
    let over = Some(over.as_str());
    assert_eq!(
        refused(store.admit_callback(1_000, &limits, absent, over)),
        capped
    );
    assert_eq!(
        refused(store.consume_callback(1_000, &limits, absent, over)),
        capped
    );

    // The cap runs before the table is read, not merely before it is judged:
    // on a store whose table cannot be read (a fresh one, so no slot is cached
    // yet), a short state meets the storage fault and an oversized one is still
    // refused as InvalidRequest.
    let (_root_faulted, config, store) = fresh();
    std::fs::write(
        config.authority_dir.join(super::super::JOURNEYS_FILE),
        b"{}",
    )
    .expect("plant an unreadable table");
    assert!(is_storage(&store.callback_journey(1_000, &limits, absent)));
    assert!(is_storage(
        &store.admit_callback(1_000, &limits, absent, None)
    ));
    assert!(is_storage(
        &store.consume_callback(1_000, &limits, absent, None)
    ));
    let over_str = "s".repeat(CALLBACK_SECRET_MAX + 1);
    assert_eq!(
        refused(store.callback_journey(1_000, &limits, &over_str)),
        capped
    );
    assert_eq!(
        refused(store.admit_callback(1_000, &limits, &over_str, None)),
        capped
    );
    assert_eq!(
        refused(store.consume_callback(1_000, &limits, &over_str, None)),
        capped
    );
    // MIK-7843: a short state with an oversized binding is capped on the
    // faulted table too, so the binding's cap also runs before the read.
    assert_eq!(
        refused(store.admit_callback(1_000, &limits, absent, Some(over_str.as_str()))),
        capped
    );
    assert_eq!(
        refused(store.consume_callback(1_000, &limits, absent, Some(over_str.as_str()))),
        capped
    );
}
