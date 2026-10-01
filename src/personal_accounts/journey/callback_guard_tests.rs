// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The callback's admission guards that run before or beside the store: the
//! oversize cap on the secrets it carries, and a record with no owner.

use super::{CALLBACK_SECRET_MAX, JourneyError, JourneyRefusal, admitted, within_cap};
use crate::personal_accounts::journey::tests::maximal_record;

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
