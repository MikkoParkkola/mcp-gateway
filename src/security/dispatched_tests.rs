// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dispatch fingerprint: equal inputs match, any change does not, and
//! nothing but an exact stored value delivers.

use super::*;

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn no_rules_is_none_and_stores_as_none() {
    assert_eq!(Dispatched::of("b", &[]), Dispatched::None);
    assert_eq!(Dispatched::None.stored(), "none");
}

#[test]
fn equal_inputs_match_in_any_order_and_any_change_does_not() {
    let one = Dispatched::of("b", &pairs(&[("a", "x"), ("c", "y")]));
    assert_eq!(one, Dispatched::of("b", &pairs(&[("c", "y"), ("a", "x")])));
    for other in [
        Dispatched::of("b", &pairs(&[("a", "x2"), ("c", "y")])),
        Dispatched::of("b2", &pairs(&[("a", "x"), ("c", "y")])),
        Dispatched::of("b", &pairs(&[("a", "x")])),
        // Length framing: moving bytes between fields changes the input.
        Dispatched::of("b", &pairs(&[("a", "xc"), ("", "y")])),
    ] {
        assert_ne!(one, other, "{other:?}");
    }
    let Dispatched::Fingerprint(hex) = &one else {
        panic!("rules make a fingerprint");
    };
    assert_eq!(hex.len(), 64);
    assert!(!one.stored().contains('x'), "the value never appears");
}

#[test]
fn only_an_exact_stored_value_delivers() {
    let now = Dispatched::of("b", &pairs(&[("a", "x")]));
    assert!(delivers(Some(&now.stored()), &now));
    assert!(delivers(Some("none"), &Dispatched::None));
    assert!(
        !delivers(None, &Dispatched::None),
        "a legacy row never delivers"
    );
    assert!(!delivers(Some(MISSING), &Dispatched::None));
    assert!(
        !delivers(Some("none"), &now),
        "rules added after a none dispatch"
    );
    assert!(
        !delivers(Some(&now.stored()), &Dispatched::None),
        "rules removed"
    );
}

#[test]
fn the_widest_reservation_is_the_widest_stored_form() {
    let widest = Dispatched::of("b", &pairs(&[("a", "x")])).stored();
    assert_eq!(WIDEST.len(), widest.len());
    assert!(WIDEST.starts_with("hmac:"));
}
