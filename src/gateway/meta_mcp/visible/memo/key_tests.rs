// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498.VISIBLE.1b hash-agreement guard: a borrowed `dyn Pair` lookup
//! only finds its owned key if the two hash alike and compare alike, so a
//! disagreement would make reads silently miss. These rows pin that
//! agreement before any map trusts it.
//!
//! Mutants these rows kill:
//!
//! - Hash the pair with a separator (in `dyn Pair`'s `Hash` only): the
//!   borrowed hash would differ from both owned hashes, killed by the
//!   three-way hash equality in `borrowed_and_owned_keys_hash_alike`.
//! - Hash in reverse order: the same row, on pairs whose halves differ
//!   (the ordinary, asymmetric, empty-half and prefix-ambiguous ones), and
//!   the `pair()` equality there against a half-swapping `pair()`.
//! - Compare only the first half: `distinct_pairs_compare_unequal`'s
//!   `("same", "x")` versus `("same", "y")` row, and the real-map rows,
//!   where such a compare would return the other entry.

use super::{
    AccountSlot, DescriptorId, Keyed, Pair, TargetKey, account_slot, slot, target, target_key,
};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};

/// Ordinary, asymmetric, empty-half, Unicode and prefix-ambiguous pairs.
const PAIRS: &[(&str, &str)] = &[
    ("alpha", "read"),
    ("ab", "c"),
    ("a", "bc"),
    ("", "x"),
    ("x", ""),
    ("", ""),
    ("ñ", "日本"),
    ("pre", "fix-x"),
    ("prefix", "-x"),
    ("same", "x"),
    ("same", "y"),
];

/// Two borrowed pairs set against one another for inequality.
type PairVersus = ((&'static str, &'static str), (&'static str, &'static str));

fn hash_of<T: Hash + ?Sized>(state: &RandomState, value: &T) -> u64 {
    state.hash_one(value)
}

#[test]
fn borrowed_and_owned_keys_hash_alike() {
    // One state, reused: each hasher built from it shares its keys, so
    // the hashes below are comparable with one another.
    let state = RandomState::new();
    for &(first, second) in PAIRS {
        let owned_target: TargetKey = target_key(first, second);
        let account = DescriptorId(second.to_owned());
        let owned_slot: AccountSlot = account_slot(first, &account);
        let borrowed = target(first, second);
        let target_dyn: &dyn Pair = &owned_target;
        let slot_dyn: &dyn Pair = &owned_slot;
        let borrowed_dyn: &dyn Pair = &borrowed;
        assert_eq!(
            target_dyn.pair(),
            (first, second),
            "a target key's pair is its text, in order: ({first:?}, {second:?})"
        );
        assert_eq!(
            slot_dyn.pair(),
            (first, second),
            "an account slot's pair is its text, in order: ({first:?}, {second:?})"
        );
        assert_eq!(
            borrowed_dyn.pair(),
            (first, second),
            "the borrowed pair is its text, in order: ({first:?}, {second:?})"
        );
        assert_eq!(
            hash_of(&state, &owned_target),
            hash_of(&state, &owned_slot),
            "the owned keys hash alike: ({first:?}, {second:?})"
        );
        assert_eq!(
            hash_of(&state, &owned_target),
            hash_of(&state, target_dyn),
            "the target key and its borrow hash alike: ({first:?}, {second:?})"
        );
        assert_eq!(
            hash_of(&state, &owned_target),
            hash_of(&state, slot_dyn),
            "the slot key and its borrow hash alike: ({first:?}, {second:?})"
        );
        assert_eq!(
            hash_of(&state, &owned_target),
            hash_of(&state, borrowed_dyn),
            "the owned and borrowed keys hash alike: ({first:?}, {second:?})"
        );
        assert!(
            target_dyn == slot_dyn,
            "the owned keys compare equal: ({first:?}, {second:?})"
        );
        assert!(
            target_dyn == borrowed_dyn,
            "the owned and borrowed keys compare equal: ({first:?}, {second:?})"
        );
        assert!(
            slot_dyn == borrowed_dyn,
            "the slot and the borrowed key compare equal: ({first:?}, {second:?})"
        );
    }
}

#[test]
fn distinct_pairs_compare_unequal() {
    // Asymmetric and prefix-ambiguous pairs (same text, split differently),
    // pairs differing only in the second half (the compare-only-the-first
    // mutant), pairs differing only in the first, and the empty halves.
    let distinct: &[PairVersus] = &[
        (("ab", "c"), ("a", "bc")),
        (("pre", "fix-x"), ("prefix", "-x")),
        (("same", "x"), ("same", "y")),
        (("x", "same"), ("y", "same")),
        (("", "x"), ("x", "")),
    ];
    for &(left, right) in distinct {
        let left_dyn: &dyn Pair = &left;
        let right_dyn: &dyn Pair = &right;
        assert!(
            left_dyn != right_dyn,
            "distinct pairs compare unequal: {left:?} and {right:?}"
        );
        let left_owned: TargetKey = target_key(left.0, left.1);
        let right_owned: TargetKey = target_key(right.0, right.1);
        let left_owned_dyn: &dyn Pair = &left_owned;
        let right_owned_dyn: &dyn Pair = &right_owned;
        assert!(
            left_owned_dyn != right_owned_dyn,
            "distinct owned keys compare unequal: {left:?} and {right:?}"
        );
        assert!(
            left_owned_dyn != right_dyn,
            "an owned key and a distinct borrow compare unequal: {left:?} and {right:?}"
        );
    }
}

#[test]
fn borrowed_lookups_find_owned_keys_in_keyed_maps() {
    // Distinct values per pair: a lookup that found a neighbouring entry
    // (the asymmetric or prefix-ambiguous one) would answer its value.
    let targets: Keyed<TargetKey, i32> = Keyed::default();
    let slots: Keyed<AccountSlot, i32> = Keyed::default();
    let mut value = 0;
    for &(first, second) in PAIRS {
        value += 1;
        targets.set(target_key(first, second), value);
        let account = DescriptorId(second.to_owned());
        slots.set(account_slot(first, &account), value);
    }
    let mut expected = 0;
    for &(first, second) in PAIRS {
        expected += 1;
        assert_eq!(
            targets.get(&target(first, second) as &(dyn Pair + '_)),
            Some(expected),
            "a borrowed lookup finds its own target entry: ({first:?}, {second:?})"
        );
        let account = DescriptorId(second.to_owned());
        assert_eq!(
            slots.get(&slot(first, &account) as &(dyn Pair + '_)),
            Some(expected),
            "a borrowed lookup finds its own slot entry: ({first:?}, {second:?})"
        );
    }
    assert_eq!(
        targets.get(&target("ab", "bc") as &(dyn Pair + '_)),
        None,
        "no entry is held under a split neither asymmetric key uses"
    );
    let missing = DescriptorId("missing".to_owned());
    assert_eq!(
        slots.get(&slot("alpha", &missing) as &(dyn Pair + '_)),
        None,
        "no entry is held under an unrecorded account"
    );
}
