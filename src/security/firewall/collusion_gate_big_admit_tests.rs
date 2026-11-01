// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A plan admits oversized steps' attachments until its room is full.

use super::*;

/// Oversized steps staged for alice until one is refused attachments, with
/// `preseed` live sketches of alice's from `SOURCE` first. N is read from
/// the charges, then checked against both sides: every admitted step fit
/// the plan's 4 MiB, the refused one met less room than one step's
/// attachments, the store's pending bytes are exactly the attachment bytes
/// the plan charged, and the N pending positions follow the live ones.
fn admit_until_full(preseed: usize) {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    for seed in 0..preseed {
        deliver(&fw, "alice", &filler(900 + seed as u64, 20 * 1024));
    }
    assert_eq!(
        detector.sketch_positions(SOURCE, "alice"),
        (0..preseed).collect::<Vec<_>>(),
        "premise: the live sketches hold the first positions"
    );
    let bytes_before = detector.sketch_bytes_held();
    let cap = 4 * super::super::super::DELIVERED_SET_CAP;
    let staged = crate::security::firewall::PlanStaging::default();
    staged.set_caller("alice");
    let mut attachments = Vec::new();
    // Held: a dropped receipt abandons its reservation.
    let mut held = Vec::new();
    let room_at_refusal = loop {
        assert!(
            attachments.len() < 20,
            "attachments were never refused room"
        );
        let (base, total) = (staged.baseline(), staged.total());
        let seed = 20 + attachments.len() as u64;
        held.push(
            fw.receipt_digest("alpha", "read", &oversized_step(seed), Some(&staged))
                .expect("staged"),
        );
        let receipt = staged.baseline() - base;
        let attached = staged.total() - total - receipt;
        if attached == 0 {
            break cap.saturating_sub(total.saturating_add(receipt));
        }
        assert!(
            total + receipt + attached <= cap,
            "a step was admitted past the plan's room"
        );
        attachments.push(attached);
    };
    let admitted = attachments.len();
    assert!(admitted >= 1, "no oversized step was given attachments");
    let largest = attachments.iter().copied().max().unwrap_or(0);
    assert!(
        room_at_refusal < largest + largest / 10,
        "a step was refused with room for its attachments ({room_at_refusal} left)"
    );
    assert!(
        detector.excuse_lost(SOURCE, "alice"),
        "the skipped step was not marked"
    );
    // The admissions, derived from the fixture alone: each step's receipt
    // and attachments by the sizing rules, its leaf hashes from its leaf
    // count, replayed against the plan's 4 MiB as the plan charges them.
    let leaf_hash_bytes = usize::try_from(STEP_LEAVES).expect("small") * 8;
    let mut derived = 0usize;
    let mut total = 0usize;
    loop {
        let step = oversized_step(20 + derived as u64);
        let (receipt, attachment) = fw.sized_step(&step, preseed + derived, total);
        total += receipt;
        if attachment > cap.saturating_sub(total) {
            break;
        }
        total += attachment;
        if total + leaf_hash_bytes <= cap {
            total += leaf_hash_bytes;
        }
        derived += 1;
    }
    assert_eq!(derived, 5, "premise: the fixture derives five admissions");
    assert_eq!(
        admitted, derived,
        "admissions differ from the fixture's derivation"
    );
    // A step's leaf hashes are charged to the plan total but
    // held beside the receipt, never in the sketch store.
    assert_eq!(
        detector.sketch_bytes_held() - bytes_before,
        attachments.iter().sum::<usize>() - admitted * leaf_hash_bytes,
        "the store's pending bytes differ from the plan's attachment charges"
    );
    assert_eq!(
        detector.sketch_positions(SOURCE, "alice"),
        (0..preseed + admitted).collect::<Vec<_>>(),
        "one pending position per admitted step, after the live ones"
    );
}

/// Oversized steps of one plan are admitted with
/// attachments while the plan's room allows; the first that does not fit
/// is skipped and marked.
#[test]
fn a_plan_admits_attachments_until_full_then_skips_and_marks() {
    admit_until_full(0);
}

/// A staged big step whose leaf hashes do not fit
/// the plan's remaining room keeps none and is marked lost, the safe
/// direction (no hashes, no subset seam, a lost-room refusal). The plan
/// starts where the step's receipt and attachments fit but its 100,000 leaf
/// hashes (800 KB) do not: both sizes derived from the fixture by the sizing
/// rules. Inverted mutant m17b (skipped step keeps its hashes, not marked).
#[test]
fn a_step_whose_leaf_hashes_do_not_fit_keeps_none_and_is_marked_lost() {
    let fw = firewall();
    let detector = fw.collusion_detector().expect("relay detection on");
    let leaves: Vec<String> = (0..100_000).map(|i| format!("leaf{i:011}")).collect();
    let step = json!({ "parts": leaves });
    let cap = 4 * super::super::super::DELIVERED_SET_CAP;
    let bound = super::super::super::DELIVERED_SET_CAP;
    let (receipt, attachment) = fw.sized_step(&step, 0, bound);
    let hashes = leaves.len() * 8;
    // Room for the receipt, the attachments and half the hashes.
    let start = cap - receipt - attachment - hashes / 2;
    assert!(
        start >= bound,
        "premise: the plan starts past the bound ({start})"
    );
    let staged = crate::security::firewall::PlanStaging::starting_at(start);
    staged.set_caller("alice");
    let digest = fw
        .receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("staged");
    assert!(
        digest.is_staged_step(),
        "premise: the step was admitted with attachments"
    );
    assert!(
        staged.total() <= cap,
        "the plan total passed its cap ({} > {cap})",
        staged.total()
    );
    let hash = fw.leaf_hash(&leaves[0]).expect("relay detection on");
    assert!(
        !digest.holds_leaf_hash(hash),
        "a step whose leaf hashes did not fit kept them"
    );
    assert!(
        detector.excuse_lost(SOURCE, "alice"),
        "a step skipped for leaf-hash room was not marked lost"
    );
}

/// With two live sketches already held, the
/// pending positions shift past them and N is still read from the charges.
#[test]
fn a_plan_beside_live_sketches_admits_at_shifted_positions() {
    admit_until_full(2);
}
