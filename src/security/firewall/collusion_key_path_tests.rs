// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8209` K1: the per-key-path join rule, row by row.

use serde_json::json;

use super::key_path_joins;

#[test]
fn content_items_join_their_text_path_only() {
    let value = json!({"content": [
        {"type": "text", "text": "ab"},
        {"type": "text", "text": "cd"},
    ]});
    assert_eq!(key_path_joins(&value), vec!["abcd", "texttext"]);
}

#[test]
fn a_missing_key_or_non_string_value_ends_a_run() {
    let value = json!({"parts": [
        {"part": "a"}, {"part": "b"}, {"other": "x"},
        {"part": "c"}, {"part": 7}, {"part": "d"}, {"part": "e"},
    ]});
    assert_eq!(key_path_joins(&value), vec!["ab", "de"]);
}

#[test]
fn an_array_of_strings_is_left_to_the_all_values_form() {
    assert!(key_path_joins(&json!({"list": ["a", "b", "c"]})).is_empty());
    assert!(key_path_joins(&json!(["a", "b"])).is_empty());
}

#[test]
fn nested_objects_are_paths_and_nested_arrays_are_their_own() {
    let value = json!({"rows": [
        {"cell": {"v": "a"}, "inner": [{"w": "x"}, {"w": "y"}]},
        {"cell": {"v": "b"}, "inner": [{"w": "z"}, {"w": "q"}]},
    ]});
    // The outer array joins `cell.v`; each inner array joins only itself.
    assert_eq!(key_path_joins(&value), vec!["ab", "xy", "zq"]);
}

#[test]
fn keys_order_as_key_sequences_and_the_gateway_slot_is_skipped() {
    let value = json!({
        "_context_integrity": {"items": [{"a": "1"}, {"a": "2"}]},
        "items": [
            {"a.b": "p", "a": {"b": "r"}},
            {"a.b": "q", "a": {"b": "s"}},
        ],
    });
    // ["a", "b"] sorts before ["a.b"].
    assert_eq!(key_path_joins(&value), vec!["rs", "pq"]);
}

/// gpt impl HIGH: a sparse array (every element a distinct key) costs its
/// leaves, not paths x elements. Counted, not timed: the walk visits each
/// object entry once, so 20,000 elements cost about 20,000 visits; the
/// quadratic walk would visit about 4e8.
#[test]
fn a_sparse_array_is_walked_in_linear_work() {
    let rows: Vec<serde_json::Value> = (0..20_000)
        .map(|i| json!({ format!("p{i:05}"): "x" }))
        .collect();
    let value = json!({ "rows": rows });
    super::VISITS.with(|v| v.set(0));
    assert!(key_path_joins(&value).is_empty());
    let visits = super::VISITS.with(std::cell::Cell::get);
    assert!(visits <= 2 * 20_000, "{visits} visits for 20,000 leaves");
}

mod digest {
    //! `MIK-8209` K2/K2a: how a digest carries its joins.
    use super::super::super::{Delivered, DeliveryDigest, Joins};
    use crate::security::firewall::collusion::{CollusionDetector, RelayParams};

    const LEAF: &str = "a leaf long enough to carry several k-grams of its own text";
    const JOIN: &str = "QUIRKY ZEBRAS VAULT OVER NINE MOSSY FJORDS EACH WINTER DAWN";

    fn detector() -> CollusionDetector {
        let mut detector = CollusionDetector::new(RelayParams::default());
        detector.keep_every_kgram();
        detector
    }

    /// Segment forms, then retained, then joins, so the per-delivery bound
    /// keeps leaf evidence first.
    #[test]
    fn fingerprints_order_is_segments_retained_joins() {
        let detector = detector();
        let (mut digest, _) = DeliveryDigest::of_leaves(&[LEAF], false);
        digest.retained = vec![42];
        let (digest, cut) = digest.with_joins(vec![JOIN.to_owned()]);
        assert!(!cut, "premise: the join fits its budget");
        let fps = digest.fingerprints(&detector);
        let at = |fp: u64| fps.iter().position(|f| *f == fp).expect("present");
        let retained = at(42);
        assert!(
            detector
                .fingerprints(LEAF)
                .iter()
                .all(|f| at(*f) < retained)
        );
        assert!(
            detector
                .fingerprints(JOIN)
                .iter()
                .all(|f| at(*f) > retained)
        );
    }

    /// `capped()` carries the join slot over: staged runs become their text.
    #[test]
    fn capped_carries_the_join_slot() {
        let (p1, p2) = ("first piece ", "second piece");
        let (staged, _) = DeliveryDigest::of_plan_step_leaves(&[p1, "kind", p2], false);
        let staged = staged.with_join_runs(vec![vec![0, 2].into()]);
        let (capped, _) = staged.capped().expect("deferred");
        match capped.joins {
            Joins::Text(joins) => assert_eq!(&*joins, &[format!("{p1}{p2}")]),
            _ => panic!("the join slot was dropped"),
        }
    }

    /// Retention leaves only fingerprints in the join slot (never runs or
    /// text), and keeps the join's fingerprints when its pieces were delivered.
    #[test]
    fn retention_leaves_only_join_fingerprints() {
        let detector = detector();
        let (p1, p2) = (
            "abcdefghijklmnopqrstuvwxyz0123",
            "456789ABCDEFGHIJKLMNOPQRSTUV",
        );
        let (staged, _) = DeliveryDigest::of_plan_step_leaves(&[p1, "kind", p2], false);
        let staged = staged.with_join_runs(vec![vec![0, 2].into()]);
        let delivered = Delivered::of_leaves(vec![p1, "kind", p2]).expect("bounded");
        let kept = staged.retaining_for(&detector, &delivered, None);
        assert!(
            matches!(kept.joins, Joins::Fps(_)),
            "the slot is not fingerprints"
        );
        let fps = kept.fingerprints(&detector);
        let join = detector.fingerprints(&format!("{p1}{p2}"));
        assert!(join.iter().all(|f| fps.contains(f)), "the join was lost");
    }

    /// gpt impl CRITICAL: a non-deferred receipt whose capped leaves all
    /// survive in the answer still drops a join the answer no longer carries.
    /// The cap kept only the head and tail leaves; the answer dropped the
    /// rows, so their join is not delivered text and must not excuse.
    #[test]
    fn a_join_the_answer_dropped_is_not_kept() {
        let detector = detector();
        let (head, tail) = ("A".repeat(3_071), "Z".repeat(3_071));
        let parts = ["a".repeat(32), "b".repeat(32), "c".repeat(32)];
        let mut leaves: Vec<&str> = vec![head.as_str()];
        leaves.extend(parts.iter().map(String::as_str));
        leaves.push(tail.as_str());
        let (capped, cut) = DeliveryDigest::of_leaves(&leaves, false);
        assert!(cut, "premise: the cap dropped the middle");
        let (digest, _) = capped.with_joins(vec![parts.concat()]);
        let delivered = Delivered::of_leaves(vec![head.as_str(), tail.as_str()]).expect("bounded");
        let kept = digest.retaining_for(&detector, &delivered, None);
        let fps = kept.fingerprints(&detector);
        let join = detector.fingerprints(&parts.concat());
        assert!(!join.is_empty(), "premise: the join holds k-grams");
        assert!(
            join.iter().all(|f| !fps.contains(f)),
            "an undelivered join was kept"
        );
    }
}
