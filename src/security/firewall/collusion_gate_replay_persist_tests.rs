// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The persisted replay snapshot (MIK-9379): a round trip records what the
//! in-memory entry recorded (E3 equivalence), text the stored result does
//! not deliver is never persisted (K27, K20a), another epoch is untrackable
//! (K26a), and two reads that both find nothing leave one entry (K16).

use std::time::Duration;

use serde_json::{Value, json};

use super::super::super::collusion::replay::{StoredKey, TestLife};
use super::super::super::collusion_digest::DeliveryDigest;
use super::super::{CollusionAction, CollusionConfig};
use super::{Adopted, SNAPSHOT_UNTRACKABLE};
use crate::security::firewall::{Firewall, FirewallConfig};

const ANSWER: &str = "the orchard ledger lists every rootstock and the grafting dates for each";
const CANARY: &str = "canaryjoinZQX";

fn firewall(action: CollusionAction) -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action,
            window_secs: 1,
            min_matches: 1,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None).keeping_every_kgram()
}

/// A digest of one delivered value leaf, `text`, with a key-path join.
fn digest(text: &str) -> DeliveryDigest {
    let (digest, _) = DeliveryDigest::of_parts(&[text], 1, false);
    digest.with_joins(vec![CANARY.to_owned()]).0
}

fn key(id: &str) -> StoredKey {
    StoredKey::Task {
        id: id.to_owned(),
        revision: 2,
    }
}

fn persisted(fw: &Firewall, digest: &DeliveryDigest, stored: &Value) -> Option<Value> {
    fw.persisted_replay(
        &[(digest, Some(1), "alpha", "read")],
        &vec![(Some(1), "alpha".to_owned(), "read".to_owned())],
        "digest-of-answer",
        stored,
    )
}

fn hour() -> Duration {
    Duration::from_secs(3600)
}

/// E3 equivalence: the entry rebuilt from the persisted form records the
/// same fingerprints as the digest it was made from, joins included.
#[test]
fn a_round_trip_records_what_the_digest_recorded() {
    let fw = firewall(CollusionAction::Block);
    let detector = fw.relay_detector().expect("relay detection on: fixture");
    let original = digest(ANSWER);
    let value = persisted(&fw, &original, &json!(ANSWER)).expect("a snapshot");
    assert_ne!(value, json!(SNAPSHOT_UNTRACKABLE), "premise: kept");
    let Adopted::Held(digests, calls, handle) = fw.adopt_replay(&key("t1"), Some(&value), hour())
    else {
        panic!("the snapshot is adopted");
    };
    assert!(
        handle.is_some(),
        "a rebuilt entry is pending, held by the read"
    );
    assert_eq!(calls.len(), 1);
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].answer_digest, "digest-of-answer");
    assert_eq!(
        digests[0].digest.fingerprints(detector),
        original.fingerprints(detector),
        "the rebuilt digest records other fingerprints"
    );
}

/// K27 and K20a: a segment the stored result does not deliver makes the
/// row hold the marker; a kept snapshot holds no join text.
#[test]
fn text_the_stored_result_lacks_is_never_persisted() {
    let fw = firewall(CollusionAction::Block);
    let value = persisted(
        &fw,
        &digest(ANSWER),
        &json!("a different stored answer entirely"),
    );
    assert_eq!(value, Some(json!(SNAPSHOT_UNTRACKABLE)));
    let kept = persisted(&fw, &digest(ANSWER), &json!(ANSWER)).expect("a snapshot");
    assert!(
        !kept.to_string().contains(CANARY),
        "the join's text was persisted: {kept}"
    );
}

/// K26a: a snapshot made under another epoch is untrackable and inserts
/// nothing; so is a form this process cannot read, and the marker.
#[test]
fn another_epoch_is_untrackable() {
    let fw = firewall(CollusionAction::Block);
    let mut value = persisted(&fw, &digest(ANSWER), &json!(ANSWER)).expect("a snapshot");
    let epoch = value["epoch"].as_u64().expect("an epoch");
    value["epoch"] = json!(epoch.wrapping_add(1));
    assert!(matches!(
        fw.adopt_replay(&key("t2"), Some(&value), hour()),
        Adopted::Untrackable
    ));
    for other in [json!(SNAPSHOT_UNTRACKABLE), json!({"epoch": epoch})] {
        assert!(
            matches!(
                fw.adopt_replay(&key("t2"), Some(&other), hour()),
                Adopted::Untrackable
            ),
            "{other}"
        );
    }
    assert_eq!(fw.replay_entries_for_test(), 0, "nothing was inserted");
    assert!(matches!(
        fw.adopt_replay(&key("t2"), None, hour()),
        Adopted::NoSnapshot
    ));
}

/// K16: two reads that both find no entry leave exactly one, pending with
/// both deliveries outstanding.
#[test]
fn two_reads_that_find_nothing_leave_one_entry() {
    let fw = std::sync::Arc::new(firewall(CollusionAction::Block));
    let value = persisted(&fw, &digest(ANSWER), &json!(ANSWER)).expect("a snapshot");
    let barrier = std::sync::Barrier::new(2);
    let handles: Vec<_> = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    match fw.adopt_replay(&key("t3"), Some(&value), hour()) {
                        Adopted::Held(_, _, handle) => handle,
                        _ => panic!("adopted"),
                    }
                })
            })
            .collect();
        threads.into_iter().map(|t| t.join().unwrap()).collect()
    });
    assert_eq!(fw.replay_entries_for_test(), 1);
    assert!(handles.iter().all(Option::is_some), "both reads hold it");
    assert_eq!(
        fw.relay.replay.life_for_test(&key("t3")),
        TestLife::Pending {
            outstanding: 2,
            delivered_off: false
        }
    );
}

/// The store writes the firewall's marker text.
#[test]
fn the_store_and_the_firewall_share_the_marker() {
    assert_eq!(
        SNAPSHOT_UNTRACKABLE,
        crate::gateway::task_service::SNAPSHOT_UNTRACKABLE
    );
}
