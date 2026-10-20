// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8408` stage 1 unit rows: the replay snapshot, the fresh replay
//! digest and the process-local store's budgets, keys and expiry. Each
//! row names the mutant it kills.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::json;

use super::super::collusion_digest::{DeliveryDigest, Judged, ReplayReceipt};
use super::super::collusion_gate::{CollusionAction, CollusionConfig, RelayCaller};
use super::big::KeptStep;
use super::replay::{ReplayReceipts, StoredKey};
use crate::security::firewall::{Firewall, FirewallConfig, FirewallVerdict, PlanStaging};

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

/// An observing firewall with a 1 s relay window and every k-gram kept, so
/// a row ages receipts with the frozen clock and never depends on the
/// per-process hash key's sample (the gate tests' `observing` shape).
fn firewall() -> Firewall {
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Observe,
            window_secs: 1,
            min_matches: 1,
            sources: vec!["alpha:*".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Firewall::from_config(config, None).keeping_every_kgram()
}

/// An egress through `alpha:send` carrying [`PROSE`], sent by `who`.
fn egress(fw: &Firewall, who: &str) -> FirewallVerdict {
    let params = json!({"name": "send", "arguments": {"text": PROSE}});
    fw.check_relay(
        RelayCaller::Keyed(who),
        "alpha",
        "send",
        &params,
        ("s", who),
    )
}

/// G31 (unit half): a replayed digest records exactly what the original
/// recording held. A plan receipt is staged, kept to its plan's answer,
/// capped and recorded for alice, the window lapses, and the snapshot's
/// fresh digest recorded for alice makes bob's relay of the text
/// refusable again while alice stays excused. Setup copied from
/// `deliver_plan_for` in `collusion_gate_p3_tests` (staged on a
/// caller-set staging, kept to the answer through `delivered_for_plan`
/// and `retain_delivered`, then `cap_kept`), with the snapshot taken
/// from that committed receipt, as a commit point takes it.
/// Mutant killed: re-derive the digest from the stored answer text
/// instead of the snapshot — the replayed fingerprints would no longer
/// equal the kept receipt's and bob would not be refused. A snapshot
/// carrying the one-shot `recorded` flag would likewise record nothing
/// and fail the last assertions.
#[test]
fn g31_a_replayed_receipt_records_what_the_original_held() {
    let fw = firewall();
    let pad = |tag: &str| {
        (0..700)
            .map(|i| format!("{tag}{i:05}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let step = json!({"a": pad("head"), "body": PROSE, "z": pad("tail")});
    let staged = PlanStaging::default();
    staged.set_caller("alice");
    let staged_digest = fw
        .receipt_digest("alpha", "read", &step, Some(&staged))
        .expect("relay detection is on: fixture");
    let answer = json!({"body": PROSE});
    let delivered = fw
        .delivered_for_plan(&answer, Some(&staged))
        .expect("the answer is under the bound: fixture");
    let digest = fw.cap_kept(fw.retain_delivered(staged_digest, &delivered, None));
    let snapshot = digest
        .replay_snapshot(Some(0), "alpha", "read")
        .expect("a kept plan receipt snapshots: fixture");
    assert_eq!(snapshot.label, Some(0));
    assert_eq!(
        (snapshot.server.as_str(), snapshot.tool.as_str()),
        ("alpha", "read")
    );
    let detector = fw
        .collusion_detector()
        .expect("relay detection is on: fixture");
    let original_fps = digest.fingerprints(detector);
    assert!(
        !original_fps.is_empty(),
        "premise: the receipt holds evidence"
    );

    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &digest);
    assert!(
        digest.recorded.load(Ordering::Relaxed),
        "premise: recorded once"
    );
    assert!(
        !egress(&fw, "bob").findings.is_empty(),
        "premise: the live receipt refuses bob"
    );
    assert!(
        egress(&fw, "alice").findings.is_empty(),
        "the holder is excused"
    );

    fw.advance_collusion_clock_for_test(Duration::from_secs(2));
    assert!(
        egress(&fw, "bob").findings.is_empty(),
        "premise: the original receipt lapsed with the window"
    );

    let replayed = DeliveryDigest::of_replay_receipt(&snapshot);
    assert!(
        !replayed.recorded.load(Ordering::Relaxed),
        "the replay digest starts unrecorded"
    );
    assert_eq!(
        replayed.fingerprints(detector),
        original_fps,
        "the replay holds exactly the original's fingerprints"
    );
    assert_eq!(replayed.is_sensitive(), digest.is_sensitive());
    fw.record_digest(RelayCaller::Keyed("alice"), "alpha", "read", &replayed);
    assert!(
        !egress(&fw, "bob").findings.is_empty(),
        "the replay recorded: bob carrying the text is refused again"
    );
    assert!(
        egress(&fw, "alice").findings.is_empty(),
        "the replay excuses its reader"
    );
}

/// A receipt snapshot with `fps` retained fingerprints, built from a seam
/// digest so its accounted size is `fps` fingerprint bytes plus the fixed
/// per-item overhead and its two one-byte source names.
fn receipt(seed: u64, fps: usize, label: Option<u32>) -> ReplayReceipt {
    let values: Vec<u64> = (0_u64..)
        .take(fps)
        .map(|i| seed.wrapping_mul(1_000_003).wrapping_add(i))
        .collect();
    DeliveryDigest::of_seam(values, true, None)
        .replay_snapshot(label, "s", "t")
        .expect("a seam receipt snapshots: fixture")
}

fn sync_key(identity: &str, round: &str, operation: &str) -> StoredKey {
    StoredKey::Sync {
        identity: identity.to_owned(),
        round: round.to_owned(),
        operation: operation.to_owned(),
    }
}

fn hour() -> Duration {
    Duration::from_secs(3600)
}

/// G33: past the total budget the oldest entry is evicted and counted; the
/// evicted key misses and a newer one hits.
/// Mutants killed: never evict (the oldest would still hit); evict the
/// newest (the newest would miss and the oldest would hit).
#[test]
fn g33_entries_past_the_total_evict_the_oldest() {
    let store = ReplayReceipts::with_budget_for_test(4 * 1024, 1024);
    let now = Instant::now();
    // 64 fingerprints: 512 fingerprint bytes plus overhead, under the
    // 1 KiB entry cap; ten of them cannot all fit the 4 KiB total.
    for i in 0..10_u64 {
        store.insert(
            sync_key("id", "r", &format!("op{i}")),
            vec![receipt(i + 1, 64, Some(0))],
            Vec::new(),
            now,
            hour(),
        );
    }
    assert!(store.evicted_for_test() > 0, "evictions are counted");
    assert!(
        store.lookup(&sync_key("id", "r", "op0"), now).is_none(),
        "the oldest entry was evicted"
    );
    assert!(
        store.lookup(&sync_key("id", "r", "op9"), now).is_some(),
        "the newest entry still hits"
    );
}

/// G34: an entry over the entry cap is not stored, and the entry the key
/// held before it goes too, so the key cannot replay an older commit.
/// Mutant killed: store the over-cap entry (the lookup would hit).
#[test]
fn g34_an_entry_over_the_entry_cap_is_not_stored() {
    let store = ReplayReceipts::with_budget_for_test(4 * 1024, 1024);
    let now = Instant::now();
    let key = sync_key("id", "r", "op");
    store.insert(
        key.clone(),
        vec![receipt(1, 8, Some(0))],
        Vec::new(),
        now,
        hour(),
    );
    assert!(
        store.lookup(&key, now).is_some(),
        "premise: the small entry is held"
    );
    // 200 fingerprints: 1600 fingerprint bytes, over the 1 KiB entry cap.
    store.insert(
        key.clone(),
        vec![receipt(2, 200, Some(0))],
        Vec::new(),
        now,
        hour(),
    );
    assert!(
        store.lookup(&key, now).is_none(),
        "the over-cap entry is not stored and its predecessor is gone"
    );
}

/// G36: past its retention an entry's lookup removes and misses;
/// re-inserting under the same key overwrites; `remove` deletes.
/// Mutant killed: keep the entry past retention (the late lookup would
/// hit); append instead of overwrite (the first insert's label and calls
/// would still be read back).
#[test]
fn g36_expiry_removes_overwrite_replaces_and_remove_deletes() {
    let store = ReplayReceipts::new();
    let now = Instant::now();
    let key = StoredKey::Task {
        id: "task-1".to_owned(),
        revision: 7,
    };
    store.insert(
        key.clone(),
        vec![receipt(1, 8, Some(1))],
        vec![(Some(1), "s".to_owned(), "t".to_owned())],
        now,
        Duration::from_secs(60),
    );
    let live = store
        .lookup(&key, now + Duration::from_secs(30))
        .expect("inside the retention: fixture");
    assert_eq!(live.receipts[0].label, Some(1));
    assert_eq!(live.calls.len(), 1);
    assert!(
        store.lookup(&key, now + Duration::from_secs(61)).is_none(),
        "past the retention the lookup misses"
    );
    store.insert(
        key.clone(),
        vec![receipt(2, 8, Some(2))],
        Vec::new(),
        now,
        hour(),
    );
    let replaced = store.lookup(&key, now).expect("re-inserted: fixture");
    assert_eq!(
        replaced.receipts[0].label,
        Some(2),
        "the re-insert overwrote"
    );
    assert!(
        replaced.calls.is_empty(),
        "the old calls went with the old entry"
    );
    store.remove(&key);
    assert!(
        store.lookup(&key, now).is_none(),
        "remove deletes the entry"
    );
}

/// G38 (unit half): a receipt judged as a big-step excuse yields no
/// snapshot, because its evidence is bound to the original caller's
/// reserved sketch position.
/// Mutant killed: snapshot it (the snapshot would be `Some`).
#[test]
fn g38_a_big_step_receipt_yields_no_snapshot() {
    let (mut digest, _) = DeliveryDigest::of_leaves(&[PROSE], true);
    digest.judged = Judged::Kept(Some(KeptStep {
        evidence: None,
        excuse: None,
    }));
    assert!(
        digest.replay_snapshot(Some(0), "alpha", "read").is_none(),
        "a Kept(Some) receipt is bound to its original caller"
    );
    digest.judged = Judged::Kept(None);
    assert!(
        digest.replay_snapshot(Some(0), "alpha", "read").is_some(),
        "control: the same receipt without a big step snapshots"
    );
}

/// G39: the sync key is the whole (identity, round, operation): another
/// identity misses, and the same identity under another operation or
/// round misses.
/// Mutant killed: key without identity (caller B would find caller A's
/// entry).
#[test]
fn g39_the_sync_key_separates_identity_round_and_operation() {
    let store = ReplayReceipts::new();
    let now = Instant::now();
    store.insert(
        sync_key("identity-a", "round-1", "op-1"),
        vec![receipt(1, 8, Some(0))],
        Vec::new(),
        now,
        hour(),
    );
    assert!(
        store
            .lookup(&sync_key("identity-a", "round-1", "op-1"), now)
            .is_some(),
        "premise: the stored key hits"
    );
    assert!(
        store
            .lookup(&sync_key("identity-b", "round-1", "op-1"), now)
            .is_none(),
        "another identity finds no entry"
    );
    assert!(
        store
            .lookup(&sync_key("identity-a", "round-1", "op-2"), now)
            .is_none(),
        "the same identity under another operation misses"
    );
    assert!(
        store
            .lookup(&sync_key("identity-a", "round-2", "op-1"), now)
            .is_none(),
        "the same identity under another round misses"
    );
}

/// N3 (MIK-8409.NESTED.3): a nested label's inner receipts count
/// against the entry cap like any other receipt. One inner receipt
/// (64 fingerprints, about 578 accounted bytes) fits the 1 KiB test
/// cap; the same entry with both inner calls' receipts under the one
/// label passes it, so the whole entry is not stored — and another
/// key's entry is untouched and still reads back (still renews).
/// Mutants killed: leave inner receipts out of the entry's byte count
/// (the two-receipt entry would be stored and hit); truncate the entry
/// to fit instead of dropping it whole (a truncated entry would hit).
#[test]
fn n3_inner_receipts_count_against_the_entry_cap() {
    let store = ReplayReceipts::with_budget_for_test(4 * 1024, 1024);
    let now = Instant::now();
    let other = sync_key("id", "r", "other");
    store.insert(
        other.clone(),
        vec![receipt(9, 8, Some(0))],
        Vec::new(),
        now,
        hour(),
    );
    let nested = sync_key("id", "r", "nested");
    let calls: Vec<(Option<u32>, String, String)> = vec![
        (Some(1), "s".to_owned(), "t".to_owned()),
        (Some(1), "u".to_owned(), "v".to_owned()),
    ];
    store.insert(
        nested.clone(),
        vec![receipt(1, 64, Some(1))],
        calls.clone(),
        now,
        hour(),
    );
    assert!(
        store.lookup(&nested, now).is_some(),
        "premise: one inner receipt fits the entry cap"
    );
    store.insert(
        nested.clone(),
        vec![receipt(1, 64, Some(1)), receipt(2, 64, Some(1))],
        calls,
        now,
        hour(),
    );
    assert!(
        store.lookup(&nested, now).is_none(),
        "both inner receipts push the entry past the cap: dropped whole, not stored"
    );
    let surviving = store
        .lookup(&other, now)
        .expect("the other entry is unaffected: fixture");
    assert_eq!(
        surviving.receipts.len(),
        1,
        "the other entry still holds its receipt and renews"
    );
}

/// G42: two firewalls built with `sharing_relay_with` share the replay
/// store exactly as they share the detector: an insert through one is
/// found through the other.
/// Mutant killed: a per-firewall store (the other firewall would miss).
#[test]
fn g42_firewalls_sharing_the_detector_share_the_replay_store() {
    let first = firewall();
    let second = firewall().sharing_relay_with(Some(&first));
    assert!(
        std::sync::Arc::ptr_eq(first.replay_receipts(), second.replay_receipts()),
        "one store beside the shared detector"
    );
    let now = Instant::now();
    let key = sync_key("id", "r", "op");
    first.replay_receipts().insert(
        key.clone(),
        vec![receipt(1, 8, Some(3))],
        Vec::new(),
        now,
        hour(),
    );
    let found = second
        .replay_receipts()
        .lookup(&key, now)
        .expect("inserted through the other firewall: fixture");
    assert_eq!(found.receipts[0].label, Some(3));
}

/// G47: two firewalls sharing the detector and the replay store,
/// with parallel commits (inserts through one) and replays
/// (lookups through the other) from several threads. Every
/// thread's replay finds its own entry — its own label comes
/// back — and the exercise completes: the store's lock is its
/// own and is never held while the detector's state lock is
/// taken (F6), so no thread's commit or replay can deadlock
/// against another's.
/// Mutant killed: a store lock held across a detector call (or
/// entries keyed loosely enough that a thread reads another's
/// back): the scope would hang, or a label would mismatch.
#[test]
fn g47_parallel_commits_and_replays_on_a_shared_store_each_find_their_own_entry() {
    let first = std::sync::Arc::new(firewall());
    let second = std::sync::Arc::new(firewall().sharing_relay_with(Some(&first)));
    let now = Instant::now();
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for i in 0..8_u32 {
            let first = std::sync::Arc::clone(&first);
            let second = std::sync::Arc::clone(&second);
            threads.push(scope.spawn(move || {
                let key = sync_key("id", "r", &format!("g47-op{i}"));
                for _ in 0..25 {
                    first.replay_receipts().insert(
                        key.clone(),
                        vec![receipt(u64::from(i) + 1, 8, Some(i))],
                        Vec::new(),
                        now,
                        hour(),
                    );
                    let found = second.replay_receipts().lookup(&key, now);
                    let found = found.expect("the thread's own entry: fixture");
                    assert_eq!(
                        found.receipts[0].label,
                        Some(i),
                        "thread {i} read another thread's entry back"
                    );
                }
            }));
        }
        for thread in threads {
            assert!(thread.join().is_ok(), "a worker thread panicked");
        }
    });
}
