// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The pending-snapshot rule (ADR-029, amended): a synchronous answer's
//! replay snapshot is captured pending at judge, each delivery holds a
//! handle, a write not under `off` keeps it, and once no handle is
//! outstanding an entry still pending that was delivered under `off` goes.
//! Store-level rows; each names the mutant it kills.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::collusion_digest::{DeliveryDigest, ReplayReceipt};
use super::replay::{ReplayHandle, ReplayReceipts, StoredKey, TestLife};

const ON: bool = false;
const OFF: bool = true;

fn receipt(seed: u64, fps: usize) -> ReplayReceipt {
    let values: Vec<u64> = (0_u64..)
        .take(fps)
        .map(|i| seed.wrapping_mul(1_000_003).wrapping_add(i))
        .collect();
    DeliveryDigest::of_seam(values, true, None)
        .replay_snapshot(Some(1), "s", "t")
        .expect("a seam receipt snapshots: fixture")
}

fn key(op: &str) -> StoredKey {
    StoredKey::Sync {
        identity: "alice".to_owned(),
        round: "r1".to_owned(),
        operation: op.to_owned(),
    }
}

fn hour() -> Duration {
    Duration::from_secs(3600)
}

/// A pending capture of one small entry under `k`; the row asserts a
/// handle came back.
fn pend(store: &Arc<ReplayReceipts>, k: &StoredKey, now: Instant, ttl: Duration) -> ReplayHandle {
    let handle = store.insert_pending(
        k.clone(),
        vec![receipt(1, 8)],
        Vec::new(),
        String::new(),
        now,
        ttl,
    );
    assert!(
        handle.is_some(),
        "a pending capture returns its delivery's handle"
    );
    handle.expect("asserted above")
}

/// A replay acquiring `k`'s pending entry; the row asserts a handle.
fn replay(store: &Arc<ReplayReceipts>, k: &StoredKey, now: Instant) -> ReplayHandle {
    let acquired = store
        .acquire(k, now)
        .and_then(|acquired| acquired.into_parts().1);
    assert!(
        acquired.is_some(),
        "a replay of a pending entry holds a handle"
    );
    acquired.expect("asserted above")
}

const PENDING_ONE: TestLife = pending(1, false);
const KEPT: TestLife = TestLife::Kept;
const ABSENT: TestLife = TestLife::Absent;

const fn pending(outstanding: u32, delivered_off: bool) -> TestLife {
    TestLife::Pending {
        outstanding,
        delivered_off,
    }
}

/// A pending capture starts with one outstanding delivery, not kept.
/// Mutant killed: `insert_pending` stores kept (no lifecycle at all).
#[test]
fn a_pending_capture_holds_one_outstanding_delivery() {
    let store = Arc::new(ReplayReceipts::new());
    let k = key("a");
    let _h = pend(&store, &k, Instant::now(), hour());
    assert_eq!(store.life_for_test(&k), PENDING_ONE);
}

/// r2: judged and written under steady `off`: nothing held after the write.
/// Mutants killed: m7 (no removal after an off-settle), m10 (no decrement).
#[test]
fn r2_steady_off_holds_no_snapshot_after_the_write() {
    let store = Arc::new(ReplayReceipts::new());
    let k = key("a");
    let h = pend(&store, &k, Instant::now(), hour());
    store.settle(h, OFF);
    assert_eq!(
        store.life_for_test(&k),
        ABSENT,
        "delivered under off, nothing is held"
    );
}

/// r3 (store half): judged under off, written under block: kept.
/// Mutant killed: a settle that never keeps.
#[test]
fn r3_a_write_not_under_off_keeps_the_snapshot() {
    let store = Arc::new(ReplayReceipts::new());
    let k = key("a");
    let h = pend(&store, &k, Instant::now(), hour());
    store.settle(h, ON);
    assert_eq!(store.life_for_test(&k), KEPT);
}

/// r9: a replay written under off, then the original written under block:
/// kept, so a later replay still finds it.
/// Mutant killed: removal at the off-settle while another delivery is
/// outstanding.
#[test]
fn r9_an_off_write_then_a_block_write_keeps_the_snapshot() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let original = pend(&store, &k, now, hour());
    let retry = replay(&store, &k, now);
    assert_eq!(store.life_for_test(&k), pending(2, false));
    store.settle(retry, OFF);
    assert_eq!(
        store.life_for_test(&k),
        pending(1, true),
        "still held for the original"
    );
    store.settle(original, ON);
    assert_eq!(store.life_for_test(&k), KEPT);
}

/// r10: the original written under block, then a replay under off: kept.
/// Mutant killed: m8 (an off-settle removes a kept entry).
#[test]
fn r10_a_block_write_then_an_off_write_keeps_it() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let original = pend(&store, &k, now, hour());
    let retry = replay(&store, &k, now);
    store.settle(original, ON);
    store.settle(retry, OFF);
    assert_eq!(store.life_for_test(&k), KEPT);
}

/// r11: an off-settle and a block-settle racing on two threads end kept,
/// whichever lands first. A stress row: 64 races, not a controlled
/// interleaving, so it shows both orders end kept rather than proving a
/// particular lost update would be caught.
#[test]
fn r11_concurrent_off_and_block_settles_end_kept() {
    for _ in 0..64 {
        let store = Arc::new(ReplayReceipts::new());
        let now = Instant::now();
        let k = key("a");
        let original = pend(&store, &k, now, hour());
        let retry = replay(&store, &k, now);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (s, b) = (Arc::clone(&store), Arc::clone(&barrier));
        let off = std::thread::spawn(move || {
            b.wait();
            s.settle(retry, OFF);
        });
        barrier.wait();
        store.settle(original, ON);
        off.join().expect("the off settle thread");
        assert_eq!(store.life_for_test(&k), KEPT);
    }
}

/// r17: an answer admission did not retain (E1) is discarded at once.
/// Mutant killed: discard as a no-op.
#[test]
fn r17_a_retained_false_capture_is_discarded() {
    let store = Arc::new(ReplayReceipts::new());
    let k = key("a");
    let h = pend(&store, &k, Instant::now(), hour());
    store.discard(h);
    assert_eq!(store.life_for_test(&k), ABSENT);
}

/// r18: a discard never touches a kept entry, nor a newer capture under
/// the same key.
/// Mutants killed: discard ignoring the lifecycle; m9 (seq ignored).
#[test]
fn r18_discard_never_touches_a_kept_or_newer_entry() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let original = pend(&store, &k, now, hour());
    let retry = replay(&store, &k, now);
    store.settle(original, ON);
    store.discard(retry);
    assert_eq!(
        store.life_for_test(&k),
        KEPT,
        "a kept entry survives a discard"
    );

    let j = key("b");
    let old = pend(&store, &j, now, hour());
    let newer = pend(&store, &j, now, hour());
    store.discard(old);
    assert_eq!(
        store.life_for_test(&j),
        PENDING_ONE,
        "the newer capture is untouched"
    );
    drop(newer);
}

/// r21: an off-settle, then the last handle dropped unwritten: removed,
/// because the only delivery that reached a client was under off.
/// Mutant killed: removal decided only at a settle.
#[test]
fn r21_off_settle_then_the_last_handle_dropped_removes() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let original = pend(&store, &k, now, hour());
    let retry = replay(&store, &k, now);
    store.settle(retry, OFF);
    drop(original);
    assert_eq!(store.life_for_test(&k), ABSENT);
}

/// r22: every handle dropped unwritten: the entry stays pending for a
/// later replay to settle (rule 3).
/// Mutant killed: removal when outstanding reaches zero without an off
/// delivery.
#[test]
fn r22_all_handles_dropped_unwritten_stays_pending() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let original = pend(&store, &k, now, hour());
    drop(original);
    assert_eq!(store.life_for_test(&k), pending(0, false));
    let later = replay(&store, &k, now);
    store.settle(later, ON);
    assert_eq!(store.life_for_test(&k), KEPT, "a later replay settles it");
}

/// r23: a handle whose entry was replaced acts on nothing.
/// Mutant killed: m9 (settle and release ignore seq).
#[test]
fn r23_a_stale_handle_is_a_no_op() {
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let k = key("a");
    let stale = pend(&store, &k, now, hour());
    let dropped_stale = replay(&store, &k, now);
    let fresh = pend(&store, &k, now, hour());
    store.settle(stale, OFF);
    assert_eq!(
        store.life_for_test(&k),
        PENDING_ONE,
        "the stale off-settle touched nothing"
    );
    drop(dropped_stale);
    assert_eq!(
        store.life_for_test(&k),
        PENDING_ONE,
        "the stale drop released nothing"
    );
    drop(fresh);
    assert_eq!(store.life_for_test(&k), pending(0, false));
}

/// r15 and r19: an insert sweeps every expired entry, not only its own
/// key's, and keeps an older entry that is still live even when a newer
/// one before it in age has expired.
/// Mutants killed: no sweep (the expired entry stays); a sweep that stops
/// at the first live entry in age order (the newer expired one stays).
#[test]
fn r15_r19_an_insert_sweeps_only_the_expired_entries() {
    let store = Arc::new(ReplayReceipts::new());
    let t0 = Instant::now();
    let (older, newer, third) = (key("older"), key("newer"), key("third"));
    drop(pend(&store, &older, t0, Duration::from_secs(10)));
    drop(pend(&store, &newer, t0, Duration::from_secs(1)));
    drop(pend(&store, &third, t0 + Duration::from_secs(5), hour()));
    assert_eq!(
        store.life_for_test(&newer),
        ABSENT,
        "the expired newer entry was swept"
    );
    assert_eq!(
        store.life_for_test(&older),
        pending(0, false),
        "the older entry is still live"
    );
}

/// r20: pending entries stay inside the store's total cap however many
/// handles are held, an evicted entry's payload is freed while its handle
/// is still alive (a handle holds no payload), and that handle acts on
/// nothing.
/// Mutants killed: a handle holding the payload (bytes outside the cap);
/// an eviction that skips pending entries.
#[test]
fn r20_pending_entries_stay_inside_the_total_cap() {
    let store = Arc::new(ReplayReceipts::with_budget_for_test(4 * 1024, 1024));
    let now = Instant::now();
    let mut held = Vec::new();
    let mut first_payload = None;
    for i in 0..10_u64 {
        let k = key(&format!("op{i}"));
        let h = store.insert_pending(
            k.clone(),
            vec![receipt(i, 64)],
            Vec::new(),
            String::new(),
            now,
            hour(),
        );
        assert!(h.is_some(), "each fits the entry cap");
        if i == 0 {
            first_payload = store.entry_weak_for_test(&k);
        }
        held.push((k, h));
        assert!(
            store.bytes_for_test() <= 4 * 1024,
            "the store stays inside its cap"
        );
    }
    let (first, h) = held.remove(0);
    assert_eq!(
        store.life_for_test(&first),
        ABSENT,
        "the oldest was evicted"
    );
    assert!(
        h.is_some(),
        "base: the evicted entry's handle is still alive"
    );
    assert!(
        first_payload.is_some_and(|weak| weak.upgrade().is_none()),
        "an evicted entry's payload is freed while its handle lives"
    );
    if let Some(h) = h {
        store.settle(h, ON);
    }
    assert_eq!(
        store.life_for_test(&first),
        ABSENT,
        "an evicted entry's handle restores nothing"
    );
}

/// p1: every order of two deliveries' outcomes (written under off,
/// written not under off, dropped unwritten) ends as the rule says. Kept
/// once any write was not under off; removed once no handle is left and
/// some write was under off; otherwise pending. Exhaustive over the 3x3
/// outcomes and both orders.
/// Mutants killed: m7, m8, m10 and any settle/release that disagrees with
/// the rule on some order.
#[test]
fn p1_every_two_delivery_order_ends_as_the_rule_says() {
    #[derive(Clone, Copy, Debug)]
    enum End {
        On,
        Off,
        Dropped,
    }
    let ends = [End::On, End::Off, End::Dropped];
    for first in ends {
        for second in ends {
            for original_first in [true, false] {
                let store = Arc::new(ReplayReceipts::new());
                let now = Instant::now();
                let k = key("a");
                let original = pend(&store, &k, now, hour());
                let retry = replay(&store, &k, now);
                let (a, b) = if original_first {
                    (original, retry)
                } else {
                    (retry, original)
                };
                for (handle, end) in [(a, first), (b, second)] {
                    match end {
                        End::On => store.settle(handle, ON),
                        End::Off => store.settle(handle, OFF),
                        End::Dropped => drop(handle),
                    }
                }
                let any_on = matches!(first, End::On) || matches!(second, End::On);
                let any_off = matches!(first, End::Off) || matches!(second, End::Off);
                let want = if any_on {
                    KEPT
                } else if any_off {
                    ABSENT
                } else {
                    pending(0, false)
                };
                assert_eq!(
                    store.life_for_test(&k),
                    want,
                    "{first:?} then {second:?} (original first: {original_first})"
                );
            }
        }
    }
}

/// One step of p1b's model check.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// A new pending capture under the key (replacing the entry).
    Insert,
    /// A replay acquiring the entry.
    Acquire,
    /// Handle `n` written not under `off`.
    On(usize),
    /// Handle `n` written under `off`.
    Off(usize),
    /// Handle `n` dropped unwritten.
    Drop(usize),
    /// The clock moves past the retention.
    Expire,
}

/// The rule as a model: the entry's sequence and lifecycle, and each
/// handle's sequence (`None` once used).
#[derive(Clone, Default)]
struct Model {
    entry: Option<(u64, TestLife)>,
    handles: Vec<Option<u64>>,
    next: u64,
    expired: bool,
}

impl Model {
    fn end(&mut self, n: usize, off: Option<bool>) {
        let Some(seq) = self.handles.get_mut(n).and_then(Option::take) else {
            return;
        };
        let Some((
            at,
            TestLife::Pending {
                outstanding,
                delivered_off,
            },
        )) = self.entry
        else {
            return;
        };
        if at != seq {
            return;
        }
        if off == Some(false) {
            self.entry = Some((at, KEPT));
            return;
        }
        let (outstanding, delivered_off) = (outstanding - 1, delivered_off || off == Some(true));
        self.entry = if outstanding == 0 && delivered_off {
            None
        } else {
            Some((at, pending(outstanding, delivered_off)))
        };
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Insert => {
                self.expired = false;
                self.entry = Some((self.next, pending(1, false)));
                self.handles.push(Some(self.next));
                self.next += 1;
            }
            Op::Acquire => match self.entry {
                Some(_) if self.expired => self.entry = None,
                Some((
                    at,
                    TestLife::Pending {
                        outstanding,
                        delivered_off,
                    },
                )) => {
                    self.entry = Some((at, pending(outstanding + 1, delivered_off)));
                    self.handles.push(Some(at));
                }
                _ => {}
            },
            Op::On(n) => self.end(n, Some(false)),
            Op::Off(n) => self.end(n, Some(true)),
            Op::Drop(n) => self.end(n, None),
            Op::Expire => self.expired = self.entry.is_some(),
        }
    }
}

/// p1b: every sequence of up to four steps (a new capture, a replay,
/// writes under and not under `off`, an unwritten drop, expiry) leaves the
/// store where the rule says, step by step: handles bound to their own
/// entry, a replaced or expired entry untouched by old handles.
/// Mutants killed: m7, m8, m9, m10, and an acquire that hands out a handle
/// for an entry other than the one it returns.
#[test]
fn p1b_every_short_sequence_matches_the_model() {
    fn ops(model: &Model) -> Vec<Op> {
        let mut all = vec![Op::Insert, Op::Acquire, Op::Expire];
        for (n, h) in model.handles.iter().enumerate() {
            if h.is_some() {
                all.extend([Op::On(n), Op::Off(n), Op::Drop(n)]);
            }
        }
        all
    }
    fn walk(trace: &mut Vec<Op>, depth: usize) {
        let mut model = Model::default();
        let store = Arc::new(ReplayReceipts::new());
        let k = key("a");
        let mut now = Instant::now();
        let mut handles: Vec<Option<ReplayHandle>> = Vec::new();
        for &op in trace.iter() {
            let marker = model.next;
            model.apply(op);
            match op {
                // Each capture carries its own marker, so a replay can be
                // checked to return the snapshot its handle belongs to.
                Op::Insert => {
                    let handle = store.insert_pending(
                        k.clone(),
                        vec![receipt(1, 8)],
                        Vec::new(),
                        format!("v{marker}"),
                        now,
                        Duration::from_secs(10),
                    );
                    assert!(handle.is_some(), "a pending capture returns its handle");
                    handles.push(handle);
                }
                Op::Acquire => {
                    if let Some((entry, handle)) = store
                        .acquire(&k, now)
                        .map(super::replay::Acquired::into_parts)
                    {
                        let want = model.entry.map(|(seq, _)| format!("v{seq}"));
                        assert_eq!(
                            Some(entry.answer_digest.clone()),
                            want,
                            "the replay returns the live entry's snapshot after {trace:?}"
                        );
                        if let Some(h) = handle {
                            handles.push(Some(h));
                        }
                    }
                }
                Op::On(n) => {
                    if let Some(h) = handles[n].take() {
                        store.settle(h, ON);
                    }
                }
                Op::Off(n) => {
                    if let Some(h) = handles[n].take() {
                        store.settle(h, OFF);
                    }
                }
                Op::Drop(n) => drop(handles[n].take()),
                Op::Expire => now += Duration::from_secs(11),
            }
            let want = model.entry.map_or(ABSENT, |(_, life)| life);
            assert_eq!(store.life_for_test(&k), want, "after {trace:?}");
            assert_eq!(
                handles.len(),
                model.handles.len(),
                "handles after {trace:?}"
            );
        }
        if depth == 0 {
            return;
        }
        let mut model = Model::default();
        for &op in trace.iter() {
            model.apply(op);
        }
        for op in ops(&model) {
            trace.push(op);
            walk(trace, depth - 1);
            trace.pop();
        }
    }
    walk(&mut Vec::new(), 4);
}

/// r25: a handle cannot be paired with a snapshot it was not taken
/// against: `Acquired::pair` refuses an entry and a handle from different
/// insertion sequences, and accepts its own pair.
/// Mutant killed: the pairing check removed (a delivery could settle an
/// entry other than the one whose receipts it staged).
#[test]
fn r25_a_handle_is_refused_for_another_entry() {
    use super::replay::Acquired;
    let store = Arc::new(ReplayReceipts::new());
    let now = Instant::now();
    let (a, b) = (key("a"), key("b"));
    let _ha = pend(&store, &a, now, hour());
    let _hb = pend(&store, &b, now, hour());
    let from_a = store.acquire(&a, now).expect("a is stored");
    let from_b = store.acquire(&b, now).expect("b is stored");
    let ((a_entry, a_handle), (_, b_handle)) = (from_a.into_parts(), from_b.into_parts());
    assert!(
        Acquired::pair(std::sync::Arc::clone(&a_entry), b_handle).is_none(),
        "b's handle is refused for a's snapshot"
    );
    assert!(
        Acquired::pair(a_entry, a_handle).is_some(),
        "control: a's own pair is accepted"
    );
}

/// The size check a stored task read is judged by (`fits`) and the store's
/// own admission agree at the exact caps: an entry of exactly either cap
/// fits and is stored; one byte less of either cap, per entry or in
/// total, and it neither fits nor is stored.
#[test]
fn fits_agrees_with_admission_at_both_caps() {
    let calls: crate::security::ReplayCalls = vec![(Some(1), "s".to_owned(), "t".to_owned())];
    let now = Instant::now();
    let probe = Arc::new(ReplayReceipts::new());
    let _ = probe.insert_pending(
        key("size"),
        vec![receipt(1, 8)],
        calls.clone(),
        String::new(),
        now,
        hour(),
    );
    let bytes = probe.bytes_for_test();
    assert!(bytes > 0, "premise: the entry was stored and counted");
    for (total, entry, admitted) in [
        (bytes * 4, bytes, true),
        (bytes, bytes * 4, true),
        (bytes * 4, bytes - 1, false),
        (bytes - 1, bytes * 4, false),
    ] {
        let store = Arc::new(ReplayReceipts::with_budget_for_test(total, entry));
        assert_eq!(
            store.fits(&[receipt(1, 8)], &calls, ""),
            admitted,
            "fits at total {total}, entry {entry} for {bytes} bytes"
        );
        let stored = store
            .insert_pending(
                key("size"),
                vec![receipt(1, 8)],
                calls.clone(),
                String::new(),
                now,
                hour(),
            )
            .is_some();
        assert_eq!(
            stored, admitted,
            "admission at total {total}, entry {entry}"
        );
    }
}
