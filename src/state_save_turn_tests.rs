// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2: writes of the usage file and of the transitions file take
//! turns, each holding its turn from the snapshot through the rename. A
//! blocking save waits for the turn and writes the state as it is when its
//! turn comes; a checkpoint save skips while the turn is held. So the last
//! write to land holds the newest state and the file never goes back.
//!
//! A held turn stands in for a write in flight (`hold_write_turn`). Every
//! check loads into a fresh instance.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ranking::SearchRanker;
use crate::transition::TransitionTracker;

/// How long a save behind a held turn is watched for a write it must not
/// make. A save that ignores the turn writes a few-byte file in well under it.
/// An absence window: a stall can only hide a wrong write, never fail the
/// row. A deterministic signal from the save path would remove the wait.
const HELD: Duration = Duration::from_secs(1);

/// One state file as the rows drive it.
struct Subject<T> {
    state: Arc<T>,
    hold: for<'a> fn(&'a T) -> parking_lot::MutexGuard<'a, ()>,
    save: fn(&T, &Path) -> std::io::Result<()>,
    checkpoint: fn(&T, &Path) -> Option<std::io::Result<()>>,
    /// Record step 0 (before the turn is taken) or step 1 (while it is held).
    record: fn(&T, u8),
    /// The count a fresh instance loads from the file.
    read: fn(&Path) -> u64,
}

fn usage() -> Subject<SearchRanker> {
    Subject {
        state: Arc::new(SearchRanker::new()),
        hold: SearchRanker::hold_write_turn,
        save: SearchRanker::save,
        checkpoint: SearchRanker::save_unless_busy,
        record: |ranker, _| ranker.record_use("srv", "alpha"),
        read: |path| {
            let fresh = SearchRanker::new();
            fresh.load(path).expect("usage file loads");
            fresh.usage_count("srv", "alpha")
        },
    }
}

fn transitions() -> Subject<TransitionTracker> {
    Subject {
        state: Arc::new(TransitionTracker::new()),
        hold: TransitionTracker::hold_write_turn,
        save: TransitionTracker::save,
        checkpoint: TransitionTracker::save_unless_busy,
        // Step 0 records a then b (one transition), step 1 adds c (two).
        record: |tracker, step| {
            if step == 0 {
                tracker.record_transition("s", "a");
                tracker.record_transition("s", "b");
            } else {
                tracker.record_transition("s", "c");
            }
        },
        read: |path| {
            let fresh = TransitionTracker::new();
            fresh.load(path).expect("transitions file loads");
            fresh.total_transitions()
        },
    }
}

/// Start a blocking save on its own thread while the test holds the turn,
/// check it writes nothing for [`HELD`], then record step 1 and return the
/// thread for the caller to release and join.
fn blocked_save<T: Send + Sync + 'static>(
    s: &Subject<T>,
    path: &Path,
) -> std::thread::JoinHandle<std::io::Result<()>> {
    let (state, save, at) = (Arc::clone(&s.state), s.save, path.to_path_buf());
    let saver = std::thread::spawn(move || save(&state, &at));
    let until = Instant::now() + HELD;
    while Instant::now() < until {
        assert!(
            !path.exists(),
            "a save wrote while another write held the turn"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    (s.record)(&s.state, 1);
    saver
}

/// T-turn: a blocking save started while the turn is held writes nothing until
/// release, then writes the state as of its turn: step 1, recorded while it
/// waited, is in the file (`late`).
fn a_save_waits_its_turn<T: Send + Sync + 'static>(s: &Subject<T>, late: u64) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    (s.record)(&s.state, 0);
    let turn = (s.hold)(&s.state);
    let saver = blocked_save(s, &path);
    drop(turn);
    saver.join().expect("the save thread").expect("the save");
    assert_eq!(
        (s.read)(&path),
        late,
        "the save wrote a state older than its turn"
    );
}

/// T-order: while a write holds the turn, a checkpoint skips and a blocking
/// save waits; the blocking save then writes a state no older than the
/// holder's, and with the turn free a checkpoint writes.
fn a_checkpoint_skips_and_a_save_waits<T: Send + Sync + 'static>(s: &Subject<T>, late: u64) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    (s.record)(&s.state, 0);
    let turn = (s.hold)(&s.state);
    assert!(
        (s.checkpoint)(&s.state, &path).is_none(),
        "a checkpoint did not skip while another write held the turn"
    );
    let saver = blocked_save(s, &path);
    drop(turn);
    saver.join().expect("the save thread").expect("the save");
    assert_eq!(
        (s.read)(&path),
        late,
        "the waiting save wrote an older state"
    );
    assert!(
        matches!((s.checkpoint)(&s.state, &path), Some(Ok(()))),
        "a checkpoint skipped with the turn free"
    );
}

#[test]
fn t_turn_usage() {
    a_save_waits_its_turn(&usage(), 2);
}

#[test]
fn t_turn_transitions() {
    a_save_waits_its_turn(&transitions(), 2);
}

#[test]
fn t_order_usage() {
    a_checkpoint_skips_and_a_save_waits(&usage(), 2);
}

#[test]
fn t_order_transitions() {
    a_checkpoint_skips_and_a_save_waits(&transitions(), 2);
}
