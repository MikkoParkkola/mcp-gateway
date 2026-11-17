// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design D-1 ordering rows: records land in swap order, a cancelled reload's
//! record is not lost, the overlay is published before the record, and an
//! unchanged reload after a grants publish is an event, not a version.
//!
//! The swap observer (`seams::Observed`) is the ground truth: each swap logs
//! its revision and files under the swap locks, each refusal at its record
//! point under `lock_reload`, each overlay publication as it happens.

use std::sync::Arc;
use std::time::Duration;

use super::record_tests::{ONE_BACKEND, THREE_BACKENDS, TWO_BACKENDS, replace_with, rig_in};
use super::seams::{self, Observed};
use super::{Outcome, Source};
use crate::config_reload::reload_context::replace::{Audit, replace_audited};
use crate::gateway::test_helpers::write_owner_only;

const REFUSED_PORT: &str = "server:\n  port: not-a-number\n";
const HANG: Duration = Duration::from_secs(30);

/// What an event or an observation says, in one comparable shape.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Applied(String),
    Refused,
}

fn steps_of_events(store: &super::ConfigHistory) -> Vec<Step> {
    store
        .events()
        .iter()
        .skip(1) // the startup record has no observation
        .map(|event| match event.outcome {
            Outcome::Applied => Step::Applied(event.revision.clone().expect("a revision")),
            Outcome::Refused => Step::Refused,
        })
        .collect()
}

fn steps_of_log(log: &[Observed]) -> Vec<Step> {
    log.iter()
        .filter_map(|entry| match entry {
            Observed::Swap { revision, .. } => Some(Step::Applied(revision.clone())),
            Observed::Refusal => Some(Step::Refused),
            Observed::Overlay { .. } => None,
        })
        .collect()
}

/// R-ORDER: concurrent reloads through each function the entry points reach
/// (`reload_outcome`: watcher tick and env poll; `manual_reload_outcome`: the
/// UI reload route and the meta tool; `replace_audited`: the UI write routes),
/// some applied with distinct bytes and some refused: the history's events are
/// in exactly the observer's order, and each version's files are its swap's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r_order_records_land_in_swap_order_through_every_entry_point() {
    let dir = tempfile::tempdir().expect("tempdir");
    let installed = seams::install(dir.path());
    let rig = rig_in(dir, ONE_BACKEND);
    let mut tasks = Vec::new();
    for round in 0..4 {
        let bytes = [ONE_BACKEND, TWO_BACKENDS, THREE_BACKENDS, REFUSED_PORT][round % 4];
        write_owner_only(&rig.path, bytes).expect("write the config");
        let ctx = Arc::clone(&rig.ctx);
        tasks.push(tokio::spawn(async move {
            let _ = ctx.reload_outcome().await;
        }));
        let ctx = Arc::clone(&rig.ctx);
        tasks.push(tokio::spawn(async move {
            let _ = ctx
                .manual_reload_outcome(Source::Ui {
                    who: format!("reloader-{round}"),
                })
                .await;
        }));
        let ctx = Arc::clone(&rig.ctx);
        let written = [TWO_BACKENDS, THREE_BACKENDS][round % 2];
        tasks.push(tokio::spawn(async move {
            let _ = replace_audited(
                ctx,
                replace_with(written),
                Audit::Off,
                Source::Ui {
                    who: format!("writer-{round}"),
                },
                Duration::from_secs(5),
            )
            .await;
        }));
    }
    for task in tasks {
        tokio::time::timeout(HANG, task)
            .await
            .expect("joined within the bound")
            .expect("the reload task");
    }
    // One refusal for certain, whichever bytes the concurrent reloads read.
    write_owner_only(&rig.path, REFUSED_PORT).expect("break the config");
    assert!(
        tokio::time::timeout(HANG, rig.ctx.reload_outcome())
            .await
            .expect("the refused reload ended within the bound")
            .is_err(),
        "refused"
    );
    let log = installed.seams.log();
    let events = steps_of_events(&rig.store);
    let observed = steps_of_log(&log);
    assert!(
        events.iter().any(|s| *s == Step::Refused)
            && events.iter().any(|s| matches!(s, Step::Applied(_))),
        "the run had both outcomes: {events:?}"
    );
    assert_eq!(events, observed, "events in exactly the observer's order");
    let snapshots = rig.store.snapshots();
    assert!(
        snapshots.len() > 1,
        "the run stored versions to check: {}",
        snapshots.len()
    );
    let files_of = |snapshot: &super::Snapshot| -> Vec<(String, Option<Vec<u8>>)> {
        snapshot
            .files
            .iter()
            .map(|file| (file.path.clone(), file.bytes.clone()))
            .collect()
    };
    for snapshot in snapshots.iter().skip(1) {
        let swapped = log.iter().find_map(|entry| match entry {
            Observed::Swap { revision, files } if *revision == snapshot.revision => Some(files),
            _ => None,
        });
        assert_eq!(
            Some(&files_of(snapshot)),
            swapped,
            "version {} holds its swap's files",
            snapshot.revision
        );
    }
    // And the other way: every swap kept its version (50 are kept, this run
    // swaps at most 12, so none is evicted), holding exactly that swap's files.
    for entry in &log {
        if let Observed::Swap { revision, files } = entry {
            let stored = snapshots
                .iter()
                .find(|snapshot| snapshot.revision == *revision)
                .map(files_of);
            assert_eq!(
                stored.as_ref(),
                Some(files),
                "swap {revision} has its stored version"
            );
        }
    }
}

/// C-CANCEL: a reload dropped while its record is in flight (parked at
/// record-reached) does not lose the record, and a second reload's record
/// lands after it. The second reload either waits for the first record's
/// guard (a seam says so) or, with the order broken, finishes while the first
/// record is parked; only then is the first record released. No timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c_cancel_a_dropped_reload_keeps_its_record_and_its_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let installed = seams::install(dir.path());
    let rig = rig_in(dir, ONE_BACKEND);
    let first_gate = installed.seams.park_record();
    write_owner_only(&rig.path, TWO_BACKENDS).expect("first bytes");
    let ctx = Arc::clone(&rig.ctx);
    let first = tokio::spawn(async move { ctx.reload_outcome().await });
    tokio::time::timeout(HANG, first_gate.arrival())
        .await
        .expect("the first record started");
    first.abort();
    let _ = first.await;
    write_owner_only(&rig.path, THREE_BACKENDS).expect("second bytes");
    let ctx = Arc::clone(&rig.ctx);
    let second = tokio::spawn(async move { ctx.reload_outcome().await });
    // Either the second reload waits for the first record's guard (the order
    // holds), or it finishes while the first record is still parked (broken).
    let decided = async {
        tokio::select! {
            () = installed.seams.guard_waited() => {}
            () = async { while !second.is_finished() { tokio::task::yield_now().await; } } => {}
        }
    };
    tokio::time::timeout(HANG, decided)
        .await
        .expect("the second reload either waited for the guard or finished");
    first_gate.release();
    tokio::time::timeout(HANG, second)
        .await
        .expect("the second reload ended")
        .expect("joined")
        .expect("the second reload applies");
    let events = steps_of_events(&rig.store);
    let observed = steps_of_log(&installed.seams.log());
    assert_eq!(observed.len(), 2, "two swaps: {observed:?}");
    assert_eq!(events, observed, "both records, in swap order");
}

/// C7: the overlay is published before the record, on both reload paths:
/// with the record parked at record-reached, the log already holds the
/// overlay after its swap, for the same revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c7_the_overlay_follows_its_swap_before_the_record_on_both_paths() {
    // (the bytes the reload reads, the path it takes)
    for (bytes, path) in [
        (TWO_BACKENDS, "applied patch"),
        (ONE_BACKEND, "empty patch"),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = seams::install(dir.path());
        let rig = rig_in(dir, ONE_BACKEND);
        let gate = installed.seams.park_record();
        write_owner_only(&rig.path, bytes).expect("write the config");
        let ctx = Arc::clone(&rig.ctx);
        let reload = tokio::spawn(async move { ctx.reload_outcome().await });
        tokio::time::timeout(HANG, gate.arrival())
            .await
            .expect("the record started");
        let log = installed.seams.log();
        let tail: Vec<&Observed> = log.iter().rev().take(2).rev().collect();
        let revision = match tail.first() {
            Some(Observed::Swap { revision, .. }) => revision.clone(),
            other => panic!("{path}: the swap must come first: {other:?} in {log:?}"),
        };
        assert_eq!(
            tail.get(1),
            Some(&&Observed::Overlay { revision }),
            "{path}: the overlay follows its swap: {log:?}"
        );
        gate.release();
        tokio::time::timeout(HANG, reload)
            .await
            .expect("the reload ended")
            .expect("joined")
            .expect("the reload applies");
    }
}

/// C11 (regression): an unchanged reload after a grants publish (the revision
/// changed, nothing recorded) is an unchanged event, not a new version.
#[tokio::test]
async fn c11_an_unchanged_reload_after_a_grants_publish_is_an_event_only() {
    let rig = super::record_tests::rig(ONE_BACKEND);
    let versions = rig.store.snapshots().len();
    rig.ctx
        .live_config
        .set_grants(Some(b"schema_version: identity_grants.v1\ngrants: []\n"));
    rig.ctx
        .reload_outcome()
        .await
        .expect("the untouched reload applies");
    let events = rig.store.events();
    let last = events.last().expect("an event");
    assert_eq!(last.outcome, Outcome::Applied);
    assert!(last.unchanged, "an unchanged event: {last:?}");
    assert_eq!(rig.store.snapshots().len(), versions, "no new version");
}
