// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8739 rows for the key-taking replay surface (the sync lookup's
//! Sync-only filter, and the empty commit's removal with relay detection
//! off), split from `relay_replay_tests` for the file-size ceiling.

use std::sync::Arc;

use super::super::super::{REPLAY_LOOKUP, RelayKey, collecting, commit_with};
use super::super::{note_task_capture, stage_plan_replay};
use super::{PROSE, completed, digest_for, relay_meta, staged_summaries, store_entry};
use crate::security::firewall::{Firewall, FirewallConfig, StoredKey};

/// T3 (MIK-8739): a task key in the sync lookup slot stages nothing and
/// looks nothing up, whether that task's entry is stored or absent. Both
/// key kinds share `replay_digests`, so the Sync-only pattern in
/// `stage_plan_replay` is all that keeps a task key out of the sync
/// lookup; `note_sync_lookup` is the slot's only writer today, so this
/// guards a future one. A hit counts nothing, so the absent case is what
/// shows that no lookup ran.
/// Mutants killed: drop the Sync filter (the stored case stages the
/// task's receipt; the absent case counts `reason=absent`); look up and
/// discard before the filter (the absent case counts `reason=absent`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t3_a_task_key_in_the_sync_lookup_slot_stages_and_looks_up_nothing() {
    let (meta, fw) = relay_meta();
    let stored = completed(&[("alpha", "read"), ("beta", "read")]);
    let digest = digest_for(&fw, "alpha", "read", PROSE);
    store_entry(
        &fw,
        &stored,
        &[(&digest, Some(0), "alpha", "read")],
        vec![(Some(0), "alpha".to_owned(), "read".to_owned())],
    );
    let present = StoredKey::Task {
        id: stored.task.id().to_owned(),
        revision: stored.revision,
    };
    assert!(
        fw.replay_digests(&present).is_some(),
        "premise: the task's entry is stored"
    );
    let absent_key = StoredKey::Task {
        id: "no-such-task".to_owned(),
        revision: 1,
    };
    let alice = RelayKey::new("alice", true);
    for (case, key) in [("stored", present), ("absent", absent_key)] {
        let measured = collecting(async {
            // `with`, not `try_with`: an unscoped slot must fail the test.
            REPLAY_LOOKUP.with(|slot| *slot.borrow_mut() = Some(key));
            stage_plan_replay(&meta, alice);
            staged_summaries()
        });
        #[cfg(feature = "metrics")]
        let (staged, absent) = crate::gateway::count_plan_replay_skipped("absent", measured);
        #[cfg(not(feature = "metrics"))]
        let staged = measured.await;
        assert!(
            staged.is_empty(),
            "a task key in the sync lookup slot staged ({case}): {staged:?}"
        );
        #[cfg(feature = "metrics")]
        assert_eq!(
            absent, 0,
            "a task key in the sync lookup slot was looked up ({case})"
        );
    }
}

/// T4 (MIK-8739): a commit with no candidates removes the prior entry
/// even through a firewall with relay detection off, which shares the
/// store with one that has it on. `store_replay` returns early with
/// detection off, so sending this commit through it would keep the
/// stale entry (F1).
/// Mutant killed: send the empty commit through `store_replay`.
#[tokio::test]
async fn t4_an_empty_commit_removes_the_entry_with_relay_detection_off() {
    let (_meta, fw) = relay_meta();
    let stored = completed(&[("alpha", "read"), ("beta", "read")]);
    let digest = digest_for(&fw, "alpha", "read", PROSE);
    store_entry(
        &fw,
        &stored,
        &[(&digest, Some(0), "alpha", "read")],
        vec![(Some(0), "alpha".to_owned(), "read".to_owned())],
    );
    let key = StoredKey::Task {
        id: stored.task.id().to_owned(),
        revision: stored.revision,
    };
    assert!(
        fw.replay_digests(&key).is_some(),
        "premise: the entry is stored"
    );
    let off = Firewall::from_config(
        FirewallConfig {
            enabled: false,
            ..FirewallConfig::default()
        },
        None,
    )
    .sharing_relay_with(Some(&fw));
    assert!(
        !off.relay_active(),
        "premise: relay detection is off on the peer"
    );
    collecting(async {
        note_task_capture(stored.task.id().to_owned(), stored.revision, None);
        commit_with(&off, true);
    })
    .await;
    assert!(
        fw.replay_digests(&key).is_none(),
        "an empty commit with relay detection off kept the prior entry"
    );
}
