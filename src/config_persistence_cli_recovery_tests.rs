// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A CLI write that finds a replace journal pending refuses rather than
//! recover it: the CLI holds no audit sink, so its recovery would go
//! unrecorded. A gateway's audited writer leaves such a journal when its write
//! fails and the rollback fails too, while the gateway keeps running.

use super::{CommentLoss, edit_config, journal, lock};

const ORIGINAL: &str = "server:\n  port: 39401\n";
const NEW: &str = "server:\n  port: 39402\n";

#[test]
fn a_cli_write_refuses_a_pending_journal_and_changes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&config, NEW).expect("config");
    // The state a failed, un-rolled-back gateway write leaves: the original
    // staged, a `staged` journal naming its digest, the new bytes in place.
    journal::stage_original(&config, ORIGINAL.as_bytes()).expect("stage");
    journal::begin(&config, crate::hashing::sha256_hex(ORIGINAL.as_bytes())).expect("journal");
    assert!(journal::exists(&config), "premise: a journal is pending");
    let journal_before = std::fs::read(journal::journal_path(&config)).expect("journal bytes");

    let refused = edit_config(&config, CommentLoss::Refuse, |_| Ok(()))
        .expect_err("a CLI write does not recover a pending journal");

    assert!(
        refused.contains("start or reload the gateway"),
        "the refusal says what to do: {refused}"
    );
    assert_eq!(
        std::fs::read(journal::journal_path(&config)).expect("the journal is still pending"),
        journal_before,
        "the journal is unchanged"
    );
    assert_eq!(
        std::fs::read_to_string(journal::original_path(&config)).unwrap(),
        ORIGINAL,
        "the staged original is unchanged"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        NEW,
        "the config is unchanged"
    );
    // The refusal released the lock: a writer can take it again at once.
    let again = lock::lock_config_blocking_deferred(
        &config,
        std::time::Instant::now() + std::time::Duration::from_millis(200),
        |_| {},
    );
    assert!(again.is_ok(), "the refusal left the lock held");
}
