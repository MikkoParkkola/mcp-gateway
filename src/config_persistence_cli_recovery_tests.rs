// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A CLI write that finds a replace journal pending recovers it on taking the
//! config lock, and records the recovery nowhere: the CLI holds no audit sink.
//! A gateway's audited writer leaves such a journal when its write fails and
//! the rollback fails too, while the gateway keeps running. This row pins
//! today's behaviour so a change to it is a visible decision.

use super::{CommentLoss, edit_config, journal};

const ORIGINAL: &str = "server:\n  port: 39401\n";
const NEW: &str = "server:\n  port: 39402\n";

#[test]
fn a_cli_write_recovers_a_pending_journal_and_records_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&config, NEW).expect("config");
    // The state a failed, un-rolled-back gateway write leaves: the original
    // staged, a `staged` journal naming its digest, the new bytes in place.
    journal::stage_original(&config, ORIGINAL.as_bytes()).expect("stage");
    journal::begin(&config, crate::hashing::sha256_hex(ORIGINAL.as_bytes())).expect("journal");
    assert!(journal::exists(&config), "premise: a journal is pending");
    let before: Vec<_> = listing(dir.path());

    edit_config(&config, CommentLoss::Refuse, |_| Ok(())).expect("the CLI write proceeds");

    assert!(!journal::exists(&config), "the CLI recovered the journal");
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        ORIGINAL,
        "the recovery rolled the file back to the staged original"
    );
    // Nothing the CLI wrote names the recovery: the only change in the
    // directory is the journal and the staged copy going away (the lock
    // sidecar stays, as every config lock does).
    let after = listing(dir.path());
    let added: Vec<_> = after.iter().filter(|name| !before.contains(name)).collect();
    assert!(
        added.iter().all(|name| name.ends_with(".lock")),
        "no record of the recovery: {added:?}"
    );
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("listing")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}
