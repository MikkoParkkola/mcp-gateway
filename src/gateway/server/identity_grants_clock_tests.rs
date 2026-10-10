// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T9: the startup grant snapshot on a host clock that
//! reads before 1970. A snapshot that cannot be dated is not recorded, so the
//! start serves no grants (`Unrecorded`) rather than grants without their
//! audit snapshot.

use super::*;

/// Start the audit with the clock before 1970 only around the audit itself.
async fn start_on_an_unreadable_clock(dir: &Path) -> Started {
    let config = config(dir, true);
    let base = control_plane_base(&config, None);
    let gateway = Gateway::new(config.clone()).await.expect("valid config");
    let meta = gateway.build_meta_mcp().await.expect("meta").meta_mcp;
    let store = build_control_plane_store(&config, &base).expect("store");
    let clock = crate::clock::test_clock::before_epoch();
    let sink = start_identity_grant_audit(&config, &meta, store.as_ref(), &base.path)
        .await
        .expect("an unrecorded start is not a config error");
    drop(clock);
    Started { store, sink, meta }
}

/// MIK-8202 RECORDER (audit) rule, P2 row 10: no sink, no grant served, no
/// snapshot record. Mutant: skip the snapshot and start.
#[tokio::test]
async fn t9_an_undatable_startup_snapshot_serves_no_grants_and_records_none() {
    // GIVEN: one active grant on disk
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    // WHEN
    let s = Box::pin(start_on_an_unreadable_clock(dir.path())).await;
    // THEN
    assert!(s.sink.is_none(), "no sink: later reloads publish nothing");
    assert!(s.served().is_empty(), "no grant is served");
    let snapshot: Vec<_> = s
        .records()
        .into_iter()
        .filter(|r| matches!(r.0, V::Loaded | V::LoadedComplete))
        .collect();
    assert!(snapshot.is_empty(), "no snapshot record: {snapshot:?}");
}

/// T9 source check: both snapshot sites take a fallible `crate::clock` sample
/// (directly or through the one helper that reads it), and no raw chrono read
/// remains in the startup audit.
#[test]
fn t9_both_snapshot_sites_read_the_fallible_clock() {
    let source = include_str!("identity_grants.rs");
    let raw = ["Utc", "::now()"].concat();
    assert!(!source.contains(&raw), "a raw chrono read remains");
    assert!(
        source.contains("crate::clock::utc_now"),
        "no fallible sample"
    );
    let sites: Vec<&str> = source
        .lines()
        .filter(|line| line.contains("auditor.snapshot("))
        .collect();
    assert_eq!(sites.len(), 2, "the two snapshot sites: {sites:?}");
    for site in sites {
        assert!(
            site.contains("snapshot_time()") || site.contains("crate::clock::utc_now"),
            "a snapshot site does not sample the clock: {site}"
        );
    }
}
