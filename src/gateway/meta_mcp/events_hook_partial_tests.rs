// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8050: a partial capability load keeps only the subscriptions of what
//! it could not read, and a directory read again clears its failure.

use super::*;

/// Alpha in `d1`, beta in `d2`, both read by the scan, a subscription to
/// each, the scan complete.
async fn two_dirs() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    Arc<CapabilityBackend>,
    MetaMcp,
) {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
        seed_subscription(store.path(), cap);
    }
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();
    // Past the grace period, as a running gateway is.
    meta.run_deferred_webhook_withdraw().await;
    (root, store, d1, d2, caps, meta)
}

/// `PARTIALSCOPE.1` (P1): `d2` cannot be read while alpha's file is deleted
/// from `d1`, which loaded. Alpha is withdrawn; beta, unread, is kept.
#[tokio::test]
async fn a_capability_deleted_from_a_loaded_directory_is_withdrawn_on_a_partial_load() {
    let (_root, store, d1, d2, caps, meta) = two_dirs().await;
    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    std::fs::remove_file(d1.join("alpha.yaml")).expect("delete alpha");
    reload(&caps, &meta).await;
    assert!(
        !subscribed(store.path(), "alpha"),
        "alpha's directory loaded without it: withdrawn"
    );
    assert!(subscribed(store.path(), "beta"), "beta was not read: kept");
}

/// Pin (P1c): alpha is defined in both directories; `d2` fails after it
/// loaded once, and alpha is deleted from `d1`. `d2` may still define it, so
/// it is kept.
#[tokio::test]
async fn a_capability_also_in_an_unread_directory_is_kept() {
    let (_root, store, d1, d2, caps, meta) = two_dirs().await;
    std::fs::write(d2.join("alpha.yaml"), capability("alpha")).expect("alpha in d2 too");
    reload(&caps, &meta).await;
    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    std::fs::remove_file(d1.join("alpha.yaml")).expect("delete alpha from d1");
    reload(&caps, &meta).await;
    assert!(subscribed(store.path(), "alpha"), "d2 may still hold alpha");
    assert!(subscribed(store.path(), "beta"));
}

/// `PARTIALSCOPE.5` (P5): `d2` loaded at the scan and is unreadable by the
/// deferred pass, and alpha's file is gone from `d1`: the deferred pass
/// withdraws alpha and keeps beta.
#[tokio::test]
async fn the_deferred_pass_on_a_partial_catalogue_withdraws_what_it_read_as_gone() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
        seed_subscription(store.path(), cap);
    }
    seed_sentinel(store.path());
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;
    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    std::fs::remove_file(d1.join("alpha.yaml")).expect("delete alpha");
    caps.reload()
        .await
        .expect("a partial reload, its notice not yet handled");
    meta.run_deferred_webhook_withdraw().await;
    assert!(
        !subscribed(store.path(), "alpha"),
        "alpha is gone: withdrawn"
    );
    assert!(subscribed(store.path(), "beta"), "beta was not read: kept");
}

/// `PARTIALSCOPE.2` (P2): during the scan, a reload fails `d2`; the scan
/// then reads `d2`. The catalogue is complete, so the deferred pass
/// withdraws a type nothing offers.
#[tokio::test]
async fn a_directory_the_scan_reads_after_a_failed_reload_clears_the_failure() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
    }
    seed_subscription(store.path(), "gamma");
    seed_sentinel(store.path());
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    std::fs::rename(&d2, root.path().join("d2.away")).expect("hide d2");
    caps.reload()
        .await
        .expect("a reload that fails d2, mid-scan");
    std::fs::rename(root.path().join("d2.away"), &d2).expect("d2 back");
    caps.load_from_directory(d2.to_str().expect("utf8"))
        .await
        .expect("the scan reads d2");
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;
    meta.run_deferred_webhook_withdraw().await;
    assert!(
        !subscribed(store.path(), "gamma"),
        "a complete catalogue withdraws the type nothing offers"
    );
}

/// `PARTIALSCOPE` round 3 CRITICAL (P9): one YAML file in a readable
/// directory cannot be read. Its capability is not proven deleted, so its
/// subscription is kept.
#[cfg(unix)]
#[tokio::test]
async fn a_capability_whose_file_cannot_be_read_is_kept() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_root, store, _d1, d2, caps, meta) = two_dirs().await;
    let file = d2.join("beta.yaml");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("lock");
    reload(&caps, &meta).await;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("unlock");
    assert!(
        subscribed(store.path(), "beta"),
        "an unreadable file is not a deletion"
    );
    assert!(subscribed(store.path(), "alpha"));
}

/// Round 4 CRITICAL (P12): `d1`'s read fails one file and admits a new
/// one; a later read cannot read `d1` at all. Both capabilities'
/// subscriptions are kept.
#[cfg(unix)]
#[tokio::test]
async fn a_capability_first_read_by_a_partial_read_is_kept_when_its_directory_fails() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_root, store, d1, _d2, caps, meta) = two_dirs().await;
    seed_subscription(store.path(), "delta");
    let alpha = d1.join("alpha.yaml");
    std::fs::set_permissions(&alpha, std::fs::Permissions::from_mode(0o000)).expect("lock");
    std::fs::write(d1.join("delta.yaml"), capability("delta")).expect("delta, new");
    reload(&caps, &meta).await;
    std::fs::set_permissions(&alpha, std::fs::Permissions::from_mode(0o600)).expect("unlock");
    std::fs::rename(&d1, d1.with_extension("away")).expect("make d1 unreadable");
    reload(&caps, &meta).await;
    assert!(subscribed(store.path(), "alpha"));
    assert!(
        subscribed(store.path(), "delta"),
        "first read by a partial read: kept"
    );
}
