// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8038 part 1: a type whose route is gone while its subscriptions
//! remain keeps its last shape, so a reload that restores it narrower is
//! refused as T52 refuses a narrowing of a live type.

use super::*;

/// [`capability`] with its `ref` field and filter replaced by `sha`: a
/// restore that drops what subscribers relied on.
fn narrower(name: &str) -> String {
    capability(name).replace("ref", "sha")
}

/// [`capability`] with a `sha` field and filter added beside `ref`.
fn wider(name: &str) -> String {
    capability(name)
        .replace(
            "data: { ref: \"{ref}\" }",
            "data: { ref: \"{ref}\", sha: \"{sha}\" }",
        )
        .replace("filters: [ref]", "filters: [ref, sha]")
}

/// Alpha in `d1`, beta in `d2`, a subscription to each, the scan complete.
async fn two_dirs() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<CapabilityBackend>,
    Registry,
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
    let (caps, registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();
    (root, store, d2, caps, registry, meta)
}

/// A partial reload: `d2` cannot be read, so beta's route goes and its
/// subscription is kept (MIK-8028).
async fn drop_d2(d2: &std::path::Path, caps: &CapabilityBackend, meta: &MetaMcp) {
    std::fs::remove_dir_all(d2).expect("make d2 unreadable");
    reload(caps, meta).await;
}

/// Bring `d2` back holding `yaml` for beta, and reload.
async fn restore_d2(d2: &std::path::Path, yaml: &str, caps: &CapabilityBackend, meta: &MetaMcp) {
    std::fs::create_dir_all(d2).expect("d2 back");
    std::fs::write(d2.join("beta.yaml"), yaml).expect("write");
    reload(caps, meta).await;
}

/// MIK-8038 `SHAPE.4` (A1): a partial reload keeps beta's subscription with
/// its route gone; a complete reload restoring beta narrower is refused.
#[tokio::test]
async fn a_narrower_restore_after_a_partial_reload_is_refused() {
    let (_root, store, d2, caps, registry, meta) = two_dirs().await;
    drop_d2(&d2, &caps, &meta).await;
    assert_eq!(routes(&registry), ["alpha.push"], "beta's route is gone");
    restore_d2(&d2, &narrower("beta"), &caps, &meta).await;
    assert_eq!(
        routes(&registry),
        ["alpha.push"],
        "the narrower restore is refused, the routes stay as they were"
    );
    assert!(
        subscribed(store.path(), "beta"),
        "and the subscription stays"
    );
}

/// MIK-8038 `SHAPE.2`-style pin (A4): a wider restore applies.
#[tokio::test]
async fn a_wider_restore_after_a_partial_reload_applies() {
    let (_root, store, d2, caps, registry, meta) = two_dirs().await;
    drop_d2(&d2, &caps, &meta).await;
    restore_d2(&d2, &wider("beta"), &caps, &meta).await;
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
    assert!(subscribed(store.path(), "beta"));
}

/// Pin (A5, A5b): with no stored subscription to beta, a narrower restore
/// applies; the retired shape protects subscribers, not routes.
#[tokio::test]
async fn a_narrower_restore_of_a_type_nobody_subscribes_to_applies() {
    let (_root, store, d2, caps, registry, meta) = two_dirs().await;
    drop_d2(&d2, &caps, &meta).await;
    let hub = meta.events().expect("hub");
    assert!(
        hub.withdraw(&["webhook.beta.push.received".to_owned()]),
        "unsubscribe beta"
    );
    assert!(!subscribed(store.path(), "beta"));
    restore_d2(&d2, &narrower("beta"), &caps, &meta).await;
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// Pin (A7): a refused restore changes nothing, and a second one is refused
/// too; the compatible restore then applies.
#[tokio::test]
async fn a_refused_restore_leaves_the_retired_shape_in_place() {
    let (_root, store, d2, caps, registry, meta) = two_dirs().await;
    drop_d2(&d2, &caps, &meta).await;
    restore_d2(&d2, &narrower("beta"), &caps, &meta).await;
    restore_d2(&d2, &narrower("beta"), &caps, &meta).await;
    assert_eq!(routes(&registry), ["alpha.push"], "refused twice");
    restore_d2(&d2, &capability("beta"), &caps, &meta).await;
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
    assert!(subscribed(store.path(), "beta"));
    // A second cycle retires the shape again.
    drop_d2(&d2, &caps, &meta).await;
    restore_d2(&d2, &narrower("beta"), &caps, &meta).await;
    assert_eq!(
        routes(&registry),
        ["alpha.push"],
        "refused in the second cycle"
    );
}

/// MIK-8038 `SHAPE.5` (A2): a reload removes beta but its withdraw fails
/// (the store cannot delete), so the subscription stays; a reload then
/// restoring beta narrower is refused.
#[cfg(unix)]
#[tokio::test]
async fn a_narrower_restore_after_a_failed_withdraw_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let (_root, store, d2, caps, registry, meta) = two_dirs().await;
    // Past the grace period, as a running gateway is: the reload withdraws
    // by state, and the locked store makes that withdraw fail.
    meta.run_deferred_webhook_withdraw().await;
    let subs = store.path().join("subs");
    std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(0o500)).expect("lock");
    std::fs::remove_file(d2.join("beta.yaml")).expect("remove beta");
    reload(&caps, &meta).await;
    std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(0o700)).expect("unlock");
    assert!(
        subscribed(store.path(), "beta"),
        "the failed withdraw kept it"
    );
    std::fs::write(d2.join("beta.yaml"), narrower("beta")).expect("write");
    reload(&caps, &meta).await;
    assert_eq!(
        routes(&registry),
        ["alpha.push"],
        "the narrower restore is refused"
    );
    assert!(subscribed(store.path(), "beta"));
}
