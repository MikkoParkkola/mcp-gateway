// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A capability reload that lands before the startup scan completes must
//! not be lost (MIK-7862, found in review of #2732).

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::{EventsConfig, WebhookConfig};
use crate::gateway::WebhookRegistry;

fn capability(name: &str) -> String {
    format!(
        "name: {name}\ndescription: hooks\nschema:\n  input: {{ type: object, properties: {{}} }}\n  \
         output: {{ type: object }}\nproviders: {{}}\nwebhooks:\n  push:\n    path: /{name}/push\n    \
         method: POST\n    transform:\n      event_type: \"{name}.push\"\n      data: {{ ref: \"{{ref}}\" }}\n    \
         event:\n      description: \"A push.\"\n      filters: [ref]\n"
    )
}

fn routes(registry: &Arc<parking_lot::RwLock<WebhookRegistry>>) -> Vec<String> {
    let mut names: Vec<String> = registry
        .read()
        .event_routes()
        .into_iter()
        .map(|(cap, route, _)| format!("{cap}.{route}"))
        .collect();
    names.sort();
    names
}

/// Store a subscription to capability `cap`'s push event in the events store
/// at `store`, as an earlier run left it: the hub loads it when it opens.
fn seed_subscription(store: &std::path::Path, cap: &str) {
    seed_named(store, cap, &format!("webhook.{cap}.push.received"));
}
/// A subscription to event type `name`, found by [`subscribed`] under `key`.
fn seed_named(store: &std::path::Path, key: &str, name: &str) {
    use std::io::Write as _;
    // Private from creation, as the store writes them: the load refuses a
    // loosened record (on Windows, an inherited DACL), so the hub would not
    // know a subscription seeded with plain `std::fs` calls.
    let subs = store.join("subs");
    if !subs.exists() {
        #[cfg(windows)]
        {
            crate::private_fs::create_dir_private(&subs).expect("subs dir");
        }
        #[cfg(not(windows))]
        {
            std::fs::create_dir_all(&subs).expect("subs dir");
        }
    }
    let row = serde_json::json!({
        "v": 1, "id": format!("sub_{key}"), "principal": "p",
        "url": "https://p.example/cb", "name": name,
        "arguments": {}, "secret": "whsec_x", "previous_secret": null,
        "previous_until": null, "granted_at": chrono::Utc::now(), "expires_at": null,
        "active": true, "failed_since": null, "last_delivery_at": null, "last_error": null
    });
    let file = subs.join(format!("sub_{key}.json"));
    crate::config_persistence::create_new_private(&file)
        .and_then(|mut f| f.write_all(&serde_json::to_vec(&row).expect("json")))
        .expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
}

/// Whether the subscription [`seed_subscription`] stored for `cap` is still there.
fn subscribed(store: &std::path::Path, cap: &str) -> bool {
    store.join("subs").join(format!("sub_{cap}.json")).exists()
}

/// Poll `done` for up to 10 s.
async fn settled(mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The reload arrives while the scan is still running: it is held, then
/// applied once the scan completes, so the new route is registered.
#[tokio::test]
async fn a_reload_during_the_startup_scan_is_applied_when_it_completes() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    let caps = Arc::new(CapabilityBackend::new(
        "hooks",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.begin_initial_scan();
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("load");
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    )));
    for cap in caps.list_capabilities() {
        registry.write().register_capability(&cap);
    }
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));
    meta.set_webhook_registry(Arc::clone(&registry));
    let hub = EventsHub::open(&EventsConfig::default(), store.path()).expect("hub");
    hub.set_webhook_registry(Arc::clone(&registry));
    meta.set_events(hub);

    // The reload lands mid-scan: a second webhook capability appears.
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("reload");
    meta.events_capabilities_reloaded("hooks");
    assert_eq!(routes(&registry), ["alpha.push"], "held while scanning");

    caps.mark_initial_scan_complete();
    meta.reconcile_events_after_scan();
    let mut applied = false;
    for _ in 0..100 {
        if routes(&registry) == ["alpha.push", "beta.push"] {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        applied,
        "the held reload was applied: {:?}",
        routes(&registry)
    );
}

type Registry = Arc<parking_lot::RwLock<WebhookRegistry>>;

/// A capability backend that has scanned `dirs` and is still marked as
/// scanning, its routes registered from what that scan read, and a `MetaMcp`
/// wired to an events hub on `store` (which loads any seeded subscriptions).
async fn wired(
    dirs: &[&std::path::Path],
    store: &std::path::Path,
) -> (Arc<CapabilityBackend>, Registry, MetaMcp) {
    let caps = Arc::new(CapabilityBackend::new(
        "hooks",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.begin_initial_scan();
    for dir in dirs {
        caps.load_from_directory(dir.to_str().expect("utf8"))
            .await
            .expect("load");
    }
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    )));
    for cap in caps.list_capabilities() {
        registry.write().register_capability(&cap);
    }
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));
    meta.set_webhook_registry(Arc::clone(&registry));
    let hub = EventsHub::open(&EventsConfig::default(), store).expect("hub");
    hub.set_webhook_registry(Arc::clone(&registry));
    meta.set_events(hub);
    (caps, registry, meta)
}

/// MIK-7944 finding 1: a reload that lands during the startup scan, but
/// whose notice the drain has not handled yet, is still in the routes the
/// startup reconcile checks, so its type's subscriptions are kept.
#[tokio::test]
async fn an_unannounced_reload_during_the_scan_keeps_its_subscriptions() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    seed_subscription(store.path(), "beta");
    let (caps, registry, meta) = wired(&[dir.path()], store.path()).await;

    // The reload lands mid-scan; no notice reaches the drain.
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    caps.load_from_directory(dir.path().to_str().expect("utf8"))
        .await
        .expect("reload");
    caps.mark_initial_scan_complete();
    meta.reconcile_events_after_scan();
    settled(|| !subscribed(store.path(), "beta") || routes(&registry).len() == 2).await;
    // Past any withdrawal the reconcile would make.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        subscribed(store.path(), "beta"),
        "the beta subscription survives the startup reconcile"
    );
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// MIK-8028 `PARTIAL.1`: a hot reload that cannot read one directory keeps
/// that directory's subscriptions; its routes go, so nothing is delivered.
#[tokio::test]
async fn a_reload_that_cannot_read_a_directory_keeps_its_subscriptions() {
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

    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        subscribed(store.path(), "beta"),
        "the unread directory's subscription is kept"
    );
    assert!(subscribed(store.path(), "alpha"));
    assert_eq!(routes(&registry), ["alpha.push"], "beta is unoffered");
}

/// MIK-8028 `PARTIAL.1`, at startup: a scan that could not read a directory
/// keeps that directory's subscriptions through the startup reconcile.
#[tokio::test]
async fn a_startup_scan_that_cannot_read_a_directory_keeps_its_subscriptions() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    seed_subscription(store.path(), "beta");
    seed_sentinel(store.path());
    let (caps, registry, meta) = wired(&[dir.path()], store.path()).await;

    // Beta's directory failed to load.
    caps.mark_initial_scan_failed();
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;
    assert!(
        subscribed(store.path(), "beta"),
        "the unread directory's subscription is kept"
    );
    assert_eq!(routes(&registry), ["alpha.push"]);
}

/// Run the startup reconcile and wait for its first pass. The store must
/// hold the `gone` sentinel ([`seed_sentinel`]): it is withdrawn under the
/// reconcile's catalogue gate, and taking the gate then waits for the
/// webhook decision that follows under the same hold.
async fn first_pass(meta: &MetaMcp, store: &std::path::Path) {
    meta.reconcile_events_after_scan();
    settled(|| !subscribed(store, "gone")).await;
    drop(meta.events().expect("hub").catalogue_lock());
    assert!(!subscribed(store, "gone"), "the startup reconcile ran");
}

/// A subscription to a backend no registry has: every startup reconcile
/// withdraws it, just before its webhook decision.
fn seed_sentinel(store: &std::path::Path) {
    seed_named(store, "gone", "backend.gone.tools_changed");
}

/// MIK-8028 `PARTIAL.2`: the next complete reload withdraws a type that is
/// still absent, and keeps the rest.
#[tokio::test]
async fn the_next_complete_reload_withdraws_a_type_still_absent() {
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
    // Past the startup grace period (MIK-8027), as a running gateway is.
    meta.run_deferred_webhook_withdraw().await;

    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        subscribed(store.path(), "beta"),
        "kept through the partial reload"
    );

    // D2 is readable again, without beta: this load is complete.
    std::fs::create_dir_all(&d2).expect("restore d2");
    caps.reload().await.expect("complete reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        !subscribed(store.path(), "beta"),
        "withdrawn once a complete load still lacks it"
    );
    assert!(subscribed(store.path(), "alpha"));
}

/// MIK-8028 `PARTIAL.1`: a partial reload still withdraws a type whose
/// capability it did read, when that capability no longer offers it.
#[tokio::test]
async fn a_partial_reload_withdraws_a_route_a_read_capability_dropped() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    // Alpha's second route, which the reload keeps.
    let pull = "  pull:\n    path: /alpha/pull\n    method: POST\n    transform:\n      \
                event_type: \"alpha.pull\"\n      data: { ref: \"{ref}\" }\n    event:\n      \
                description: \"A pull.\"\n      filters: [ref]\n";
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
        seed_subscription(store.path(), cap);
    }
    std::fs::write(d1.join("alpha.yaml"), capability("alpha") + pull).expect("alpha pull");
    seed_named(store.path(), "alpha_pull", "webhook.alpha.pull.received");
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();

    // Alpha is read again with its pull route only; beta's directory is not.
    let bare = capability("alpha");
    let bare = bare.split("webhooks:").next().expect("head");
    std::fs::write(d1.join("alpha.yaml"), format!("{bare}webhooks:\n{pull}"))
        .expect("rewrite alpha");
    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    meta.events_capabilities_reloaded("hooks");
    assert!(
        !subscribed(store.path(), "alpha"),
        "a read capability's dropped route is withdrawn"
    );
    assert!(
        subscribed(store.path(), "alpha_pull"),
        "the read capability's kept route keeps its subscription"
    );
    assert!(
        subscribed(store.path(), "beta"),
        "the unread directory's subscription is kept"
    );
}

/// MIK-8037 `WATCHGONE.3`: the watch catalogue reads completeness with its
/// contents: incomplete until the startup scan completes, incomplete after a
/// reload that could not read a directory (and without that directory's
/// capabilities), complete once every directory loads again. `present` names
/// every capability read, REST-served or not.
#[tokio::test]
async fn the_watch_catalogue_reports_a_partial_load() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    for (dir, cap) in [(&d1, "alpha"), (&d2, "beta")] {
        std::fs::create_dir_all(dir).expect("dir");
        std::fs::write(dir.join(format!("{cap}.yaml")), capability(cap)).expect("write");
    }
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    assert!(
        !meta.watch_catalogue().complete,
        "the scan is still running"
    );
    caps.mark_initial_scan_complete();
    let whole = meta.watch_catalogue();
    assert!(whole.complete, "every directory read");
    assert!(whole.present.contains("alpha") && whole.present.contains("beta"));
    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    let partial = meta.watch_catalogue();
    assert!(!partial.complete, "a directory was not read");
    assert!(partial.present.contains("alpha") && !partial.present.contains("beta"));
    std::fs::create_dir_all(&d2).expect("dir");
    std::fs::write(d2.join("beta.yaml"), capability("beta")).expect("write");
    caps.reload().await.expect("complete reload");
    assert!(
        meta.watch_catalogue().complete,
        "every directory read again"
    );
}

/// MIK-8037: every catalogue write moves the generation the watch source
/// compares before it revokes: a reload, an unload and a registration.
#[tokio::test]
async fn every_catalogue_write_moves_the_generation() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(root.path().join("alpha.yaml"), capability("alpha")).expect("write");
    let (caps, _registry, _meta) = wired(&[root.path()], store.path()).await;
    let start = caps.catalogue_generation();
    caps.reload().await.expect("reload");
    let reloaded = caps.catalogue_generation();
    assert!(reloaded > start, "a reload");
    assert!(caps.unload_capability("alpha"), "unloaded");
    let unloaded = caps.catalogue_generation();
    assert!(unloaded > reloaded, "an unload");
    caps.load_from_directory(root.path().to_str().expect("utf8"))
        .await
        .expect("register");
    assert!(caps.catalogue_generation() > unloaded, "a registration");
}

/// `capability(name)` with an account the gate cannot resolve: its directory
/// reads, and the admission gate refuses it.
fn refused(name: &str) -> String {
    format!("{}auth:\n  account: missing\n", capability(name))
}

/// A backend whose `d1` holds `alpha`, and whose `d2` holds `beta` and the
/// refused `gamma`, after a complete startup scan; and its watch view.
async fn with_refused(root: &std::path::Path) -> (Arc<CapabilityBackend>, MetaMcp) {
    let (d1, d2) = (root.join("d1"), root.join("d2"));
    for dir in [&d1, &d2] {
        std::fs::create_dir_all(dir).expect("dir");
    }
    std::fs::write(d1.join("alpha.yaml"), capability("alpha")).expect("write");
    std::fs::write(d2.join("beta.yaml"), capability("beta")).expect("write");
    std::fs::write(d2.join("gamma.yaml"), refused("gamma")).expect("write");
    let accounts = Arc::new(crate::identity_propagation::AccountStrategyRegistry::default());
    let executor = CapabilityExecutor::new().with_account_strategies(accounts);
    let caps = Arc::new(CapabilityBackend::new("hooks", Arc::new(executor)));
    caps.begin_initial_scan();
    for dir in [&d1, &d2] {
        let dir = dir.to_str().expect("utf8");
        caps.load_from_directory(dir).await.expect("load");
    }
    caps.mark_initial_scan_complete();
    assert!(!caps.has_capability("gamma"), "the gate refused it");
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(Arc::clone(&caps));
    (caps, meta)
}

/// MIK-8037 (review of #3406): a capability the startup load read but the
/// account gate refused is read, not unread, so its absence is confirmed.
#[tokio::test]
async fn a_capability_refused_at_load_counts_as_read() {
    let root = tempfile::tempdir().expect("root");
    let (_caps, meta) = with_refused(root.path()).await;
    assert!(meta.watch_catalogue().present.contains("gamma"), "read");
}

/// MIK-8037 (review of #3406): a partial reload counts as read what the gate
/// refused in a directory it read, and only that: a capability refused
/// earlier in the directory it could not read is unread again.
#[tokio::test]
async fn a_capability_refused_at_a_partial_reload_counts_as_read() {
    let root = tempfile::tempdir().expect("root");
    let (caps, meta) = with_refused(root.path()).await;
    let d1 = root.path().join("d1");
    std::fs::write(d1.join("delta.yaml"), refused("delta")).expect("write");
    std::fs::remove_dir_all(root.path().join("d2")).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    let partial = meta.watch_catalogue();
    assert!(!partial.complete, "a directory was not read");
    assert!(partial.present.contains("delta"), "read, then refused");
    assert!(!partial.present.contains("beta"), "unread");
    assert!(
        !partial.present.contains("gamma"),
        "refused before, unread now"
    );
}

/// MIK-8037 (review of #3406): an unload, a rug-pull quarantine's for one,
/// is a confirmed removal: a partial catalogue counts the unloaded capability
/// as read, so its subscriptions end rather than wait for a complete load.
/// An unload of a name not loaded marks nothing.
#[tokio::test]
async fn an_unloaded_capability_counts_as_read_in_a_partial_catalogue() {
    let root = tempfile::tempdir().expect("root");
    let (caps, meta) = with_refused(root.path()).await;
    std::fs::remove_dir_all(root.path().join("d2")).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    assert!(caps.unload_capability("alpha"), "unloaded");
    assert!(
        !caps.unload_capability("beta"),
        "not loaded: nothing to unload"
    );
    let partial = meta.watch_catalogue();
    assert!(!partial.complete, "a directory was not read");
    assert!(partial.present.contains("alpha"), "removed, not unread");
    assert!(!partial.present.contains("beta"), "still unread");
}

/// MIK-8037 (review of #3406): a rug-pull quarantine unloads a capability and
/// the reload that follows cannot load its file back; when that reload is
/// partial, the unload still counts as read.
#[tokio::test]
async fn an_unload_survives_a_partial_reload_that_cannot_restore_it() {
    let root = tempfile::tempdir().expect("root");
    let (caps, meta) = with_refused(root.path()).await;
    let d1 = root.path().join("d1");
    assert!(caps.unload_capability("alpha"), "unloaded");
    std::fs::remove_file(d1.join("alpha.yaml")).expect("its file no longer loads");
    std::fs::remove_dir_all(root.path().join("d2")).expect("make d2 unreadable");
    caps.reload().await.expect("partial reload");
    let partial = meta.watch_catalogue();
    assert!(!partial.complete, "a directory was not read");
    assert!(partial.present.contains("alpha"), "unloaded, not unread");
}

/// MIK-8037 (review of #3406): admitting a name again clears its unload mark,
/// so once its own directory goes unread it is unread like any other.
#[tokio::test]
async fn an_admission_clears_the_unload_mark() {
    let root = tempfile::tempdir().expect("root");
    let (caps, meta) = with_refused(root.path()).await;
    assert!(caps.unload_capability("alpha"), "unloaded");
    caps.reload().await.expect("complete reload");
    assert!(caps.has_capability("alpha"), "admitted again");
    std::fs::remove_dir_all(root.path().join("d1")).expect("make d1 unreadable");
    caps.reload().await.expect("partial reload");
    let partial = meta.watch_catalogue();
    assert!(!partial.complete, "a directory was not read");
    assert!(!partial.present.contains("alpha"), "unread, not unloaded");
}

/// Alpha scanned, a beta subscription stored, and the startup reconcile's
/// first pass over: where every grace-period row (MIK-8027) starts.
async fn after_first_pass() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<CapabilityBackend>,
    Registry,
    MetaMcp,
) {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    seed_subscription(store.path(), "beta");
    seed_sentinel(store.path());
    let (caps, registry, meta) = wired(&[dir.path()], store.path()).await;
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;
    (dir, store, caps, registry, meta)
}

/// A hot reload and its notice, as the capability watcher delivers them.
async fn reload(caps: &CapabilityBackend, meta: &MetaMcp) {
    caps.reload().await.expect("reload");
    meta.events_capabilities_reloaded("hooks");
}

/// MIK-8027 `RESID.1`: a reload inside the grace period that offers beta
/// keeps the subscription the startup pass found unoffered.
#[tokio::test]
async fn a_type_a_reload_offers_inside_the_grace_period_keeps_its_subscription() {
    let (dir, store, caps, registry, meta) = after_first_pass().await;
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    reload(&caps, &meta).await;
    meta.run_deferred_webhook_withdraw().await;
    assert!(
        subscribed(store.path(), "beta"),
        "beta's subscription outlives the startup pass"
    );
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// MIK-8027 `RESID.3`: a type nothing offers again is still withdrawn, by
/// the deferred pass.
#[tokio::test]
async fn a_type_nothing_offers_again_is_withdrawn_by_the_deferred_pass() {
    let (_dir, store, _caps, _registry, meta) = after_first_pass().await;
    meta.run_deferred_webhook_withdraw().await;
    assert!(!subscribed(store.path(), "beta"));
}

/// The deferred pass withdraws nothing from a partial catalogue.
#[tokio::test]
async fn the_deferred_pass_withdraws_nothing_from_a_partial_catalogue() {
    let root = tempfile::tempdir().expect("root");
    let store = tempfile::tempdir().expect("store");
    let (d1, d2) = (root.path().join("d1"), root.path().join("d2"));
    std::fs::create_dir_all(&d1).expect("d1");
    std::fs::create_dir_all(&d2).expect("d2");
    std::fs::write(d1.join("a.yaml"), capability("alpha")).expect("write");
    seed_subscription(store.path(), "beta");
    seed_sentinel(store.path());
    let (caps, _registry, meta) = wired(&[&d1, &d2], store.path()).await;
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;

    std::fs::remove_dir_all(&d2).expect("make d2 unreadable");
    reload(&caps, &meta).await;
    meta.run_deferred_webhook_withdraw().await;
    assert!(
        subscribed(store.path(), "beta"),
        "a partial catalogue proves nothing about beta"
    );
}

/// An unrelated reload inside the grace period withdraws nothing it did
/// not remove; a later reload that offers beta keeps beta's subscription.
#[tokio::test]
async fn an_unrelated_reload_inside_the_grace_period_keeps_an_unoffered_type() {
    let (dir, store, caps, registry, meta) = after_first_pass().await;
    let alpha = capability("alpha") + "# edited\n";
    std::fs::write(dir.path().join("a.yaml"), alpha).expect("edit alpha");
    reload(&caps, &meta).await;
    assert!(
        subscribed(store.path(), "beta"),
        "an unrelated reload keeps beta"
    );
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    reload(&caps, &meta).await;
    meta.run_deferred_webhook_withdraw().await;
    assert!(subscribed(store.path(), "beta"));
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// A type kept through the grace period is withdrawn by the deferred pass
/// when nothing has offered it: a deferral, never a retention.
#[tokio::test]
async fn a_type_still_unoffered_at_the_deadline_is_withdrawn_then() {
    let (dir, store, caps, _registry, meta) = after_first_pass().await;
    let alpha = capability("alpha") + "# edited\n";
    std::fs::write(dir.path().join("a.yaml"), alpha).expect("edit alpha");
    reload(&caps, &meta).await;
    assert!(
        subscribed(store.path(), "beta"),
        "kept inside the grace period"
    );
    meta.run_deferred_webhook_withdraw().await;
    assert!(
        !subscribed(store.path(), "beta"),
        "withdrawn at the deadline"
    );
}

/// A reload whose notice has not arrived is applied by the deferred pass,
/// which refreshes the routes before it decides.
#[tokio::test]
async fn an_unannounced_reload_is_applied_by_the_deferred_pass() {
    let (dir, store, caps, registry, meta) = after_first_pass().await;
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    caps.reload().await.expect("reload, notice still queued");
    meta.run_deferred_webhook_withdraw().await;
    assert!(subscribed(store.path(), "beta"));
    assert_eq!(routes(&registry), ["alpha.push", "beta.push"]);
}

/// A refresh of beta inside the grace period answers `-32011` and leaves
/// beta's stored row as it was.
#[tokio::test]
async fn a_refresh_inside_the_grace_period_answers_not_found_and_keeps_the_row() {
    let (_dir, store, _caps, _registry, meta) = after_first_pass().await;
    let row = store.path().join("subs").join("sub_beta.json");
    let before = std::fs::read(&row).ok();
    assert!(before.is_some(), "beta's row outlives the startup pass");
    let caller = crate::events::Caller {
        principal: Some("p".to_owned()),
        read_key: None,
        credential: crate::events::Credential {
            kind: crate::security::audit::CredentialKind::None,
            principal: String::new(),
            api_key: None,
            expires_at: None,
            binding: None,
        },
        visible_backends: std::collections::HashSet::new(),
        admin: false,
    };
    let params = serde_json::json!({ "name": "webhook.beta.push.received" });
    let refused = meta
        .events()
        .expect("hub")
        .subscribe(&caller, Some(&params))
        .await
        .expect_err("beta is not offered");
    assert_eq!(refused.code, -32011);
    assert_eq!(
        std::fs::read(&row).ok(),
        before,
        "the refresh wrote nothing"
    );
}

/// A reload inside the grace period that removes a route the startup scan
/// registered withdraws its subscription at once, as outside it.
#[tokio::test]
async fn a_route_a_reload_removes_inside_the_grace_period_is_withdrawn_at_once() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    seed_subscription(store.path(), "beta");
    seed_sentinel(store.path());
    let (caps, _registry, meta) = wired(&[dir.path()], store.path()).await;
    caps.mark_initial_scan_complete();
    first_pass(&meta, store.path()).await;
    assert!(subscribed(store.path(), "beta"), "beta is offered");

    std::fs::remove_file(dir.path().join("b.yaml")).expect("remove beta");
    reload(&caps, &meta).await;
    assert!(
        !subscribed(store.path(), "beta"),
        "the removal withdraws it"
    );
}

/// A route the startup scan registered and an unannounced reload removed
/// before the first pass is withdrawn by that pass, as a reload inside the
/// grace period withdraws what it removes: a narrower restore must not
/// inherit the subscription.
#[tokio::test]
async fn a_route_removed_before_the_first_pass_is_withdrawn_by_it() {
    let dir = tempfile::tempdir().expect("dir");
    let store = tempfile::tempdir().expect("store");
    std::fs::write(dir.path().join("a.yaml"), capability("alpha")).expect("write");
    std::fs::write(dir.path().join("b.yaml"), capability("beta")).expect("write");
    seed_subscription(store.path(), "alpha");
    seed_subscription(store.path(), "beta");
    seed_sentinel(store.path());
    let (caps, registry, meta) = wired(&[dir.path()], store.path()).await;
    caps.mark_initial_scan_complete();
    std::fs::remove_file(dir.path().join("b.yaml")).expect("remove beta");
    caps.reload()
        .await
        .expect("reload, its notice not yet handled");
    first_pass(&meta, store.path()).await;
    assert_eq!(routes(&registry), ["alpha.push"]);
    assert!(
        !subscribed(store.path(), "beta"),
        "the first pass withdraws the type its refresh removed"
    );
    assert!(subscribed(store.path(), "alpha"), "and nothing else");
}
