// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config watcher follows its link chain (#453).
//!
//! The real-watcher rows run on Linux only: inotify is what the `ConfigMap`
//! deployment runs on, and macOS `FSEvents` ignores `NonRecursive`, so a green
//! there could come from a directory the design never asked to watch.

use std::collections::BTreeSet;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::chain_dirs;

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonical")
}

fn set(dirs: &[&Path]) -> BTreeSet<PathBuf> {
    dirs.iter().map(|d| canonical(d)).collect()
}

/// Point `link` at `target` atomically, the way a deploy does: a new link
/// renamed over the old one.
fn retarget(link: &Path, target: &Path) {
    // Named from the whole file name, not `with_extension`: for a dot-led
    // name like `..data` that can land on the link itself.
    let name = link.file_name().expect("link name").to_string_lossy();
    let tmp = link.with_file_name(format!("{name}.retarget-tmp"));
    symlink(target, &tmp).expect("tmp link");
    std::fs::rename(&tmp, link).expect("rename over link");
}

/// T6c: every hop's directory, canonical, and never the `..data` link path.
#[test]
fn t6c_chain_dirs_names_every_hop_and_no_link_directory() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("cfg");
    let ts1 = cfg.join("..ts1");
    std::fs::create_dir_all(&ts1).unwrap();
    std::fs::write(ts1.join("gateway.yaml"), "a: 1\n").unwrap();
    symlink("..ts1", cfg.join("..data")).unwrap();
    symlink("..data/gateway.yaml", cfg.join("gateway.yaml")).unwrap();

    let (dirs, end) = chain_dirs(&cfg.join("gateway.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&cfg, &ts1]));
    assert_eq!(end, canonical(&ts1.join("gateway.yaml")));
    assert!(
        dirs.contains(&canonical(&cfg)),
        "the named link's directory stays in the set"
    );
}

/// T6c (mid-chain): a link in a third directory is part of the chain.
#[test]
fn t6c_a_mid_chain_link_directory_is_in_the_set() {
    let root = tempfile::tempdir().expect("root");
    let (c, d, e) = (
        root.path().join("c"),
        root.path().join("d"),
        root.path().join("e"),
    );
    for dir in [&c, &d, &e] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(e.join("cfg.yaml"), "a: 1\n").unwrap();
    symlink(e.join("cfg.yaml"), d.join("l2")).unwrap();
    symlink(d.join("l2"), c.join("l")).unwrap();

    let (dirs, _) = chain_dirs(&c.join("l")).expect("chain");
    assert_eq!(dirs, set(&[&c, &d, &e]));
}

/// T6: a link cycle ends at the hop bound instead of looping.
#[test]
fn t6_a_link_cycle_is_an_error_not_a_hang() {
    let root = tempfile::tempdir().expect("root");
    let (a, b) = (root.path().join("a"), root.path().join("b"));
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    assert!(chain_dirs(&a).is_err());
}

/// `R/current -> <target>` beside `R/rel1/cfg.yaml`: the Capistrano layout.
fn release_link(root: &Path, target: &Path) -> PathBuf {
    let r = root.join("R");
    std::fs::create_dir_all(r.join("rel1")).unwrap();
    std::fs::write(r.join("rel1").join("cfg.yaml"), "a: 1\n").unwrap();
    symlink(target, r.join("current")).unwrap();
    r
}

/// T6d: a directory link that is the file's own parent is followed, and the
/// directory holding it is in the set.
#[test]
fn t6d_a_release_directory_link_and_its_holder_are_in_the_set() {
    let root = tempfile::tempdir().expect("root");
    let r = release_link(root.path(), Path::new("rel1"));
    let (dirs, end) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &r.join("rel1")]));
    assert_eq!(end, canonical(&r.join("rel1").join("cfg.yaml")));
}

/// T6e: a relative directory-link target with `..`.
#[test]
fn t6e_a_relative_target_with_parent_components() {
    let root = tempfile::tempdir().expect("root");
    let other = root.path().join("other").join("rel1");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("cfg.yaml"), "a: 1\n").unwrap();
    let r = root.path().join("R");
    std::fs::create_dir_all(&r).unwrap();
    symlink("../other/rel1", r.join("current")).unwrap();
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &other]));
}

/// T6f: an absolute directory-link target.
#[test]
fn t6f_an_absolute_target() {
    let root = tempfile::tempdir().expect("root");
    let abs = root.path().join("R").join("rel1");
    let r = release_link(root.path(), &abs);
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &abs]));
}

/// T6g: a directory link to a directory link held in another directory.
#[test]
fn t6g_a_directory_link_chain_across_directories() {
    let root = tempfile::tempdir().expect("root");
    let (r, s) = (root.path().join("R"), root.path().join("S"));
    std::fs::create_dir_all(s.join("rel1")).unwrap();
    std::fs::create_dir_all(&r).unwrap();
    std::fs::write(s.join("rel1").join("cfg.yaml"), "a: 1\n").unwrap();
    symlink("rel1", s.join("mid")).unwrap();
    symlink(s.join("mid"), r.join("current")).unwrap();
    let (dirs, _) = chain_dirs(&r.join("current").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&r, &s, &s.join("rel1")]));
}

/// T6h: a directory link above the file's immediate parent is resolved, not
/// watched: its holder is not in the set.
#[test]
fn t6h_a_high_directory_link_is_not_watched() {
    let root = tempfile::tempdir().expect("root");
    let sub = root.path().join("real").join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("cfg.yaml"), "a: 1\n").unwrap();
    symlink(root.path().join("real"), root.path().join("hi")).unwrap();
    let (dirs, _) =
        chain_dirs(&root.path().join("hi").join("sub").join("cfg.yaml")).expect("chain");
    assert_eq!(dirs, set(&[&sub]));
}

/// T6 (directory links): a directory-link cycle ends at the same bound.
#[test]
fn t6_a_directory_link_cycle_is_an_error_not_a_hang() {
    let root = tempfile::tempdir().expect("root");
    let r = root.path().join("R");
    std::fs::create_dir_all(&r).unwrap();
    symlink("b", r.join("a")).unwrap();
    symlink("a", r.join("b")).unwrap();
    assert!(chain_dirs(&r.join("a").join("cfg.yaml")).is_err());
}

/// T9: an env-file directory that is not watched is not protected, so the
/// chain can still watch it when the config lives there too.
#[test]
fn t9_an_env_directory_that_was_not_watched_is_not_protected() {
    let root = tempfile::tempdir().expect("root");
    let mut watcher = notify::recommended_watcher(|_| {}).expect("watcher");
    let missing = root.path().join("missing").join(".env");
    assert!(super::watch_env_dirs(&mut watcher, &[missing]).is_empty());
}

/// T12: a directory that cannot be watched warns once until it leaves the
/// wanted set, and again if it comes back and still fails.
#[test]
fn t12_a_repeated_watch_failure_warns_once() {
    use std::sync::atomic::Ordering;
    let root = tempfile::tempdir().expect("root");
    let missing = root.path().join("missing");
    let watcher = notify::recommended_watcher(|_| {}).expect("watcher");
    let chain = super::ChainWatch::new(watcher, BTreeSet::new());
    let wanted = BTreeSet::from([missing.clone()]);
    chain.reconcile(&wanted);
    chain.reconcile(&wanted);
    assert_eq!(
        chain.watch_warnings.load(Ordering::SeqCst),
        1,
        "warned per retry"
    );
    chain.reconcile(&BTreeSet::new());
    chain.reconcile(&wanted);
    assert_eq!(
        chain.watch_warnings.load(Ordering::SeqCst),
        2,
        "a directory that left the chain was never forgotten"
    );
}

/// T14: the config path keeps a directory link, where the parent-resolving
/// form used for event matching erases it.
#[test]
fn t14_the_named_config_path_keeps_its_directory_link() {
    let root = tempfile::tempdir().expect("root");
    let r = release_link(root.path(), Path::new("rel1"));
    let named = r.join("current").join("cfg.yaml");
    let resolved = crate::config_reload::absolute_watch_path(named.clone());
    assert_ne!(resolved, named, "premise: event matching resolves the link");
    assert_eq!(
        crate::config_reload::named_config_path(named.clone()),
        named
    );
}

#[cfg(target_os = "linux")]
mod real_watcher {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::super::{ChainWatch, spawn_rewatch_task};
    use super::*;
    use crate::config_reload::{ConfigWatcher, ReloadTrigger};

    struct Harness {
        chain: Arc<ChainWatch>,
        events: tokio::sync::mpsc::Receiver<ReloadTrigger>,
        shutdown: tokio::sync::broadcast::Sender<()>,
        task: tokio::task::JoinHandle<()>,
    }

    fn start(named: &Path) -> Harness {
        let (tx, events) = tokio::sync::mpsc::channel(32);
        let (wake_tx, mut wake_rx) = tokio::sync::watch::channel(());
        let (shutdown, _) = tokio::sync::broadcast::channel(1);
        // As `ConfigWatcher::start` does: the operator's path, made absolute
        // without resolving links, and one resolve once the watches are live.
        let named = crate::config_reload::named_config_path(named.to_path_buf());
        let chain = ConfigWatcher::create_notify_watcher(tx.clone(), wake_tx, &named, &[])
            .expect("watcher starts");
        wake_rx.mark_changed();
        let task = spawn_rewatch_task(named, Arc::clone(&chain), wake_rx, tx, shutdown.subscribe());
        Harness {
            chain,
            events,
            shutdown,
            task,
        }
    }

    impl Harness {
        /// Swallow triggers until a full second passes without one. A closed
        /// channel (every sender dropped, as after shutdown) is idle too.
        async fn drain_idle(&mut self) {
            while let Ok(Some(_)) =
                tokio::time::timeout(Duration::from_secs(1), self.events.recv()).await
            {}
        }

        /// At least one trigger within `secs`. A closed channel is none.
        async fn triggered_within(&mut self, secs: u64) -> bool {
            matches!(
                tokio::time::timeout(Duration::from_secs(secs), self.events.recv()).await,
                Ok(Some(_))
            )
        }

        /// Wakes the rewatch task has finished handling.
        fn wakes(&self) -> usize {
            self.chain.wakes_handled.load(Ordering::SeqCst)
        }

        /// Wait until the task has handled more than `seen` wakes.
        async fn wait_wakes_above(&self, seen: usize) {
            tokio::time::timeout(Duration::from_secs(10), async {
                while self.wakes() <= seen {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("the rewatch task never handled wake {}", seen + 1));
        }

        /// Wait until the ledger holds `dir`: the watch is in place.
        async fn wait_watched(&self, dir: &Path) {
            let dir = canonical(dir);
            tokio::time::timeout(Duration::from_secs(10), async {
                while !self.chain.watched().contains(&dir) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{} was never watched", dir.display()));
        }
    }

    /// `C/L -> A/cfg.yaml`, with B holding the next release.
    fn release_tree() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let (a, b, c) = (
            root.path().join("a"),
            root.path().join("b"),
            root.path().join("c"),
        );
        for dir in [&a, &b, &c] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(a.join("cfg.yaml"), "a: 1\n").unwrap();
        std::fs::write(b.join("cfg.yaml"), "b: 1\n").unwrap();
        symlink(a.join("cfg.yaml"), c.join("l")).unwrap();
        (root, a, b, c)
    }

    /// T1 (RELOAD.1, .3): after a retarget across directories, a write to the
    /// new target reloads.
    #[tokio::test]
    async fn t1_a_write_to_a_retargeted_link_in_another_directory_reloads() {
        let (_root, _a, b, c) = release_tree();
        let mut h = start(&c.join("l"));
        retarget(&c.join("l"), &b.join("cfg.yaml"));
        h.wait_watched(&b).await;
        h.drain_idle().await;
        std::fs::write(b.join("cfg.yaml"), "b: 2\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "a write to the new target reloaded nothing"
        );
        let _ = h.shutdown.send(());
    }

    /// T3 (RELOAD.2): a directory the chain has left is no longer watched.
    #[tokio::test]
    async fn t3_a_directory_left_by_the_chain_is_unwatched() {
        let (_root, a, b, c) = release_tree();
        let h = start(&c.join("l"));
        assert_eq!(
            h.chain.watched(),
            set(&[&a, &c]),
            "premise: startup watches A and C"
        );
        retarget(&c.join("l"), &b.join("cfg.yaml"));
        h.wait_watched(&b).await;
        assert_eq!(h.chain.watched(), set(&[&b, &c]), "A is still watched");
        let _ = h.shutdown.send(());
    }

    /// T8: a retarget by unlink and re-create is followed. The re-create is
    /// an event on the named link itself.
    #[tokio::test]
    async fn t8_an_unlink_and_relink_retarget_is_followed() {
        let (_root, a, b, c) = release_tree();
        let mut h = start(&c.join("l"));
        h.wait_wakes_above(0).await;
        let seen = h.wakes();
        std::fs::remove_file(c.join("l")).unwrap();
        h.wait_wakes_above(seen).await;
        assert_eq!(
            h.chain.watched(),
            set(&[&a, &c]),
            "the last good set was dropped"
        );
        symlink(b.join("cfg.yaml"), c.join("l")).unwrap();
        h.wait_watched(&b).await;
        h.drain_idle().await;
        std::fs::write(b.join("cfg.yaml"), "b: 2\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "a write to the relinked target reloaded nothing"
        );
        let _ = h.shutdown.send(());
    }

    /// T10: a chain that cannot resolve (the target deleted mid-update) keeps
    /// the last good watches.
    #[tokio::test]
    async fn t10_an_unresolvable_chain_keeps_the_last_good_watches() {
        let (_root, a, _b, c) = release_tree();
        let h = start(&c.join("l"));
        h.wait_wakes_above(0).await;
        let seen = h.wakes();
        std::fs::remove_file(a.join("cfg.yaml")).unwrap();
        std::fs::write(c.join("nudge.txt"), "x").unwrap();
        h.wait_wakes_above(seen).await;
        assert_eq!(
            h.chain.watched(),
            set(&[&a, &c]),
            "the last good set was dropped"
        );
        let _ = h.shutdown.send(());
    }

    /// `R/current -> rel1`, with `R/rel2` holding the next release.
    fn capistrano() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let r = super::release_link(root.path(), Path::new("rel1"));
        std::fs::create_dir_all(r.join("rel2")).unwrap();
        std::fs::write(r.join("rel2").join("cfg.yaml"), "b: 1\n").unwrap();
        (root, r)
    }

    /// T11: a Capistrano `current` retarget (by rename) is followed.
    #[tokio::test]
    async fn t11_a_release_directory_link_retarget_is_followed() {
        let (_root, r) = capistrano();
        let mut h = start(&r.join("current").join("cfg.yaml"));
        h.wait_wakes_above(0).await;
        assert!(
            h.chain.watched().contains(&canonical(&r)),
            "R is not watched"
        );
        retarget(&r.join("current"), Path::new("rel2"));
        h.wait_watched(&r.join("rel2")).await;
        h.drain_idle().await;
        std::fs::write(r.join("rel2").join("cfg.yaml"), "b: 2\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "a write to the new release reloaded nothing"
        );
        let _ = h.shutdown.send(());
    }

    /// T13: the same retarget done as unlink then re-create.
    #[tokio::test]
    async fn t13_a_non_atomic_release_link_retarget_is_followed() {
        let (_root, r) = capistrano();
        let mut h = start(&r.join("current").join("cfg.yaml"));
        h.wait_wakes_above(0).await;
        let seen = h.wakes();
        std::fs::remove_file(r.join("current")).unwrap();
        h.wait_wakes_above(seen).await;
        assert_eq!(
            h.chain.watched(),
            set(&[&r, &r.join("rel1")]),
            "the last good set was dropped"
        );
        symlink("rel2", r.join("current")).unwrap();
        h.wait_watched(&r.join("rel2")).await;
        h.drain_idle().await;
        std::fs::write(r.join("rel2").join("cfg.yaml"), "b: 2\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "a write to the new release reloaded nothing"
        );
        let _ = h.shutdown.send(());
    }

    /// T17: the watcher starts on the path as named, before any rewatch task
    /// can repair it: the release link's holder is watched from the start.
    #[tokio::test]
    async fn t17_the_watcher_starts_on_the_named_path() {
        let (_root, r) = capistrano();
        let (tx, _events) = tokio::sync::mpsc::channel(32);
        let (wake_tx, _wake_rx) = tokio::sync::watch::channel(());
        let named = crate::config_reload::named_config_path(r.join("current").join("cfg.yaml"));
        let chain =
            ConfigWatcher::create_notify_watcher(tx, wake_tx, &named, &[]).expect("watcher starts");
        assert_eq!(chain.watched(), set(&[&r, &r.join("rel1")]));
    }

    fn profile_config(description: &str) -> String {
        format!("routing_profiles:\n  p:\n    description: \"{description}\"\n")
    }

    struct Started {
        watcher: ConfigWatcher,
        live: Arc<crate::config_reload::LiveConfig>,
        _shutdown: tokio::sync::broadcast::Sender<()>,
    }

    fn start_gateway_watcher(named: &Path) -> Started {
        use crate::config::{Config, EnvOverlay, LiveEnv, ResolvedEnvFiles};
        let live = Arc::new(crate::config_reload::LiveConfig::new(Config::default()));
        let env = Arc::new(LiveEnv::new(
            Arc::new(EnvOverlay::none()),
            ResolvedEnvFiles::default(),
        ));
        let (shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let watcher = ConfigWatcher::start(
            named.to_path_buf(),
            Arc::clone(&live),
            Arc::new(crate::backend::BackendRegistry::new()),
            &Config::default(),
            env,
            None,
            shutdown_rx,
        )
        .expect("the watcher starts");
        Started {
            watcher,
            live,
            _shutdown: shutdown,
        }
    }

    fn description(live: &crate::config_reload::LiveConfig) -> Option<String> {
        live.get()
            .routing_profiles
            .get("p")
            .map(|p| p.description.clone())
    }

    /// T15: through `ConfigWatcher::start`, a release retarget reloads the new
    /// release's bytes, not the old release's.
    #[tokio::test]
    async fn t15_start_reloads_the_new_release_after_a_retarget() {
        let (_root, r) = capistrano();
        // Owner-only, as a config the loader accepts must be.
        for rel in ["rel1", "rel2"] {
            crate::gateway::test_helpers::write_owner_only(
                r.join(rel).join("cfg.yaml"),
                profile_config(rel),
            )
            .unwrap();
        }
        let g = start_gateway_watcher(&r.join("current").join("cfg.yaml"));
        let chain = g.watcher.chain();
        tokio::time::timeout(Duration::from_secs(10), async {
            while chain.wakes_handled.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the initial resolve ran");
        retarget(&r.join("current"), Path::new("rel2"));
        let reached = tokio::time::timeout(Duration::from_secs(10), async {
            while description(&g.live).as_deref() != Some("rel2") {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "the live config never showed the new release: {:?}",
            description(&g.live)
        );
    }

    /// T16: `start` resolves once as soon as its watches are live, and that
    /// resolve leaves the named release loaded.
    #[tokio::test]
    async fn t16_start_resolves_once_when_the_watches_are_live() {
        let (_root, r) = capistrano();
        crate::gateway::test_helpers::write_owner_only(
            r.join("rel1").join("cfg.yaml"),
            profile_config("rel1"),
        )
        .unwrap();
        let g = start_gateway_watcher(&r.join("current").join("cfg.yaml"));
        let loaded = tokio::time::timeout(Duration::from_secs(10), async {
            while description(&g.live).as_deref() != Some("rel1") {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            loaded.is_ok(),
            "the initial resolve did not leave the named release loaded"
        );
        assert_eq!(g.watcher.chain().wakes_handled.load(Ordering::SeqCst), 1);
    }

    /// T18: a chain that cannot be resolved at startup (the target missing
    /// mid-update) does not fail the start: the named link's own directory is
    /// watched, and the chain is repaired on the next event.
    #[tokio::test]
    async fn t18_an_unresolvable_chain_at_startup_watches_the_named_directory() {
        let root = tempfile::tempdir().expect("root");
        let (a, c) = (root.path().join("a"), root.path().join("c"));
        for dir in [&a, &c] {
            std::fs::create_dir_all(dir).unwrap();
        }
        symlink(a.join("cfg.yaml"), c.join("l")).unwrap();
        let (tx, _events) = tokio::sync::mpsc::channel(32);
        let (wake_tx, _wake_rx) = tokio::sync::watch::channel(());
        let named = crate::config_reload::named_config_path(c.join("l"));
        let chain = ConfigWatcher::create_notify_watcher(tx, wake_tx, &named, &[])
            .expect("a dangling link does not fail the start");
        assert_eq!(chain.watched(), set(&[&c]));
    }

    /// T18b: a chain unresolvable at startup is repaired when its target
    /// appears in a directory nobody watches yet: the task keeps re-resolving
    /// while the chain is broken, not only on events.
    #[tokio::test]
    async fn t18b_a_chain_broken_at_startup_is_repaired_without_an_event() {
        let root = tempfile::tempdir().expect("root");
        let (a, c) = (root.path().join("a"), root.path().join("c"));
        for dir in [&a, &c] {
            std::fs::create_dir_all(dir).unwrap();
        }
        symlink(a.join("cfg.yaml"), c.join("l")).unwrap();
        let h = start(&c.join("l"));
        h.wait_wakes_above(0).await;
        std::fs::write(a.join("cfg.yaml"), "a: 1\n").unwrap();
        h.wait_watched(&a).await;
        let _ = h.shutdown.send(());
    }

    /// T19: the task's first resolve always reloads, so a retarget that lands
    /// after the config was read but before the task starts is picked up even
    /// when it moves only the end of the chain and no watch.
    #[tokio::test]
    async fn t19_a_retarget_before_the_task_starts_is_reloaded() {
        let (_root, a, _b, c) = release_tree();
        std::fs::write(a.join("cfg2.yaml"), "a: 2\n").unwrap();
        let (tx, mut events) = tokio::sync::mpsc::channel(32);
        let (wake_tx, mut wake_rx) = tokio::sync::watch::channel(());
        let (shutdown, _) = tokio::sync::broadcast::channel(1);
        let named = crate::config_reload::named_config_path(c.join("l"));
        let chain = ConfigWatcher::create_notify_watcher(tx.clone(), wake_tx, &named, &[])
            .expect("watcher starts");
        retarget(&c.join("l"), &a.join("cfg2.yaml"));
        tokio::time::sleep(Duration::from_millis(300)).await;
        while events.try_recv().is_ok() {}
        wake_rx.mark_changed();
        let _task = spawn_rewatch_task(named, chain, wake_rx, tx, shutdown.subscribe());
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(5), events.recv()).await,
                Ok(Some(_))
            ),
            "the first resolve did not reload the retargeted config"
        );
        let _ = shutdown.send(());
    }

    /// T4 (control): an in-place write through an unchanged link reloads.
    #[tokio::test]
    async fn t4_an_in_place_write_to_the_target_reloads() {
        let (_root, a, _b, c) = release_tree();
        let mut h = start(&c.join("l"));
        h.drain_idle().await;
        std::fs::write(a.join("cfg.yaml"), "a: 2\n").unwrap();
        assert!(h.triggered_within(10).await);
        let _ = h.shutdown.send(());
    }

    /// T5 (control): an unrelated file beside the link reloads nothing.
    #[tokio::test]
    async fn t5_an_unrelated_file_beside_the_link_reloads_nothing() {
        let (_root, _a, _b, c) = release_tree();
        let mut h = start(&c.join("l"));
        h.drain_idle().await;
        std::fs::write(c.join("unrelated.txt"), "x").unwrap();
        assert!(
            !h.triggered_within(3).await,
            "an unrelated file triggered a reload"
        );
        let _ = h.shutdown.send(());
    }

    /// T6b: shutdown ends the rewatch task and drops the watcher.
    #[tokio::test]
    async fn t6b_shutdown_ends_the_task_and_the_watcher() {
        let (_root, a, _b, c) = release_tree();
        let mut h = start(&c.join("l"));
        let _ = h.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(2), &mut h.task)
            .await
            .expect("the rewatch task ended")
            .expect("the task did not panic");
        assert!(
            h.chain.watcher.lock().is_none(),
            "the watcher outlived shutdown"
        );
        h.drain_idle().await;
        std::fs::write(a.join("cfg.yaml"), "a: 3\n").unwrap();
        assert!(
            !h.triggered_within(2).await,
            "a dropped watcher still fired"
        );
    }

    /// T7: a retarget of a mid-chain link, heard only in that link's own
    /// directory, is followed.
    #[tokio::test]
    async fn t7_a_mid_chain_retarget_is_followed() {
        let root = tempfile::tempdir().expect("root");
        let (named_dir, mid) = (root.path().join("c"), root.path().join("d"));
        let (first, second) = (root.path().join("e"), root.path().join("f"));
        for dir in [&named_dir, &mid, &first, &second] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(first.join("cfg.yaml"), "e: 1\n").unwrap();
        std::fs::write(second.join("cfg.yaml"), "f: 1\n").unwrap();
        symlink(first.join("cfg.yaml"), mid.join("l2")).unwrap();
        symlink(mid.join("l2"), named_dir.join("l")).unwrap();
        let mut h = start(&named_dir.join("l"));
        retarget(&mid.join("l2"), &second.join("cfg.yaml"));
        h.wait_watched(&second).await;
        h.drain_idle().await;
        std::fs::write(second.join("cfg.yaml"), "f: 2\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "the mid-chain retarget was not followed"
        );
        let _ = h.shutdown.send(());
    }

    /// T2 (the hypothesis): a Kubernetes `ConfigMap` update. Kubelet writes a new
    /// timestamped directory, swaps `..data` onto it, then deletes the old one.
    #[tokio::test]
    async fn t2_a_configmap_projection_update_reloads_and_is_followed() {
        let root = tempfile::tempdir().expect("root");
        let cfg = root.path().join("cfg");
        let (ts1, ts2) = (cfg.join("..ts1"), cfg.join("..ts2"));
        std::fs::create_dir_all(&ts1).unwrap();
        std::fs::write(ts1.join("gateway.yaml"), "v: 1\n").unwrap();
        symlink("..ts1", cfg.join("..data")).unwrap();
        symlink("..data/gateway.yaml", cfg.join("gateway.yaml")).unwrap();
        let mut h = start(&cfg.join("gateway.yaml"));
        h.drain_idle().await;

        // Before the swap nothing the gateway reads has changed.
        std::fs::create_dir_all(&ts2).unwrap();
        std::fs::write(ts2.join("gateway.yaml"), "v: 2\n").unwrap();
        assert!(
            !h.triggered_within(1).await,
            "a pre-swap write triggered a reload"
        );

        retarget(&cfg.join("..data"), Path::new("..ts2"));
        assert!(
            h.triggered_within(10).await,
            "the ..data swap reloaded nothing"
        );
        std::fs::remove_dir_all(&ts1).unwrap();
        h.wait_watched(&ts2).await;
        h.drain_idle().await;
        assert_eq!(
            h.chain.watched(),
            set(&[&cfg, &ts2]),
            "..ts1 is still watched"
        );

        std::fs::write(ts2.join("gateway.yaml"), "v: 3\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "a write to the new generation reloaded nothing"
        );
        let _ = h.shutdown.send(());
    }
}
