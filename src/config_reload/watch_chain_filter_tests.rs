// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which events wake the rewatch task (MIK-8013). Each wake re-resolves the
//! config's whole link chain, so a write beside the config that cannot move
//! the chain must not cost one. The real-watcher rows also cover a chain
//! directory recreated in place and a chain that heals (MIK-8024).

use std::collections::BTreeSet;
use std::path::PathBuf;

use super::{ChainNames, resolve_chain};

fn canonical(path: &std::path::Path) -> PathBuf {
    std::fs::canonicalize(path).expect("canonical")
}

/// Before any resolve, and after a failed one, every event wakes the task.
#[test]
fn no_chain_wakes_on_any_path() {
    let names = ChainNames::default();
    assert!(names.may_move_chain(&[PathBuf::from("/x/unrelated")]));
}

/// A resolved chain wakes only on its own paths (Linux; elsewhere on every
/// path), and a pathless event always wakes.
#[test]
fn a_chain_wakes_on_its_paths_only() {
    let names = ChainNames::default();
    names.set(Some(BTreeSet::from([PathBuf::from("/c/gateway.yaml")])));
    assert!(names.may_move_chain(&[PathBuf::from("/c/gateway.yaml")]));
    assert!(names.may_move_chain(&[PathBuf::from("/c/.tmp"), PathBuf::from("/c/gateway.yaml")]));
    assert_eq!(
        names.may_move_chain(&[PathBuf::from("/c/perf.data")]),
        !cfg!(target_os = "linux")
    );
    assert!(names.may_move_chain(&[]));
}

/// A rescan means events were lost, so it wakes whatever path it carries.
#[test]
fn a_rescan_wakes_on_an_unrelated_path() {
    use notify::event::{Event, EventKind, Flag};
    let names = ChainNames::default();
    names.set(Some(BTreeSet::from([PathBuf::from("/c/gateway.yaml")])));
    let unrelated = Event::new(EventKind::Any).add_path(PathBuf::from("/c/perf.data"));
    assert_eq!(names.concerns(&unrelated), !cfg!(target_os = "linux"));
    assert!(names.concerns(&unrelated.set_flag(Flag::Rescan)));
}

/// What the notify callback does with one event, for a config whose chain
/// is resolved: (woke the task, queued a reload). The filter holds what the
/// rewatch task sets for a plain file: the file and its directory.
fn callback_on(event: &notify::Event, cfg: &std::path::Path) -> (bool, bool) {
    let names = ChainNames::default();
    let dir = cfg.parent().expect("a directory");
    names.set(Some(BTreeSet::from([canonical(cfg), canonical(dir)])));
    let (wake, woken) = tokio::sync::watch::channel(());
    let (reload, mut reloads) = tokio::sync::mpsc::channel(4);
    super::super::watcher::handle_watch_event(event, &names, cfg, &wake, &reload);
    (woken.has_changed().unwrap(), reloads.try_recv().is_ok())
}

/// An edit to the config wakes the task and reloads; reading it does neither
/// (the reload's own read must not wake the task again); an event on the
/// watched directory itself wakes without a reload; on Linux a file beside
/// it does neither; a rescan does both whatever path it carries.
#[test]
fn the_callback_wakes_and_reloads_for_the_config_and_rescans_only() {
    use notify::event::{
        AccessKind, AccessMode, CreateKind, DataChange, Event, EventKind, Flag, ModifyKind,
        RemoveKind,
    };
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    std::fs::write(&cfg, "a: 1\n").unwrap();
    let beside = canonical(root.path()).join("perf.data");

    let edit = Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Content)))
        .add_path(canonical(&cfg));
    assert_eq!(callback_on(&edit, &cfg), (true, true));

    let read = Event::new(EventKind::Access(AccessKind::Close(AccessMode::Read)))
        .add_path(canonical(&cfg));
    assert_eq!(callback_on(&read, &cfg), (false, false));

    let dir_gone =
        Event::new(EventKind::Remove(RemoveKind::Folder)).add_path(canonical(root.path()));
    assert_eq!(callback_on(&dir_gone, &cfg), (true, false));

    let unrelated = Event::new(EventKind::Create(CreateKind::File)).add_path(beside.clone());
    let off_linux = !cfg!(target_os = "linux");
    assert_eq!(callback_on(&unrelated, &cfg), (off_linux, false));

    let rescan = Event::new(EventKind::Other)
        .add_path(beside)
        .set_flag(Flag::Rescan);
    assert_eq!(callback_on(&rescan, &cfg), (true, true));
}

/// A plain file's chain names the file, canonical, and nothing beside it.
#[test]
fn a_plain_file_names_itself() {
    let root = tempfile::tempdir().expect("root");
    let cfg = root.path().join("gateway.yaml");
    std::fs::write(&cfg, "a: 1\n").unwrap();
    let chain = resolve_chain(&cfg).expect("resolves");
    assert_eq!(chain.names, BTreeSet::from([canonical(&cfg)]));
}

/// A `ConfigMap` layout names the projected link, the `..data` directory link
/// and the file it ends at: the three paths an update touches.
#[cfg(unix)]
#[test]
fn a_configmap_chain_names_every_link_on_it() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().expect("root");
    let generation = root.path().join("..2026_10_07");
    std::fs::create_dir(&generation).unwrap();
    std::fs::write(generation.join("gateway.yaml"), "a: 1\n").unwrap();
    symlink("..2026_10_07", root.path().join("..data")).unwrap();
    symlink("..data/gateway.yaml", root.path().join("gateway.yaml")).unwrap();

    let chain = resolve_chain(&root.path().join("gateway.yaml")).expect("resolves");
    let real = canonical(root.path());
    assert_eq!(
        chain.names,
        BTreeSet::from([
            real.join("gateway.yaml"),
            real.join("..data"),
            real.join("..2026_10_07").join("gateway.yaml"),
        ])
    );
}

/// While the chain cannot be resolved, the record of removed and renamed
/// paths keeps only those the ledger holds, the ones a rewatch acts on.
#[test]
fn a_broken_chain_keeps_only_watched_paths_on_record() {
    use notify::event::{Event, EventKind, ModifyKind, RemoveKind, RenameMode};
    let watcher =
        notify::recommended_watcher(|_: notify::Result<notify::Event>| {}).expect("watcher");
    let chain = super::ChainWatch::with_names(watcher, std::sync::Arc::default());
    let on_ledger = PathBuf::from("/c/conf");
    chain.ledger.lock().insert(on_ledger.clone());
    let removed = Event::new(EventKind::Remove(RemoveKind::Folder))
        .add_path(on_ledger.clone())
        .add_path(PathBuf::from("/c/old.log"));
    let renamed = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::From)))
        .add_path(PathBuf::from("/c/app.log"));
    chain.names.note_gone(&removed);
    chain.names.note_gone(&renamed);
    chain.keep_gone_watched();
    assert_eq!(chain.names.take_gone(), BTreeSet::from([on_ledger]));
}

// Linux-only (W-L9): the real-watcher rows run on inotify.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod real_watcher {
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use super::super::tests::real_watcher::{Harness, start};

    /// Wait until the task has handled every wake it was sent: the count
    /// stops moving for half a second. Ten seconds of constant wakes fail.
    async fn settled_wakes(h: &Harness) -> usize {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut seen = h.wakes();
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let now = h.wakes();
                if now == seen {
                    return now;
                }
                seen = now;
            }
        })
        .await
        .expect("the rewatch task never stopped waking")
    }

    fn plain_config() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().expect("root");
        let cfg = root.path().join("gateway.yaml");
        std::fs::write(&cfg, "a: 1\n").expect("config");
        (root, cfg)
    }

    fn write_unrelated(dir: &Path, count: usize) {
        for i in 0..count {
            std::fs::write(dir.join(format!("perf-{i}.data")), "x").unwrap();
        }
    }

    /// MIK-8013.WATCH.2: 1000 files written beside the config run no chain
    /// re-resolution. The config edit after them is the barrier: notify
    /// delivers events in order and the callback wakes the task before it
    /// sends the reload, so once the reload arrives every earlier event was
    /// judged. Multi-threaded, so the rewatch task resolves while the files
    /// are written: on one thread every wake would coalesce after the writes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch2_unrelated_files_beside_the_config_resolve_nothing() {
        let (root, cfg) = plain_config();
        let mut h = start(&cfg);
        h.wait_wakes_above(0).await;
        h.drain_idle().await;
        settled_wakes(&h).await;
        h.chain.names.passed.lock().clear();
        let dropped_before = h.chain.names.dropped.load(Ordering::SeqCst);

        write_unrelated(root.path(), 1000);
        std::fs::write(&cfg, "a: 2\n").unwrap();
        assert!(h.triggered_within(10).await, "the config edit reloads");

        // Every unrelated file reached the callback and was dropped there, so
        // none woke the task (each wake is one re-resolution); only the
        // edit's own events passed.
        let dropped = h.chain.names.dropped.load(Ordering::SeqCst) - dropped_before;
        assert!(
            dropped >= 1000,
            "only {dropped} unrelated events were judged"
        );
        let config = std::fs::canonicalize(&cfg).unwrap();
        let passed = h.chain.names.passed.lock().clone();
        assert!(
            !passed.is_empty() && passed.iter().all(|paths| paths.contains(&config)),
            "events that woke the task: {passed:?}"
        );
        let _ = h.shutdown.send(());
    }

    /// MIK-8013.WATCH.3: an atomic rename onto the config (write a temporary
    /// file, rename it over the config) still reloads.
    #[tokio::test]
    async fn watch3_an_atomic_rename_onto_the_config_reloads() {
        let (root, cfg) = plain_config();
        let mut h = start(&cfg);
        h.wait_wakes_above(0).await;
        h.drain_idle().await;

        let tmp = root.path().join(".gateway.yaml.tmp");
        std::fs::write(&tmp, "a: 2\n").unwrap();
        std::fs::rename(&tmp, &cfg).unwrap();
        assert!(h.triggered_within(10).await, "the rename reloads");
        let _ = h.shutdown.send(());
    }

    /// The config's directory replaced in place by `replace`, then a new
    /// config written there, with the rewatch task settled after it. The
    /// pause outlasts a broken-chain retry, so the next trigger can only come
    /// from a later event.
    async fn replaced_config_dir(
        replace: impl FnOnce(&Path),
    ) -> (tempfile::TempDir, std::path::PathBuf, Harness) {
        let root = tempfile::tempdir().expect("root");
        let conf = root.path().join("conf");
        std::fs::create_dir(&conf).unwrap();
        let cfg = conf.join("gateway.yaml");
        std::fs::write(&cfg, "a: 1\n").unwrap();
        let mut h = start(&cfg);
        h.wait_wakes_above(0).await;
        h.drain_idle().await;

        replace(&conf);
        std::fs::create_dir(&conf).unwrap();
        std::fs::write(&cfg, "a: 2\n").unwrap();
        settled_wakes(&h).await;
        tokio::time::sleep(super::super::CHAIN_RETRY + Duration::from_millis(500)).await;
        settled_wakes(&h).await;
        h.drain_idle().await;
        (root, cfg, h)
    }

    /// `MIK-8024.WATCHDIR.1`: the config's directory deleted and recreated at
    /// the same path is watched again. Its inotify watch died with the old
    /// directory, so an edit in the new one is heard only through a new watch.
    #[tokio::test]
    async fn watchdir1_a_recreated_config_directory_is_watched_again() {
        let (_root, cfg, mut h) =
            replaced_config_dir(|conf| std::fs::remove_dir_all(conf).unwrap()).await;
        std::fs::write(&cfg, "a: 3\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "an edit in the recreated directory was not heard"
        );
        let _ = h.shutdown.send(());
    }

    /// `MIK-8024.WATCHDIR.1`, restored late: the directory stays missing long
    /// enough for its deletion to wake a resolve that fails, so the record of
    /// the dead watch must outlive that failure. Multi-threaded, so the task
    /// resolves while the test thread waits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchdir1_a_directory_restored_after_a_failed_resolve_is_watched() {
        let (_root, cfg, mut h) = replaced_config_dir(|conf| {
            std::fs::remove_dir_all(conf).unwrap();
            std::thread::sleep(Duration::from_secs(1));
        })
        .await;
        std::fs::write(&cfg, "a: 3\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "an edit in the restored directory was not heard"
        );
        let _ = h.shutdown.send(());
    }

    /// `MIK-8024.WATCHDIR.1`, renamed away: the old watch followed the
    /// directory to its new name. The new directory at the path is watched,
    /// and a write in the old one is no longer heard as the config.
    #[tokio::test]
    async fn watchdir1_a_config_directory_renamed_away_is_rewatched() {
        let (root, cfg, mut h) = replaced_config_dir(|conf| {
            std::fs::rename(conf, conf.with_file_name("conf.old")).unwrap();
        })
        .await;
        std::fs::write(root.path().join("conf.old/gateway.yaml"), "a: 9\n").unwrap();
        assert!(
            !h.triggered_within(2).await,
            "a write in the renamed-away directory reloaded"
        );
        std::fs::write(&cfg, "a: 3\n").unwrap();
        assert!(
            h.triggered_within(10).await,
            "an edit in the new directory was not heard"
        );
        let _ = h.shutdown.send(());
    }

    /// `MIK-8024.WATCHDIR.2`: a chain that heals after failing to resolve sends
    /// one reload, though its end and directories are what they were. The
    /// watcher here hears nothing, so only the task's own wakes can reload.
    #[tokio::test]
    async fn watchdir2_a_healed_chain_reloads_once() {
        use std::sync::Arc;
        let root = tempfile::tempdir().expect("root");
        let cfg = root.path().join("gateway.yaml");
        std::fs::write(&cfg, "a: 1\n").unwrap();
        let named = super::super::named_config_path(cfg.clone());
        let deaf =
            notify::recommended_watcher(|_: notify::Result<notify::Event>| {}).expect("watcher");
        let chain = super::super::ChainWatch::with_names(deaf, Arc::default());
        let (reload, mut reloads) = tokio::sync::mpsc::channel(8);
        let (wake, mut woken) = tokio::sync::watch::channel(());
        let (shutdown, _) = tokio::sync::broadcast::channel(1);
        woken.mark_changed();
        let _task = super::super::spawn_rewatch_task(
            named,
            Arc::clone(&chain),
            woken,
            reload,
            shutdown.subscribe(),
            Duration::from_secs(3600),
            crate::config_reload::env_poll::EnvPoller::new(
                Arc::new(crate::config::LiveEnv::default()),
                Arc::default(),
                std::path::PathBuf::new(),
            ),
            Duration::from_secs(3600),
        );
        let handled = |n: usize| {
            let chain = Arc::clone(&chain);
            async move {
                tokio::time::timeout(Duration::from_secs(10), async {
                    while chain.wakes_handled.load(Ordering::SeqCst) < n {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("the rewatch task stalled");
            }
        };
        handled(1).await;
        assert!(
            matches!(
                tokio::time::timeout(Duration::from_secs(5), reloads.recv()).await,
                Ok(Some(_))
            ),
            "the first resolve reloads"
        );

        std::fs::remove_file(&cfg).unwrap();
        wake.send_replace(());
        handled(2).await;
        std::fs::write(&cfg, "a: 2\n").unwrap();
        let seen = chain.wakes_handled.load(Ordering::SeqCst);
        wake.send_replace(());
        handled(seen + 1).await;

        let mut healed = 0;
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(1), reloads.recv()).await {
            healed += 1;
        }
        assert_eq!(healed, 1, "reloads after the chain healed");
        let _ = shutdown.send(());
    }
}
