// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared byte writer: gateway.yaml's exact bytes under the config lock
//! pair, then one reload, and the old file back whenever that reload refuses.

use std::{path::Path, path::PathBuf, sync::Arc, time::Duration};

use super::reload_context::replace::{
    Expected, FileRevision, Replace, ReplaceError, Replaced, replace_detached,
};
use super::*;
use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const WAIT: Duration = Duration::from_secs(5);

/// A commented config, so the bytes test sees comments survive.
const START: &str =
    "# operator's note\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n";
/// The same file with backend `b` added and every comment kept.
const NEXT: &str = "# operator's note\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

fn setup() -> (tempfile::TempDir, PathBuf, Arc<ReloadContext>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let ctx = context(&path);
    (dir, path, ctx)
}

fn context(path: &Path) -> Arc<ReloadContext> {
    let running = Config::load(Some(path)).expect("config loads");
    Arc::new(
        ReloadContext::new(
            path.to_path_buf(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    )
}

/// Replace gateway.yaml with `bytes`.
fn to(expected: Expected, bytes: &'static str, replaced: Replaced) -> Replace {
    Replace {
        expected,
        compute: Box::new(move |_| Ok(bytes.as_bytes().to_vec())),
        replaced,
    }
}

fn running_has_b(ctx: &ReloadContext) -> bool {
    ctx.live_config.get().backends.contains_key("b")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read")
}

/// Every name in `dir`, for "nothing staged beside it" assertions.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// T1: the file holds exactly the given bytes, comments included, and the
/// running config is reloaded from them; nothing is left beside it.
#[tokio::test]
async fn replaced_bytes_land_exactly_and_are_reloaded() {
    let (dir, path, ctx) = setup();
    let expected = Expected::Revision(FileRevision::of(START.as_bytes()));

    let outcome = replace_detached(
        Arc::clone(&ctx),
        to(expected, NEXT, Replaced::Discard),
        WAIT,
    )
    .await
    .expect("the replace applies");

    assert_eq!(read(&path), NEXT);
    assert!(running_has_b(&ctx), "the reload must publish the new bytes");
    assert_eq!(outcome.revision, Some(FileRevision::of(NEXT.as_bytes())));
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T2: a diff made from an earlier version is refused with the current
/// revision; nothing is written or reloaded.
#[tokio::test]
async fn a_stale_revision_is_refused_with_the_current_one() {
    let (_dir, path, ctx) = setup();
    let earlier = Expected::Revision(FileRevision::of(b"backends: {}\n"));

    let failure = replace_detached(Arc::clone(&ctx), to(earlier, NEXT, Replaced::Discard), WAIT)
        .await
        .expect_err("a stale diff must not apply");

    match failure {
        ReplaceError::Stale { current } => assert_eq!(current, FileRevision::of(START.as_bytes())),
        other => panic!("expected Stale, got {other:?}"),
    }
    assert_eq!(read(&path), START);
    assert!(!running_has_b(&ctx));
}

/// T3: a compute refusal writes nothing and stages nothing.
#[tokio::test]
async fn a_refused_compute_writes_and_stages_nothing() {
    let (dir, path, ctx) = setup();
    let refuse = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Err("the splice cannot be proven".to_string())),
        replaced: Replaced::KeepBeside,
    };

    let failure = replace_detached(ctx, refuse, WAIT)
        .await
        .expect_err("a refusal must not apply");

    assert!(matches!(failure, ReplaceError::Refused(_)));
    assert_eq!(read(&path), START);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T3b: gateway.yaml bytes that are not UTF-8 are refused.
#[tokio::test]
async fn non_utf8_config_bytes_are_refused() {
    let (_dir, path, ctx) = setup();
    let bad = Replace {
        expected: Expected::Any,
        compute: Box::new(|_| Ok(vec![0xff, 0xfe, b'\n'])),
        replaced: Replaced::Discard,
    };

    let failure = replace_detached(ctx, bad, WAIT)
        .await
        .expect_err("not UTF-8");

    assert!(matches!(failure, ReplaceError::Refused(_)));
    assert_eq!(read(&path), START);
}

/// T5 (first copy; the clash suffix needs the clock seam): a kept-beside
/// replacement leaves one owner-only `.rejected` copy of the replaced bytes.
#[tokio::test]
async fn kept_beside_leaves_the_replaced_bytes() {
    let (dir, _path, ctx) = setup();

    let outcome = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::KeepBeside), WAIT)
        .await
        .expect("applies");

    let copy = outcome.kept_beside.expect("a kept copy");
    assert_eq!(
        copy.parent(),
        Some(dir.path().canonicalize().expect("dir").as_path())
    );
    assert!(
        copy.to_string_lossy().ends_with(".rejected"),
        "{}",
        copy.display()
    );
    assert_eq!(read(&copy), START);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&copy).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the copy can hold secrets");
    }
}

/// T8b: a reload refused by the posture check rolls the file back byte for
/// byte; the running config never changed and no journal is left.
#[tokio::test]
async fn a_refused_reload_rolls_the_file_back() {
    // A public URL over open tools: the posture check refuses the reload
    // (as in `tests/posture_refusal.rs`).
    const EXPOSED: &str = "server:\n  public_url: \"https://gw.example.com\"\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
    let (dir, path, ctx) = setup();

    let failure = replace_detached(
        Arc::clone(&ctx),
        to(Expected::Any, EXPOSED, Replaced::Discard),
        WAIT,
    )
    .await
    .expect_err("the posture refuses the reload");

    assert!(
        matches!(failure, ReplaceError::ReloadRefused(_)),
        "{failure:?}"
    );
    assert_eq!(read(&path), START, "refused bytes never stay on disk");
    assert!(!running_has_b(&ctx));
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T11: with the sidecar lock held past the wait, the call is Busy and
/// nothing is written.
#[tokio::test]
async fn a_held_lock_reports_busy() {
    let (_dir, path, ctx) = setup();
    let lock = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&path),
    );
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the lock");

    let failure = replace_detached(
        ctx,
        to(Expected::Any, NEXT, Replaced::Discard),
        Duration::from_millis(300),
    )
    .await
    .expect_err("the lock is held");

    assert!(matches!(failure, ReplaceError::Busy));
    assert_eq!(read(&path), START);
    drop(held);
}

/// T6f (first half): a symlinked gateway.yaml naming the file loaded at
/// start is written through, the link stays, and a second save through it
/// succeeds too (the trusted identity advanced).
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_config_is_written_through_twice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let ctx = context(&link);

    replace_detached(
        Arc::clone(&ctx),
        to(Expected::Any, NEXT, Replaced::Discard),
        WAIT,
    )
    .await
    .expect("applies through the link");
    replace_detached(ctx, to(Expected::Any, START, Replaced::Discard), WAIT)
        .await
        .expect("a second save through the link applies");

    assert!(
        std::fs::symlink_metadata(&link)
            .expect("lstat")
            .file_type()
            .is_symlink()
    );
    assert_eq!(read(&real), START);
}

/// T6f (second half): a link re-pointed outside the config directory after
/// start is refused, and nothing is written where it points.
#[cfg(unix)]
#[tokio::test]
async fn a_repointed_link_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.yaml");
    write_owner_only(&real, START).expect("write config");
    let link = dir.path().join("gateway.yaml");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let ctx = context(&link);
    let outside = tempfile::tempdir().expect("outside");
    let victim = outside.path().join("victim.yaml");
    write_owner_only(&victim, START).expect("write victim");
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(&victim, &link).expect("re-point");

    let failure = replace_detached(ctx, to(Expected::Any, NEXT, Replaced::Discard), WAIT)
        .await
        .expect_err("a re-pointed link is refused");

    assert!(
        matches!(failure, ReplaceError::Unsupported(_)),
        "{failure:?}"
    );
    assert_eq!(read(&victim), START);
}

/// T13: a compute returning the current bytes writes nothing and still
/// reloads once.
#[tokio::test]
async fn unchanged_bytes_write_nothing_and_still_reload() {
    let (_dir, path, ctx) = setup();
    let before = std::fs::metadata(&path)
        .expect("stat")
        .modified()
        .expect("mtime");

    let outcome = replace_detached(ctx, to(Expected::Any, START, Replaced::KeepBeside), WAIT)
        .await
        .expect("an unchanged file still applies");

    assert_eq!(read(&path), START);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime"),
        before
    );
    assert_eq!(outcome.revision, None);
    assert_eq!(outcome.kept_beside, None);
}

/// The disk a writer killed after its rename leaves: `bytes` in place, the
/// original staged, the journal `staged`.
fn crashed_after_rename(path: &Path, bytes: &str) {
    use crate::config_persistence::journal;
    let original = journal::stage_original(path, START.as_bytes()).expect("stage");
    journal::begin(
        path,
        &original,
        FileRevision::of(START.as_bytes()).as_str().to_owned(),
    )
    .expect("journal");
    write_owner_only(crate::identity_grants::journal::resolved(path), bytes).expect("rename");
}

fn lock_now(
    path: &Path,
) -> impl std::future::Future<
    Output = Result<ExclusiveFileLock, crate::config_persistence::lock::NotLocked>,
> + '_ {
    crate::config_persistence::lock::lock_config(path, std::time::Instant::now() + WAIT)
}

/// T7: a `staged` journal is rolled back by the next holder of the config
/// lock, byte for byte, and leaves nothing beside the file.
#[tokio::test]
async fn the_next_lock_holder_rolls_a_staged_journal_back() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);

    drop(
        lock_now(&path)
            .await
            .expect("the lock recovers the journal"),
    );

    assert_eq!(read(&path), START);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T8: an `all_renamed` journal keeps the new bytes; recovery only cleans up.
#[tokio::test]
async fn an_all_renamed_journal_keeps_the_new_bytes() {
    let (dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    crate::config_persistence::journal::mark_all_renamed(&path).expect("mark");

    drop(
        lock_now(&path)
            .await
            .expect("the lock recovers the journal"),
    );

    assert_eq!(read(&path), NEXT);
    assert_eq!(names(dir.path()), [".gateway.yaml.lock", "gateway.yaml"]);
}

/// T9: a `staged` journal whose original is gone cannot be acted on: the
/// lock is refused with the manual step, and no file changes.
#[tokio::test]
async fn a_journal_without_its_original_refuses_the_lock() {
    let (_dir, path, _ctx) = setup();
    crashed_after_rename(&path, NEXT);
    std::fs::remove_file(crate::config_persistence::journal::original_path(&path)).expect("rm");

    match lock_now(&path).await {
        Err(crate::config_persistence::lock::NotLocked::Failed(message)) => {
            assert!(
                message.contains("copy the staged original over"),
                "{message}"
            );
        }
        Err(other) => panic!("expected a refusal, got {other:?}"),
        Ok(_) => panic!("an unusable journal must refuse the lock"),
    }
    assert_eq!(read(&path), NEXT);
    assert!(crate::config_persistence::journal::exists(&path));
}

/// T6g: a stranded candidate that does not even parse never blocks an
/// ordinary edit: `mutate_locked` skips its preflight while a journal is
/// pending, the lock restores the original and a reload follows, and the
/// edit lands on the restored file.
#[tokio::test]
async fn an_edit_recovers_a_stranded_unparseable_file_first() {
    let (_dir, path, ctx) = setup();
    crashed_after_rename(&path, "backends: [this is: not: yaml\n");

    let result = ctx
        .mutate_and_reload_outcome_within(&path, WAIT, |config: &mut Config| {
            let backend = config.backends["a"].clone();
            config.backends.insert("b".to_string(), backend);
            Ok::<(), String>(())
        })
        .await;

    assert!(
        matches!(result, Ok(ConfigMutation::Applied(..))),
        "the edit must apply after recovery"
    );
    let on_disk = Config::load(Some(&path)).expect("the restored, edited file loads");
    assert!(on_disk.backends.contains_key("a") && on_disk.backends.contains_key("b"));
    assert!(running_has_b(&ctx));
    assert!(!crate::config_persistence::journal::exists(&path));
}
