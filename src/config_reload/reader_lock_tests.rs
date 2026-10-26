// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload that did not start the write takes the reload lock, then the
//! config sidecar, so it never loads bytes a refused write is about to roll
//! back; it reads without the sidecar only where no writer can exist.

use std::{path::Path, sync::Arc, time::Duration};

use super::*;
use crate::config::Config;
use crate::fs_lock::ExclusiveFileLock;
use crate::gateway::test_helpers::write_owner_only;

const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
const NEXT: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

fn context(path: &Path) -> ReloadContext {
    let running = Config::load(Some(path)).expect("config loads");
    ReloadContext::new(
        path.to_path_buf(),
        Arc::new(LiveConfig::new(running)),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
}

fn has_b(ctx: &ReloadContext) -> bool {
    ctx.live_config.get().backends.contains_key("b")
}

/// The disk a writer killed after its rename leaves: `bytes` in place, the
/// original staged, the journal `staged`.
fn crashed_after_rename(path: &Path, original: &str, bytes: &str) {
    use crate::config_persistence::journal;
    journal::stage_original(path, original.as_bytes()).expect("stage");
    journal::begin(path, crate::hashing::sha256_hex(original.as_bytes())).expect("journal");
    write_owner_only(crate::identity_grants::journal::resolved(path), bytes).expect("rename");
}

/// T12b: a sidecar held past the wait makes the reload skip, naming the
/// lock; once it is free, the next reload loads the file.
#[tokio::test]
async fn a_held_sidecar_skips_the_reload_until_it_is_free() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write");
    let ctx = context(&path);
    write_owner_only(&path, NEXT).expect("edit");
    let lock = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&path),
    );
    let held = ExclusiveFileLock::try_acquire(&lock).expect("the test holds the sidecar");

    let skipped = ctx
        .reload_outcome()
        .await
        .expect_err("a held sidecar skips");
    assert!(skipped.contains("skipped"), "{skipped}");
    assert!(!has_b(&ctx));

    drop(held);
    ctx.reload_outcome().await.expect("a free sidecar loads");
    assert!(has_b(&ctx));
}

/// T7 for readers: a crashed write's journal is recovered by the next
/// watcher-style reload, which then loads the original, not the candidate.
#[tokio::test]
async fn a_reload_recovers_a_crashed_write_before_loading() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write");
    let ctx = context(&path);
    crashed_after_rename(&path, START, NEXT);

    ctx.reload_outcome()
        .await
        .expect("the reload recovers and loads");

    assert_eq!(std::fs::read_to_string(&path).expect("read"), START);
    assert!(!has_b(&ctx), "the refused candidate never loads");
    assert!(!crate::config_persistence::journal::exists(&path));
}

/// A directory this account cannot write, for the unwritable-directory
/// rule; `None` under root, where permissions do not bind.
#[cfg(unix)]
fn unwritable_dir(with_journal: bool) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    use std::os::unix::fs::PermissionsExt as _;
    if rustix::process::geteuid().is_root() {
        return None;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write");
    if with_journal {
        crashed_after_rename(&path, START, NEXT);
    }
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).expect("chmod");
    Some((dir, path))
}

#[cfg(unix)]
fn writable_again(dir: &tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// T12e: in a directory this account cannot write (a root-owned config
/// under an unprivileged gateway) with no journal, a reload loads without
/// the sidecar, as reloads always did.
#[cfg(unix)]
#[tokio::test]
async fn an_unwritable_directory_without_a_journal_loads_unlocked() {
    let Some((dir, path)) = unwritable_dir(false) else {
        return;
    };
    let ctx = context(&path);

    let loaded = ctx.reload_outcome().await;

    writable_again(&dir);
    loaded.expect("no writer can exist, so the reload loads");
}

/// T12e: the same directory with a pending journal skips the reload and
/// names the action, rather than load either version.
#[cfg(unix)]
#[tokio::test]
async fn an_unwritable_directory_with_a_journal_skips_and_says_why() {
    let Some((dir, path)) = unwritable_dir(true) else {
        return;
    };
    let ctx = context(&path);

    let skipped = ctx.reload_outcome().await;

    writable_again(&dir);
    let skipped = skipped.expect_err("a pending journal on an unlockable file skips");
    assert!(
        skipped.contains("resolve the pending write from the writable side"),
        "{skipped}"
    );
}
