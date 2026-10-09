// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8042 (family config-writers): one writer loads, edits and writes
//! gateway.yaml under a single hold of the config lock, so a concurrent
//! writer's change is never lost, and the comments an edit drops are named
//! by one shared helper (MIK-8051 AC4).

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use super::{CommentLoss, edit_config, edit_config_text, when_waiting_for_lock};
use crate::config::{BackendConfig, Config};

fn backend(command: &str) -> BackendConfig {
    serde_yaml::from_str(&format!("command: {command}\n")).expect("backend")
}

fn names(path: &Path) -> Vec<String> {
    let config = Config::load_literal_with_text(path).expect("loads").0;
    let mut names: Vec<String> = config.backends.keys().cloned().collect();
    names.sort();
    names
}

fn config_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write");
    (dir, path)
}

/// Another writer adds backend `x` through the locked editor, released from
/// inside our edit. Under one lock hold it must wait for our write, then
/// edit the result; a writer that read before the lock overwrites it.
fn with_a_concurrent_add<T>(path: &Path, ours: impl FnOnce(Option<&mpsc::Sender<()>>) -> T) -> T {
    let (go, started) = mpsc::channel::<()>();
    let (finished, done) = mpsc::channel::<()>();
    let at = path.to_path_buf();
    let other = std::thread::spawn(move || {
        started.recv().expect("released");
        let added = edit_config(&at, CommentLoss::Refuse, |config| {
            config.backends.insert("x".into(), backend("x-server"));
            Ok(())
        });
        let _ = finished.send(());
        added
    });
    let result = ours(Some(&go));
    // Ours is written; the other writer now gets the lock if it waited.
    let _ = done.recv_timeout(Duration::from_secs(30));
    other
        .join()
        .expect("other writer")
        .expect("other writer wrote");
    result
}

/// Release the other writer from inside our edit, and return once it has
/// tried the lock and queued behind ours: its edit must see our write.
fn release(go: Option<&mpsc::Sender<()>>, path: &Path) {
    if let Some(go) = go {
        let queued = when_waiting_for_lock(path);
        go.send(()).expect("release");
        assert!(
            queued.recv_timeout(Duration::from_secs(10)).is_ok(),
            "the other writer never waited for the config lock"
        );
    }
}

/// CAS.1/2: two overlapping adds both survive.
#[test]
fn an_add_racing_another_add_keeps_both() {
    let (_dir, path) = config_file("backends:\n  a:\n    command: a-server\n");
    with_a_concurrent_add(&path, |go| {
        edit_config(&path, CommentLoss::Refuse, |config| {
            release(go, &path);
            config.backends.insert("y".into(), backend("y-server"));
            Ok(())
        })
        .expect("ours written")
    });
    let names = names(&path);
    assert!(
        names.contains(&"x".to_string()) && names.contains(&"y".to_string()),
        "{names:?}"
    );
}

/// CAS.1/2: a remove racing another writer's add keeps that add.
#[test]
fn a_remove_racing_an_add_keeps_the_add() {
    let (_dir, path) =
        config_file("backends:\n  a:\n    command: a-server\n  b:\n    command: b-server\n");
    with_a_concurrent_add(&path, |go| {
        edit_config(&path, CommentLoss::Refuse, |config| {
            release(go, &path);
            config.backends.remove("b");
            Ok(())
        })
        .expect("ours written")
    });
    assert_eq!(names(&path), vec!["a".to_string(), "x".to_string()]);
}

/// CAS.3: `--force` (Rewrite) loads, edits and writes in the same hold. A
/// port change cannot be spliced, so ours rewrites the whole file.
#[test]
fn a_forced_rewrite_racing_an_add_keeps_the_add() {
    let (_dir, path) = config_file("# mine\nbackends:\n  a:\n    command: a-server\n");
    let edited = with_a_concurrent_add(&path, |go| {
        edit_config(&path, CommentLoss::Rewrite, |config| {
            release(go, &path);
            config.server.port = 39_999;
            Ok(())
        })
        .expect("ours written")
    });
    let config = Config::load_literal_with_text(&path).expect("loads").0;
    assert_eq!(config.server.port, 39_999);
    assert_eq!(names(&path), vec!["a".to_string(), "x".to_string()]);
    assert_eq!(
        edited,
        ["line 1"],
        "the rewrite names the comment it dropped"
    );
}

/// `upgrade`'s byte-keeping rewrite reads the text under the lock.
#[test]
fn a_text_rewrite_racing_an_add_keeps_the_add() {
    let (_dir, path) = config_file("# note\nbackends:\n  a:\n    command: a-server\n");
    with_a_concurrent_add(&path, |go| {
        edit_config_text(&path, |current| {
            release(go, &path);
            Ok(current.map(|text| text.replace("# note", "# renamed")))
        })
        .expect("ours written")
    });
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(text.contains("# renamed"), "{text}");
    assert!(names(&path).contains(&"x".to_string()), "{text}");
}

/// `init` creates only: a file that exists by the time it holds the lock is
/// refused and left as it is.
#[test]
fn a_create_only_text_write_refuses_an_existing_file() {
    let (_dir, path) = config_file("backends:\n  a:\n    command: a-server\n");
    let refused = edit_config_text(&path, |current| match current {
        None => Ok(Some("backends: {}\n".to_string())),
        Some(_) => Err("already exists".to_string()),
    });
    assert_eq!(refused, Err("already exists".to_string()));
    assert_eq!(names(&path), vec!["a".to_string()]);
}

/// GH462: text that would not load as a config is refused, never written.
#[test]
fn a_text_write_that_would_not_load_is_refused() {
    let (_dir, path) = config_file("backends:\n  a:\n    command: a-server\n");
    let refused = edit_config_text(&path, |_| Ok(Some("backends: [\n".to_string())));
    let error = refused.expect_err("refused");
    assert!(error.starts_with("Not saved:"), "{error}");
    assert_eq!(names(&path), vec!["a".to_string()]);
}

/// A path that is not a regular file is refused before it is read: a FIFO
/// would block the read, a device would never end it.
#[test]
fn a_text_edit_of_a_non_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::create_dir(&path).expect("dir in the way");
    let error = edit_config_text(&path, |_| Ok(None)).expect_err("refused");
    assert!(error.contains("not a regular file"), "{error}");
}

/// MIK-8051 AC4: a removal names the comment lines inside the removed entry,
/// from the one shared helper.
#[test]
fn a_removal_names_the_comments_it_took() {
    let (_dir, path) = config_file(
        "backends:\n  a:\n    command: a-server\n  b:\n    # b's note\n    command: b-server\n",
    );
    let edited = edit_config(&path, CommentLoss::Refuse, |config| {
        config.backends.remove("b");
        Ok(())
    })
    .expect("removed");
    assert_eq!(edited, ["line 5"]);
}

/// MIK-8051 AC4: the CLI keeps no second copy of the dropped-comment compare.
#[test]
fn the_cli_keeps_no_copy_of_the_comment_compare() {
    let cli = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/config_write.rs");
    let text = std::fs::read_to_string(cli).expect("read");
    assert!(
        !text.contains("fn dropped_comments"),
        "the CLI still has its own copy"
    );
}

/// CAS.4: no public config writer takes a `bool`.
#[test]
fn no_public_config_writer_takes_a_bool() {
    let lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config_persistence.rs");
    let text = std::fs::read_to_string(lib).expect("read");
    let flagged: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("pub fn ") && line.contains(": bool"))
        .collect();
    assert!(flagged.is_empty(), "{flagged:?}");
}
