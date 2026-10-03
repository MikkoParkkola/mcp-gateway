// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Watch-path resolution for the config file and its symlink chain.

use super::*;

/// A bare relative config path must still resolve to a watchable directory.
///
/// `Path::parent` answers `Some("")` for `gateway.yaml`, and watching an empty
/// path fails — which silently disabled hot-reload for the invocation the
/// installer itself prints.
#[test]
fn watch_dir_of_bare_filename_is_current_dir() {
    use std::path::{Path, PathBuf};
    assert_eq!(
        super::watch_dir_of(Path::new("gateway.yaml")),
        PathBuf::from(".")
    );
    assert_eq!(
        super::watch_dir_of(Path::new("etc/gateway.yaml")),
        PathBuf::from("etc")
    );
    assert_eq!(
        super::watch_dir_of(Path::new("/etc/gateway.yaml")),
        PathBuf::from("/etc")
    );
}

/// A watched path must be absolute, because events are matched by equality.
///
/// A relative `-c gateway.yaml` matched no event, so config hot-reload was
/// silently dead for the invocation the installer prints.
#[test]
fn absolute_watch_path_resolves_relative_paths() {
    use std::path::PathBuf;
    let resolved = super::absolute_watch_path(PathBuf::from("Cargo.toml"));
    assert!(
        resolved.is_absolute(),
        "expected an absolute path, got {resolved:?}"
    );
    assert!(resolved.ends_with("Cargo.toml"));

    // A path that does not exist yet still comes back absolute: an `env_file`
    // the operator writes later must match the event `notify` reports for it.
    let missing = super::absolute_watch_path(PathBuf::from("no/such/gateway.yaml"));
    assert!(
        missing.is_absolute(),
        "expected an absolute path, got {missing:?}"
    );
    assert!(missing.ends_with("no/such/gateway.yaml"));
}

/// A symlinked config file must be watched where the operator points at it.
/// Resolving the final component aims the watcher at the symlink target's
/// directory, so a deploy that retargets the symlink writes nowhere the
/// watcher is looking and the gateway keeps serving the superseded config.
#[test]
fn absolute_watch_path_keeps_a_symlinked_file_unresolved() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("release.yaml");
    write_owner_only(&real, "servers: {}\n").expect("write");
    let link = dir.path().join("gateway.yaml");
    crate::test_symlink::symlink(&real, &link).expect("symlink");

    let resolved = super::absolute_watch_path(link);
    assert!(
        resolved.ends_with("gateway.yaml"),
        "expected the symlink path to survive, got {resolved:?}"
    );
    // The parent chain is still resolved: macOS reports events under the real
    // directory (`/private/var`, not `/var`), and the watcher compares paths
    // for equality.
    assert_eq!(
        resolved.parent(),
        std::fs::canonicalize(dir.path()).ok().as_deref(),
        "expected the parent chain to be canonical, got {resolved:?}"
    );
}

#[test]
fn config_watch_paths_covers_the_symlink_and_its_target() {
    // GIVEN: a config the operator names through a symlink
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("release.yaml");
    write_owner_only(&target, "backends: {}\n").expect("write target");
    let link = dir.path().join("gateway.yaml");
    crate::test_symlink::symlink(&target, &link).expect("symlink");

    // WHEN: we work out which paths the watcher has to recognise
    let paths = super::config_watch_paths(link.clone());

    // THEN: both the operator-named link and its target are covered, so
    // neither an in-place write to the target nor a retarget goes unseen.
    let canonical_dir = std::fs::canonicalize(dir.path()).expect("canonical dir");
    assert!(
        paths.contains(&canonical_dir.join("gateway.yaml")),
        "the operator-named path must stay watched: {paths:?}"
    );
    assert!(
        paths.contains(&canonical_dir.join("release.yaml")),
        "the symlink target must be watched too: {paths:?}"
    );
}

#[test]
fn config_watch_paths_of_a_plain_file_is_a_single_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("gateway.yaml");
    write_owner_only(&file, "backends: {}\n").expect("write");

    let paths = super::config_watch_paths(file);

    assert_eq!(
        paths.len(),
        1,
        "no duplicate watch for a plain file: {paths:?}"
    );
}

#[test]
fn a_retargeted_symlink_is_matched_at_its_new_target() {
    // GIVEN: a config named through a link, pointed at one release
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first.yaml");
    let second = dir.path().join("second.yaml");
    write_owner_only(&first, "a: 1").unwrap();
    write_owner_only(&second, "a: 2").unwrap();
    let link = dir.path().join("gateway.yaml");
    crate::test_symlink::symlink(&first, &link).unwrap();
    let paths_at_startup = super::config_watch_paths(link.clone());

    // WHEN: the deployment repoints the link at the next release and writes it
    std::fs::remove_file(&link).unwrap();
    crate::test_symlink::symlink(&second, &link).unwrap();
    let event = notify::Event {
        kind: EventKind::Modify(notify::event::ModifyKind::Data(
            notify::event::DataChange::Any,
        )),
        paths: vec![std::fs::canonicalize(&second).unwrap()],
        attrs: EventAttributes::default(),
    };

    // THEN: the write is recognised, which a path list frozen at startup
    // cannot do — it still names the release the link no longer points at.
    assert!(
        !super::is_config_event(&event, &paths_at_startup),
        "the frozen list is exactly what this test exists to rule out"
    );
    assert!(super::is_config_event_for(&event, &link));
}
