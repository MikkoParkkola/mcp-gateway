// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH462 I/O failure fixtures and the loader and mutation rows that use them.

use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) enum Failure {
    // Unix-only: chmod 0 (POSIX mode bits); Windows enforces access through DACLs.
    #[cfg(unix)]
    Unreadable,
    #[cfg(unix)]
    DeniedParent,
    Dangling,
}

#[cfg(unix)]
pub(super) struct RestorePermissions(PathBuf, std::fs::Permissions);

#[cfg(unix)]
impl Drop for RestorePermissions {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.0, self.1.clone()).unwrap();
    }
}

#[cfg(not(unix))]
// Never constructed here; not `Copy`, so the rows can still `drop` the guard.
pub(super) type RestorePermissions = Box<()>;

/// A symlink whose target does not exist. On Windows a missing target is a file link.
fn dangling_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

pub(super) fn prepare(home: &Path, failure: Failure) -> PathBuf {
    let parent = home.join("config");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("gateway.yaml");
    if matches!(failure, Failure::Dangling) {
        dangling_symlink(&parent.join("missing-target.yaml"), &path);
    } else {
        write_config_fixture(&path, &baseline()).unwrap();
        assert!(Config::load_literal(Some(&path)).is_ok());
    }
    path
}

#[cfg(unix)]
pub(super) fn deny(path: &Path, failure: Failure) -> Option<RestorePermissions> {
    use std::os::unix::fs::PermissionsExt;
    let target = match failure {
        Failure::Unreadable => path,
        Failure::DeniedParent => path.parent().unwrap(),
        Failure::Dangling => return dangling_check(path),
    };
    let restore = RestorePermissions(
        target.to_owned(),
        std::fs::metadata(target).unwrap().permissions(),
    );
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o0)).unwrap();
    // An elevated runner must not silently skip an ineffective fixture.
    assert_eq!(
        std::fs::File::open(path).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    if matches!(failure, Failure::DeniedParent) {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    Some(restore)
}

#[cfg(not(unix))]
pub(super) fn deny(path: &Path, failure: Failure) -> Option<RestorePermissions> {
    match failure {
        Failure::Dangling => dangling_check(path),
    }
}

fn dangling_check(path: &Path) -> Option<RestorePermissions> {
    assert!(std::fs::symlink_metadata(path).unwrap().is_symlink());
    assert_eq!(
        std::fs::File::open(path).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    None
}

// GH462.CONFIG.3: helper matrix, independent of admin/setup error mapping.
macro_rules! loader_io_case {
    ($name:ident, $failure:expr) => {
        #[test]
        fn $name() {
            let failure = $failure;
            let home = tempfile::tempdir().unwrap();
            let path = prepare(home.path(), failure);
            let before = tree_snapshot(home.path());
            let guard = deny(&path, failure);
            let result = load_existing_or_default(&path);
            drop(guard);
            assert!(result.is_err(), "{failure:?} was mistaken for absence");
            assert_eq!(tree_snapshot(home.path()), before);
        }
    };
}

#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
loader_io_case!(gh462_loader_unreadable, Failure::Unreadable);
#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
loader_io_case!(gh462_loader_denied_parent, Failure::DeniedParent);
loader_io_case!(gh462_loader_dangling, Failure::Dangling);

// GH462.CONFIG.3: six failure/path pairs; context helper asserts live invariants.
macro_rules! mutation_io_case {
    ($name:ident, $failure:expr, $with_context:expr) => {
        #[tokio::test]
        async fn $name() {
            let failure = $failure;
            let home = tempfile::tempdir().unwrap();
            let path = prepare(home.path(), failure);
            let before = tree_snapshot(home.path());
            let guard = deny(&path, failure);
            refused_mutation(&path, $with_context).await;
            drop(guard);
            assert_eq!(tree_snapshot(home.path()), before);
        }
    };
}

#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
mutation_io_case!(gh462_unreadable_without_context, Failure::Unreadable, false);
#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
mutation_io_case!(gh462_unreadable_with_context, Failure::Unreadable, true);
#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
mutation_io_case!(
    gh462_denied_parent_without_context,
    Failure::DeniedParent,
    false
);
#[cfg(unix)] // Unix-only: failure injected with chmod 0 (POSIX mode bits).
mutation_io_case!(
    gh462_denied_parent_with_context,
    Failure::DeniedParent,
    true
);
mutation_io_case!(gh462_dangling_without_context, Failure::Dangling, false);
mutation_io_case!(gh462_dangling_with_context, Failure::Dangling, true);
