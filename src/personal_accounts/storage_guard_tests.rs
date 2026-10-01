// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the account store's directory checks refuse: a path through a file or a
//! link, a directory others can read, and a directory it cannot create.

use std::os::unix::fs::PermissionsExt as _;

use super::{AccountError, create_directory, private_directory, validate_path};

/// A component the filesystem cannot even look up (longer than NAME_MAX).
fn unlookable(root: &std::path::Path) -> std::path::PathBuf {
    root.join("n".repeat(300))
}

/// Mutant: a path through a file or a symlink is accepted, or an inspection
/// failure is read as "absent" and the check passes.
#[test]
fn a_store_path_must_be_real_directories_or_absent() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    validate_path(&base.join("absent")).expect("control: an absent tail is allowed");

    let file = base.join("file");
    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        validate_path(&file.join("below")),
        Err(AccountError::InvalidConfiguration)
    );
    let link = base.join("link");
    std::os::unix::fs::symlink(&base, &link).unwrap();
    assert_eq!(
        validate_path(&link.join("below")),
        Err(AccountError::InvalidConfiguration)
    );
    assert_eq!(
        validate_path(&unlookable(&base)),
        Err(AccountError::StorageUnavailable)
    );
}

/// Mutant: a store directory readable by others, or a link, is pinned as private.
#[test]
fn a_store_directory_must_be_private_and_not_a_link() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let private = base.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    private_directory(&private).expect("control: 0700 is private");

    let open = base.join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(
        private_directory(&open).err(),
        Some(AccountError::InvalidConfiguration)
    );
    let link = base.join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    assert_eq!(
        private_directory(&link).err(),
        Some(AccountError::InvalidConfiguration)
    );
    assert_eq!(
        private_directory(&base.join("absent")).err(),
        Some(AccountError::StorageUnavailable)
    );
}

/// Mutant: creating the store directory over a file, or after a failed
/// inspection or mkdir, is reported as success.
#[test]
fn a_store_directory_is_created_private_or_refused() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let made = base.join("a").join("b");
    create_directory(&made).expect("control: parents are created");
    assert_eq!(
        std::fs::metadata(&made).unwrap().permissions().mode() & 0o077,
        0
    );
    create_directory(&made).expect("control: an existing private directory is accepted");

    let file = base.join("file");
    std::fs::write(&file, b"").unwrap();
    assert_eq!(
        create_directory(&file),
        Err(AccountError::InvalidConfiguration)
    );
    assert_eq!(
        create_directory(&unlookable(&base)),
        Err(AccountError::StorageUnavailable)
    );

    // A parent that cannot be written to refuses the mkdir. Skipped for a
    // caller the permission bits do not bind (root).
    let locked = base.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(locked.join("probe"), b"").is_err() {
        assert_eq!(
            create_directory(&locked.join("child")),
            Err(AccountError::StorageUnavailable)
        );
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
}
