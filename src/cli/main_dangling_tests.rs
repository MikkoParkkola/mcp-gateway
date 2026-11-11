// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Discovery persistence keeps a dangling config symlink (GH462).

use super::*;

// GH462.CONFIG.3 / GH462.CONFIG.5: existing symlink differs from a missing config.
#[test]
fn gh462_discovery_persistence_preserves_dangling_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("discovered.yaml");
    let target = dir.path().join("absent-target.yaml");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &output).unwrap();
    // A missing target is a file link on Windows; Developer Mode allows creating it.
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &output).unwrap();
    #[cfg(unix)] // Unix-only: (dev, ino) file identity via MetadataExt.
    let identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&output).unwrap();
        (metadata.dev(), metadata.ino())
    };
    let result = write_discovered_to_config(
        &[make_discovered_server("gh462-import")],
        Some(&output),
        CommentLoss::Refuse,
    );
    assert!(
        result.is_err(),
        "a dangling symlink was replaced by defaults"
    );
    assert_eq!(std::fs::read_link(&output).unwrap(), target);
    #[cfg(unix)] // Unix-only: (dev, ino) file identity via MetadataExt.
    {
        use std::os::unix::fs::MetadataExt;
        let after = std::fs::symlink_metadata(&output).unwrap();
        assert_eq!((after.dev(), after.ino()), identity);
    }
    assert!(!target.exists());
}
