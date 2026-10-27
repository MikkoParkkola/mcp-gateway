// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `cap pin`: pin a capability file in place under the same directory lock
//! the capability writer takes. Apart from the web UI's writer, so a build
//! without the web UI keeps it.

use std::path::Path;
use std::time::Instant;

use super::compute_capability_hash;
use crate::config_persistence::lock::NotLocked;
use crate::config_persistence::{FileMode, Symlink, write_atomic};

/// `cap pin`: pin `file` in place under its directory's lock (D8). A link
/// is followed, as `cap pin` always has, and the lock is the resolved file's
/// directory, the same lock the editor takes there, so the two never write
/// one file at once.
///
/// # Errors
///
/// The file cannot be resolved, locked, read or written, or is not YAML.
pub fn pin_file(file: &Path) -> Result<String, String> {
    pin_file_until(file, Instant::now() + std::time::Duration::from_secs(5))
}

/// [`pin_file`], waiting for the lock until `deadline`.
fn pin_file_until(file: &Path, deadline: Instant) -> Result<String, String> {
    let real = std::fs::canonicalize(file)
        .map_err(|e| format!("cannot resolve {}: {e}", file.display()))?;
    let dir = real
        .parent()
        .ok_or_else(|| format!("{} has no directory", real.display()))?;
    let _held = crate::config_persistence::lock::lock_config_blocking(
        &dir.join("capabilities"),
        deadline,
        |lock| eprintln!("Waiting for {} (another write holds it)", lock.display()),
    )
    .map_err(|e| match e {
        NotLocked::Busy => format!(
            "{} is held by another write; retry",
            crate::config_persistence::lock::lock_path(&dir.join("capabilities")).display()
        ),
        NotLocked::Failed(error) => error,
    })?;
    let content = std::fs::read_to_string(&real)
        .map_err(|e| format!("cannot read {}: {e}", real.display()))?;
    crate::yaml::from_str::<crate::yaml::Value>(&content)
        .map_err(|e| format!("not a valid YAML file ({}): {e}", real.display()))?;
    let hash = compute_capability_hash(&content);
    let pinned = super::rewrite_with_pin(&content, &hash);
    let mode = if cfg!(windows) {
        FileMode::Private
    } else {
        FileMode::Inherit
    };
    write_atomic(&real, pinned.as_bytes(), mode, Symlink::Replace)
        .map_err(|e| format!("cannot write {}: {e}", real.display()))?;
    Ok(hash)
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::{Duration, Instant};

    use super::pin_file_until;
    use crate::capability::{compute_capability_hash, rewrite_with_pin};
    use crate::config_persistence::lock::lock_config;

    const TEXT: &str = "fulcrum: \"1.0\"\nname: kept\ndescription: Original\n";

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn pinned(text: &str) -> String {
        rewrite_with_pin(text, &compute_capability_hash(text))
    }

    fn dir_with(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("kept.yaml");
        std::fs::write(&file, text).unwrap();
        (dir, file)
    }

    // ── T17: `cap pin` takes the resolved directory's lock ────────────────

    #[tokio::test]
    async fn cap_pin_follows_the_link_under_the_real_directory_lock() {
        let (real_dir, real_file) = dir_with(TEXT);
        let links = tempfile::tempdir().unwrap();
        let link = links.path().join("link.yaml");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        let held = lock_config(&real_dir.path().join("capabilities"), soon())
            .await
            .unwrap();
        let refused = pin_file_until(&link, Instant::now());
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(
            std::fs::read_to_string(&real_file).unwrap(),
            TEXT,
            "nothing written while held"
        );
        assert!(
            !links.path().join(".capabilities.lock").exists(),
            "the link's directory is not the lock"
        );
        drop(held);

        let hash = pin_file_until(&link, soon()).expect("pins once the lock is free");
        assert_eq!(hash, compute_capability_hash(TEXT));
        assert_eq!(std::fs::read_to_string(&real_file).unwrap(), pinned(TEXT));
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
