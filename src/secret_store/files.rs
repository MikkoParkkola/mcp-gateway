// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `files` store: one new owner-only file per secret under
//! `<config dir>/secrets/`, referenced as `file:<absolute path>` (ADR-028
//! rule 4).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::{SecretStore, StoreError, StoreKind};

/// The `file:` reader's limit, 64 KiB, less the one newline every file gets.
const LIMIT: usize = 64 * 1024 - 1;

/// Owner-only secret files in one directory.
pub(crate) struct FilesStore {
    dir: PathBuf,
}

impl FilesStore {
    /// The store for a config in `config_dir`: `<config_dir>/secrets/`.
    pub(crate) fn new(config_dir: &Path) -> Self {
        Self {
            dir: config_dir.join("secrets"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

fn failed(what: &str, error: &std::io::Error) -> StoreError {
    StoreError::Failed(format!("{what}: {error}"))
}

impl SecretStore for FilesStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Files
    }

    fn limit(&self) -> usize {
        LIMIT
    }

    fn accepts(&self, value: &[u8]) -> Result<(), StoreError> {
        // The `file:` reader drops one trailing `\r\n` as readily as `\n`, so
        // a final CR would be lost once the newline is added.
        if value.ends_with(b"\r") {
            return Err(StoreError::Unrepresentable(
                "a value ending in a carriage return cannot be stored as a secret file",
            ));
        }
        Ok(())
    }

    fn probe(&self) -> Result<(), StoreError> {
        crate::events::create_private_dir(&self.dir)
            .map_err(|e| failed("cannot create the secrets directory", &e))?;
        // An existing directory is reused only if it is owner-only: unix
        // forces 0700 above, Windows judges the DACL here.
        #[cfg(windows)]
        {
            let handle = crate::private_fs::open_dir(&self.dir)
                .map_err(|e| failed("cannot open the secrets directory", &e))?;
            crate::private_fs::judge_dir(&handle, &self.dir).map_err(|reason| {
                StoreError::Failed(format!(
                    "the secrets directory {} is not owner-only: {reason:?}",
                    self.dir.display()
                ))
            })?;
        }
        Ok(())
    }

    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        match std::fs::symlink_metadata(self.path(name)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(failed("cannot inspect a secret file", &e)),
        }
    }

    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        let path = std::path::absolute(self.path(name))
            .map_err(|e| failed("cannot resolve the secrets directory", &e))?;
        let mut file = match crate::config_persistence::create_new_private(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Exists);
            }
            Err(e) => return Err(failed("cannot create a secret file", &e)),
        };
        // The `file:` reader drops exactly one trailing newline, so one is
        // added: the value reads back byte for byte, its own newlines kept.
        file.write_all(value)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|e| failed("cannot write a secret file", &e))?;
        crate::events::sync_dir(&self.dir)
            .map_err(|e| failed("cannot sync the secrets directory", &e))?;
        Ok(format!("file:{}", path.display()))
    }

    fn delete(&self, name: &str) -> Result<(), StoreError> {
        std::fs::remove_file(self.path(name)).map_err(|e| failed("cannot remove a secret file", &e))
    }
}
