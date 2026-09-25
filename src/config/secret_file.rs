// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refuse a config or env file that other local users can read (MIK 7570
//! CONFIG.2).
//!
//! Unix only. Windows has no mode bits, and ACL inspection is out of scope;
//! the upgrade note says so.

use std::path::Path;

use crate::{Error, Result};

/// The UPGRADING-4.0 item that documents this rule. One place to renumber.
const UPGRADE_ITEM: u32 = 31;

/// Which kind of file a refusal is about. It only changes the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretFile {
    /// The gateway config file.
    Config,
    /// A file listed under `env_files`.
    EnvFile,
}

/// Why a file's mode is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A world bit is set.
    World,
    /// The group may write it.
    GroupWrite,
    /// The group may read a file this process owns, so the group bit is not
    /// how this process reads it.
    GroupReadOwned,
}

/// The rule on `mode & 0o777`, given who owns the file and who we are.
///
/// Group read is allowed only on a file this process does not own: there the
/// group bit is how it reads the file, as with a root-owned Kubernetes
/// projection under `fsGroup`.
#[must_use]
pub(crate) fn secret_file_refusal(mode: u32, file_uid: u32, euid: u32) -> Option<Refusal> {
    let m = mode & 0o777;
    if m & 0o007 != 0 {
        return Some(Refusal::World);
    }
    if m & 0o020 != 0 {
        return Some(Refusal::GroupWrite);
    }
    if m & 0o040 != 0 && file_uid == euid {
        return Some(Refusal::GroupReadOwned);
    }
    None
}

/// Refuse `path` when its mode lets other users read or change it.
///
/// Follows symlinks, which Kubernetes `..data` links need.
pub(crate) fn check_secret_file(path: &Path, what: SecretFile) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let noun = match what {
        SecretFile::Config => "config file",
        SecretFile::EnvFile => "env file",
    };
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::Config(format!("Cannot stat {noun} {}: {e}", path.display())))?;
    let euid = rustix::process::geteuid().as_raw();
    let Some(refusal) = secret_file_refusal(meta.mode(), meta.uid(), euid) else {
        return Ok(());
    };
    let mode = meta.mode() & 0o777;
    let gid = meta.gid();
    let lets = match refusal {
        Refusal::World if mode & 0o004 != 0 => "lets other users read it".to_string(),
        Refusal::World => "lets other users change it".to_string(),
        Refusal::GroupWrite => format!("lets group {gid} change it"),
        Refusal::GroupReadOwned => format!("lets group {gid} read it"),
    };
    Err(Error::Config(format!(
        "Refusing to load {noun} {path}: mode {mode:04o} {lets}, and it can hold credentials. \
         Fix: chmod 600 {path} (the container runs as UID 1001; see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM}).",
        path = path.display(),
    )))
}

#[cfg(test)]
#[path = "secret_file_tests.rs"]
mod tests;
