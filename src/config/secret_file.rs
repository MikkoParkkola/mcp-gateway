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
const UPGRADE_ITEM: u32 = 35;

/// Which kind of file a refusal is about. It only changes the wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretFile {
    /// The gateway config file.
    Config,
    /// A file listed under `env_files`.
    EnvFile,
    /// The target of a `file:` secret reference (C9).
    Reference,
}

impl SecretFile {
    /// The largest file this kind may be. A `file:` secret is one value, so a
    /// larger file is a wrong path, not a secret.
    const fn max_bytes(self) -> Option<u64> {
        match self {
            Self::Config | Self::EnvFile => None,
            Self::Reference => None,
        }
    }
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

/// Read `path` through one handle, refusing it when its mode lets other users
/// read or change it.
///
/// The verdict is taken with `fstat` on the handle the bytes are then read
/// from, so a file swapped or loosened between the check and the read cannot
/// slip through. Opening follows symlinks, which Kubernetes `..data` links need.
pub(crate) fn read_secret_file(path: &Path, what: SecretFile) -> Result<String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    let noun = match what {
        SecretFile::Config => "config file",
        SecretFile::EnvFile => "env file",
        SecretFile::Reference => "secret file",
    };
    let cannot =
        |e: std::io::Error| Error::Config(format!("Cannot read {noun} {}: {e}", path.display()));
    let mut file = std::fs::File::open(path).map_err(cannot)?;
    let meta = file.metadata().map_err(cannot)?;
    let euid = rustix::process::geteuid().as_raw();
    if let Some(refusal) = secret_file_refusal(meta.mode(), meta.uid(), euid) {
        let mode = meta.mode() & 0o777;
        let gid = meta.gid();
        let lets = match refusal {
            Refusal::World if mode & 0o004 != 0 => "lets other users read it".to_string(),
            Refusal::World => "lets other users change it".to_string(),
            Refusal::GroupWrite => format!("lets group {gid} change it"),
            Refusal::GroupReadOwned => format!("lets group {gid} read it"),
        };
        let fix = refusal_fix(path, meta.uid() == euid, what);
        return Err(Error::Config(format!(
            "Refusing to load {noun} {}: mode {mode:04o} {lets}, and it can hold credentials. {fix}",
            path.display()
        )));
    }
    let text = if let Some(limit) = what.max_bytes() {
        // Bounded on the handle the mode was judged on: a size taken from a
        // separate `stat` could describe a different file than the one read.
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(cannot)?;
        if bytes.len() as u64 > limit {
            return Err(Error::Config(format!(
                "Refusing to load {noun} {}: it is larger than {} KiB, the limit for one secret.",
                path.display(),
                limit / 1024
            )));
        }
        String::from_utf8(bytes).map_err(|_| {
            Error::Config(format!(
                "Cannot read {noun} {}: it is not UTF-8.",
                path.display()
            ))
        })?
    } else {
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(cannot)?;
        text
    };
    Ok(text)
}

/// The fix to print for a refused file, given whether this process owns it.
///
/// `chmod 600` is only a fix on a file this process owns: on one another uid
/// owns it would lock the gateway out. There the fix is the group route the
/// Helm chart takes.
fn refusal_fix(path: &Path, owned: bool, what: SecretFile) -> String {
    if owned {
        format!(
            "Fix: chmod 600 {} (see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM}).",
            path.display()
        )
    } else if what == SecretFile::Reference {
        format!(
            "Fix: clear the world and group-write bits; on Kubernetes mount the Secret with \
             defaultMode: 288 (octal 0440) and set podSecurityContext.fsGroup to a group this \
             process is in (see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM})."
        )
    } else {
        format!(
            "Fix: clear the world and group-write bits; on Kubernetes give the pod an \
             fsGroup this process is in (the Helm chart pins podSecurityContext.fsGroup \
             to 1001, the image's group) and keep the config volume's defaultMode at \
             288 (octal 0440) (see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM})."
        )
    }
}

#[cfg(test)]
#[path = "secret_file_tests.rs"]
mod tests;
