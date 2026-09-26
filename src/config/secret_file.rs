// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refuse a file that other local users can read when it holds a secret, or
//! change when it decides whom the gateway trusts (MIK 7570 CONFIG.2, F18).
//!
//! The mode check is Unix only. Windows has no mode bits, and ACL inspection
//! is out of scope; the upgrade note says so. There the file is read as is.

use std::path::Path;

use crate::{Error, Result};

/// The UPGRADING-4.0 item that documents this rule. One place to renumber.
#[cfg(unix)]
const UPGRADE_ITEM: u32 = 35;

/// Which kind of file is read. It sets the wording, the rule and the size cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SecretFile {
    /// The gateway config file.
    Config,
    /// A file listed under `env_files`.
    EnvFile,
    /// The target of a `file:` secret reference (C9).
    Reference,
    /// A TLS private key: `mtls.server_key`, or a CA key given to the CLI.
    TlsKey,
    /// An OAuth token file under `~/.mcp-gateway/oauth/`.
    OAuthToken,
    /// A capability `file:/path.json:field` credential.
    CredentialFile,
    /// `mtls.server_cert` or `mtls.ca_cert`.
    TlsCert,
    /// `mtls.crl_path`.
    TlsCrl,
    /// The identity-grants file.
    IdentityGrants,
    /// A control-plane `grants.json` or `policies.json`.
    ControlPlaneCollection,
}

/// What a file's mode must protect.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protects {
    /// It holds a secret: others may neither read nor change it.
    Secrecy,
    /// It decides whom the gateway trusts: others may read it, not change it.
    Integrity,
}

impl SecretFile {
    /// The largest file this kind may be. A `file:` secret is one value, so a
    /// larger file is a wrong path, not a secret.
    const fn max_bytes(self) -> Option<u64> {
        match self {
            Self::Reference => Some(64 * 1024),
            _ => None,
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Config => "config file",
            Self::EnvFile => "env file",
            Self::Reference => "secret file",
            Self::TlsKey => "TLS private key",
            Self::OAuthToken => "OAuth token file",
            Self::CredentialFile => "credential file",
            Self::TlsCert => "TLS certificate",
            Self::TlsCrl => "certificate revocation list",
            Self::IdentityGrants => "identity grants file",
            Self::ControlPlaneCollection => "control-plane file",
        }
    }

    #[cfg(unix)]
    pub(crate) const fn protects(self) -> Protects {
        match self {
            Self::TlsCert | Self::TlsCrl | Self::IdentityGrants | Self::ControlPlaneCollection => {
                Protects::Integrity
            }
            _ => Protects::Secrecy,
        }
    }
}

/// Why [`read_guarded_file`] did not return the text.
#[derive(Debug)]
pub(crate) enum GuardedRead {
    /// Opening or reading failed; `NotFound` stays visible to the caller.
    Io(std::io::Error),
    /// The file was opened and refused: its type, mode, size or encoding. The text
    /// names the file and the fix, never the content.
    Refused(String),
}

/// A refusal is `PermissionDenied`, so a caller that speaks `io::Error` fails
/// closed on it and still sees `NotFound` for a missing file.
impl From<GuardedRead> for std::io::Error {
    fn from(read: GuardedRead) -> Self {
        match read {
            GuardedRead::Io(e) => e,
            GuardedRead::Refused(text) => Self::new(std::io::ErrorKind::PermissionDenied, text),
        }
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
/// The integrity rule on `mode & 0o777`: others may read, not write. Whoever
/// owns the file, a group or world write bit lets someone else change whom the
/// gateway trusts.
#[must_use]
pub(crate) fn integrity_file_refusal(mode: u32) -> Option<Refusal> {
    let m = mode & 0o777;
    if m & 0o002 != 0 {
        return Some(Refusal::World);
    }
    if m & 0o020 != 0 {
        return Some(Refusal::GroupWrite);
    }
    None
}

/// Read `path` through one handle, refusing it when its mode breaks the rule
/// `what` [protects](SecretFile::protects).
///
/// The verdict is taken with `fstat` on the handle the bytes are then read
/// from, so a file swapped or loosened between the check and the read cannot
/// slip through. Opening follows symlinks, which Kubernetes `..data` links need.
///
/// # Errors
///
/// [`GuardedRead::Io`] when the file cannot be opened or read, and
/// [`GuardedRead::Refused`] for a file that is not a regular file (Unix), a
/// refused mode, an oversized `Reference`, or text that is not UTF-8.
pub(crate) fn read_guarded_file(
    path: &Path,
    what: SecretFile,
) -> std::result::Result<String, GuardedRead> {
    use std::io::Read as _;

    let noun = what.noun();
    let mut file = open_without_blocking(path).map_err(GuardedRead::Io)?;
    #[cfg(unix)]
    check_mode(&file, path, what)?;
    let mut bytes = Vec::new();
    match what.max_bytes() {
        // Bounded on the handle the mode was judged on: a size taken from a
        // separate `stat` could describe a different file than the one read.
        Some(limit) => {
            (&mut file)
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(GuardedRead::Io)?;
            if bytes.len() as u64 > limit {
                return Err(GuardedRead::Refused(format!(
                    "Refusing to load {noun} {}: it is larger than {} KiB, the limit for one secret.",
                    path.display(),
                    limit / 1024
                )));
            }
        }
        None => {
            file.read_to_end(&mut bytes).map_err(GuardedRead::Io)?;
        }
    }
    String::from_utf8(bytes).map_err(|_| {
        GuardedRead::Refused(format!(
            "Cannot read {noun} {}: it is not UTF-8.",
            path.display()
        ))
    })
}

/// Opens `path` for reading without waiting on it (F18 A2). A plain open of a
/// FIFO blocks until a writer appears, so it would hang before `check_mode`
/// could refuse it. `O_NONBLOCK` has no effect on reading a regular file, the
/// only kind that is ever read; `O_NOCTTY` keeps a terminal from becoming ours.
#[cfg(unix)]
fn open_without_blocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits().cast_signed())
        .open(path)
}

/// Windows: no file types or modes are checked (UPGRADING item 35).
#[cfg(not(unix))]
fn open_without_blocking(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// What a non-regular file is, for the refusal text.
#[cfg(unix)]
fn file_kind(kind: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt as _;
    if kind.is_dir() {
        "directory"
    } else if kind.is_fifo() {
        "FIFO"
    } else if kind.is_char_device() {
        "character device"
    } else if kind.is_block_device() {
        "block device"
    } else if kind.is_socket() {
        "socket"
    } else {
        "non-regular file"
    }
}

/// The type and mode verdict on an open handle, as a refusal naming the fix.
#[cfg(unix)]
fn check_mode(
    file: &std::fs::File,
    path: &Path,
    what: SecretFile,
) -> std::result::Result<(), GuardedRead> {
    use std::os::unix::fs::MetadataExt as _;

    let meta = file.metadata().map_err(GuardedRead::Io)?;
    // Type before mode, on the same handle: nothing but a regular file is read.
    if !meta.file_type().is_file() {
        return Err(GuardedRead::Refused(format!(
            "Refusing to load {} {}: it is a {}, not a regular file.",
            what.noun(),
            path.display(),
            file_kind(meta.file_type())
        )));
    }
    let euid = rustix::process::geteuid().as_raw();
    let owned = meta.uid() == euid;
    let (refusal, why) = match what.protects() {
        Protects::Secrecy => (
            secret_file_refusal(meta.mode(), meta.uid(), euid),
            "it can hold credentials",
        ),
        Protects::Integrity => (
            integrity_file_refusal(meta.mode()),
            "it decides whom the gateway trusts",
        ),
    };
    let Some(refusal) = refusal else {
        return Ok(());
    };
    let mode = meta.mode() & 0o777;
    let gid = meta.gid();
    let lets = match refusal {
        Refusal::World if what.protects() == Protects::Secrecy && mode & 0o004 != 0 => {
            "lets other users read it".to_string()
        }
        Refusal::World => "lets other users change it".to_string(),
        Refusal::GroupWrite => format!("lets group {gid} change it"),
        Refusal::GroupReadOwned => format!("lets group {gid} read it"),
    };
    Err(GuardedRead::Refused(format!(
        "Refusing to load {} {}: mode {mode:04o} {lets}, and {why}. {}",
        what.noun(),
        path.display(),
        refusal_fix(path, owned, what)
    )))
}

/// A secret-bearing or trust file read outside `config` (F18). Each maps to
/// the private [`SecretFile`] class that sets its mode rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckedFile {
    /// `mtls.server_key`.
    TlsKey,
    /// `mtls.server_cert` or `mtls.ca_cert`.
    TlsCert,
    /// `mtls.crl_path`.
    TlsCrl,
    /// An OAuth token file.
    OAuthToken,
    /// A capability `file:/path.json:field` credential.
    CredentialFile,
    /// The identity-grants file.
    IdentityGrants,
    /// A control-plane `grants.json` or `policies.json`.
    ControlPlaneCollection,
}

/// The one mode-checked read for files outside `config` (F18): open once,
/// judge the mode on that handle, then read.
///
/// # Errors
///
/// An `io::Error` whose message names the file and the reason. A refused mode,
/// size or encoding is `PermissionDenied`; a missing file keeps `NotFound`.
pub(crate) fn read_checked_file(path: &Path, what: CheckedFile) -> std::io::Result<String> {
    let class = match what {
        CheckedFile::TlsKey => SecretFile::TlsKey,
        CheckedFile::TlsCert => SecretFile::TlsCert,
        CheckedFile::TlsCrl => SecretFile::TlsCrl,
        CheckedFile::OAuthToken => SecretFile::OAuthToken,
        CheckedFile::CredentialFile => SecretFile::CredentialFile,
        CheckedFile::IdentityGrants => SecretFile::IdentityGrants,
        CheckedFile::ControlPlaneCollection => SecretFile::ControlPlaneCollection,
    };
    read_guarded_file(path, class).map_err(|e| match e {
        GuardedRead::Io(e) => std::io::Error::new(
            e.kind(),
            format!("Cannot read {} {}: {e}", class.noun(), path.display()),
        ),
        refused @ GuardedRead::Refused(_) => refused.into(),
    })
}

/// [`read_guarded_file`] with both failures as today's `Error::Config` texts.
pub(crate) fn read_secret_file(path: &Path, what: SecretFile) -> Result<String> {
    read_guarded_file(path, what).map_err(|e| match e {
        GuardedRead::Io(e) => Error::Config(format!(
            "Cannot read {} {}: {e}",
            what.noun(),
            path.display()
        )),
        GuardedRead::Refused(text) => Error::Config(text),
    })
}

/// The fix to print for a refused file, given whether this process owns it.
///
/// `chmod 600` is only a fix on a file this process owns: on one another uid
/// owns it would lock the gateway out. There the fix is the group route the
/// Helm chart takes. An integrity file keeps its read bits (`chmod go-w`).
#[cfg(unix)]
fn refusal_fix(path: &Path, owned: bool, what: SecretFile) -> String {
    let see = format!("(see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM})");
    match (what.protects(), owned, what) {
        (Protects::Integrity, true, _) => format!("Fix: chmod go-w {} {see}.", path.display()),
        (Protects::Integrity, false, _) => {
            format!("Fix: clear the group- and world-write bits {see}.")
        }
        (Protects::Secrecy, true, _) => format!("Fix: chmod 600 {} {see}.", path.display()),
        (Protects::Secrecy, false, SecretFile::Config | SecretFile::EnvFile) => format!(
            "Fix: clear the world and group-write bits; on Kubernetes give the pod an \
             fsGroup this process is in (the Helm chart pins podSecurityContext.fsGroup \
             to 1001, the image's group) and keep the config volume's defaultMode at \
             288 (octal 0440) {see}."
        ),
        (Protects::Secrecy, false, _) => format!(
            "Fix: clear the world and group-write bits; on Kubernetes mount the Secret with \
             defaultMode: 288 (octal 0440) and set podSecurityContext.fsGroup to a group this \
             process is in {see}."
        ),
    }
}

#[cfg(all(test, unix))]
#[path = "secret_file_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "secret_file_population_tests.rs"]
mod population_tests;

#[cfg(all(test, unix))]
#[path = "secret_file_type_tests.rs"]
mod type_tests;
