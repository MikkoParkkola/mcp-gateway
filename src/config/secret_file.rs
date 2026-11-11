// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refuse a file that other local users can read when it holds a secret, or
//! change when it decides whom the gateway trusts (MIK 7570 CONFIG.2, F18).
//!
//! Unix judges the mode bits on the open handle. Windows has none, so it
//! judges the handle's DACL and owner by the same two classes (UPGRADING-4.0
//! item 99).

use std::path::Path;

use crate::{Error, Result};

/// The UPGRADING-4.0 item that documents this rule. One place to renumber.
#[cfg(unix)]
const UPGRADE_ITEM: u32 = 35;
/// The item that adds the owner rule.
#[cfg(unix)]
const OWNER_UPGRADE_ITEM: u32 = 96;

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
    /// An MCP Events store record (a subscription holds its `whsec` secret).
    EventsRecord,
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
    /// A replace journal or the staged original a crash recovery restores as
    /// gateway.yaml. A refusal never suggests fixing its owner or mode:
    /// either file may be another account's plant, and fixing it would make
    /// the next recovery restore it ([`RECOVERY_FILE_FIX`]).
    RecoveryFile,
    /// A v2 recovery journal, with the recovery rule and a 1 MiB read limit.
    #[cfg(test)]
    RecoveryJournalV2,
}

/// The Windows DACL refusal: the guard's `head`, then `detail` (the found
/// refusals and the repair) for every class but a recovery file, which gets
/// the `found` refusals and its guidance, never an icacls repair.
/// Platform-neutral, so every platform's tests read it.
#[cfg(any(windows, test))]
fn acl_refusal_text(
    what: SecretFile,
    head: &str,
    found: &str,
    detail: impl FnOnce() -> String,
) -> String {
    match what.recovery_guidance() {
        Some(guidance) => format!("{head} ({found}). {guidance}"),
        None => format!("{head}{}", detail()),
    }
}

/// The not-UTF-8 refusal, with the class's fix when it has one.
fn not_utf8_message(what: SecretFile, path: &Path) -> String {
    let fix = what.fix_text(String::new);
    let gap = if fix.is_empty() { "" } else { " " };
    format!(
        "Cannot read {} {}: it is not UTF-8.{gap}{fix}",
        what.noun(),
        path.display()
    )
}

/// The refusal of something that is not a regular file (`kind`).
#[cfg(any(unix, test))]
fn not_regular_message(what: SecretFile, path: &Path, kind: &str) -> String {
    format!(
        "Refusing to load {} {}: it is a {kind}, not a regular file. {}",
        what.noun(),
        path.display(),
        what.fix_text(|| "Write the content to a regular file.".to_owned())
    )
}

/// What a refused replace journal or staged original gets instead of an
/// owner or mode fix: the one place this guidance is written.
const RECOVERY_FILE_FIX: &str = "Both the replace journal and its staged original are \
     untrusted: another account could have planted them with a matching digest. Leave their \
     owner and mode alone, because fixing them would make the next recovery restore them. Check \
     gateway.yaml against a known-good copy, move both files aside, then retry.";

/// What a file's mode must protect.
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
            #[cfg(test)]
            Self::RecoveryJournalV2 => Some(1_048_576),
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
            Self::EventsRecord => "events store record",
            Self::CredentialFile => "credential file",
            Self::TlsCert => "TLS certificate",
            Self::TlsCrl => "certificate revocation list",
            Self::IdentityGrants => "identity grants file",
            Self::ControlPlaneCollection => "control-plane file",
            #[cfg(not(test))]
            Self::RecoveryFile => "replace journal or staged original",
            #[cfg(test)]
            Self::RecoveryFile | Self::RecoveryJournalV2 => "replace journal or staged original",
        }
    }

    /// The one place a class's refusal guidance is decided: a recovery file
    /// gets [`RECOVERY_FILE_FIX`] in place of any owner, mode or ACL fix,
    /// whatever the refusal.
    const fn recovery_guidance(self) -> Option<&'static str> {
        match self {
            #[cfg(not(test))]
            Self::RecoveryFile => Some(RECOVERY_FILE_FIX),
            #[cfg(test)]
            Self::RecoveryFile | Self::RecoveryJournalV2 => Some(RECOVERY_FILE_FIX),
            _ => None,
        }
    }

    /// The fix a refusal of this class prints: `usual` for every class but a
    /// recovery file ([`Self::recovery_guidance`]). Every refusal branch
    /// takes its fix from here.
    fn fix_text(self, usual: impl FnOnce() -> String) -> String {
        self.recovery_guidance().map_or_else(usual, str::to_owned)
    }

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
    /// The owner is neither this process nor root, so it can chmod the file at will.
    ForeignOwner,
    /// A world bit is set.
    World,
    /// The group may write it.
    GroupWrite,
    /// The group may read a file this process owns, so the group bit is not
    /// how this process reads it.
    GroupReadOwned,
}

/// Whether `file_uid` is an account that is neither this process (`euid`) nor
/// root, so it can change a file it owns whatever the mode says.
#[cfg(unix)]
#[must_use]
const fn foreign_owner(file_uid: u32, euid: u32) -> bool {
    file_uid != euid && file_uid != 0
}

#[cfg(unix)]
/// The rule given who owns the file and who we are: the owner is this process
/// or root, then the mode (`mode & 0o777`) rule below.
///
/// Group read is allowed only on a file this process does not own: there the
/// group bit is how it reads the file, as with a root-owned Kubernetes
/// projection under `fsGroup`.
#[must_use]
pub(crate) fn secret_file_refusal(mode: u32, file_uid: u32, euid: u32) -> Option<Refusal> {
    if foreign_owner(file_uid, euid) {
        return Some(Refusal::ForeignOwner);
    }
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
/// The integrity rule: the owner is this process or root, and on `mode & 0o777`
/// others may read, not write. A group or world write bit lets someone else
/// change whom the gateway trusts, and so does a foreign owner, who can chmod.
#[must_use]
pub(crate) fn integrity_file_refusal(mode: u32, file_uid: u32, euid: u32) -> Option<Refusal> {
    if foreign_owner(file_uid, euid) {
        return Some(Refusal::ForeignOwner);
    }
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
    let bytes = read_guarded_bytes(path, what)?;
    String::from_utf8(bytes).map_err(|_| GuardedRead::Refused(not_utf8_message(what, path)))
}

/// [`read_guarded_file`] without the UTF-8 check, for a file whose lines are
/// judged one by one (the grant-change journal: one torn append must not make
/// every later line unreadable).
fn read_guarded_bytes(path: &Path, what: SecretFile) -> std::result::Result<Vec<u8>, GuardedRead> {
    use std::io::Read as _;

    let noun = what.noun();
    let mut file = open_for_guarded_read(path).map_err(GuardedRead::Io)?;
    #[cfg(unix)]
    check_mode(&file, path, what)?;
    #[cfg(windows)]
    check_acl(&file, path, what)?;
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
    Ok(bytes)
}

/// Opens `path` for reading without waiting on it (F18 A2). A plain open of a
/// FIFO blocks until a writer appears, so it would hang before `check_mode`
/// could refuse it. `O_NONBLOCK` has no effect on reading a regular file, the
/// only kind that is ever read; `O_NOCTTY` keeps a terminal from becoming ours.
#[cfg(unix)]
fn open_for_guarded_read(path: &Path) -> std::io::Result<std::fs::File> {
    crate::open_nonblocking::open_nonblocking(path)
}

/// Windows: opens the file the way unix does, following links, so the handle
/// judged and read is the target's. Directories open too (`BACKUP_SEMANTICS`),
/// so they are refused as not a regular file rather than as a raw error.
#[cfg(windows)]
fn open_for_guarded_read(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};
    std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// The type and DACL verdict on an open handle, as a refusal naming every
/// broken rule and the repair for this file's class.
#[cfg(windows)]
fn check_acl(
    file: &std::fs::File,
    path: &Path,
    what: SecretFile,
) -> std::result::Result<(), GuardedRead> {
    use crate::private_fs::{file_refusals_for, refusal_detail};

    let found = file_refusals_for(file, what.protects());
    if found.is_empty() {
        return Ok(());
    }
    let shown = path.display().to_string();
    let head = format!("Refusing to load {} {shown}", what.noun());
    // A recovery file gets the guard's facts and no repair line: an icacls
    // repair would make the next recovery restore a plant.
    let text = acl_refusal_text(what, &head, &format!("{found:?}"), || {
        refusal_detail(&shown, &found, what.protects())
    });
    Err(GuardedRead::Refused(text))
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
        return Err(GuardedRead::Refused(not_regular_message(
            what,
            path,
            file_kind(meta.file_type()),
        )));
    }
    let euid = rustix::process::geteuid().as_raw();
    match class_refusal(what.protects(), meta.mode(), meta.uid(), euid) {
        None => Ok(()),
        Some(refusal) => Err(GuardedRead::Refused(refusal_message(
            what,
            path,
            refusal,
            (meta.mode() & 0o777, meta.uid(), meta.gid()),
            euid,
        ))),
    }
}

/// The one verdict for a file of class `protects`: the same owner and mode
/// facts feed both rules, so neither class can be wired with the wrong uid.
#[cfg(unix)]
#[must_use]
fn class_refusal(protects: Protects, mode: u32, file_uid: u32, euid: u32) -> Option<Refusal> {
    match protects {
        Protects::Secrecy => secret_file_refusal(mode, file_uid, euid),
        Protects::Integrity => integrity_file_refusal(mode, file_uid, euid),
    }
}

/// The refusal text: names the file, what is wrong and the fix, never content.
/// `facts` is the file's `(mode & 0o777, owner uid, group gid)`.
#[cfg(unix)]
fn refusal_message(
    what: SecretFile,
    path: &Path,
    refusal: Refusal,
    (mode, file_uid, gid): (u32, u32, u32),
    euid: u32,
) -> String {
    let why = match what.protects() {
        Protects::Secrecy => "it can hold credentials",
        Protects::Integrity => "it decides whom the gateway trusts",
    };
    if refusal == Refusal::ForeignOwner {
        return foreign_owner_message(what, path, (file_uid, euid), why);
    }
    let lets = match refusal {
        Refusal::ForeignOwner => String::new(), // answered above
        Refusal::World if what.protects() == Protects::Secrecy && mode & 0o004 != 0 => {
            "lets other users read it".to_string()
        }
        Refusal::World => "lets other users change it".to_string(),
        Refusal::GroupWrite => format!("lets group {gid} change it"),
        Refusal::GroupReadOwned => format!("lets group {gid} read it"),
    };
    format!(
        "Refusing to load {} {}: mode {mode:04o} {lets}, and {why}. {}",
        what.noun(),
        path.display(),
        refusal_fix(path, file_uid == euid, what)
    )
}

/// `path` as one POSIX shell word, so a copied fix cannot split on a space,
/// read a leading `-` as an option or run metacharacters. Plain paths stay bare.
#[cfg(unix)]
fn shell_arg(path: &Path) -> String {
    let text = path.to_string_lossy();
    shlex::try_quote(&text).map_or_else(|_| text.to_string(), std::borrow::Cow::into_owned)
}

/// The owner refusal: another account owns the file, so it can chmod it at will.
/// `chown` keeps the mode, so the fix also clears what the mode rules refuse: a
/// secret file needs `chmod 600` (a group-read mode stays refused once this
/// process owns the file) and a trust file `chmod go-w`.
#[cfg(unix)]
fn foreign_owner_message(
    what: SecretFile,
    path: &Path,
    (file_uid, euid): (u32, u32),
    why: &str,
) -> String {
    let shown = shell_arg(path);
    let chmod = match what.protects() {
        Protects::Secrecy => "chmod 600",
        Protects::Integrity => "chmod go-w",
    };
    let fix = what.fix_text(|| {
        format!(
            "Fix: chown {euid} -- {shown} && {chmod} -- {shown} (see UPGRADING-4.0 \u{a7}{OWNER_UPGRADE_ITEM})."
        )
    });
    format!(
        "Refusing to load {noun} {path}: it is owned by uid {file_uid}, which is neither this \
         process (uid {euid}) nor root, so that account can change it at will, and {why}. {fix}",
        noun = what.noun(),
        path = path.display(),
    )
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
    /// An MCP Events store record.
    EventsRecord,
    /// A capability `file:/path.json:field` credential.
    CredentialFile,
    /// The identity-grants file.
    IdentityGrants,
    /// A control-plane `grants.json` or `policies.json`.
    ControlPlaneCollection,
    /// `gateway.yaml`, reread by a read-only report.
    Config,
}

/// The one mode-checked read for files outside `config` (F18): open once,
/// judge the mode on that handle, then read.
///
/// # Errors
///
/// An `io::Error` whose message names the file and the reason. A refused mode,
/// size or encoding is `PermissionDenied`; a missing file keeps `NotFound`.
pub(crate) fn read_checked_file(path: &Path, what: CheckedFile) -> std::io::Result<String> {
    let bytes = read_checked_bytes(path, what)?;
    String::from_utf8(bytes).map_err(|_| {
        GuardedRead::Refused(format!(
            "Cannot read {} {}: it is not UTF-8.",
            checked_class(what).noun(),
            path.display()
        ))
        .into()
    })
}

fn checked_class(what: CheckedFile) -> SecretFile {
    match what {
        CheckedFile::TlsKey => SecretFile::TlsKey,
        CheckedFile::TlsCert => SecretFile::TlsCert,
        CheckedFile::TlsCrl => SecretFile::TlsCrl,
        CheckedFile::OAuthToken => SecretFile::OAuthToken,
        CheckedFile::EventsRecord => SecretFile::EventsRecord,
        CheckedFile::CredentialFile => SecretFile::CredentialFile,
        CheckedFile::IdentityGrants => SecretFile::IdentityGrants,
        CheckedFile::ControlPlaneCollection => SecretFile::ControlPlaneCollection,
        CheckedFile::Config => SecretFile::Config,
    }
}

/// [`read_checked_file`] without the UTF-8 check, for a file whose lines are
/// judged one by one.
///
/// # Errors
///
/// As [`read_checked_file`], less the encoding refusal.
pub(crate) fn read_checked_bytes(path: &Path, what: CheckedFile) -> std::io::Result<Vec<u8>> {
    let class = checked_class(what);
    read_guarded_bytes(path, class).map_err(|e| match e {
        GuardedRead::Io(e) => std::io::Error::new(
            e.kind(),
            format!("Cannot read {} {}: {e}", class.noun(), path.display()),
        ),
        refused @ GuardedRead::Refused(_) => refused.into(),
    })
}

/// Why [`read_config_text`] returned no text.
#[derive(Debug)]
pub(crate) enum UnreadConfig {
    /// The guard refused the file: its type, mode, owner or encoding. The
    /// text names the file and the fix, never the content.
    Refused(String),
    /// Opening or reading it failed; the text names the file and the error.
    Failed(String),
    /// The config read was handed a replace journal or staged original:
    /// a caller bug, refused so it fails loudly.
    NotTheConfig(String),
}

/// gateway.yaml read the way every loader reads it, for a caller that writes
/// it next: `None` when it does not exist, and the guard's refusal kept apart
/// from an I/O failure, never told by an OS error code.
///
/// # Errors
///
/// [`UnreadConfig::Refused`] for a file the guard refuses,
/// [`UnreadConfig::Failed`] when it cannot be opened or read,
/// [`UnreadConfig::NotTheConfig`] for a replace journal or staged original,
/// by name or by file identity.
pub(crate) fn read_config_text(path: &Path) -> std::result::Result<Option<String>, UnreadConfig> {
    // Refused, not read as a recovery file: switching class here would hide
    // the wrong caller, and a caller that hands the config read a journal or
    // staged original must fail loudly.
    // A relative path resolves against the working directory, as the read
    // below does; without one, the path is compared as given.
    if is_recovery_file(&std::env::current_dir().unwrap_or_default(), path) {
        return Err(UnreadConfig::NotTheConfig(format!(
            "{} is a replace journal or staged original, not a config; only crash recovery reads it",
            path.display()
        )));
    }
    if is_linked_to_its_recovery_files(path) {
        return Err(UnreadConfig::NotTheConfig(format!(
            "{} is the same file as its replace journal or staged original; only crash recovery reads it",
            path.display()
        )));
    }
    read_text_of(path, SecretFile::Config)
}

/// `path`, canonical; for a missing file, its canonical parent plus its name;
/// `path` itself when even the parent cannot be resolved.
fn canonical_or_parent(path: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(path)
        .ok()
        .or_else(|| {
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
            let parent = std::fs::canonicalize(parent.unwrap_or_else(|| Path::new("."))).ok()?;
            Some(parent.join(path.file_name()?))
        })
        .unwrap_or_else(|| path.to_path_buf())
}

/// Whether `path`, resolved against `base` when relative, is the replace
/// journal or staged original of some config:
/// the config its name would belong to is derived, recovery's own helpers
/// are applied to that config, and the results are compared canonical, so a
/// symlink to one, or a spelling through another directory, is still that
/// file. Nothing here is listed or opened, so nothing can fail open.
fn is_recovery_file(base: &Path, path: &Path) -> bool {
    use crate::config_persistence::journal::{config_beside, journal_path, original_path};
    let target = canonical_or_parent(&base.join(path));
    config_beside(&target).is_some_and(|config| {
        [journal_path(&config), original_path(&config)]
            .iter()
            .any(|file| canonical_or_parent(file) == target)
    })
}

/// Whether `path` is the same file as its own replace journal or staged
/// original under another name (a hard link), which no path comparison sees.
/// Compared only for files that exist; a hard link between two different
/// configs is out of scope.
fn is_linked_to_its_recovery_files(path: &Path) -> bool {
    use crate::config_persistence::journal::{journal_path, original_path};
    // A config that cannot be stat'ed has nothing to compare; the read that
    // follows reports it.
    file_identity(path).is_ok_and(|config| {
        [journal_path(path), original_path(path)]
            .iter()
            .any(|file| file_identity(file).is_ok_and(|id| id == config))
    })
}

/// (device, inode) of what `path` names, read without opening it, so a FIFO
/// cannot block the read.
#[cfg(unix)]
fn file_identity(path: &Path) -> std::io::Result<(u64, u128)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), u128::from(meta.ino())))
}

/// (volume serial, file id) of what `path` names, from a handle opened for
/// attributes only. Unix keeps its own stat above: the shared helper opens
/// the file there, which would block on a FIFO.
#[cfg(windows)]
fn file_identity(path: &Path) -> std::io::Result<(u64, u128)> {
    crate::security::transparency_log::rotation::path_id(path)
}

/// [`read_config_text`] for a replace journal or its staged original: the
/// same rule, with a refusal that never suggests fixing the file's owner or
/// mode ([`SecretFile::RecoveryFile`]).
///
/// # Errors
///
/// As [`read_config_text`].
pub(crate) fn read_recovery_text(path: &Path) -> std::result::Result<Option<String>, UnreadConfig> {
    read_text_of(path, SecretFile::RecoveryFile)
}

/// [`read_recovery_text`] with a 1 MiB limit for the v2 recovery journal.
///
/// # Errors
///
/// As [`read_recovery_text`], also refusing an oversized journal.
#[cfg(test)]
pub(crate) fn read_recovery_journal_v2(
    path: &Path,
) -> std::result::Result<Option<String>, UnreadConfig> {
    read_text_of(path, SecretFile::RecoveryJournalV2)
}

fn read_text_of(
    path: &Path,
    what: SecretFile,
) -> std::result::Result<Option<String>, UnreadConfig> {
    match read_guarded_file(path, what) {
        Ok(text) => Ok(Some(text)),
        Err(GuardedRead::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(GuardedRead::Io(e)) => Err(UnreadConfig::Failed(format!(
            "Cannot read {} {}: {e}",
            what.noun(),
            path.display()
        ))),
        Err(GuardedRead::Refused(text)) => Err(UnreadConfig::Refused(text)),
    }
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
    what.fix_text(|| usual_refusal_fix(path, owned, what))
}

/// [`refusal_fix`] for every class but a recovery file.
#[cfg(unix)]
fn usual_refusal_fix(path: &Path, owned: bool, what: SecretFile) -> String {
    let see = format!("(see UPGRADING-4.0 \u{a7}{UPGRADE_ITEM})");
    match (what.protects(), owned, what) {
        (Protects::Integrity, true, _) => format!("Fix: chmod go-w -- {} {see}.", shell_arg(path)),
        (Protects::Integrity, false, _) => {
            format!("Fix: clear the group- and world-write bits {see}.")
        }
        (Protects::Secrecy, true, _) => format!("Fix: chmod 600 -- {} {see}.", shell_arg(path)),
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

// Unix-only (W-L1): asserts POSIX mode bits; Windows checks secret files by DACL (`secret_file_windows_tests.rs`).
#[cfg(all(test, unix))]
#[path = "secret_file_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "secret_file_population_tests.rs"]
mod population_tests;

/// The refusal text for a recovery file, every kind, read on every platform.
#[cfg(test)]
#[path = "secret_file_recovery_text_tests.rs"]
mod recovery_text_tests;

// Unix-only (W-L8): FIFO and device-file fixtures (`mkfifo`, `/dev/null`).
#[cfg(all(test, unix))]
#[path = "secret_file_type_tests.rs"]
mod type_tests;

#[cfg(all(test, windows))]
#[path = "secret_file_windows_tests.rs"]
mod windows_tests;
