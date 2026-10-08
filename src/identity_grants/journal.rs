// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change journal: one line per successful `identity grants` change
//! (MIK-7570.AUDIT.4).
//!
//! Exists for the bundled CLI; not a stable API.
//!
//! The CLI cannot write the gateway's governance log (one writer per log,
//! #1570), and a grant file edit carries no authenticated actor. So each CLI
//! change appends an entry here, beside the grant file, and the gateway
//! ingests it. See `docs/design/2026-09-28-grant-change-journal.md` section 3.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{IdentityGrant, IdentityGrantFile};

/// Journal line format version.
pub const JOURNAL_VERSION: u32 = 1;

/// The actor every journal entry names: the CLI has no authenticated identity.
pub const UNKNOWN_ACTOR: &str = "unknown";

/// What a CLI change did.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalVerb {
    /// A new grant id.
    Add,
    /// An existing grant id overwritten with `--replace`.
    Replace,
    /// A grant revoked.
    Revoke,
}

/// One journal line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalEntry {
    /// Line format version.
    pub v: u32,
    /// Random id; the gateway's record for this entry is keyed on it.
    pub entry_id: String,
    /// What the change did.
    pub verb: JournalVerb,
    /// The grant changed.
    pub grant_id: String,
    /// Digest of the row before the change; `None` for an add.
    pub prev_digest: Option<String>,
    /// Digest of the row after the change.
    pub digest: String,
    /// Expiry of the row after the change.
    pub expires_at: Option<DateTime<Utc>>,
    /// The CLI's clock at the change.
    pub at: DateTime<Utc>,
    /// Always [`UNKNOWN_ACTOR`].
    pub actor: String,
    /// OS account that ran the CLI. Unauthenticated: a hint, not an identity.
    pub os_account: Option<String>,
}

/// Why a CLI change did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    /// Nothing was written: bad input, unknown or duplicate id, or a failed grant-file write.
    Refused(String),
    /// The grant file changed but its journal entry could not be written.
    Unjournalled(String),
}

impl std::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(reason) => f.write_str(reason),
            Self::Unjournalled(reason) => write!(
                f,
                "grant file changed but the journal append was not confirmed ({reason}); \
                 this change may have no journal entry"
            ),
        }
    }
}

/// The grant file's one identity, whatever spelling names it (MIK-7715): its
/// real path, or, before the file exists, its real directory plus its name.
/// A symlink whose target does not exist yet resolves as that target, so the
/// first change creates the target and keeps the link. A path that resolves
/// none of these ways is returned as given.
///
/// The journal and lock derive from this, so a CLI and a gateway that spell
/// one grant file two ways (a symlink, relative against absolute) share them.
/// `gateway.yaml`'s lock and atomic replace use it too (MIK-8153).
pub(crate) fn resolved(grants: &Path) -> PathBuf {
    resolved_within(grants, 8)
}

/// [`resolved`], following at most `hops` dangling links, so a link loop ends.
fn resolved_within(grants: &Path, hops: u8) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(grants) {
        return real;
    }
    let parent = grants
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let (Ok(target), Some(left)) = (std::fs::read_link(grants), hops.checked_sub(1)) {
        return resolved_within(&parent.join(target), left);
    }
    match (std::fs::canonicalize(parent), grants.file_name()) {
        (Ok(dir), Some(name)) => dir.join(name),
        _ => grants.to_path_buf(),
    }
}

/// The journal beside the resolved grant file: its name plus `.journal.jsonl`.
#[must_use]
pub fn journal_path(grants: &Path) -> PathBuf {
    journal_beside(&resolved(grants))
}

fn journal_beside(grants: &Path) -> PathBuf {
    let mut name = grants.file_name().unwrap_or_default().to_os_string();
    name.push(".journal.jsonl");
    grants.with_file_name(name)
}

/// A 4.0.0 pre-release kept the journal beside the grant path as spelled,
/// so a path spelled through a symlink left it beside the link. Called under
/// the lock: while the resolved journal does not exist yet, that one is
/// renamed to it, which keeps its owner and mode for the checked reader
/// (MIK-7715). It is never copied or merged: a journal on another filesystem,
/// or one beside a resolved journal that already exists, is left in place
/// and named in a warning, for an operator to append by hand.
async fn adopt_spelled_journal(spelled: &Path, grants: &Path) {
    let (old, new) = (journal_beside(spelled), journal_path(grants));
    if !tokio::fs::symlink_metadata(&old)
        .await
        .is_ok_and(|meta| meta.is_file())
        || resolved(&old) == resolved(&new)
    {
        return;
    }
    let outcome = if tokio::fs::symlink_metadata(&new).await.is_ok() {
        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    } else {
        tokio::fs::rename(&old, &new).await
    };
    if let Err(error) = outcome {
        tracing::warn!(%error, from = %old.display(), to = %new.display(), "a grant journal from a pre-release path is not read; append its entries to the journal beside the real grant file, then remove it");
    }
}

/// The lock file both the CLI and the gateway take around a grant change.
///
/// A separate file that is never renamed, so a held lock survives the grant
/// file's atomic replace. Beside the resolved grant file, like the journal.
#[must_use]
pub(crate) fn lock_path(grants: &Path) -> PathBuf {
    let grants = resolved(grants);
    let mut name = std::ffi::OsString::from(".");
    name.push(grants.file_name().unwrap_or_default());
    name.push(".journal.lock");
    grants.with_file_name(name)
}

/// `sha256:<hex>` over the serialised row.
///
/// Serde field order is declaration order, so the bytes are stable. A new
/// field on `IdentityGrant` must be skipped when default, or every existing
/// grant's digest changes and reads as an out-of-band edit.
#[must_use]
pub fn grant_digest(grant: &IdentityGrant) -> String {
    // Plain fields and string-keyed data only, so serialisation cannot fail;
    // an empty preimage would be a digest that matches nothing real.
    let bytes = serde_json::to_vec(grant).expect("an identity grant always serialises");
    sha256_tag(&bytes)
}

fn sha256_tag(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

/// A change the CLI applies to the grant file: mutate it and name what it did.
pub type GrantChange =
    Box<dyn FnOnce(&mut IdentityGrantFile) -> Result<(JournalVerb, String), String> + Send>;

/// Apply one CLI change under the journal lock: read, mutate, write the grant
/// file, then append the entry. Returns the row as written.
///
/// # Errors
///
/// [`ChangeError::Refused`] when nothing was written, and
/// [`ChangeError::Unjournalled`] when the file changed but the append failed.
pub async fn apply_change(
    grants: &Path,
    create_if_missing: bool,
    change: GrantChange,
) -> Result<IdentityGrant, ChangeError> {
    apply_change_with(
        grants,
        create_if_missing,
        change,
        os_account(),
        &Hooks::default(),
    )
    .await
}

/// The OS account running the CLI, from the environment. A hint only: the
/// variable is whatever the caller's shell says.
fn os_account() -> Option<String> {
    ["USER", "USERNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Test seams for the change sequence; production passes the default.
#[derive(Default)]
pub(crate) struct Hooks {
    /// Fail the grant-file write (the lock is taken normally).
    pub(crate) fail_grant_write: bool,
    /// Fail the journal append after the grant file is written.
    pub(crate) fail_append: bool,
    /// Runs between the grant-file write and the append, with the lock held.
    pub(crate) after_grant_write: Option<Box<dyn Fn() + Send + Sync>>,
}

pub(crate) async fn apply_change_with(
    grants: &Path,
    create_if_missing: bool,
    change: GrantChange,
    os_account: Option<String>,
    hooks: &Hooks,
) -> Result<IdentityGrant, ChangeError> {
    if !create_if_missing && !grants.exists() {
        return Err(ChangeError::Refused(format!(
            "identity grants file {} does not exist",
            grants.display()
        )));
    }
    let spelled = grants;
    let grants = &resolve_for_change(grants).await?;
    // Held until this function returns: from before the read to after the
    // append, so a gateway reload never sees the file without its entry.
    let _lock = acquire_lock(grants).await.map_err(ChangeError::Refused)?;
    adopt_spelled_journal(spelled, grants).await;
    // Refuse before the grant file is touched: a journal other users can
    // write to never takes an entry (append_line re-checks), so the change
    // would land unjournalled.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let journal = journal_path(grants);
        // A link reports 0777 whatever it points at; append_line refuses links.
        if let Ok(meta) = tokio::fs::symlink_metadata(&journal).await
            && meta.is_file()
            && meta.permissions().mode() & 0o022 != 0
        {
            return Err(ChangeError::Refused(writable_journal(&journal)));
        }
    }

    let mut file = match super::read_identity_grants_file(grants).await {
        Ok(file) => file,
        Err(_) if create_if_missing && !grants.exists() => IdentityGrantFile::new(Vec::new()),
        Err(error) => return Err(ChangeError::Refused(error)),
    };
    // A hand-edited file can repeat an id. The CLI edits the first match while
    // the loader keeps the last, so no single "row before" exists: refuse
    // rather than journal a digest for a row that was not in force.
    let mut before = std::collections::BTreeMap::<String, String>::new();
    for row in &file.grants {
        if before
            .insert(row.grant_id.clone(), grant_digest(row))
            .is_some()
        {
            return Err(ChangeError::Refused(format!(
                "grant id '{}' appears more than once in {}; remove the duplicate by hand first",
                row.grant_id,
                grants.display()
            )));
        }
    }
    let (verb, grant_id) = change(&mut file).map_err(ChangeError::Refused)?;
    let row = file
        .grants
        .iter()
        .find(|row| row.grant_id == grant_id)
        .cloned()
        .ok_or_else(|| ChangeError::Refused(format!("grant id '{grant_id}' not written")))?;

    if hooks.fail_grant_write {
        return Err(ChangeError::Refused(
            "injected grant-file write failure".to_string(),
        ));
    }
    super::write_identity_grants_file(grants, &file)
        .await
        .map_err(ChangeError::Refused)?;
    // The rename above lands the new grant file, but a rename is not durable
    // until its directory entry is fsynced: without this, a crash can revert
    // to the old grant file while the journal entry below still describes
    // the new one. The journal's own append syncs its directory on creation
    // (below); the grant file needs the same treatment on every change.
    #[cfg(unix)]
    {
        let dir_path = grants.clone();
        tokio::task::spawn_blocking(move || sync_dir(&dir_path))
            .await
            .map_err(|e| ChangeError::Unjournalled(e.to_string()))?
            .map_err(|e| ChangeError::Unjournalled(format!("grant directory sync: {e}")))?;
    }

    let entry = JournalEntry {
        v: JOURNAL_VERSION,
        entry_id: uuid::Uuid::new_v4().to_string(),
        verb,
        prev_digest: before.get(&grant_id).cloned(),
        grant_id,
        digest: grant_digest(&row),
        expires_at: row.expires_at,
        at: Utc::now(),
        actor: UNKNOWN_ACTOR.to_string(),
        os_account,
    };
    if hooks.fail_append {
        return Err(ChangeError::Unjournalled(
            "injected append failure".to_string(),
        ));
    }
    let mut line =
        serde_json::to_vec(&entry).map_err(|e| ChangeError::Unjournalled(e.to_string()))?;
    line.push(b'\n');
    let journal = journal_path(grants);
    // Last step before the append, so a probe here sees the lock state the
    // append itself runs under.
    if let Some(hook) = &hooks.after_grant_write {
        hook();
    }
    tokio::task::spawn_blocking(move || append_line(&journal, &line))
        .await
        .map_err(|e| ChangeError::Unjournalled(e.to_string()))?
        .map_err(|e| ChangeError::Unjournalled(e.to_string()))?;
    Ok(row)
}

/// The grant file a change writes: the path resolved so the lock, the read,
/// the write and the append all name one file. Writing the real file also
/// keeps a symlinked grant path a symlink: the atomic replace would swap the
/// link itself for a regular file. A chain of links that never resolves is
/// refused, for the same reason.
async fn resolve_for_change(grants: &Path) -> Result<PathBuf, ChangeError> {
    let mut target = resolved(grants);
    if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ChangeError::Refused(format!("could not lock the grant journal: {e}")))?;
        // Again, now that a directory it named may exist.
        target = resolved(&target);
    }
    if tokio::fs::symlink_metadata(&target)
        .await
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        return Err(ChangeError::Refused(format!(
            "identity grants file {} is a chain of symlinks that does not resolve",
            grants.display()
        )));
    }
    Ok(target)
}

/// Take the journal lock off the runtime; the CLI may wait behind a reload.
async fn acquire_lock(grants: &Path) -> Result<crate::fs_lock::ExclusiveFileLock, String> {
    let lock = lock_path(grants);
    tokio::task::spawn_blocking(move || crate::fs_lock::ExclusiveFileLock::acquire(&lock))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("could not lock the grant journal: {e}"))
}

/// The directory to fsync for `path`'s durability: its parent, or "." for a
/// bare file name (an empty parent is the current directory).
#[cfg(unix)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

/// Refusal text for a journal other users can write to.
#[cfg(unix)]
fn writable_journal(journal: &Path) -> String {
    format!(
        "grant journal {} is writable by group or other; refusing to use an \
         untrusted file (check its entries against the grant file or restore a \
         trusted copy, then chmod go-w it)",
        journal.display()
    )
}

/// Windows: create the journal owner-only, or open the existing one and judge
/// it exactly as the reader judges it (Integrity: others may read, never
/// change) before anything is appended. The open does not follow a link, so a
/// planted link or directory is refused by [`file_refusals_for`] instead of
/// being written through.
#[cfg(windows)]
fn open_journal_windows(journal: &Path) -> std::io::Result<std::fs::File> {
    use crate::config::Protects;
    use crate::private_fs::{Share, create_file_private, file_refusals_for, refusal_detail};
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, READ_CONTROL,
    };
    // Shared like the custody sidecars, so a concurrent guarded read is not a
    // sharing violation; appends are serialised by the grant lock.
    match create_file_private(journal, Share::LockSidecar) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        created => return created,
    }
    let file = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(journal)?;
    let found = file_refusals_for(&file, Protects::Integrity);
    if found.is_empty() {
        return Ok(file);
    }
    let shown = journal.display().to_string();
    // The check comes first: a repair run before it would make an untrusted
    // journal look trusted to the next reader (MIK-7881).
    Err(std::io::Error::other(format!(
        "Refusing to append to the grant journal {shown}. Check its entries against \
         the grant file, or restore a trusted copy, before running any repair below.\n\
         Refused{}",
        refusal_detail(&shown, &found, Protects::Integrity)
    )))
}

/// Append one line, owner-only, and flush it to disk. A journal whose last
/// byte is not a newline (a torn earlier append) gets one first, so the new
/// entry starts on its own line.
fn append_line(journal: &Path, line: &[u8]) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    #[cfg(not(windows))]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    opts.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Never follow a planted link: the append and the chmod below would
        // land on whatever file it points at.
        opts.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    let created = !journal.exists();
    #[cfg(windows)]
    let mut file = open_journal_windows(journal)?;
    #[cfg(not(windows))]
    let mut file = opts.open(journal)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("grant journal is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = file.metadata()?.permissions().mode();
        // A journal another local account can write to may already hold
        // entries this process never wrote. Repairing its mode to 0600 would
        // launder that history: the next read sees only "owner-only" and
        // trusts bytes it should refuse. Only tighten read exposure (e.g.
        // 0644); refuse when the write bits themselves are open.
        if mode & 0o022 != 0 {
            return Err(std::io::Error::other(writable_journal(journal)));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    if file.metadata()?.len() > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    file.write_all(line)?;
    file.sync_data()?;
    #[cfg(unix)]
    if created {
        sync_dir(journal)?;
    }
    #[cfg(not(unix))]
    let _ = created;
    Ok(())
}

/// The journal read back: entries in file order and the lines that did not parse.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedJournal {
    /// Parsed entries, in file order.
    pub(crate) entries: Vec<JournalEntry>,
    /// `sha256:<hex>` of each complete line that did not parse.
    pub(crate) torn: Vec<String>,
}

/// Parse journal bytes. A final line with no newline is a CLI mid-append and
/// is left for the next read; a bad line that later bytes follow is torn.
#[must_use]
pub(crate) fn parse_journal(bytes: &[u8]) -> ParsedJournal {
    let mut parsed = ParsedJournal::default();
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // The segment after the last newline is unterminated: wait for it.
    lines.pop();
    for line in lines.into_iter().filter(|line| !line.is_empty()) {
        match serde_json::from_slice::<JournalEntry>(line) {
            // A later format may change what a line means: refuse it like a
            // damaged line (reported, never consumed) rather than guess.
            Ok(entry) if entry.v == JOURNAL_VERSION => parsed.entries.push(entry),
            Ok(_) | Err(_) => parsed.torn.push(sha256_tag(line)),
        }
    }
    parsed
}

/// The rows the gateway serves: the last row per grant id, as
/// `LocalIdentityGrantStore::from_grants` keeps it, in grant-id order.
#[must_use]
pub(crate) fn served_rows(
    rows: &[IdentityGrant],
) -> std::collections::BTreeMap<&str, &IdentityGrant> {
    rows.iter()
        .map(|row| (row.grant_id.as_str(), row))
        .collect()
}

/// The served rows active at `now` by `IdentityGrant::is_active_at`: what a
/// startup snapshot records as `loaded`.
#[must_use]
pub(crate) fn active_rows(rows: &[IdentityGrant], now: DateTime<Utc>) -> Vec<&IdentityGrant> {
    served_rows(rows)
        .into_values()
        .filter(|row| row.is_active_at(now))
        .collect()
}

/// What a gateway reload reads under the journal lock: the grant file, parsed
/// or refused, and the journal.
pub(crate) struct LockedRead {
    /// Held until dropped; the caller keeps it across publish and record.
    /// `None` on a read-only filesystem, where the lock file cannot exist
    /// and nothing can write (see [`read_locked`]).
    pub(crate) guard: Option<crate::fs_lock::ExclusiveFileLock>,
    /// The grant file, or the reason it was refused.
    pub(crate) grants: Result<IdentityGrantFile, String>,
    /// The journal beside it.
    pub(crate) journal: crate::config_reload::grant_audit::JournalRead,
}

/// Take the journal lock, polling [`crate::fs_lock::ExclusiveFileLock::try_lease`]
/// for at most `wait`, then read the grant file and the journal under it
/// (design 5.4). The one gateway reader of the grant file on an audited path,
/// so no read happens without the lock, except on a read-only filesystem,
/// where nothing can write. When the lock file cannot be created because its
/// directory is missing or not writable, the grant file is reported as
/// unreadable (`grants: Err`) and is not read.
///
/// # Errors
///
/// `None` when the lock stayed busy for `wait`, or failed in any other way.
pub(crate) async fn read_locked(grants: &Path, wait: std::time::Duration) -> Option<LockedRead> {
    use crate::config_reload::grant_audit::JournalRead;
    let spelled = grants;
    let grants = &resolved(grants);
    let lock = lock_path(grants);
    let deadline = tokio::time::Instant::now() + wait;
    let guard = loop {
        let path = lock.clone();
        let attempt = tokio::task::spawn_blocking(move || {
            crate::fs_lock::ExclusiveFileLock::try_lease(&path)
        })
        .await
        .ok()?;
        match attempt {
            Ok(Some(guard)) => break Some(guard),
            Ok(None) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Ok(None) => return None,
            // A read-only filesystem (a Kubernetes Secret or ConfigMap mount)
            // has no writer at all, and such mounts update by an atomic
            // symlink swap: read without the lock. A directory that is only
            // unwritable for this process is not that case, since root or
            // the file's owner can still run the CLI there.
            Err(error) if error.kind() == std::io::ErrorKind::ReadOnlyFilesystem => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(%error, path = %lock.display(), "grant journal lock cannot be created; reading the grant file without it");
                });
                break None;
            }
            // No lock means no read. A missing or unwritable directory
            // reads as an unreadable grant file, so `fail_on_error` decides
            // at startup and a reload refuses.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Some(LockedRead {
                    guard: None,
                    grants: Err(format!(
                        "grant journal lock {} cannot be taken: {error}",
                        lock.display()
                    )),
                    journal: JournalRead::Missing,
                });
            }
            Err(error) => {
                tracing::error!(%error, path = %lock.display(), "grant journal lock unavailable");
                return None;
            }
        }
    };
    if guard.is_some() {
        adopt_spelled_journal(spelled, grants).await;
    }
    let file = super::read_identity_grants_file(grants).await;
    let journal = journal_path(grants);
    let read = tokio::task::spawn_blocking(move || {
        crate::config::read_checked_bytes(&journal, crate::config::CheckedFile::IdentityGrants)
    })
    .await;
    let journal = match read {
        Ok(Ok(bytes)) => JournalRead::Bytes(bytes),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => JournalRead::Missing,
        Ok(Err(e)) => JournalRead::Unreadable(e.to_string()),
        Err(e) => JournalRead::Unreadable(e.to_string()),
    };
    Some(LockedRead {
        guard,
        grants: file,
        journal,
    })
}

#[cfg(all(test, windows))]
#[path = "journal_windows_tests.rs"]
mod windows_tests;
