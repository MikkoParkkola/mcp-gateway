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
                "grant file changed but the journal append failed ({reason}); \
                 this change has no journal entry"
            ),
        }
    }
}

/// The journal beside `grants`: the grant file's name plus `.journal.jsonl`.
#[must_use]
pub fn journal_path(grants: &Path) -> PathBuf {
    let mut name = grants.file_name().unwrap_or_default().to_os_string();
    name.push(".journal.jsonl");
    grants.with_file_name(name)
}

/// The lock file both the CLI and the gateway take around a grant change.
///
/// A separate file that is never renamed, so a held lock survives the grant
/// file's atomic replace.
#[must_use]
pub(crate) fn lock_path(grants: &Path) -> PathBuf {
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
    // Held until this function returns: from before the read to after the
    // append, so a gateway reload never sees the file without its entry.
    let _lock = acquire_lock(grants).await.map_err(ChangeError::Refused)?;

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
    if let Some(hook) = &hooks.after_grant_write {
        hook();
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
    tokio::task::spawn_blocking(move || append_line(&journal, &line))
        .await
        .map_err(|e| ChangeError::Unjournalled(e.to_string()))?
        .map_err(|e| ChangeError::Unjournalled(e.to_string()))?;
    Ok(row)
}

/// Take the journal lock off the runtime; the CLI may wait behind a reload.
async fn acquire_lock(grants: &Path) -> Result<crate::fs_lock::ExclusiveFileLock, String> {
    let lock = lock_path(grants);
    tokio::task::spawn_blocking(move || {
        if let Some(parent) = lock.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        crate::fs_lock::ExclusiveFileLock::acquire(&lock)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("could not lock the grant journal: {e}"))
}

/// Append one line, owner-only, and flush it to disk. A journal whose last
/// byte is not a newline (a torn earlier append) gets one first, so the new
/// entry starts on its own line.
fn append_line(journal: &Path, line: &[u8]) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Never follow a planted link: the append and the chmod below would
        // land on whatever file it points at.
        opts.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT: never follow a link.
        opts.custom_flags(0x0020_0000);
    }
    let created = !journal.exists();
    let mut file = opts.open(journal)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("grant journal is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
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
    if created && let Some(dir) = journal.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
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
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the gateway reads the journal once ingestion lands"
    )
)]
#[must_use]
pub(crate) fn parse_journal(bytes: &[u8]) -> ParsedJournal {
    let mut parsed = ParsedJournal::default();
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // The segment after the last newline is unterminated: wait for it.
    lines.pop();
    for line in lines.into_iter().filter(|line| !line.is_empty()) {
        match serde_json::from_slice::<JournalEntry>(line) {
            Ok(entry) => parsed.entries.push(entry),
            Err(_) => parsed.torn.push(sha256_tag(line)),
        }
    }
    parsed
}
