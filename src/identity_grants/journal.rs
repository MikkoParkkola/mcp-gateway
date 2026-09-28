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
                 the gateway will record this change as out-of-band"
            ),
        }
    }
}

/// The journal beside `grants`: the grant file's name plus `.journal.jsonl`.
#[must_use]
pub fn journal_path(grants: &Path) -> PathBuf {
    let _ = grants;
    PathBuf::new()
}

/// The lock file both the CLI and the gateway take around a grant change.
#[allow(dead_code, reason = "red-first stub")]
#[must_use]
pub(crate) fn lock_path(grants: &Path) -> PathBuf {
    let _ = grants;
    PathBuf::new()
}

/// `sha256:<hex>` over the serialised row.
#[must_use]
pub fn grant_digest(grant: &IdentityGrant) -> String {
    let _ = grant;
    String::new()
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

fn os_account() -> Option<String> {
    None
}

/// Test seams for the change sequence; production passes the default.
#[allow(dead_code, reason = "red-first stub")]
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
    let _ = (os_account, hooks);
    let mut file = match super::read_identity_grants_file(grants).await {
        Ok(file) => file,
        Err(_) if create_if_missing && !grants.exists() => IdentityGrantFile::new(Vec::new()),
        Err(error) => return Err(ChangeError::Refused(error)),
    };
    let (_, grant_id) = change(&mut file).map_err(ChangeError::Refused)?;
    super::write_identity_grants_file(grants, &file)
        .await
        .map_err(ChangeError::Refused)?;
    file.grants
        .into_iter()
        .find(|row| row.grant_id == grant_id)
        .ok_or_else(|| ChangeError::Refused(format!("grant id '{grant_id}' not written")))
}

/// The journal read back: entries in file order and the lines that did not parse.
#[allow(dead_code, reason = "red-first stub")]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedJournal {
    /// Parsed entries, in file order.
    pub(crate) entries: Vec<JournalEntry>,
    /// `sha256:<hex>` of each complete line that did not parse.
    pub(crate) torn: Vec<String>,
}

/// Parse journal bytes. A final line with no newline is a CLI mid-append and
/// is left for the next read; a bad line that later bytes follow is torn.
#[allow(dead_code, reason = "red-first stub")]
#[must_use]
pub(crate) fn parse_journal(bytes: &[u8]) -> ParsedJournal {
    let _ = bytes;
    ParsedJournal::default()
}
