// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a caller hands the gateway.yaml writer and what it gets back: the
//! request, its parts, the accepted outcome and every refusal. The writer
//! itself is the parent module; it re-exports each name here.

use std::path::PathBuf;
use std::sync::Arc;

use crate::config_persistence::keyedit::Template;
use crate::gateway::restart_config_floor::Refusal;
use crate::secret_store::{NewSecretOwned, SaveError, SecretStore, Vault};

use super::{FileRevision, RefusalClass, ReplaceReload, StatusChange};

/// What the file must hold for the write to go ahead.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) enum Expected {
    /// Whatever it holds.
    Any,
    /// The bytes the caller's diff or history view was made from.
    Revision(FileRevision),
}

/// What happens to the bytes a successful write replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) enum Replaced {
    /// Removed once the new bytes are accepted.
    Discard,
    /// Kept beside the file as `gateway.yaml.<UTC time>.rejected`.
    KeepBeside,
}

/// The new bytes, from the current ones; `Err` refuses the write.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
/// It runs before any store entry exists: a secret field is a slot in the
/// template, which the writer fills with its entry's reference afterwards.
pub(crate) type Compute = Box<dyn FnOnce(&[u8]) -> Result<Template, String> + Send>;

/// Secrets a replacement saves with the file: created in the store under the
/// config hold, after the revision check and before `compute`, which writes
/// their references. The writer keeps them when the new bytes stand, deletes
/// them only when the old file provably stayed, and otherwise leaves them
/// listed as unused.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
pub(crate) struct SecretStep {
    pub(crate) vault: Vault,
    pub(crate) store: Arc<dyn SecretStore + Send + Sync>,
    pub(crate) values: Vec<NewSecretOwned>,
}

/// One replacement of gateway.yaml.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) struct Replace {
    pub(crate) expected: Expected,
    pub(crate) compute: Compute,
    pub(crate) replaced: Replaced,
    pub(crate) secrets: Option<SecretStep>,
    /// What a candidate that changes the single-user status gets.
    pub(crate) status_change: StatusChange,
}

/// A replacement that was written and accepted.
#[derive(Debug)]
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and the configuration-history restore"
    )
)]
pub(crate) struct ReplaceOutcome {
    /// The new revision; `None` when the bytes were already the file's.
    pub(crate) revision: Option<FileRevision>,
    /// The kept copy, for [`Replaced::KeepBeside`].
    pub(crate) kept_beside: Option<PathBuf>,
    /// The reload it ended with.
    pub(crate) reload: ReplaceReload,
    /// Each stored secret's field and the reference the written file holds for
    /// it, in the secret step's order; empty without one. Read from this write
    /// itself, never from the file afterwards (another writer may follow).
    pub(crate) secrets: Vec<(String, String)>,
}

/// Why nothing was applied. Every kind but `RollbackFailed` and
/// `Unconfirmed` leaves the old file on disk and running; those two leave a
/// journal that the next holder of the config lock recovers.
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "the error payloads are read by the first callers: the web UI settings save and the configuration-history restore"
)]
pub(crate) enum ReplaceError {
    /// A lock stayed held past the wait; nothing was read.
    Busy,
    /// The config gate refused the write before anything was read: a restart
    /// is being prepared (`Busy`, retry later) or the gateway is going down.
    Gated(Refusal),
    /// The file changed since the caller's view; its current revision.
    Stale { current: FileRevision },
    /// The compute refused, or produced bytes that are not UTF-8 text. Bytes
    /// the loader rejects are `ReloadRefused`, after the rollback.
    Refused(String),
    /// Auth is on and no audit log is configured: the gateway's own posture
    /// refuses every config write (`NO_AUDIT_LOG` is its text). A type, so
    /// a route answers it by what it is, never by matching words.
    NoAuditLog,
    /// The audit log refused an intent (the operation's or its recovery's); nothing written.
    AuditRefused(String),
    /// gateway.yaml no longer resolves to the file this gateway started on.
    Unsupported(String),
    /// Staging the original or the journal failed; nothing was replaced.
    Stage(String),
    /// Writing the new bytes failed; the original is back.
    Write(String),
    /// The reload refused the new bytes, or the check of them before any
    /// entry or write did; the original stands.
    ReloadRefused { class: RefusalClass, reason: String },
    /// Putting the original back failed; the journal stays `staged`.
    RollbackFailed { journal: PathBuf, error: String },
    /// The reload accepted the bytes but that could not be recorded
    /// durably; nothing is acknowledged.
    Unconfirmed { journal: PathBuf, error: String },
    /// Anything else: a lock that cannot be taken at all, an unusable
    /// journal, an unreadable file, a write task that died.
    Failed(String),
    /// The secret store refused the [`SecretStep`]; nothing was written.
    Secrets(SaveError<std::convert::Infallible>),
    /// gateway.yaml does not exist; nothing was written.
    NoConfigFile,
    /// The read check every loader applies refused gateway.yaml (its type,
    /// mode, owner or encoding); nothing was written. The text names the
    /// file and the fix, for the log only.
    ConfigRefused(String),
}
