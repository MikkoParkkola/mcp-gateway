// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable record types of the events store and their private file I/O
//! (design §5): one JSON file per record, written owner-only through a temp
//! file, a rename and a directory sync.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Highest record version this build loads.
pub(crate) const MAX_LOADABLE_VERSION: u32 = 1;

/// One subscription. `secret` and `previous_secret` are the only sensitive
/// fields; `Debug` redacts both.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Subscription {
    pub v: u32,
    pub id: String,
    pub principal: String,
    /// The API key the principal presented, if any: every re-check
    /// resolves the key's expiry and backend scope from live config (I2).
    pub api_key: Option<ApiKeyRef>,
    pub url: String,
    pub name: String,
    pub arguments: Value,
    pub secret: String,
    pub previous_secret: Option<String>,
    pub previous_until: Option<DateTime<Utc>>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub active: bool,
    pub failed_since: Option<DateTime<Utc>>,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// An API key as a caller presented it: its configured name and the
/// principal derived from its secret's digest. A key replaced under the same
/// name derives another principal, so it no longer matches (I2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApiKeyRef {
    pub name: String,
    pub principal: String,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("principal", &self.principal)
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .field(
                "previous_secret",
                &self.previous_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Subscription {
    /// Live at `now`: not past its expiry.
    pub(crate) fn live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

/// The recorded opt-in of one `(principal, url)`. `Debug` shows the
/// callback host only: a path or query can carry a capability token.
#[derive(Clone, Serialize, Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "verified_at is the persisted field name the design fixes"
)]
pub(crate) struct Verified {
    pub v: u32,
    pub principal: String,
    pub url: String,
    pub verified_at: DateTime<Utc>,
    /// When the pair's last subscription ended; `None` while one is live.
    pub last_subscription_ended_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = url::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));
        f.debug_struct("Verified")
            .field("principal", &self.principal)
            .field("host", &host)
            .field("verified_at", &self.verified_at)
            .field(
                "last_subscription_ended_at",
                &self.last_subscription_ended_at,
            )
            .finish_non_exhaustive()
    }
}

/// The file name of a `(principal, url)` verification record.
pub(crate) fn verified_file(principal: &str, url: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(serde_json::to_vec(&[principal, url]).unwrap_or_default());
    format!("{}.json", hex::encode(digest))
}

/// Create `dir` (and parents) owner-only.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match crate::private_fs::create_dir_private(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
}

/// Where a write left its record.
#[derive(Debug)]
pub(crate) enum Placed {
    /// Renamed into place and the directory synced.
    Durable,
    /// Renamed into place, but the directory sync failed: the record is
    /// visible and may not survive a crash.
    NotSynced(std::io::Error),
}

impl Placed {
    /// `Err` unless the write is durable.
    pub(crate) fn durable(self) -> std::io::Result<()> {
        match self {
            Self::Durable => Ok(()),
            Self::NotSynced(error) => Err(error),
        }
    }
}

/// Write `value` to `dir/name` owner-only, through a temp file and a rename.
/// `Err` means the record was not put in place and the previous file, if
/// any, is untouched; past the rename the outcome is a [`Placed`].
pub(crate) fn write_record<T: Serialize>(
    dir: &Path,
    name: &str,
    value: &T,
) -> std::io::Result<Placed> {
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    let temp = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
    // The handle is closed before the rename: Windows refuses to move a file
    // that is still open under an exclusive share mode.
    let written = {
        let mut file = crate::config_persistence::create_new_private(&temp)?;
        file.write_all(&bytes).and_then(|()| file.sync_all())
    };
    let staged = written.and_then(|()| rename(&temp, &dir.join(name)));
    if staged.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    staged?;
    Ok(match sync_dir(dir) {
        Ok(()) => Placed::Durable,
        Err(error) => Placed::NotSynced(error),
    })
}

/// Remove `dir/name`; a missing file is already removed.
pub(crate) fn remove_record(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        // Unlinked: memory must follow, so a failed sync is logged, not
        // returned as though the record were still there.
        _ => {
            if let Err(error) = sync_dir(dir) {
                tracing::warn!(%error, dir = %dir.display(), "events store: directory sync failed after unlink");
            }
            Ok(())
        }
    }
}

/// Every `*.json` record in `dir` this build can load. A record of an
/// unreadable version or shape is skipped and logged, never deleted.
pub(crate) fn load_records<T: for<'de> Deserialize<'de>>(dir: &Path) -> Vec<(PathBuf, T)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for path in entries.flatten().map(|e| e.path()) {
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Mode-checked on the handle it is read from: a subscription file
        // holds a secret, so a loosened or foreign-owned one is refused.
        let parsed =
            crate::config::read_checked_bytes(&path, crate::config::CheckedFile::EventsRecord)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .filter(|v| {
                    v.get("v")
                        .and_then(Value::as_u64)
                        .is_some_and(|v| v <= u64::from(MAX_LOADABLE_VERSION))
                })
                .and_then(|v| serde_json::from_value::<T>(v).ok());
        if let Some(record) = parsed {
            records.push((path, record));
        } else {
            tracing::warn!(path = %path.display(), "events store record skipped");
        }
    }
    records
}

fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::private_fs::replace(from, to)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::private_fs::sync_dir(dir)
    }
    #[cfg(not(windows))]
    {
        std::fs::File::open(dir)?.sync_all()
    }
}
