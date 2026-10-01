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
    /// The API key the principal presented, if any: the fan-out re-check
    /// resolves the key's backend scope from live config (I2).
    pub api_key_name: Option<String>,
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

/// Write `value` to `dir/name` durably and owner-only. `Err` means the
/// record was not put in place; the previous file, if any, is untouched.
pub(crate) fn write_record<T: Serialize>(dir: &Path, name: &str, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    let temp = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
    let mut file = crate::config_persistence::create_new_private(&temp)?;
    let staged = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| rename(&temp, &dir.join(name)));
    if staged.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    staged?;
    // Past the rename the record is in place: an error from here on would
    // tell the caller it was not, so a failed directory sync is logged.
    if let Err(error) = sync_dir(dir) {
        tracing::warn!(%error, dir = %dir.display(), "events store: directory sync failed after rename");
    }
    Ok(())
}

/// Remove `dir/name`; a missing file is already removed.
pub(crate) fn remove_record(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => sync_dir(dir),
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
        let parsed = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|v| {
                v.get("v")
                    .and_then(Value::as_u64)
                    .is_some_and(|v| v <= u64::from(MAX_LOADABLE_VERSION))
            })
            .and_then(|v| serde_json::from_value::<T>(v).ok());
        match parsed {
            Some(record) => records.push((path, record)),
            None => tracing::warn!(path = %path.display(), "events store record skipped"),
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
