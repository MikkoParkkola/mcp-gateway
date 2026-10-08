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
    /// How the subscriber's credential was presented, for the audit
    /// record's `who`. Absent on records written before it was kept.
    #[serde(default)]
    pub credential_kind: Option<crate::security::audit::CredentialKind>,
    /// The audit principal of that credential (a digest, never the secret).
    #[serde(default)]
    pub credential_principal: Option<String>,
    /// The caller key the read verdict judges this principal's frames under
    /// (MIN.2): formed when the subscription was made, only when the verdict
    /// is on. Absent on older records, whose deliveries count as
    /// unattributable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_key: Option<String>,
    /// What every attempt re-checks for a credential that is not an API key
    /// (design F9, MIK-7769). A bound kind without one is refused.
    #[serde(default)]
    pub binding: Option<LiveBinding>,
    /// An early record's bare key name, which binds no secret: such a
    /// subscription fails every re-check and is deleted. Never written.
    #[serde(default, rename = "api_key_name", skip_serializing)]
    pub legacy_api_key_name: Option<String>,
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
    /// The top-level payload fields its event carried when it was last
    /// committed: a restored route without one of them holds it (MIK-8076).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload_fields: Vec<String>,
    /// When the routes stopped offering or serving it (MIK-8057, MIK-8076);
    /// cleared when they serve it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unoffered_since: Option<DateTime<Utc>>,
    /// The latest a held row lives: `unoffered_since` plus the maximum
    /// lease, whatever its refreshes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_until: Option<DateTime<Utc>>,
}

/// The credential a caller presented, as events keep it: never the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Credential {
    pub kind: crate::security::audit::CredentialKind,
    /// The audit principal: the validated credential's digest.
    pub principal: String,
    /// Set only for a configured API key: the one credential whose live
    /// scope the re-check can read.
    // ci-allow-secret-debug: a key's name and digest-derived principal, never the secret.
    pub api_key: Option<ApiKeyRef>,
    /// When the credential itself stops being valid, if it says.
    pub expires_at: Option<DateTime<Utc>>,
    /// What a delivery attempt re-checks for a credential that is not an
    /// API key.
    pub binding: Option<LiveBinding>,
}

/// The live fact a non-API-key credential is re-checked against before
/// every delivery attempt (design F9, MIK-7769). Never a secret: a
/// temporary token's `jti`, a verified identity, or a session handle's
/// digest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum LiveBinding {
    /// A key-server temporary token, by its `jti`.
    KeyServerToken { jti: String },
    /// A delegated OIDC bearer: the identity the key-server policy reads.
    OidcBearer {
        issuer: String,
        subject: String,
        email: String,
        groups: Vec<String>,
        /// The bearer's `iat`: the running max token age still bounds it.
        #[serde(default)]
        issued_at: Option<u64>,
        /// The verifying provider's configuration digest at subscribe time.
        #[serde(default)]
        provider_sha256: Option<String>,
    },
    /// The static bearer of a row written before the full digest was kept:
    /// its principal (a 12-hex fingerprint) is the credential principal.
    StaticBearer,
    /// The static bearer, by the SHA-256 of the bearer itself (MIK-7889).
    StaticBearerSha256 { bearer_sha256: String },
    /// A dashboard session, by the SHA-256 of its handle.
    DashboardSession { session_sha256: String },
}

impl LiveBinding {
    /// The credential kind this binding re-checks.
    pub(crate) const fn kind(&self) -> crate::security::audit::CredentialKind {
        use crate::security::audit::CredentialKind as Kind;
        match self {
            Self::KeyServerToken { .. } => Kind::KeyServerToken,
            Self::OidcBearer { .. } => Kind::OidcBearer,
            Self::StaticBearer | Self::StaticBearerSha256 { .. } => Kind::StaticBearer,
            Self::DashboardSession { .. } => Kind::DashboardSession,
        }
    }
}

impl std::fmt::Debug for LiveBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The variant only: an email is personal data.
        f.write_str(match self {
            Self::KeyServerToken { .. } => "KeyServerToken",
            Self::OidcBearer { .. } => "OidcBearer",
            Self::StaticBearer | Self::StaticBearerSha256 { .. } => "StaticBearer",
            Self::DashboardSession { .. } => "DashboardSession",
        })
    }
}

impl Credential {
    /// Whether delivery may outlive this credential only up to a bound: every
    /// kind but an API key, whose expiry and grant every attempt re-reads.
    pub(crate) const fn bounded(&self) -> bool {
        !matches!(
            self.kind,
            crate::security::audit::CredentialKind::ApiKey
                | crate::security::audit::CredentialKind::None
        )
    }
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
    /// When the row stops being live: its expiry or the bound of its hold,
    /// whichever comes first; `None` when neither is set.
    pub(crate) fn effective_expiry(&self) -> Option<DateTime<Utc>> {
        match (self.expires_at, self.held_until) {
            (Some(at), Some(bound)) => Some(at.min(bound)),
            (at, bound) => at.or(bound),
        }
    }

    /// Live at `now`: not past its effective expiry.
    pub(crate) fn live(&self, now: DateTime<Utc>) -> bool {
        self.effective_expiry().is_none_or(|at| at > now)
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

/// Remove `dir/name` and sync `dir`; `Err` unless the removal is durable.
pub(crate) fn remove_record_durable(dir: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => sync_dir(dir),
    }
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
                        // No build wrote a version 0.
                        .is_some_and(|v| (1..=u64::from(MAX_LOADABLE_VERSION)).contains(&v))
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
