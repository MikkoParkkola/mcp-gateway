// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! OAuth Token Storage
//!
//! Persists OAuth tokens to disk for reuse across gateway restarts.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{Error, Result};

/// OAuth token information
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Access token
    pub access_token: String,

    /// Token type (usually "Bearer")
    #[serde(default = "default_token_type")]
    pub token_type: String,

    /// Refresh token (optional)
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Token expiration time (Unix timestamp)
    #[serde(default)]
    pub expires_at: Option<u64>,

    /// Granted scopes
    #[serde(default)]
    pub scope: Option<String>,

    /// OAuth token endpoint stored with the token for executor-level refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// OAuth `client_id` stored alongside the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// OAuth `client_secret` stored alongside the token (optional; prefer Keychain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

/// What a credential's refreshes have shown, kept beside its token (MIK-8018).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefreshState {
    /// A refresh answer once carried a refresh token different from the one
    /// sent: the server rotates, so a refresh token whose exchange had an
    /// unknown outcome may already be consumed.
    #[serde(default)]
    pub(crate) rotates: bool,
    /// SHA-256 (hex) of the refresh token an exchange was started with and has
    /// not settled; set before sending, cleared when the exchange settles. Left
    /// set by a process that died mid-exchange.
    #[serde(default)]
    pub(crate) in_flight: Option<String>,
    /// The sidecar exists but could not be read: whatever marker it held is
    /// lost, so the stored token may be in flight (MIK-8091). Never written.
    #[serde(skip)]
    pub(crate) damaged: bool,
}

impl RefreshState {
    /// What an unreadable sidecar reads as: rotating, and possibly holding a
    /// marker for the stored token.
    fn unreadable() -> Self {
        Self {
            rotates: true,
            in_flight: None,
            damaged: true,
        }
    }
}

// Manual `Debug` that redacts the bearer/refresh secrets and the client
// secret. A derived `Debug` would print `access_token`, `refresh_token`, and
// `client_secret` verbatim into any trace or error context — a full compromise
// of the stored OAuth credential. Only non-secret metadata is shown; secret
// presence is surfaced as a redaction marker so diagnostics stay useful.
impl std::fmt::Debug for TokenInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact_opt = |v: &Option<String>| if v.is_some() { "<redacted>" } else { "None" };
        f.debug_struct("TokenInfo")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("refresh_token", &redact_opt(&self.refresh_token))
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &redact_opt(&self.client_secret))
            .finish()
    }
}

impl TokenInfo {
    /// Create token info from OAuth token response
    pub fn from_response(
        access_token: String,
        token_type: Option<String>,
        refresh_token: Option<String>,
        expires_in: Option<u64>,
        scope: Option<String>,
    ) -> Self {
        let expires_at = expires_in.map(|secs| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + secs
        });

        Self {
            access_token,
            token_type: token_type.unwrap_or_else(default_token_type),
            refresh_token,
            expires_at,
            scope,
            token_endpoint: None,
            client_id: None,
            client_secret: None,
        }
    }

    /// Check if the token is expired (with 60 second buffer)
    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Consider expired 60 seconds before actual expiry
            now + 60 >= expires_at
        } else {
            // No expiry = doesn't expire
            false
        }
    }

    /// Time until expiration
    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.and_then(|expires_at| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if expires_at > now {
                Some(Duration::from_secs(expires_at - now))
            } else {
                None
            }
        })
    }
}

/// Token storage for persisting OAuth tokens
pub struct TokenStorage {
    /// Base directory for token storage
    base_dir: PathBuf,
}

impl TokenStorage {
    /// Create a new token storage with the given base directory
    ///
    /// # Errors
    ///
    /// Returns an error if the storage directory cannot be created.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)
                .map_err(|e| Error::OAuth(format!("Failed to create token storage dir: {e}")))?;
        }

        Ok(Self { base_dir })
    }

    /// Create token storage in the default location (~/.mcp-gateway/oauth)
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined or the
    /// storage directory cannot be created.
    pub fn default_location() -> Result<Self> {
        let home = crate::home_dir::home_dir()
            .ok_or_else(|| Error::OAuth("Cannot determine home directory".to_string()))?;

        Self::new(home.join(".mcp-gateway").join("oauth"))
    }

    /// Generate a storage key for a backend
    fn storage_key(backend_name: &str, resource_url: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(backend_name.as_bytes());
        hasher.update(b":");
        hasher.update(resource_url.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }

    /// Resolved token-file path. `pub(crate)` for the 3.x credential migration, which needs a path and not the naming scheme.
    pub(crate) fn token_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!("{key}_tokens.json"))
    }

    /// Load tokens for a backend
    pub fn load(&self, backend_name: &str, resource_url: &str) -> Option<TokenInfo> {
        let path = self.token_path(backend_name, resource_url);

        if !path.exists() {
            debug!(backend = %backend_name, "No stored tokens found");
            return None;
        }

        let content = super::token_file::read(&path, backend_name)?;
        match serde_json::from_str::<TokenInfo>(&content) {
            Ok(token) => {
                if token.is_expired() {
                    debug!(backend = %backend_name, "Stored token is expired");
                    // Keep the token info in case we can refresh it
                    Some(token)
                } else {
                    info!(backend = %backend_name, expires_in = ?token.time_until_expiry(), "Loaded valid token");
                    Some(token)
                }
            }
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Failed to parse stored token");
                None
            }
        }
    }

    /// Save tokens for a backend
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be serialized or written to disk.
    pub fn save(&self, backend_name: &str, resource_url: &str, token: &TokenInfo) -> Result<()> {
        let path = self.token_path(backend_name, resource_url);

        let content = serde_json::to_string_pretty(token)
            .map_err(|e| Error::OAuth(format!("Failed to serialize token: {e}")))?;

        // Through a scratch file, not `fs::write` followed by
        // `set_permissions`. Writing in place puts the access token into a file
        // created at the umask, or into whatever file already holds that path,
        // and tightens it only afterwards; the secret is readable for the whole
        // write. The scratch file carries 0600 from creation and `rename` hands
        // the destination that mode, so no moment exists at which the token is
        // world-readable. A refresh has to overwrite, so this replaces rather
        // than linking first-writer-wins the way `save_client_id` does.
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("token");
        let tmp = self.create_secret_tmp(file_name)?;
        let tmp = Self::write_secret_tmp(tmp, &content)?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::OAuth(format!("Failed to write token file: {e}")));
        }

        super::token_file::forget(&path);
        info!(backend = %backend_name, "Saved OAuth token");
        Ok(())
    }

    /// Delete tokens for a backend
    ///
    /// # Errors
    ///
    /// Returns an error if the token file exists but cannot be deleted.
    pub fn delete(&self, backend_name: &str, resource_url: &str) -> Result<()> {
        let path = self.token_path(backend_name, resource_url);

        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| Error::OAuth(format!("Failed to delete token file: {e}")))?;
            info!(backend = %backend_name, "Deleted OAuth token");
        }

        Ok(())
    }

    /// Path to the refresh-state sidecar beside a credential's token file
    /// (MIK-8018). Separate from the token record so every token save, from a
    /// refresh or a login, carries the rotation observation forward untouched.
    pub(crate) fn refresh_state_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!("{key}_refresh.json"))
    }

    /// The credential's refresh state; default when none was ever written.
    ///
    /// A sidecar that exists but cannot be read or parsed reads as "the server
    /// rotates" and as damaged (MIK-8018, MIK-8091): the stored refresh token
    /// is then retired rather than sent, since the lost sidecar may have
    /// marked it in flight. The retirement rewrites the file.
    #[must_use]
    pub(crate) fn load_refresh_state(
        &self,
        backend_name: &str,
        resource_url: &str,
    ) -> RefreshState {
        let path = self.refresh_state_path(backend_name, resource_url);
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RefreshState::default(),
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Unreadable refresh state; assuming the server rotates");
                return RefreshState::unreadable();
            }
        };
        serde_json::from_str(&content).unwrap_or_else(|e| {
            warn!(backend = %backend_name, error = %e, "Corrupt refresh state; assuming the server rotates");
            RefreshState::unreadable()
        })
    }

    /// Replace the credential's refresh state, through a 0600 scratch file.
    ///
    /// # Errors
    ///
    /// Returns an error if the state cannot be serialized or written to disk.
    pub(crate) fn save_refresh_state(
        &self,
        backend_name: &str,
        resource_url: &str,
        state: &RefreshState,
    ) -> Result<()> {
        let path = self.refresh_state_path(backend_name, resource_url);
        let content = serde_json::to_string(state)
            .map_err(|e| Error::OAuth(format!("Failed to serialize refresh state: {e}")))?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("refresh");
        let tmp = self.create_secret_tmp(file_name)?;
        let tmp = Self::write_secret_tmp(tmp, &content)?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(Error::OAuth(format!("Failed to write refresh state: {e}")));
        }
        Ok(())
    }

    /// Get the file path for a backend's dynamically-registered client id.
    pub(crate) fn client_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!("{key}_client.json"))
    }

    /// Path to the advisory-lock sidecar guarding a backend's `client_id`
    /// corrupt-final repair (see [`repair_corrupt_final`](Self::repair_corrupt_final)).
    /// Never renamed or linked itself, so the held fd's lock survives the
    /// final file's remove/relink underneath it.
    fn client_lock_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!(".{key}_client.lock"))
    }

    /// Load a previously-registered dynamic client id for a backend.
    ///
    /// Returns `None` if no client has been registered yet or the record is
    /// unreadable. Persisting this is what prevents a fresh Dynamic Client
    /// Registration (and its browser authorize tab) on every connection.
    #[must_use]
    pub fn load_client_id(&self, backend_name: &str, resource_url: &str) -> Option<String> {
        let path = self.client_path(backend_name, resource_url);
        if !path.exists() {
            return None;
        }
        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<String>(&content) {
                Ok(id) => Some(id),
                Err(e) => {
                    warn!(backend = %backend_name, error = %e, "Failed to parse stored client_id");
                    None
                }
            },
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Failed to read client_id file");
                None
            }
        }
    }

    /// Persist a dynamically-registered client id for a backend.
    ///
    /// Returns the id that is now authoritative on disk: the one passed in when
    /// this call won the first-registration race, and a pre-existing one when
    /// another gateway instance sharing this directory registered first.
    ///
    /// The write is atomic and never exposes a world-readable window: content
    /// goes to a per-process temp file created with `O_EXCL` and mode `0600`
    /// (on unix) before it is linked into place. Creating with `O_EXCL` also
    /// guarantees a leftover temp from a crashed run is never truncated/reused.
    /// `hard_link` fails with `AlreadyExists` when the final path is already
    /// present, so a concurrent second instance adopts the existing id instead
    /// of clobbering it (last-write-wins would churn the id across instances,
    /// the very bug this persistence exists to prevent). A corrupt/unreadable
    /// final file is repaired under an exclusive advisory lock (see
    /// [`repair_corrupt_final`](Self::repair_corrupt_final)) so two processes
    /// that both observe the corruption can never race to remove each other's
    /// freshly-written valid file.
    ///
    /// # Errors
    ///
    /// Returns an error when the id cannot be serialized, when a unique temp
    /// file cannot be created, when the temp file cannot be written (in which
    /// case the temp file is removed before the error is returned -- see
    /// [`write_secret_tmp`](Self::write_secret_tmp)), when the existing final
    /// file is unreadable and cannot be self-healed, or when the atomic link
    /// fails for a reason other than the final path already existing.
    pub fn save_client_id(
        &self,
        backend_name: &str,
        resource_url: &str,
        client_id: &str,
    ) -> Result<String> {
        let path = self.client_path(backend_name, resource_url);
        let content = serde_json::to_string(client_id)
            .map_err(|e| Error::OAuth(format!("Failed to serialize client_id: {e}")))?;

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("client");

        // Create the temp file with O_EXCL so a leftover temp from a crashed
        // prior run is never truncated/reused: `create_new` fails with
        // `AlreadyExists` rather than opening (and emptying) an existing path.
        // On unix the 0600 mode is applied atomically at creation, closing the
        // world-readable window that a post-write chmod would otherwise leave.
        let tmp = self.create_secret_tmp(file_name)?;
        let tmp = Self::write_secret_tmp(tmp, &content)?;

        // First-writer-wins: `hard_link` fails with `AlreadyExists` when the
        // final path already exists, so a concurrent instance adopts the
        // existing id instead of clobbering it. A corrupt/unreadable existing
        // file is unusable and gets repaired under a cross-process lock (see
        // `repair_corrupt_final` for why the repair must be serialized).
        let result = match fs::hard_link(&tmp, &path) {
            Ok(()) => {
                info!(backend = %backend_name, "Saved registered OAuth client_id");
                Ok(client_id.to_string())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match self.load_client_id(backend_name, resource_url) {
                    Some(existing) => {
                        info!(backend = %backend_name, "client_id already persisted by another instance; adopting it");
                        Ok(existing)
                    }
                    None => self.repair_corrupt_final(
                        backend_name,
                        resource_url,
                        &path,
                        &tmp,
                        client_id,
                    ),
                }
            }
            Err(e) => Err(Error::OAuth(format!("Failed to persist client_id: {e}"))),
        };
        let _ = fs::remove_file(&tmp);
        result
    }

    /// Repair a corrupt/unreadable final `client_id` file under an exclusive
    /// advisory lock (MIK-6750 r7).
    ///
    /// Without serialization, two processes that both observe
    /// `load_client_id` return `None` for the same corrupt final can race:
    /// process A reads `None`, process B repairs the file with a valid id and
    /// returns, then process A — still acting on its stale `None` read —
    /// removes B's freshly-written file and links its own, so the disk ends
    /// up authoritative for A's id while B has already adopted its own. This
    /// takes an exclusive `flock` on a `.lock` sidecar (never renamed, so the
    /// held fd's lock survives the final file's remove/relink) across
    /// re-read → remove → `hard_link`, so only one process repairs at a time
    /// and a final that has become valid while we waited is never removed.
    fn repair_corrupt_final(
        &self,
        backend_name: &str,
        resource_url: &str,
        path: &std::path::Path,
        tmp: &std::path::Path,
        client_id: &str,
    ) -> Result<String> {
        let lock_path = self.client_lock_path(backend_name, resource_url);
        let _lock = crate::fs_lock::ExclusiveFileLock::acquire(&lock_path)
            .map_err(|e| Error::OAuth(format!("Failed to acquire client_id repair lock: {e}")))?;

        // Re-read under the lock: another process may have healed the file
        // between our caller's unlocked read (which found it corrupt) and
        // this call acquiring the lock. Never remove a final that now parses.
        if let Some(existing) = self.load_client_id(backend_name, resource_url) {
            info!(backend = %backend_name, "client_id healed by another instance while waiting for the repair lock; adopting it");
            return Ok(existing);
        }

        warn!(backend = %backend_name, "Existing client_id file is unreadable; removing and re-persisting from validated temp");
        let _ = fs::remove_file(path);

        match fs::hard_link(tmp, path) {
            Ok(()) => {
                info!(backend = %backend_name, "Saved registered OAuth client_id (self-healed corrupt final)");
                Ok(client_id.to_string())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // An unlocked fast-path writer (a fresh, non-repair save)
                // won the link in the gap between our remove and this retry.
                // Adopt whatever it left if valid; this is the same
                // first-writer-wins contract as the normal case above.
                self.load_client_id(backend_name, resource_url)
                    .ok_or_else(|| {
                        Error::OAuth(
                            "client_id file exists but is unreadable and could not be self-healed"
                                .to_string(),
                        )
                    })
            }
            Err(e) => Err(Error::OAuth(format!(
                "Failed to persist client_id during self-heal: {e}"
            ))),
        }
    }

    /// Write `content` into the just-created temp file and return its path on
    /// success.
    ///
    /// On any write or `fsync` failure (e.g. `ENOSPC`, `EIO`) the temp file is
    /// removed (best-effort) before the error propagates, so a transient
    /// write failure never leaks a private `0600` temp file under `base_dir`
    /// (MIK-6750 r8, minor -- the previous code returned early via `?`
    /// without cleanup, orphaning the temp on every such error).
    fn write_secret_tmp(tmp: (fs::File, PathBuf), content: &str) -> Result<PathBuf> {
        use std::io::Write as _;
        let (mut file, tmp_path) = tmp;
        let written = file
            .write_all(content.as_bytes())
            .and_then(|()| file.sync_all());
        // Close before cleanup: Windows cannot delete a file held open
        // without delete sharing.
        drop(file);
        match written {
            Ok(()) => Ok(tmp_path),
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                Err(Error::OAuth(format!("Failed to write temp file: {e}")))
            }
        }
    }

    /// Atomically create a private temp file (`0600` on unix, an owner-only
    /// DACL on Windows) for a write, retrying with a fresh nonce if a stale
    /// temp path collides.
    ///
    /// Returns the open [`File`] handle plus its path, so the caller writes
    /// through the handle the access limit was set on.
    fn create_secret_tmp(&self, file_name: &str) -> Result<(fs::File, PathBuf)> {
        static TMP_NONCE: AtomicU64 = AtomicU64::new(0);
        for _ in 0..8 {
            let nonce = TMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let tmp = self
                .base_dir
                .join(format!("{file_name}.tmp.{}.{nonce}", std::process::id()));
            match crate::config_persistence::create_new_private(&tmp) {
                Ok(file) => return Ok((file, tmp)),
                // Stale temp collided; try the next nonce.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(Error::OAuth(format!("Failed to create temp file: {e}")));
                }
            }
        }
        Err(Error::OAuth(
            "Failed to create a unique temp file after 8 attempts".to_string(),
        ))
    }

    /// Delete a stored client id so the next connection re-registers.
    ///
    /// Called when the authorization server rejects the persisted id with
    /// `invalid_client` (e.g. the registration was revoked or garbage-collected
    /// server-side). Without this there is no in-product recovery from a stale
    /// registration short of manual file deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be deleted.
    pub fn delete_client_id(&self, backend_name: &str, resource_url: &str) -> Result<()> {
        let path = self.client_path(backend_name, resource_url);
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| Error::OAuth(format!("Failed to delete client_id file: {e}")))?;
            info!(backend = %backend_name, "Deleted stored OAuth client_id");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
