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
        let home = dirs::home_dir()
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

    /// Get the file path for a backend's tokens
    fn token_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
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

        match fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<TokenInfo>(&content) {
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
            },
            Err(e) => {
                warn!(backend = %backend_name, error = %e, "Failed to read token file");
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

        fs::write(&path, content)
            .map_err(|e| Error::OAuth(format!("Failed to write token file: {e}")))?;

        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(&path, perms);
        }

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

    /// Get the file path for a backend's dynamically-registered client id.
    pub(crate) fn client_path(&self, backend_name: &str, resource_url: &str) -> PathBuf {
        let key = Self::storage_key(backend_name, resource_url);
        self.base_dir.join(format!("{key}_client.json"))
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
    /// (on unix) *before* it is linked into place. Creating with `O_EXCL` also
    /// guarantees a leftover temp from a crashed run is never truncated/reused.
    /// `hard_link` fails with `AlreadyExists` when the final path is already
    /// present, so a concurrent second instance adopts the existing id instead
    /// of clobbering it (last-write-wins would churn the id across instances —
    /// the very bug this persistence exists to prevent). If the existing final
    /// file is corrupt/unreadable, it is removed and the link retried once so a
    /// validated id becomes authoritative rather than silently diverging.
    ///
    /// # Errors
    ///
    /// Returns an error when the id cannot be serialized, a unique temp file
    /// cannot be created or written, the existing final file is unreadable and
    /// cannot be self-healed, or the atomic link fails for any reason other than
    /// the final path already existing.
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
        let tmp = self.create_client_tmp(file_name)?;

        #[cfg(unix)]
        let write_result = {
            use std::io::Write as _;
            let (mut file, tmp) = tmp;
            file.write_all(content.as_bytes())
                .and_then(|()| file.sync_all())
                .map(|()| tmp)
        };
        #[cfg(not(unix))]
        let write_result = { fs::write(&tmp, &content).map(|()| tmp) };

        let tmp = write_result
            .map_err(|e| Error::OAuth(format!("Failed to write client_id temp file: {e}")))?;

        // First-writer-wins: `hard_link` fails with `AlreadyExists` when the
        // final path already exists, so a concurrent instance adopts the
        // existing id instead of clobbering it. A corrupt/unreadable existing
        // file, however, is unusable — self-heal by removing it and retrying
        // the link once so our validated temp becomes authoritative.
        let mut heal_attempts = 0u8;
        let result = loop {
            match fs::hard_link(&tmp, &path) {
                Ok(()) => {
                    info!(backend = %backend_name, "Saved registered OAuth client_id");
                    break Ok(client_id.to_string());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    match self.load_client_id(backend_name, resource_url) {
                        Some(existing) => {
                            info!(backend = %backend_name, "client_id already persisted by another instance; adopting it");
                            break Ok(existing);
                        }
                        None if heal_attempts < 1 => {
                            // On-disk file is corrupt/unreadable; remove it and
                            // retry the link so our validated temp wins.
                            heal_attempts += 1;
                            warn!(backend = %backend_name, "Existing client_id file is unreadable; removing and re-persisting from validated temp");
                            let _ = fs::remove_file(&path);
                        }
                        None => {
                            break Err(Error::OAuth(
                                "client_id file exists but is unreadable and could not be self-healed".to_string(),
                            ));
                        }
                    }
                }
                Err(e) => break Err(Error::OAuth(format!("Failed to persist client_id: {e}"))),
            }
        };
        let _ = fs::remove_file(&tmp);
        result
    }

    /// Atomically create a private (`0600` on unix) temp file for a `client_id`
    /// write, retrying with a fresh nonce if a stale temp path collides.
    ///
    /// Returns the open [`File`] handle plus its path on unix (so the caller
    /// writes through the same fd the mode was set on), and just the path on
    /// other platforms.
    #[cfg(unix)]
    fn create_client_tmp(&self, file_name: &str) -> Result<(fs::File, PathBuf)> {
        use std::os::unix::fs::OpenOptionsExt as _;

        static TMP_NONCE: AtomicU64 = AtomicU64::new(0);
        for _ in 0..8 {
            let nonce = TMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let tmp = self
                .base_dir
                .join(format!("{file_name}.tmp.{}.{nonce}", std::process::id()));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
            {
                Ok(file) => return Ok((file, tmp)),
                // Stale temp collided; try the next nonce.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(Error::OAuth(format!(
                        "Failed to create client_id temp file: {e}"
                    )));
                }
            }
        }
        Err(Error::OAuth(
            "Failed to create a unique client_id temp file after 8 attempts".to_string(),
        ))
    }

    /// Non-unix fallback: pick a fresh temp path via `create_new`, closing the
    /// handle immediately so the caller can `fs::write` it (no unix mode bits).
    #[cfg(not(unix))]
    fn create_client_tmp(&self, file_name: &str) -> Result<PathBuf> {
        static TMP_NONCE: AtomicU64 = AtomicU64::new(0);
        for _ in 0..8 {
            let nonce = TMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let tmp = self
                .base_dir
                .join(format!("{file_name}.tmp.{}.{nonce}", std::process::id()));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
            {
                Ok(_) => return Ok(tmp),
                // Stale temp collided; try the next nonce.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(Error::OAuth(format!(
                        "Failed to create client_id temp file: {e}"
                    )));
                }
            }
        }
        Err(Error::OAuth(
            "Failed to create a unique client_id temp file after 8 attempts".to_string(),
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
mod tests {
    use super::*;

    #[test]
    fn client_id_round_trips_and_is_absent_before_registration() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).expect("create store");
        let (backend, resource) = ("beeper", "http://127.0.0.1:23373/v0/mcp");

        // No client registered yet -> None (would trigger DCR + browser tab).
        assert_eq!(store.load_client_id(backend, resource), None);

        // Persist then reload -> stable id, so the next connection reuses it.
        let persisted = store
            .save_client_id(backend, resource, "persisted-client-123")
            .expect("save client_id");
        assert_eq!(persisted, "persisted-client-123");
        assert_eq!(
            store.load_client_id(backend, resource),
            Some("persisted-client-123".to_string())
        );

        // A different backend must not collide.
        assert_eq!(store.load_client_id("other", resource), None);
    }

    #[cfg(unix)]
    #[test]
    fn save_client_id_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        let (backend, resource) = ("b", "http://localhost");

        store.save_client_id(backend, resource, "cid").unwrap();
        let path = store.client_path(backend, resource);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "client_id file must be owner-only, got {mode:o}"
        );
    }

    #[test]
    fn save_client_id_is_first_writer_wins() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        let (backend, resource) = ("b", "http://localhost");

        // First write wins and is returned verbatim.
        assert_eq!(
            store.save_client_id(backend, resource, "first").unwrap(),
            "first"
        );
        // A concurrent second write does NOT clobber; it adopts the existing id.
        assert_eq!(
            store.save_client_id(backend, resource, "second").unwrap(),
            "first"
        );
        assert_eq!(
            store.load_client_id(backend, resource),
            Some("first".to_string())
        );

        // After deletion, the next write wins again (re-registration path).
        store.delete_client_id(backend, resource).unwrap();
        assert_eq!(store.load_client_id(backend, resource), None);
        assert_eq!(
            store.save_client_id(backend, resource, "third").unwrap(),
            "third"
        );
    }

    #[test]
    fn delete_client_id_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        // Deleting a non-existent record is a no-op, not an error.
        store.delete_client_id("nope", "http://localhost").unwrap();
    }

    #[test]
    fn save_client_id_concurrent_same_backend_converges() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        let (backend, resource) = ("b", "http://localhost");

        // Many threads register distinct ids for the SAME backend at once.
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .save_client_id(backend, resource, &format!("cid-{i}"))
                        .expect("save")
                })
            })
            .collect();
        let returned: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every caller must observe the SAME authoritative id (first wins), and
        // it must match what is on disk.
        let on_disk = store.load_client_id(backend, resource).expect("persisted");
        assert!(
            returned.iter().all(|r| *r == on_disk),
            "callers disagreed with disk: returned={returned:?} disk={on_disk}"
        );

        // No temp files leaked.
        let leaked = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leaked, 0, "temp files leaked");
    }

    #[test]
    fn save_client_id_self_heals_corrupt_final_file() {
        // GIVEN: an existing client_id file whose contents are corrupt
        // (not a valid JSON string), so load_client_id() returns None.
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        let (backend, resource) = ("b", "http://localhost");
        let final_path = store.client_path(backend, resource);
        fs::write(&final_path, b"\x00\x00not json at all").unwrap();
        assert_eq!(
            store.load_client_id(backend, resource),
            None,
            "precondition: corrupt file must be unreadable"
        );

        // WHEN: we persist a fresh id over the corrupt file.
        let returned = store
            .save_client_id(backend, resource, "healed-id")
            .expect("self-heal should succeed");

        // THEN: the validated id is authoritative and readable from disk,
        // instead of silently diverging from a broken on-disk record.
        assert_eq!(returned, "healed-id");
        assert_eq!(
            store.load_client_id(backend, resource),
            Some("healed-id".to_string()),
            "disk must match the returned id after self-heal"
        );
    }

    #[test]
    fn save_client_id_self_heals_zero_byte_final_file() {
        // GIVEN: a zero-byte final file (empty => not a valid JSON string).
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        let (backend, resource) = ("b", "http://localhost");
        fs::write(store.client_path(backend, resource), b"").unwrap();

        // WHEN / THEN: save self-heals and returns a readable id.
        let returned = store.save_client_id(backend, resource, "cid").unwrap();
        assert_eq!(returned, "cid");
        assert_eq!(
            store.load_client_id(backend, resource),
            Some("cid".to_string())
        );
    }

    #[test]
    fn save_client_id_never_truncates_a_leftover_tmp() {
        // GIVEN: leftover temp files (as if a prior run crashed mid-write),
        // seeded with sentinel content. O_EXCL create_new must never open —
        // and therefore never truncate — an existing path, whether or not the
        // nonce collides with one the writer picks.
        let dir = tempfile::tempdir().unwrap();
        let store = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        let (backend, resource) = ("b", "http://localhost");

        let file_name = store
            .client_path(backend, resource)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();
        let sentinel = b"DO-NOT-TRUNCATE";
        let leftovers: Vec<PathBuf> = (0..4)
            .map(|n| {
                let p = dir
                    .path()
                    .join(format!("{file_name}.tmp.{}.{n}", std::process::id()));
                fs::write(&p, sentinel).unwrap();
                p
            })
            .collect();

        // WHEN: we persist a client_id.
        let returned = store.save_client_id(backend, resource, "safe-id").unwrap();

        // THEN: the save produced a valid, readable authoritative id...
        assert_eq!(returned, "safe-id");
        assert_eq!(
            store.load_client_id(backend, resource),
            Some("safe-id".to_string())
        );
        // ...and every seeded leftover is byte-for-byte intact (never emptied).
        for p in &leftovers {
            assert_eq!(
                fs::read(p).unwrap(),
                sentinel,
                "leftover temp file was truncated/overwritten: {}",
                p.display()
            );
        }
    }

    // =========================================================================
    // TokenInfo::from_response
    // =========================================================================

    #[test]
    fn test_token_expiry() {
        // Token that expires in 1 hour
        let token =
            TokenInfo::from_response("test_token".to_string(), None, None, Some(3600), None);
        assert!(!token.is_expired());

        // Token that expired
        let mut expired = token.clone();
        expired.expires_at = Some(0);
        assert!(expired.is_expired());
    }

    #[test]
    fn debug_redacts_secret_fields() {
        // The manual `Debug` impl must never leak the access token, refresh
        // token, or client secret into logs / traces / error context.
        let token = TokenInfo {
            access_token: "ACCESS-SECRET-VALUE".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: Some("REFRESH-SECRET-VALUE".to_string()),
            expires_at: Some(4_102_444_800),
            scope: Some("read write".to_string()),
            token_endpoint: Some("https://idp.example/token".to_string()),
            client_id: Some("public-client-id".to_string()),
            client_secret: Some("CLIENT-SECRET-VALUE".to_string()),
        };

        let dbg = format!("{token:?}");
        for secret in [
            "ACCESS-SECRET-VALUE",
            "REFRESH-SECRET-VALUE",
            "CLIENT-SECRET-VALUE",
        ] {
            assert!(!dbg.contains(secret), "Debug leaked secret {secret}: {dbg}");
        }
        assert!(
            dbg.contains("<redacted>"),
            "expected redaction marker: {dbg}"
        );
        // Non-secret metadata remains visible for diagnostics.
        assert!(dbg.contains("Bearer"), "token_type should stay visible");
        assert!(
            dbg.contains("public-client-id"),
            "client_id is not a secret"
        );
    }

    #[test]
    fn test_token_no_expiry() {
        let token = TokenInfo::from_response("test_token".to_string(), None, None, None, None);
        assert!(!token.is_expired());
    }

    #[test]
    fn from_response_sets_default_token_type() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        assert_eq!(token.token_type, "Bearer");
    }

    #[test]
    fn from_response_preserves_custom_token_type() {
        let token =
            TokenInfo::from_response("tok".to_string(), Some("MAC".to_string()), None, None, None);
        assert_eq!(token.token_type, "MAC");
    }

    #[test]
    fn from_response_stores_refresh_token() {
        let token = TokenInfo::from_response(
            "access".to_string(),
            None,
            Some("refresh_123".to_string()),
            None,
            None,
        );
        assert_eq!(token.refresh_token, Some("refresh_123".to_string()));
    }

    #[test]
    fn from_response_calculates_expiry() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, Some(3600), None);
        assert!(token.expires_at.is_some());
        // Should be roughly now + 3600
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let diff = token.expires_at.unwrap() - now;
        assert!((3598..=3602).contains(&diff)); // allow 2 sec slack
    }

    #[test]
    fn from_response_no_expiry_when_none() {
        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        assert!(token.expires_at.is_none());
    }

    #[test]
    fn from_response_stores_scope() {
        let token = TokenInfo::from_response(
            "tok".to_string(),
            None,
            None,
            None,
            Some("read write".to_string()),
        );
        assert_eq!(token.scope, Some("read write".to_string()));
    }

    // =========================================================================
    // TokenInfo::is_expired
    // =========================================================================

    #[test]
    fn is_expired_with_60_second_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Token that "expires" in 30 seconds - within 60s buffer, so treated as expired
        let token = TokenInfo {
            expires_at: Some(now + 30),
            ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
        };
        assert!(token.is_expired());
    }

    #[test]
    fn is_not_expired_beyond_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Token expires in 120 seconds - well beyond 60s buffer
        let token = TokenInfo {
            expires_at: Some(now + 120),
            ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
        };
        assert!(!token.is_expired());
    }

    // =========================================================================
    // TokenInfo::time_until_expiry
    // =========================================================================

    #[test]
    fn time_until_expiry_future_token() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = TokenInfo {
            expires_at: Some(now + 3600),
            ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
        };
        let ttl = token.time_until_expiry().unwrap();
        assert!(ttl.as_secs() >= 3598 && ttl.as_secs() <= 3601);
    }

    #[test]
    fn time_until_expiry_expired_token() {
        let token = TokenInfo {
            expires_at: Some(0), // long expired
            ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
        };
        assert!(token.time_until_expiry().is_none());
    }

    #[test]
    fn time_until_expiry_no_expiry() {
        let token = TokenInfo {
            expires_at: None,
            ..TokenInfo::from_response("tok".to_string(), None, None, None, None)
        };
        assert!(token.time_until_expiry().is_none());
    }

    // =========================================================================
    // TokenInfo serialization roundtrip
    // =========================================================================

    #[test]
    fn token_info_serialization_roundtrip() {
        let original = TokenInfo::from_response(
            "access_token_xyz".to_string(),
            Some("Bearer".to_string()),
            Some("refresh_abc".to_string()),
            Some(7200),
            Some("read write".to_string()),
        );
        let json = serde_json::to_string(&original).unwrap();
        let restored: TokenInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.access_token, original.access_token);
        assert_eq!(restored.token_type, original.token_type);
        assert_eq!(restored.refresh_token, original.refresh_token);
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.scope, original.scope);
    }

    // =========================================================================
    // TokenStorage - storage_key
    // =========================================================================

    #[test]
    fn storage_key_is_deterministic() {
        let k1 = TokenStorage::storage_key("backend1", "http://localhost");
        let k2 = TokenStorage::storage_key("backend1", "http://localhost");
        assert_eq!(k1, k2);
    }

    #[test]
    fn storage_key_differs_for_different_inputs() {
        let k1 = TokenStorage::storage_key("backend1", "http://localhost");
        let k2 = TokenStorage::storage_key("backend2", "http://localhost");
        let k3 = TokenStorage::storage_key("backend1", "http://other");
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn storage_key_has_expected_length() {
        let key = TokenStorage::storage_key("test", "http://example.com");
        assert_eq!(key.len(), 16); // first 16 hex chars of SHA256
    }

    // =========================================================================
    // TokenStorage - save/load/delete roundtrip
    // =========================================================================

    #[test]
    fn storage_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token = TokenInfo::from_response(
            "my_access_token".to_string(),
            Some("Bearer".to_string()),
            Some("my_refresh".to_string()),
            Some(3600),
            Some("read".to_string()),
        );

        storage
            .save("mybackend", "http://localhost:8080", &token)
            .unwrap();

        let loaded = storage.load("mybackend", "http://localhost:8080").unwrap();
        assert_eq!(loaded.access_token, "my_access_token");
        assert_eq!(loaded.refresh_token, Some("my_refresh".to_string()));
    }

    #[test]
    fn storage_load_nonexistent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        assert!(storage.load("nonexistent", "http://localhost").is_none());
    }

    #[test]
    fn storage_delete_removes_token() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        storage.save("backend", "http://localhost", &token).unwrap();
        assert!(storage.load("backend", "http://localhost").is_some());

        storage.delete("backend", "http://localhost").unwrap();
        assert!(storage.load("backend", "http://localhost").is_none());
    }

    #[test]
    fn storage_delete_nonexistent_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();
        // Should not error when deleting non-existent token
        storage
            .delete("no_such_backend", "http://localhost")
            .unwrap();
    }

    #[test]
    fn storage_overwrite_updates_token() {
        let dir = tempfile::tempdir().unwrap();
        let storage = TokenStorage::new(dir.path().to_path_buf()).unwrap();

        let token1 = TokenInfo::from_response("token_v1".to_string(), None, None, None, None);
        storage
            .save("backend", "http://localhost", &token1)
            .unwrap();

        let token2 = TokenInfo::from_response("token_v2".to_string(), None, None, None, None);
        storage
            .save("backend", "http://localhost", &token2)
            .unwrap();

        let loaded = storage.load("backend", "http://localhost").unwrap();
        assert_eq!(loaded.access_token, "token_v2");
    }

    #[test]
    fn storage_creates_directory_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("deeply").join("nested").join("oauth");
        let storage = TokenStorage::new(nested).unwrap();

        let token = TokenInfo::from_response("tok".to_string(), None, None, None, None);
        storage.save("b", "http://localhost", &token).unwrap();
        assert!(storage.load("b", "http://localhost").is_some());
    }
}
