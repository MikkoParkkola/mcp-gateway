// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Where the `email_hash` installation key lives: one owner-only file,
//! `<data_dir>/key-server-email-hmac.json`, written once on the first enabled
//! start and read on every start after. It holds the key (generated mode) or
//! names a configured one (configured mode), and the key id the key must
//! match. Losing it loses lookup of every earlier record, so a missing file
//! with retained hashed records refuses startup instead of making a new key.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::email_hash::EmailHashKey;

/// The key file, under the gateway data directory.
pub(crate) const FILE: &str = "key-server-email-hmac.json";
/// Its lock: concurrent first starts serialise here and load the winner.
const LOCK: &str = ".key-server-email-hmac.lock";
/// What the lock guards, as a refusal names it.
const SUBJECT: &str = "the key-server email HMAC envelope";
/// How long a start waits for another holding the lock (the vault's wait).
const LOCK_WAIT: Duration = Duration::from_secs(30);
/// The envelope's schema version.
const VERSION: u32 = 1;

/// Whether the key is kept in the file or configured elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Generated,
    Configured,
}

/// The file's content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    mode: Mode,
    /// SHA-256 of the decoded key bytes: the key this file names.
    key_id: String,
    /// The key, 64 lowercase hex digits; generated mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_hex: Option<String>,
    /// Ids of keys an explicit reset retired, newest last.
    #[serde(default)]
    previous_key_ids: Vec<String>,
    /// Whether the audit log holds this key's creation record. Written false
    /// with the file and set once the record is appended, so a crash between
    /// the two heals on the next start.
    #[serde(default)]
    creation_recorded: bool,
}

impl Drop for Envelope {
    /// A generated key's text is wiped with the envelope that held it.
    fn drop(&mut self) {
        if let Some(hex) = self.key_hex.as_mut() {
            zeroize::Zeroize::zeroize(hex);
        }
    }
}

/// The audit-log event that marks a key's creation; it carries the key id
/// only.
pub(crate) const CREATED_EVENT: &str = "key_server.email_hash_key_created";

/// The fields of the creation record for `key_id`.
pub(crate) fn creation_fields(key_id: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("event".into(), CREATED_EVENT.into());
    fields.insert("email_hash_key_id".into(), key_id.into());
    fields
}

/// Whether any retained segment of the audit log at `log` holds email-hash
/// history: a creation record, or any record carrying `email_hash` or
/// `email_hash_key_id` at any depth. Fails closed: a segment that cannot be
/// read, or a line that is not a JSON entry, is an error, never "no history".
pub(crate) fn history_in(log: &Path) -> Result<bool, String> {
    use crate::security::transparency_log::{Malformed, log_contains_entry};
    log_contains_entry(
        log,
        "email-hash history scan",
        Malformed::Refuse,
        holds_history,
    )
    .map_err(|e| {
        format!(
            "cannot read the audit log {} for email-hash history: {e}",
            log.display()
        )
    })
}

/// Append the creation record for `key_id` to `log`, unless a retained
/// segment already holds it: a start that crashed after appending but before
/// marking the file recorded must not append the same record twice. The
/// check fails closed like [`history_in`].
pub(crate) fn record_creation(
    log: &crate::security::TransparencyLogger,
    key_id: &str,
) -> Result<(), String> {
    use crate::security::transparency_log::{Malformed, log_contains_entry};
    let path = log.path();
    let already = log_contains_entry(&path, "email-hash creation check", Malformed::Refuse, |e| {
        e.get("event").and_then(|v| v.as_str()) == Some(CREATED_EVENT)
            && e.get("email_hash_key_id").and_then(|v| v.as_str()) == Some(key_id)
    })
    .map_err(|e| format!("cannot read the audit log {}: {e}", path.display()))?;
    if already {
        return Ok(());
    }
    log.append_event_synced(
        creation_fields(key_id),
        &crate::security::audit::AuditEnvelope::gateway(),
    )
    .map(|_| ())
    .map_err(|e| format!("cannot record the email-hash key in the audit log: {e}"))
}

/// Whether `value`, at any depth, is a creation record or carries an
/// `email_hash` or `email_hash_key_id` field.
fn holds_history(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("event").and_then(|v| v.as_str()) == Some(CREATED_EVENT)
                || map.contains_key("email_hash")
                || map.contains_key("email_hash_key_id")
                || map.values().any(holds_history)
        }
        serde_json::Value::Array(items) => items.iter().any(holds_history),
        _ => false,
    }
}

/// Paths of the key file and its lock under `data_dir`.
fn paths(data_dir: &Path) -> (PathBuf, PathBuf) {
    (data_dir.join(FILE), data_dir.join(LOCK))
}

/// The installation key for `data_dir`, creating the key file on a first
/// start. `configured` is the already resolved text of
/// `key_server.audit_email_hmac_secret_ref`, when set. `has_history` says
/// whether any retained record carries an `email_hash`; it runs only when the
/// file is missing.
pub(crate) fn resolve(
    data_dir: &Path,
    configured: Option<&str>,
    has_history: impl FnOnce() -> Result<bool, String>,
    record_creation: impl FnOnce(&str) -> Result<(), String>,
) -> Result<EmailHashKey, String> {
    let (file, lock) = paths(data_dir);
    let _held = take_lock(&lock, LOCK_WAIT)?;
    let (key, mut envelope) = match std::fs::symlink_metadata(&file) {
        Ok(_) => load(&file, configured)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if has_history()? {
                return Err(format!(
                    "{}: missing, but retained audit records carry an email_hash; restore \
                     the file from backup (a new key would make every earlier record \
                     unfindable)",
                    file.display()
                ));
            }
            create(&file, configured)?;
            load(&file, configured)?
        }
        Err(e) => return Err(format!("{}: {e}", file.display())),
    };
    if !envelope.creation_recorded {
        record_creation(&envelope.key_id)?;
        envelope.creation_recorded = true;
        rewrite(&file, &envelope)?;
    }
    Ok(key)
}

fn take_lock(lock: &Path, wait: Duration) -> Result<crate::fs_lock::ExclusiveFileLock, String> {
    use crate::config_persistence::lock::{NotLocked, lock_file_blocking};
    lock_file_blocking(lock, SUBJECT, Instant::now() + wait).map_err(|e| match e {
        NotLocked::Busy => format!(
            "another start held {SUBJECT} (lock file {}) for {}s; nothing was read or written",
            lock.display(),
            wait.as_secs()
        ),
        NotLocked::Failed(why) | NotLocked::Refused(why) => why,
    })
}

/// Write the first envelope: the configured key, else a new random one.
fn create(file: &Path, configured: Option<&str>) -> Result<(), String> {
    use rand::RngExt as _;
    use zeroize::Zeroize as _;
    let (mode, key_hex) = if let Some(text) = configured {
        (Mode::Configured, text.trim_end_matches('\n').to_owned())
    } else {
        let bytes: [u8; 32] = rand::rng().random();
        (Mode::Generated, hex::encode(bytes))
    };
    let key = EmailHashKey::from_hex(&key_hex)
        .map_err(|e| format!("key_server.audit_email_hmac_secret_ref: {e}"))?;
    let envelope = Envelope {
        version: VERSION,
        mode,
        key_id: key.key_id(),
        key_hex: if mode == Mode::Generated {
            Some(key_hex)
        } else {
            let mut copy = key_hex;
            copy.zeroize();
            None
        },
        previous_key_ids: Vec::new(),
        creation_recorded: false,
    };
    let mut json = serde_json::to_vec_pretty(&envelope).map_err(|e| e.to_string())?;
    let published =
        crate::config::publish_new_file(file, &json, |from, to| std::fs::hard_link(from, to));
    json.zeroize();
    // `envelope` wipes its key text when it drops.
    published.map_err(|e| format!("{}: cannot create it: {e}", file.display()))
}

/// Read and check an existing envelope; switch its mode if the operator moved
/// the same key between the file and a configured reference.
fn load(file: &Path, configured: Option<&str>) -> Result<(EmailHashKey, Envelope), String> {
    let refused = |why: String| format!("{}: {why}; restore it from backup", file.display());
    let mut text =
        crate::config::secret_ref::read_file_ref("the key-server email HMAC envelope", file)
            .map_err(|e| refused(e.to_string()))?;
    let parsed = serde_json::from_str::<Envelope>(&text);
    // The text may hold the key: wiped whether or not it parsed.
    zeroize::Zeroize::zeroize(&mut text);
    // serde's message can quote the offending value, which may be the key
    // itself: name only where the file stops making sense.
    let mut envelope = parsed.map_err(|e| {
        refused(format!(
            "not a valid envelope ({:?} error at line {} column {})",
            e.classify(),
            e.line(),
            e.column()
        ))
    })?;
    if envelope.version != VERSION {
        return Err(refused(format!(
            "schema version {} is not {VERSION}",
            envelope.version
        )));
    }
    let stored = match (envelope.mode, envelope.key_hex.as_deref()) {
        (Mode::Generated, Some(hex)) => {
            Some(EmailHashKey::from_hex(hex).map_err(|e| refused(e.to_string()))?)
        }
        (Mode::Generated, None) => return Err(refused("generated mode without key_hex".into())),
        (Mode::Configured, None) => None,
        (Mode::Configured, Some(_)) => {
            return Err(refused("configured mode with a stored key".into()));
        }
    };
    let given = configured
        .map(EmailHashKey::from_hex)
        .transpose()
        .map_err(|e| format!("key_server.audit_email_hmac_secret_ref: {e}"))?;
    let key = match (stored, given) {
        (Some(stored), None) => stored,
        (None, Some(given)) => given,
        (None, None) => {
            return Err(format!(
                "{}: names a configured key; set key_server.audit_email_hmac_secret_ref",
                file.display()
            ));
        }
        // Generated file, now configured: the same key may move to a
        // reference; another key may not.
        (Some(stored), Some(given)) => {
            if stored.key_id() != given.key_id() {
                return Err(format!(
                    "key_server.audit_email_hmac_secret_ref names another key than {}; a new \
                     key needs an explicit reset",
                    file.display()
                ));
            }
            envelope.mode = Mode::Configured;
            if let Some(mut hex) = envelope.key_hex.take() {
                zeroize::Zeroize::zeroize(&mut hex);
            }
            rewrite(file, &envelope)?;
            given
        }
    };
    if key.key_id() != envelope.key_id {
        return Err(refused("the key does not match the key id it names".into()));
    }
    // A configured file whose reference was dropped keeps refusing above; a
    // configured key that the operator now wants in the file is an explicit
    // reset, not a start-time switch.
    Ok((key, envelope))
}

/// Replace the envelope under the held lock, wiping the serialised copy.
fn rewrite(file: &Path, envelope: &Envelope) -> Result<(), String> {
    use zeroize::Zeroize as _;
    let mut json = serde_json::to_vec_pretty(envelope).map_err(|e| e.to_string())?;
    // An owner-only atomic replace under the held lock. A power loss can
    // bring back the old envelope: an unset recorded flag then re-checks the
    // log (no second record), and a reverted mode switch keeps the same key.
    let written = crate::config_persistence::write_atomic(
        file,
        &json,
        crate::config_persistence::FileMode::Private,
        crate::config_persistence::Symlink::Replace,
    );
    json.zeroize();
    written.map_err(|e| format!("{}: cannot rewrite it: {e}", file.display()))
}

#[cfg(all(test, unix))]
#[path = "email_hmac_store_tests.rs"]
mod tests;
