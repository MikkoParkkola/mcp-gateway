// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Declarative `save_file` post-step (MIK-7782, ATTACH.1).
//!
//! Runs on a REST response before any transform: the payload field is decoded
//! and written under `capabilities.files.downloads`, and the caller gets
//! `{saved_path, size, filename}` instead of the bytes. The directory is never
//! caller-chosen, the file name is one validated path component, and the write
//! never follows or replaces an existing entry.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::FileRoots;
use crate::{Error, Result};

/// Absolute ceiling for `max_bytes`, whatever a file declares.
pub const HARD_MAX_BYTES: u64 = 100 * 1024 * 1024;
const DEFAULT_MAX_BYTES: u64 = 25 * 1024 * 1024;

/// Payload encoding of the response field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveEncoding {
    /// RFC 4648 section 5 alphabet; padding optional.
    Base64url,
    /// Standard alphabet; padding optional.
    Base64,
}

/// The `save_file` block of a REST provider config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveFileSpec {
    /// Response field holding the payload.
    pub data: String,
    /// How the payload is encoded.
    pub encoding: SaveEncoding,
    /// File name template; `{param}` slots take string call parameters.
    pub filename: String,
    /// Largest decoded size accepted.
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

fn refuse(msg: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("save_file: {msg}"))
}

fn is_dos_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let digits = |rest: &str| {
        let mut it = rest.chars();
        matches!(
            (it.next(), it.next()),
            (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
        )
    };
    stem.strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(digits)
}

/// One portable path component, or the reason it is refused.
///
/// # Errors
///
/// A message naming the rule the name breaks.
pub fn validate_filename(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err("file name is empty or a dot name".into());
    }
    if name.len() > 255 {
        return Err("file name is longer than 255 bytes".into());
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
    {
        return Err("file name holds a separator, ':' or control character".into());
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err("file name ends in a dot or space".into());
    }
    if is_dos_device(name) {
        return Err("file name is a reserved device name".into());
    }
    Ok(())
}

/// One left-to-right pass, so a parameter value that itself looks like `{x}`
/// is never expanded again. A missing or non-string slot stays literal.
fn render_filename(template: &str, params: &Value) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let tail = &rest[open..];
        if let Some(close) = tail.find('}') {
            match params.get(&tail[1..close]).and_then(Value::as_str) {
                Some(value) => out.push_str(value),
                None => out.push_str(&tail[..=close]),
            }
            rest = &tail[close + 1..];
        } else {
            out.push_str(tail);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn decode(spec: &SaveFileSpec, encoded: &str) -> Result<Vec<u8>> {
    let cap = spec.max_bytes.min(HARD_MAX_BYTES);
    let trimmed = encoded.trim_end_matches('=');
    if (trimmed.len() as u64).saturating_mul(3) / 4 > cap {
        return Err(refuse(format!("payload is larger than {cap} bytes")));
    }
    let engine: &dyn Fn(&str) -> std::result::Result<Vec<u8>, base64::DecodeError> =
        match spec.encoding {
            SaveEncoding::Base64url => &|s| URL_SAFE_NO_PAD.decode(s),
            SaveEncoding::Base64 => &|s| STANDARD_NO_PAD.decode(s),
        };
    let bytes = engine(trimmed).map_err(|e| refuse(format!("payload is not valid base64: {e}")))?;
    if bytes.len() as u64 > cap {
        return Err(refuse(format!("payload is larger than {cap} bytes")));
    }
    Ok(bytes)
}

/// Serializes the quota check and the write, so two saves cannot both fit.
/// Held for the whole blocking write, so a cancelled caller cannot release it
/// while the write is still running.
static SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn dir_size(root: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    for entry in std::fs::read_dir(root)? {
        let meta = entry?.metadata()?;
        if meta.is_file() {
            total += meta.len();
        }
    }
    Ok(total)
}

fn create_new(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(path)
}

/// Quota check, create-new write and cleanup, all on one blocking thread.
fn write_unique(root: &std::path::Path, name: &str, bytes: &[u8], quota: u64) -> Result<Value> {
    use std::io::Write as _;
    let _guard = SAVE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let used = dir_size(root).map_err(refuse)?;
    if used.saturating_add(bytes.len() as u64) > quota {
        return Err(refuse("downloads quota would be exceeded"));
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 0..=99 {
        let candidate = if n == 0 {
            name.to_owned()
        } else {
            format!("{stem}_{n}{ext}")
        };
        let path = root.join(&candidate);
        match create_new(&path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(bytes).and_then(|()| f.flush()) {
                    drop(f);
                    let _ = std::fs::remove_file(&path);
                    return Err(refuse(e));
                }
                return Ok(json!({
                    "saved_path": path.to_string_lossy(),
                    "size": bytes.len(),
                    "filename": candidate,
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(refuse(e)),
        }
    }
    Err(refuse("no free file name after 99 attempts"))
}

/// Decode the payload and write it; returns `{saved_path, size, filename}`.
///
/// # Errors
///
/// A refusal naming the rule (unset root, bad name, size, quota) or the I/O
/// failure; a partial file is removed.
pub async fn save(
    spec: &SaveFileSpec,
    response: &Value,
    params: &Value,
    roots: &FileRoots,
) -> Result<Value> {
    let root = roots
        .downloads
        .as_deref()
        .ok_or_else(|| refuse("needs capabilities.files.downloads, which is not configured"))?;
    let root = tokio::fs::canonicalize(root)
        .await
        .map_err(|_| refuse("capabilities.files.downloads does not exist"))?;
    let name = render_filename(&spec.filename, params);
    validate_filename(&name).map_err(refuse)?;
    let encoded = response
        .get(&spec.data)
        .and_then(Value::as_str)
        .ok_or_else(|| refuse(format!("response has no string field '{}'", spec.data)))?;
    let bytes = decode(spec, encoded)?;
    let quota = roots.downloads_quota_bytes;
    tokio::task::spawn_blocking(move || write_unique(&root, &name, &bytes, quota))
        .await
        .map_err(refuse)?
}

#[cfg(test)]
#[path = "save_file_tests.rs"]
mod tests;
