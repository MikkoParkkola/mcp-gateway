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
use tokio::io::AsyncWriteExt as _;

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

fn render_filename(template: &str, params: &Value) -> String {
    let mut out = template.to_string();
    if let Some(map) = params.as_object() {
        for (k, v) in map {
            if let Some(s) = v.as_str() {
                out = out.replace(&format!("{{{k}}}"), s);
            }
        }
    }
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
static SAVE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn dir_size(root: &std::path::Path) -> std::io::Result<u64> {
    let mut total = 0;
    let mut rd = tokio::fs::read_dir(root).await?;
    while let Some(e) = rd.next_entry().await? {
        let meta = e.metadata().await?;
        if meta.is_file() {
            total += meta.len();
        }
    }
    Ok(total)
}

async fn create_new(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    let mut o = tokio::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(0o600);
    o.open(path).await
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

    let _guard = SAVE_LOCK.lock().await;
    let used = dir_size(&root).await.map_err(|e| refuse(e))?;
    if used.saturating_add(bytes.len() as u64) > roots.downloads_quota_bytes {
        return Err(refuse("downloads quota would be exceeded"));
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name.as_str(), ""),
    };
    for n in 0..=99 {
        let candidate = if n == 0 {
            name.clone()
        } else {
            format!("{stem}_{n}{ext}")
        };
        let path = root.join(&candidate);
        match create_new(&path).await {
            Ok(mut f) => {
                let written = f.write_all(&bytes).await.and(f.flush().await);
                if let Err(e) = written {
                    drop(f);
                    let _ = tokio::fs::remove_file(&path).await;
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

#[cfg(test)]
#[path = "save_file_tests.rs"]
mod tests;
