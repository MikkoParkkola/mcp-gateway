// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record key's text (MIK-8697): a `SecretRef` when one is configured, else
//! the fallback key file, created on first use. Fails closed.

use std::io::Write as _;
use std::path::Path;

use super::secret_ref::{SecretRef, read_file_ref};
use crate::{Error, Result};

/// The resolved key text: `configured` resolved as a `SecretRef` (errors name
/// `field`), else the 64 hex digits of `key_file`, which is created when absent.
///
/// # Errors
///
/// An unresolvable `SecretRef`; a key file that cannot be created or read, is
/// too permissive or is not 64 lowercase hex digits, naming its path.
pub(crate) fn resolve_record_key_text(
    configured: Option<&str>,
    overlay: &super::EnvOverlay,
    key_file: &Path,
    field: &str,
) -> Result<String> {
    if let Some(text) = configured {
        return SecretRef::parse(text).resolve(field, overlay);
    }
    let refused = |why: String| {
        Error::ConfigValidation(format!(
            "record key file {}: {why}; restore it from backup, or set {field}",
            key_file.display()
        ))
    };
    match std::fs::symlink_metadata(key_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            publish_new_key(key_file, |from, to| std::fs::hard_link(from, to))
                .map_err(|e| refused(format!("cannot create it: {e}")))?;
        }
        Err(e) => return Err(refused(e.to_string())),
        Ok(_) => {}
    }
    read_key_file(key_file, field)
}

/// [`resolve_record_key_text`] for a reader that must create nothing: the
/// configured `SecretRef`, else an existing key file, else `None`. A report
/// the command line prints never writes key material where none exists.
///
/// # Errors
///
/// As [`resolve_record_key_text`], except that a missing key file is `None`.
pub(crate) fn read_record_key_text(
    configured: Option<&str>,
    overlay: &super::EnvOverlay,
    key_file: &Path,
    field: &str,
) -> Result<Option<String>> {
    if let Some(text) = configured {
        return SecretRef::parse(text).resolve(field, overlay).map(Some);
    }
    match std::fs::symlink_metadata(key_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => read_key_file(key_file, field).map(Some),
    }
}

/// The 64 hex digits of an existing `key_file`. The guarded reader enforces
/// owner-only mode (or DACL) and strips the one trailing newline, exactly as
/// for the same file named by a `file:` `SecretRef`.
fn read_key_file(key_file: &Path, field: &str) -> Result<String> {
    let refused = |why: String| {
        Error::ConfigValidation(format!(
            "record key file {}: {why}; restore it from backup, or set {field}",
            key_file.display()
        ))
    };
    let text =
        read_file_ref("the record key file", key_file).map_err(|e| refused(e.to_string()))?;
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refused(
            "it must hold exactly 64 lowercase hex digits".into(),
        ));
    }
    Ok(text)
}

/// Write a new key to a private temp file and publish it under `key_file` with
/// a no-replace hard link: a reader never sees a short key, and when two first
/// starts race, the first link wins and both read it. Where hard links are
/// unsupported (FAT, some network filesystems), `link` fails and so does
/// startup: there is no fallback to a rename-over or a plain write.
fn publish_new_key(
    key_file: &Path,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use rand::RngExt as _;
    let dir = key_file.parent().unwrap_or(Path::new("."));
    let bytes: [u8; 32] = rand::rng().random();
    let nonce: [u8; 8] = rand::rng().random();
    let mut temp_name = key_file.file_name().unwrap_or_default().to_owned();
    temp_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        hex::encode(nonce)
    ));
    let temp = dir.join(temp_name);
    let published = (|| {
        let mut file = crate::config_persistence::create_new_private(&temp)?;
        file.write_all(format!("{}\n", hex::encode(bytes)).as_bytes())?;
        file.sync_all()?;
        drop(file);
        match link(&temp, key_file) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            linked => linked,
        }
    })();
    // Removed whether or not this process won the link; a crash before this
    // line leaves a stray temp, which no reader ever opens.
    let _ = std::fs::remove_file(&temp);
    published?;
    sync_dir(dir)
}

#[cfg(test)]
#[path = "record_key_tests.rs"]
mod tests;

/// Make the link durable, as the events store does after a rename.
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
