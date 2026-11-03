// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `mcp-gateway upgrade` removes grant rows that name no one. A row whose
//! subject or owner has an empty authority or subject matches no caller, so it
//! grants nothing; since such a row is refused at load, the upgrade removes
//! it. The original is backed up first and the rewrite is atomic; a grants
//! file with no such row is not touched, so a second run changes nothing.

use std::path::Path;

/// A row the upgrade removed: its id and the field that named no one. Never
/// any other content of the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    /// The row's `grant_id`.
    pub grant_id: String,
    /// `"subject"` or `"owner"`.
    pub field: String,
}

/// Remove every row naming no one from the grants file at `path`, backing the
/// original up to `backup` first. `write` replaces a file atomically. Returns
/// the removed rows; none means nothing was written.
///
/// # Errors
///
/// A read, parse or write failure. A failed rewrite leaves the original.
pub fn remove_nameless_rows(
    path: &Path,
    backup: &Path,
    write: impl Fn(&Path, &str) -> std::io::Result<()>,
) -> std::io::Result<Vec<Removed>> {
    // The loader's own mode-checked read: a file it would refuse to load is
    // not rewritten either.
    let content =
        match crate::config::read_checked_file(path, crate::config::CheckedFile::IdentityGrants) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
    let Some((file, removed)) =
        super::matching::strip_nameless(&content).map_err(std::io::Error::other)?
    else {
        return Ok(Vec::new());
    };
    let text = super::grants_text(path, &file).map_err(std::io::Error::other)?;
    // The original first: a rewrite that fails after it leaves both the
    // backup and, by the atomic replace, the original itself.
    write(backup, &content)?;
    write(path, &text)?;
    Ok(removed
        .into_iter()
        .map(|(grant_id, field)| Removed { grant_id, field })
        .collect())
}

#[cfg(test)]
#[path = "nameless_upgrade_tests.rs"]
mod tests;
