// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reading an OAuth token file through the mode check (F18 R2).
//!
//! `TokenStorage::load` runs on every token lookup, so a refused file is an
//! ERROR once per path and DEBUG after that. A good read or a save clears the
//! path, so a file loosened again after a repair gets a fresh ERROR.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, PoisonError};

use tracing::{debug, error, warn};

use crate::config::{CheckedFile, read_checked_file};

/// Token files refused since they last read cleanly or were saved.
static REFUSED: LazyLock<Mutex<HashSet<PathBuf>>> = LazyLock::new(Default::default);

/// The token file's text, or `None` (logged) when it cannot be read or its
/// mode lets other users read it. `None` is what a missing token means, so the
/// backend asks for authorisation again and the next save writes a 0600 file.
pub(super) fn read(path: &Path, backend_name: &str) -> Option<String> {
    match read_checked_file(path, CheckedFile::OAuthToken) {
        Ok(text) => {
            forget(path);
            Some(text)
        }
        // A refused mode, and an unreadable file, are one case to the caller.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let text = e.to_string();
            let first = REFUSED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(path.to_path_buf());
            if first {
                error!(backend = %backend_name, "{text}");
            } else {
                debug!(backend = %backend_name, "{text}");
            }
            None
        }
        Err(e) => {
            warn!(backend = %backend_name, error = %e, "Failed to read token file");
            None
        }
    }
}

/// Clears `path` from the refused set: it was just written 0600.
pub(super) fn forget(path: &Path) {
    REFUSED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(path);
}

#[cfg(all(test, unix))]
#[path = "token_file_tests.rs"]
mod tests;
