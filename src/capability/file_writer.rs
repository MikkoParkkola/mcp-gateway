// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one writer for capability files: locked per directory, atomic,
//! checked against the base the editor loaded, the pin rewritten in place.
//!
//! Red-first stub: the API the tests are written against. Every change is
//! refused until the writer lands.

use std::path::Path;
use std::time::Instant;

use crate::identity_propagation::AccountStrategyRegistry;

/// What the editor loaded: no file, or the SHA-256 (lowercase hex) of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Base {
    Absent,
    Bytes(String),
}

/// How the pin line is treated: rewritten for a save, kept for a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinUpdate {
    InPlace,
    Verbatim,
}

/// The change to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Change {
    Write(String),
    Delete,
}

/// What happened to the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinChange {
    Kept,
    Updated,
    Added,
    None,
}

/// A committed change: the hashes before and after (the next base).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Committed {
    pub(crate) before: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) pin: PinChange,
}

/// One validation error, with its position or field where it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldError {
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) field: Option<String>,
    pub(crate) message: String,
}

/// Why nothing was written. `patch` is a unified diff the admin can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refused {
    Stale {
        patch: String,
        current_sha256: Option<String>,
    },
    PinMismatch {
        patch: String,
    },
    Unpin {
        patch: String,
    },
    PinAmbiguous {
        patch: String,
    },
    Symlinked {
        real_path: String,
    },
    Unwritable {
        error: String,
        patch: String,
    },
    LockBusy,
    Invalid {
        errors: Vec<FieldError>,
        patch: String,
    },
}

/// One change to one capability file: `<dir>/<name>.yaml`.
#[derive(Debug, Clone)]
pub(crate) struct Edit<'a> {
    pub(crate) dir: &'a Path,
    pub(crate) name: &'a str,
    pub(crate) base: Base,
    pub(crate) change: Change,
    pub(crate) pin: PinUpdate,
}

/// Commit `edit` under its directory's lock.
pub(crate) async fn commit(
    edit: Edit<'_>,
    accounts: Option<&AccountStrategyRegistry>,
    deadline: Instant,
) -> Result<Committed, Refused> {
    let _ = (edit, accounts, deadline);
    Err(Refused::Unwritable {
        error: "the capability writer is not built".into(),
        patch: String::new(),
    })
}

/// [`commit`] with `observe` called on the target path after the base check
/// and before the rename: the seam for the swap race and the rename failure.
#[cfg(test)]
pub(crate) async fn commit_observed(
    edit: Edit<'_>,
    accounts: Option<&AccountStrategyRegistry>,
    deadline: Instant,
    observe: impl FnOnce(&Path) + Send,
) -> Result<Committed, Refused> {
    let _ = observe;
    commit(edit, accounts, deadline).await
}

#[cfg(test)]
#[path = "file_writer_tests.rs"]
mod tests;
