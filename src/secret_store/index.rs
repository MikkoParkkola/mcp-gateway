// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The entry index, `<config dir>/secrets-index.jsonl` (ADR-028 rule 6).
//!
//! Every name a save is about to create is appended and synced, with its
//! directory, before the create runs, so a crash between the two leaves a
//! name the listing can still check. A rolled-back name is appended as
//! removed. No store is ever enumerated: that would return values.

use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{StoreError, StoreKind};

/// One index line: a created entry, or the removal of one.
#[derive(Serialize, Deserialize)]
struct Line {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    removed_at: Option<u64>,
}

/// The index of one config directory.
pub(super) struct Index {
    path: PathBuf,
}

fn failed(what: &str, error: &std::io::Error) -> StoreError {
    StoreError::Failed(format!("{what}: {error}"))
}

/// Milliseconds since the epoch; 0 for a clock set before it, which only
/// dates an index line.
fn now_ms() -> u64 {
    crate::clock::unix_millis().unwrap_or(0)
}

impl Index {
    /// The index beside `config_dir`'s `secrets/`, outside it.
    pub(super) fn at(config_dir: &Path) -> Self {
        Self {
            path: config_dir.join("secrets-index.jsonl"),
        }
    }

    /// Records that `name` is about to be created in `kind`, durably.
    pub(super) fn append_created(&self, name: &str, kind: StoreKind) -> Result<(), StoreError> {
        self.append(&Line {
            name: name.to_owned(),
            store: Some(kind.as_str().to_owned()),
            created_at: Some(now_ms()),
            removed_at: None,
        })
    }

    /// Records that this save removed `name` again.
    pub(super) fn append_removed(&self, name: &str) -> Result<(), StoreError> {
        self.append(&Line {
            name: name.to_owned(),
            store: None,
            created_at: None,
            removed_at: Some(now_ms()),
        })
    }

    fn append(&self, line: &Line) -> Result<(), StoreError> {
        let mut file = match crate::config_persistence::create_new_private(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&self.path)
                .map_err(|e| failed("cannot open the secrets index", &e))?,
            Err(e) => return Err(failed("cannot create the secrets index", &e)),
        };
        let mut text = serde_json::to_string(line)
            .map_err(|e| StoreError::Failed(format!("cannot encode an index line: {e}")))?;
        // A torn last line from a crash is closed first, so it stays one
        // unreadable line instead of corrupting this one.
        if !ends_with_newline(&mut file).map_err(|e| failed("cannot read the secrets index", &e))? {
            text.insert(0, '\n');
        }
        text.push('\n');
        file.write_all(text.as_bytes())
            .map_err(|e| failed("cannot write the secrets index", &e))?;
        sync_file(&file).map_err(|e| failed("cannot sync the secrets index", &e))?;
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        sync_dir(dir).map_err(|e| failed("cannot sync the secrets index directory", &e))
    }

    /// Every name created and not removed, with its store, oldest first.
    /// Unreadable lines, such as a torn last one, are skipped.
    pub(super) fn live(&self) -> Result<Vec<(String, String)>, StoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(failed("cannot read the secrets index", &e)),
        };
        let mut live: Vec<(String, String)> = Vec::new();
        for line in text
            .lines()
            .filter_map(|l| serde_json::from_str::<Line>(l).ok())
        {
            if line.removed_at.is_some() {
                live.retain(|(name, _)| *name != line.name);
            } else if let Some(store) = line.store {
                live.push((line.name, store));
            }
        }
        Ok(live)
    }
}

/// Whether `file` is empty or ends in a newline.
fn ends_with_newline(file: &mut std::fs::File) -> std::io::Result<bool> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(true);
    }
    file.seek(std::io::SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

#[cfg(not(test))]
fn sync_file(file: &std::fs::File) -> std::io::Result<()> {
    file.sync_all()
}

#[cfg(not(test))]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    crate::events::sync_dir(dir)
}

#[cfg(test)]
use sync_seam::{sync_dir, sync_file};

/// Records every index sync on this thread, and can fail them, so a test can
/// show the line is durable before any create (ADR-028 rule 6).
#[cfg(test)]
pub(super) mod sync_seam {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    thread_local! {
        pub(in crate::secret_store) static SYNCED: RefCell<Vec<&'static str>> =
            const { RefCell::new(Vec::new()) };
        pub(in crate::secret_store) static FAIL: Cell<bool> = const { Cell::new(false) };
    }

    fn record(what: &'static str) -> std::io::Result<()> {
        SYNCED.with(|synced| synced.borrow_mut().push(what));
        if FAIL.with(Cell::get) {
            return Err(std::io::Error::other("injected sync failure"));
        }
        Ok(())
    }

    pub(super) fn sync_file(file: &std::fs::File) -> std::io::Result<()> {
        record("index")?;
        file.sync_all()
    }

    pub(super) fn sync_dir(dir: &Path) -> std::io::Result<()> {
        record("index dir")?;
        crate::events::sync_dir(dir)
    }
}
