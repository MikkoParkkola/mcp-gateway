// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Replay one record kind from the invocation log, newest first, to the
//! oldest line kept: the decision set's startup read.
//!
//! Each record is handed over with its `entry_hash`, the identity live
//! delivery also uses, so a record read here and delivered live is one
//! record. A rotation that drops the page's segment restarts the read once.

use std::io;
use std::path::Path;

use serde_json::{Map, Value};

use super::reader::{Limits, read_page};

/// Records per page and bytes per page: one page bounds memory, not the
/// replay, which reads to the retention edge.
const PAGE: Limits = Limits {
    matches: 512,
    bytes: 4 * 1024 * 1024,
};

/// What a replay read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(in crate::gateway::ui) struct Replayed {
    /// Records of the kind handed over.
    pub(in crate::gateway::ui) records: u64,
    /// Lines that were not a JSON record, skipped.
    pub(in crate::gateway::ui) unreadable: u64,
}

/// Hand every kept record of `kind` in the log at `path` to `each`, newest
/// first, with its entry hash. A record without one is skipped: it cannot be
/// told apart from its live delivery.
pub(in crate::gateway::ui) fn records(
    path: &Path,
    kind: &str,
    mut each: impl FnMut(&Map<String, Value>, &str),
) -> io::Result<Replayed> {
    let mut replayed = Replayed::default();
    let mut cursor = None;
    let mut restarted = false;
    loop {
        let page = read_page(path, None, cursor.as_ref(), PAGE, |line| {
            line.entry.get("kind").and_then(Value::as_str) == Some(kind)
        })?;
        if page.cursor_reset && cursor.is_some() {
            if restarted {
                return Err(io::Error::other("the log rotated past the replay twice"));
            }
            restarted = true;
        }
        replayed.unreadable += page.unreadable.len() as u64;
        for line in &page.lines {
            let Some(record) = line.entry.as_object() else {
                continue;
            };
            let Some(hash) = record.get("entry_hash").and_then(Value::as_str) else {
                continue;
            };
            each(record, hash);
            replayed.records += 1;
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(replayed),
        }
    }
}
