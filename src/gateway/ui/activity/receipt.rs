// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One row's receipt: its allowlisted fields, its link to the record before
//! it, and its signature state. A governance row says whether a reason and a
//! rollback summary were recorded and how long they are, never their text:
//! operator free text can hold anything, a pasted secret included.

use std::path::Path;

use serde_json::{Map, Value, json};

use super::access::Access;
use super::reader::{Line, Which};
use super::rows::{Kind, kind_of, owned_by, row};
use super::seek::{Reads, oldest_counter, seek};
use crate::security::transparency_log::recompute_entry_hash;

/// What a receipt says for evidence this gateway version does not record.
pub(super) const NOT_RECORDED: &str = "not recorded by this gateway version";

/// A row id: which log, the counter, and the first 16 hex of its hash.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RowId {
    pub(super) log: Which,
    pub(super) counter: u64,
    pub(super) hash16: String,
}

pub(super) fn parse_id(id: &str) -> Option<RowId> {
    let (log, rest) = match id.strip_prefix('g') {
        Some(rest) => (Which::Governance, rest),
        None => (Which::Invocation, id),
    };
    let (counter, hash16) = rest.split_once('-')?;
    let counter = counter.parse().ok()?;
    let valid = hash16.len() == 16
        && hash16
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    valid.then(|| RowId {
        log,
        counter,
        hash16: hash16.to_string(),
    })
}

fn hash_of(entry: &Value, key: &str) -> Option<String> {
    entry.get(key).and_then(Value::as_str).map(str::to_string)
}

/// How a record links to the one before it: `verified` when the kept log
/// holds the predecessor, intact, and its hash is this record's
/// `prev_entry_hash`; `broken` when it does not match, is edited, or is
/// missing from the middle of the kept log; `first_in_kept_log` when this is
/// the oldest record kept. Every rotated segment opens with an open record numbered
/// just below its first listed row, so a listed row's predecessor is kept.
fn link(log: &Path, entry: &Value, reads: &mut Reads) -> std::io::Result<&'static str> {
    let prev = hash_of(entry, "prev_entry_hash");
    let counter = entry.get("counter").and_then(Value::as_u64).unwrap_or(0);
    if prev.as_deref() == Some("genesis") || counter < 2 {
        return Ok("first_in_kept_log");
    }
    Ok(match seek(log, counter - 1, reads)? {
        // The predecessor's own hash is recomputed: a stored hash says
        // nothing about fields edited beside it.
        Some(before) => {
            let stored = hash_of(&before.entry, "entry_hash");
            let intact = recompute_entry_hash(&before.entry).ok() == stored;
            if intact && stored == prev {
                "verified"
            } else {
                "broken"
            }
        }
        // Missing: the start of the kept log only if nothing older is kept;
        // a gap in the middle is a broken chain, not a retention boundary.
        None if oldest_counter(log, reads)? == Some(counter) => "first_in_kept_log",
        None => "broken",
    })
}

fn recorded(entry: &Value, key: &str) -> Value {
    match entry.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => json!({"recorded": true, "length": text.chars().count()}),
        _ => json!({"recorded": false}),
    }
}

/// What a receipt and an export row add to a list row: for a call, the
/// decision evidence (not recorded yet); for a config change, whether a
/// reason and a rollback summary were recorded, never their text.
pub(super) fn add_evidence(body: &mut Map<String, Value>, kind: Kind, e: &Value) {
    match kind {
        Kind::Config => {
            body.insert("reason".into(), recorded(e, "reason"));
            body.insert("rollback_summary".into(), recorded(e, "rollback_summary"));
        }
        Kind::Call => {
            body.insert("decision".into(), NOT_RECORDED.into());
            body.insert("reach".into(), NOT_RECORDED.into());
        }
        Kind::AdminAction => {}
    }
}

/// The receipt for `id`, or `None` (404) when the kept log does not hold it
/// or the caller may not read it.
pub(super) fn receipt(
    log: &Path,
    id: &RowId,
    access: &Access,
    secret: Option<&[u8]>,
) -> std::io::Result<Option<Value>> {
    let mut reads = Reads::default();
    let Some(found) = seek(log, id.counter, &mut reads)? else {
        return Ok(None);
    };
    let hash_matches = hash_of(&found.entry, "entry_hash")
        .and_then(|h| h.strip_prefix("sha256:").map(|h| h.starts_with(&id.hash16)))
        .unwrap_or(false);
    if !hash_matches {
        return Ok(None);
    }
    let line = Line {
        log: id.log,
        entry: found.entry,
        segment: found.segment,
    };
    let Some(kind) = kind_of(&line) else {
        return Ok(None);
    };
    if let Access::Own { issuer, subject } = access
        && !owned_by(&line, kind, issuer, subject)
    {
        return Ok(None);
    }
    let Some(Value::Object(mut body)) = row(&line, secret) else {
        return Ok(None);
    };
    let e = &line.entry;
    body.insert(
        "chain".into(),
        json!({
            "counter": e.get("counter"),
            "prev_entry_hash": e.get("prev_entry_hash"),
            "entry_hash": e.get("entry_hash"),
            "link": link(log, e, &mut reads)?,
        }),
    );
    add_evidence(&mut body, kind, e);
    Ok(Some(body.into()))
}

#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;
