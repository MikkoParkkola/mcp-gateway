// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity export: the list's rows under the same filters and access,
//! as NDJSON closed by a signed manifest, or as CSV closed by an `#end` line.
//! Both stop at the first cap reached and say which, so a cut file never
//! reads as a whole one.

use std::path::Path;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::access::Access;
use super::csv::{Cell, CsvWriter, Truncated};
use super::reader::{Cursor, Limits, Line, Which, read_page};
use super::rows::{Check, Filter, Kind, kind_of, row};
use crate::trust::provenance_public::{ACTIVITY_EXPORT_DOMAIN, ProvenancePublicSigner};

/// The caps, whichever comes first.
#[derive(Debug, Clone, Copy)]
pub(super) struct Caps {
    pub(super) rows: usize,
    pub(super) bytes: usize,
    pub(super) scan: u64,
}

pub(super) const CAPS: Caps = Caps {
    rows: 10_000,
    bytes: 64 << 20,
    scan: 512 << 20,
};

/// Room kept inside the byte cap for the NDJSON manifest line, so the whole
/// download stays within the cap.
pub(super) const MANIFEST_RESERVE: usize = 4096;

/// Room kept inside the byte cap for the CSV header and `#end` line.
pub(super) fn csv_framing() -> usize {
    // The longest `#end` line: a row count of the cap's width, the longest state.
    CsvWriter::new(&COLUMNS).finish(Truncated::Bytes).len() + CAPS.rows.to_string().len()
}

/// Rows read per pass over the logs, so memory stays bounded by one pass.
const PASS: usize = 100;

/// One exported row: the list row plus the entry's own chain and HMAC fields,
/// and why its integrity failed, when it did.
fn export_row(line: &Line, kind: Kind, check: &Check<'_>) -> Option<Value> {
    // The list row already names why integrity failed, when it did.
    let Value::Object(mut r) = row(line, check)? else {
        return None;
    };
    let e = &line.entry;
    for key in ["sig", "key_id"] {
        if let Some(v) = e.get(key) {
            r.insert(key.into(), v.clone());
        }
    }
    super::receipt::add_evidence(&mut r, kind, e);
    Some(Value::Object(r))
}

/// The rows an export holds, and why it stopped.
pub(super) struct Collected {
    pub(super) rows: Vec<Value>,
    /// The log each row came from, in step with `rows`.
    pub(super) sources: Vec<Which>,
    /// Lines examined that could not be read, and matched records that could
    /// not be projected: named in the signed manifest, never dropped silently.
    pub(super) unreadable: usize,
    pub(super) truncated: Truncated,
    /// Each log's anchor state (invocation, governance), reported even when
    /// no row fails, so a broken anchor is never a clean-looking export.
    pub(super) signing_anchor: [&'static str; 2],
}

/// Read matching rows newest first until a cap. `size` is a row's encoded
/// size in the output format, so the byte cap applies to what is written.
pub(super) fn collect(
    inv: &Path,
    gov: Option<&Path>,
    filter: &Filter,
    access: &Access,
    check: &Check<'_>,
    caps: Caps,
    size: impl Fn(&Value) -> usize,
) -> std::io::Result<Collected> {
    let keep = |line: &Line| {
        kind_of(line).is_some_and(|kind| filter.matches(line, kind) && access.admits(line, kind))
    };
    let mut c = Collected {
        rows: Vec::new(),
        sources: Vec::new(),
        unreadable: 0,
        truncated: Truncated::None,
        signing_anchor: [Which::Invocation, Which::Governance].map(|w| check.report(w)),
    };
    // The report is taken when the export ends, after every row was judged,
    // so a legacy fault a row met is in it.
    let done = |mut c: Collected, truncated| {
        c.truncated = truncated;
        c.signing_anchor = [Which::Invocation, Which::Governance].map(|w| check.report(w));
        Ok(c)
    };
    let mut bytes = 0_usize;
    let mut scanned = 0_u64;
    let mut cursor: Option<Cursor> = None;
    loop {
        let limits = Limits {
            matches: PASS,
            bytes: caps.scan.saturating_sub(scanned),
        };
        let page = read_page(inv, gov, cursor.as_ref(), limits, keep)?;
        // A pass after the first that restarted (retention removed the
        // segment the export was in) would append newer rows to older ones.
        if cursor.is_some() && page.cursor_reset {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "the log rotated past this export while it ran",
            ));
        }
        scanned += page.bytes_examined;
        c.unreadable += page.unreadable.len();
        for line in &page.lines {
            let Some(kind) = kind_of(line) else { continue };
            // A matched record that cannot be projected (no counter or hash)
            // is counted, never dropped silently.
            let Some(r) = export_row(line, kind, check) else {
                c.unreadable += 1;
                continue;
            };
            if c.rows.len() == caps.rows {
                return done(c, Truncated::Rows);
            }
            let n = size(&r);
            if bytes + n > caps.bytes {
                return done(c, Truncated::Bytes);
            }
            bytes += n;
            c.rows.push(r);
            c.sources.push(line.log);
        }
        #[cfg(test)]
        tests::between_passes();
        match page.next {
            None => return done(c, Truncated::None),
            // The page stopped on the scan budget that was left: the cap.
            Some(_) if page.scan_exhausted => return done(c, Truncated::Scan),
            Some(next) => cursor = Some(next),
        }
    }
}

/// The NDJSON size of a row: its JSON and a newline.
pub(super) fn ndjson_size(row: &Value) -> usize {
    row.to_string().len() + 1
}

/// The signed NDJSON export: one row per line, then the manifest. The
/// manifest's signature covers its canonical JSON (RFC 8785) without the
/// signature member, and the manifest names the SHA-256 of every byte before
/// it, so a changed row, a changed manifest field or a removed manifest each
/// fail the offline check.
pub(super) fn ndjson(
    collected: &Collected,
    filters: Value,
    signer: &ProvenancePublicSigner,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut integrity_failed = 0_usize;
    for r in &collected.rows {
        if r.get("integrity").is_some() {
            integrity_failed += 1;
        }
        bytes.extend_from_slice(r.to_string().as_bytes());
        bytes.push(b'\n');
    }
    // By source log, not by row kind: an admin action can sit in either.
    let counters = |log: Which| -> Value {
        let mut it = collected
            .rows
            .iter()
            .zip(&collected.sources)
            .filter(|(_, source)| **source == log)
            .filter_map(|(r, _)| r["counter"].as_u64());
        match (it.next(), it.next_back()) {
            (Some(newest), Some(oldest)) => json!([oldest, newest]),
            (Some(only), None) => json!([only, only]),
            _ => Value::Null,
        }
    };
    let mut manifest = Map::new();
    manifest.insert("kind".into(), "manifest".into());
    manifest.insert("rows".into(), collected.rows.len().into());
    manifest.insert("filters".into(), filters);
    manifest.insert(
        "counters".into(),
        json!({"invocation": counters(Which::Invocation), "governance": counters(Which::Governance)}),
    );
    manifest.insert("integrity_failed".into(), integrity_failed.into());
    let [inv, gov] = collected.signing_anchor;
    manifest.insert(
        "signing_anchor".into(),
        json!({"invocation": inv, "governance": gov}),
    );
    let faults = [inv, gov]
        .iter()
        .filter(|a| !matches!(**a, "ok" | "no_secret" | "none"))
        .count();
    manifest.insert("anchor_faults".into(), faults.into());
    manifest.insert("unreadable".into(), collected.unreadable.into());
    manifest.insert("truncated".into(), collected.truncated.as_str().into());
    manifest.insert("sha256".into(), hex::encode(Sha256::digest(&bytes)).into());
    manifest.insert("kid".into(), signer.kid().into());
    let canonical = serde_json_canonicalizer::to_vec(&Value::Object(manifest.clone()))
        // invariant: the manifest holds only strings, integers and objects of them, which RFC 8785 always canonicalises.
        .expect("a manifest of JSON values canonicalises");
    manifest.insert(
        "public_signature".into(),
        signer.sign_bytes(ACTIVITY_EXPORT_DOMAIN, &canonical).into(),
    );
    bytes.extend_from_slice(Value::Object(manifest).to_string().as_bytes());
    bytes.push(b'\n');
    bytes
}

/// The CSV columns, in order.
const COLUMNS: [&str; 32] = [
    "id",
    "kind",
    "counter",
    "timestamp",
    "outcome",
    "error_code",
    "server",
    "tool",
    "route",
    "trace_id",
    "request_hash",
    "response_hash",
    "who_credential_kind",
    "who_account",
    "who_authority",
    "who_subject",
    "action",
    "actor_id",
    "target_id",
    "surface",
    "method",
    "http_status",
    "signature",
    "integrity",
    // A legacy record nothing anchors.
    "unanchored",
    "prev_entry_hash",
    "entry_hash",
    "sig",
    "key_id",
    "decision",
    "reach",
    "findings",
    "findings_truncated",
];

fn cell_value<'a>(row: &'a Value, column: &str) -> Option<&'a Value> {
    match column.strip_prefix("who_") {
        Some(field) => row.get("who")?.get(field),
        None => row.get(column),
    }
}

fn cells(row: &Value) -> Vec<String> {
    COLUMNS
        .iter()
        .map(|c| match cell_value(row, c) {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        })
        .collect()
}

/// The CSV size of a row, for the byte cap: a file with the row, less the
/// same file without it.
pub(super) fn csv_size(row: &Value) -> usize {
    let empty = CsvWriter::new(&[]).finish(Truncated::None).len();
    let mut w = CsvWriter::new(&[]);
    push_row(&mut w, row);
    w.finish(Truncated::None).len() - empty
}

fn push_row(w: &mut CsvWriter, row: &Value) {
    let text = cells(row);
    let typed: Vec<Cell<'_>> = COLUMNS
        .iter()
        .zip(&text)
        .map(|(c, t)| match cell_value(row, c) {
            Some(Value::Number(n)) if n.is_i64() => Cell::Int(n.as_i64().unwrap_or_default()),
            Some(Value::Number(n)) if n.is_u64() => {
                Cell::Int(i64::try_from(n.as_u64().unwrap_or_default()).unwrap_or(i64::MAX))
            }
            Some(Value::Number(n)) => Cell::Float(n.as_f64().unwrap_or_default()),
            _ => Cell::Text(t),
        })
        .collect();
    w.row(&typed);
}

/// The CSV export: the same rows and columns, unsigned, ending in `#end`.
pub(super) fn csv(collected: &Collected) -> String {
    let mut w = CsvWriter::new(&COLUMNS);
    for r in &collected.rows {
        push_row(&mut w, r);
    }
    w.finish(collected.truncated)
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
