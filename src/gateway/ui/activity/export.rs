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
use super::rows::{Filter, Kind, kind_of, owned_by, row};
use crate::security::transparency_log::recompute_entry_hash;
use crate::security::transparency_log::signature::{SignatureState, signature_state};
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

/// Rows read per pass over the logs, so memory stays bounded by one pass.
const PASS: usize = 100;

/// One exported row: the list row plus the entry's own chain and HMAC fields,
/// and why its integrity failed, when it did.
fn export_row(line: &Line, kind: Kind, secret: Option<&[u8]>) -> Option<Value> {
    let Value::Object(mut r) = row(line, secret)? else {
        return None;
    };
    let e = &line.entry;
    for key in ["sig", "key_id"] {
        if let Some(v) = e.get(key) {
            r.insert(key.into(), v.clone());
        }
    }
    let stored = e.get("entry_hash").and_then(Value::as_str);
    let hash_ok = recompute_entry_hash(e).is_ok_and(|h| Some(h.as_str()) == stored);
    if !hash_ok {
        r.insert("integrity".into(), "hash_failed".into());
    } else if signature_state(e, secret) == SignatureState::Invalid {
        r.insert("integrity".into(), "sig_failed".into());
    }
    super::receipt::add_evidence(&mut r, kind, e);
    Some(Value::Object(r))
}

/// The rows an export holds, and why it stopped.
pub(super) struct Collected {
    pub(super) rows: Vec<Value>,
    /// The log each row came from, in step with `rows`.
    pub(super) sources: Vec<Which>,
    pub(super) truncated: Truncated,
}

/// Read matching rows newest first until a cap. `size` is a row's encoded
/// size in the output format, so the byte cap applies to what is written.
pub(super) fn collect(
    inv: &Path,
    gov: Option<&Path>,
    filter: &Filter,
    access: &Access,
    secret: Option<&[u8]>,
    caps: Caps,
    size: impl Fn(&Value) -> usize,
) -> std::io::Result<Collected> {
    let keep = |line: &Line| {
        kind_of(line).is_some_and(|kind| {
            filter.matches(line, kind)
                && match access {
                    Access::All => true,
                    Access::Own { issuer, subject } => owned_by(line, kind, issuer, subject),
                }
        })
    };
    let mut rows = Vec::new();
    let mut sources = Vec::new();
    let mut bytes = 0_usize;
    let mut scanned = 0_u64;
    let mut cursor: Option<Cursor> = None;
    loop {
        let limits = Limits {
            matches: PASS,
            bytes: caps.scan.saturating_sub(scanned),
        };
        let page = read_page(inv, gov, cursor.as_ref(), limits, keep)?;
        scanned += page.bytes_examined;
        for line in &page.lines {
            let Some(kind) = kind_of(line) else { continue };
            let Some(r) = export_row(line, kind, secret) else {
                continue;
            };
            if rows.len() == caps.rows {
                return Ok(Collected {
                    rows,
                    sources,
                    truncated: Truncated::Rows,
                });
            }
            let n = size(&r);
            if bytes + n > caps.bytes {
                return Ok(Collected {
                    rows,
                    sources,
                    truncated: Truncated::Bytes,
                });
            }
            bytes += n;
            rows.push(r);
            sources.push(line.log);
        }
        match page.next {
            None => {
                return Ok(Collected {
                    rows,
                    sources,
                    truncated: Truncated::None,
                });
            }
            // The page stopped on the scan budget that was left: the cap.
            Some(_) if page.scan_exhausted => {
                return Ok(Collected {
                    rows,
                    sources,
                    truncated: Truncated::Scan,
                });
            }
            Some(next) => cursor = Some(next),
        }
    }
}

fn truncated_str(t: Truncated) -> &'static str {
    match t {
        Truncated::None => "none",
        Truncated::Rows => "rows",
        Truncated::Bytes => "bytes",
        Truncated::Scan => "scan",
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
    manifest.insert(
        "truncated".into(),
        truncated_str(collected.truncated).into(),
    );
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
const COLUMNS: [&str; 31] = [
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
    "prev_entry_hash",
    "entry_hash",
    "sig",
    "key_id",
    "decision",
    "reach",
    "findings",
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
