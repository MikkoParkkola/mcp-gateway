// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The signing anchor, `<path>.sigstart`: where this log began signing, and
//! a digest of the bytes written before that, so a reader can tell a record
//! that predates signing from one whose signature was stripped later.
//!
//! The writer makes it once (first start, v3 migration, unanchored legacy)
//! or fails closed (`closed`) when the boundary was lost; it never moves.
//! Every reader loads it through [`load`] and places each unsigned record
//! with [`Anchor::place`].

use std::io;
use std::path::Path;

use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};

use super::segments::{self, sibling};
use super::{HmacSha256, sha256_raw, sig_message};

/// Bytes per digested chunk of a legacy file: a reader hashes only the
/// chunks a record's line touches, so its cost does not grow with the file.
pub(crate) const CHUNK: u64 = 1 << 20;

/// Whether signing has a known start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    /// Signing began at (`segment_seq`, `offset`).
    Open,
    /// The start was lost to tampering: no record is exempt.
    Closed,
}

/// One kept file below the anchor, frozen when the anchor was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyFile {
    pub(crate) seq: u64,
    /// Bytes digested: the whole file when sealed, the anchor's offset in
    /// the anchor's own file.
    pub(crate) len: u64,
    /// Hex sha256 of each [`CHUNK`] of `[0, len)`.
    pub(crate) chunks: Vec<String>,
}

/// The sidecar's body; the file is this plus `mac`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SigStart {
    /// For reports only: not covered by the MAC, so a crash before a new
    /// log id persists cannot break the sidecar. Binding to this log comes
    /// from `legacy`.
    pub(crate) log_id: String,
    pub(crate) state: State,
    pub(crate) segment_seq: u64,
    pub(crate) offset: u64,
    /// The chain counter at the anchor, for reports and verify.
    pub(crate) counter: u64,
    pub(crate) legacy: Vec<LegacyFile>,
    /// A v3 log whose head was trimmed: records below the anchor are shown
    /// with a flag, since nothing proves they predate signing.
    pub(crate) unanchored: bool,
    /// Its event record is written. `false` means the next open owes it.
    pub(crate) announced: bool,
}

#[derive(Serialize, Deserialize)]
struct OnDisk {
    #[serde(flatten)]
    body: SigStart,
    mac: String,
}

/// Why a sidecar cannot be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The MAC does not verify.
    Mac,
    /// It names an anchor past the first kept position without digesting
    /// every kept byte below it.
    Coverage,
    /// Not one parseable sidecar.
    Torn,
    /// It could not be read.
    Unreadable,
}

impl Fault {
    /// The report's name for it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Coverage => "coverage",
            Self::Torn => "torn",
            Self::Unreadable => "unreadable",
        }
    }
}

/// What a reader holds for one log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Anchor {
    /// No secret configured: signatures are not checked at all.
    NoSecret,
    /// A secret, and no sidecar.
    Absent,
    /// A verified sidecar.
    Known(SigStart),
    /// A sidecar that cannot be trusted.
    Broken(Fault),
}

impl Anchor {
    /// The log-wide report value.
    pub(crate) fn report(&self) -> &'static str {
        match self {
            Self::NoSecret => "no_secret",
            Self::Absent => "missing",
            Self::Known(s) if s.state == State::Closed => "closed",
            Self::Known(_) => "ok",
            Self::Broken(f) => f.as_str(),
        }
    }
}

fn mac(body: &SigStart, secret: &[u8], key_id: &str) -> io::Result<String> {
    let mut covered = serde_json::to_value(body).map_err(io::Error::other)?;
    if let Some(o) = covered.as_object_mut() {
        o.remove("log_id");
    }
    let canonical = serde_json::to_string(&covered).map_err(io::Error::other)?;
    let digest = sha256_raw(format!("sigstart|{canonical}").as_bytes());
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    m.update(&sig_message(&digest, key_id));
    Ok(hex::encode(m.finalize().into_bytes()))
}

/// The sidecar's bytes for `body`: one JSON line carrying its MAC.
pub(crate) fn encode(body: &SigStart, secret: &[u8], key_id: &str) -> io::Result<Vec<u8>> {
    let file = OnDisk {
        body: body.clone(),
        mac: mac(body, secret, key_id)?,
    };
    let mut out = serde_json::to_vec(&file).map_err(io::Error::other)?;
    out.push(b'\n');
    Ok(out)
}

/// Parse and verify sidecar bytes (coverage is checked by [`load`]).
pub(crate) fn decode(raw: &[u8], secret: &[u8], key_id: &str) -> Result<SigStart, Fault> {
    let text = std::str::from_utf8(raw).map_err(|_| Fault::Torn)?;
    let line = text.strip_suffix('\n').ok_or(Fault::Torn)?;
    if line.contains('\n') {
        return Err(Fault::Torn);
    }
    let file: OnDisk = serde_json::from_str(line).map_err(|_| Fault::Torn)?;
    let want = mac(&file.body, secret, key_id).map_err(|_| Fault::Torn)?;
    let ok: bool = subtle::ConstantTimeEq::ct_eq(want.as_bytes(), file.mac.as_bytes()).into();
    if ok { Ok(file.body) } else { Err(Fault::Mac) }
}

/// The anchor of the log at `path`, as a reader sees it.
pub(crate) fn load(path: &Path, secret: Option<&[u8]>, key_id: &str) -> Anchor {
    let Some(secret) = secret.filter(|s| !s.is_empty()) else {
        return Anchor::NoSecret;
    };
    let raw = match std::fs::read(sibling(path, "sigstart")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Anchor::Absent,
        Err(_) => return Anchor::Broken(Fault::Unreadable),
    };
    match decode(&raw, secret, key_id) {
        Ok(body) if covers(path, &body) => Anchor::Known(body),
        Ok(_) => Anchor::Broken(Fault::Coverage),
        Err(f) => Anchor::Broken(f),
    }
}

/// Where a line sits: its file's segment number and its byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinePos {
    /// A line read from the log.
    At { segment: u64, offset: u64, len: u64 },
    /// A record the writer just announced: after every anchor.
    Newest,
}

/// What a reader says about an unsigned record whose hash recomputes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placed {
    /// Written before signing began; `unanchored` when nothing proves it.
    Legacy { unanchored: bool },
    /// Not exempt: the reason the exports name.
    Invalid(&'static str),
}

/// Per-request memory of chunks already hashed, so a page of records in one
/// chunk hashes it once.
#[derive(Debug, Default)]
pub(crate) struct Checked(std::collections::HashMap<(u64, u64), bool>);

/// The kept files of `path` as (seq, file): sealed segments, then the active one.
fn kept(path: &Path) -> io::Result<Vec<(u64, std::path::PathBuf)>> {
    let sealed = segments::list_segments(path)?;
    let after = sealed.last().map_or(0, |s| s.seq + 1);
    let mut out: Vec<_> = sealed.into_iter().map(|s| (s.seq, s.path)).collect();
    if path.exists() {
        out.push((
            segments::active_segment_seq(path, after),
            path.to_path_buf(),
        ));
    }
    Ok(out)
}

/// Every kept byte below an `open` anchor is digested (lead condition on
/// round 3 J4): without it, a sidecar from another log, or one stripped of
/// its digests, would exempt this log's records.
fn covers(path: &Path, body: &SigStart) -> bool {
    if body.state == State::Closed {
        return true;
    }
    let Ok(files) = kept(path) else {
        return false;
    };
    let listed = |seq: u64| body.legacy.iter().find(|l| l.seq == seq);
    files.iter().all(|(seq, _)| {
        if *seq < body.segment_seq {
            listed(*seq).is_some()
        } else if *seq == body.segment_seq && body.offset > 0 {
            listed(*seq).is_some_and(|l| l.len == body.offset)
        } else {
            true
        }
    }) && body
        .legacy
        .iter()
        .all(|l| l.chunks.len() as u64 == l.len.div_ceil(CHUNK))
}

/// The file holding segment `seq` of `path`: sealed, else the active file.
fn file_of(path: &Path, seq: u64) -> std::path::PathBuf {
    let sealed = segments::sealed_path(path, seq);
    if sealed.exists() {
        sealed
    } else {
        path.to_path_buf()
    }
}

/// Hex sha256 of `file`'s bytes `[start, end)`, or `None` when unreadable.
fn digest(file: &Path, start: u64, end: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(file).ok()?;
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity(usize::try_from(end - start).ok()?);
    f.take(end - start).read_to_end(&mut buf).ok()?;
    (buf.len() as u64 == end - start).then(|| hex::encode(sha256_raw(&buf)))
}

impl Anchor {
    /// Place an unsigned record of the log at `path`.
    pub(crate) fn place(&self, path: &Path, pos: LinePos, checked: &mut Checked) -> Placed {
        let body = match self {
            Self::NoSecret => return Placed::Legacy { unanchored: false },
            Self::Absent => return Placed::Invalid("sigstart_missing"),
            Self::Broken(f) => return Placed::Invalid(broken_reason(*f)),
            Self::Known(b) if b.state == State::Closed => return Placed::Invalid("sig_missing"),
            Self::Known(b) => b,
        };
        let LinePos::At {
            segment,
            offset,
            len,
        } = pos
        else {
            return Placed::Invalid("sig_missing");
        };
        if (segment, offset) >= (body.segment_seq, body.offset) {
            return Placed::Invalid("sig_missing");
        }
        let Some(frozen) = body.legacy.iter().find(|l| l.seq == segment) else {
            return Placed::Invalid("legacy_unlisted");
        };
        if offset + len > frozen.len {
            return Placed::Invalid("legacy_unlisted");
        }
        let file = file_of(path, segment);
        if segment != body.segment_seq
            && std::fs::metadata(&file).map(|m| m.len()).ok() != Some(frozen.len)
        {
            return Placed::Invalid("legacy_edited");
        }
        let last = (offset + len).saturating_sub(1) / CHUNK;
        for chunk in offset / CHUNK..=last {
            let ok = *checked.0.entry((segment, chunk)).or_insert_with(|| {
                let start = chunk * CHUNK;
                let end = (start + CHUNK).min(frozen.len);
                usize::try_from(chunk)
                    .ok()
                    .and_then(|i| frozen.chunks.get(i))
                    .is_some_and(|want| digest(&file, start, end).as_deref() == Some(want))
            });
            if !ok {
                return Placed::Invalid("legacy_edited");
            }
        }
        Placed::Legacy {
            unanchored: body.unanchored,
        }
    }
}

fn broken_reason(f: Fault) -> &'static str {
    match f {
        Fault::Mac => "sigstart_mac",
        Fault::Coverage => "sigstart_coverage",
        Fault::Torn => "sigstart_torn",
        Fault::Unreadable => "sigstart_unreadable",
    }
}

// ── Writer ───────────────────────────────────────────────────────────────────

/// The first verified signed record of a log: where it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FirstSigned {
    pub(super) segment: u64,
    pub(super) offset: u64,
    pub(super) counter: u64,
}

/// What an open does about the sidecar, decided before tail repair writes
/// anything (round 3 J5), so a record the repair signs cannot change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Plan {
    /// No secret, or a verified sidecar whose event is already written.
    Nothing,
    /// A verified sidecar whose event a crash left unwritten.
    Owed(SigStart),
    /// A sidecar that does not verify: keep it, raise the invalid record.
    Raise(Fault),
    /// The boundary is lost: write `closed`, owe the rebuilt record.
    Rebuild { signed_found: bool },
    /// A v3.5.1 log from genesis: anchor at its first signed record.
    Migrate(FirstSigned),
    /// A v3 log with a trimmed head: anchor at its first surviving signed
    /// record, flagged.
    Unanchored(FirstSigned),
    /// No signing history: anchor at the end, no event.
    FirstStart,
}

/// Parsed lines of `file` with their offsets and lengths (newline included).
fn lines_of(file: &Path) -> io::Result<Vec<(u64, u64, serde_json::Value)>> {
    use std::io::BufRead;
    let mut r = io::BufReader::new(std::fs::File::open(file)?);
    let (mut at, mut out, mut buf) = (0u64, Vec::new(), Vec::new());
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf)? as u64;
        if n == 0 {
            return Ok(out);
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&buf) {
            out.push((at, n, v));
        }
        at += n;
    }
}

/// The first record of the kept files whose hash recomputes and whose HMAC
/// verifies under `secret`.
pub(super) fn first_signed(path: &Path, secret: &[u8]) -> io::Result<Option<FirstSigned>> {
    for (segment, file) in kept(path)? {
        for (offset, _, v) in lines_of(&file)? {
            let Some(stored) = v.get("entry_hash").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let intact = super::recompute_entry_hash(&v).is_ok_and(|h| h == stored);
            if intact
                && super::verify::is_signed_entry(&v)
                && super::verify_entry_sig(&v, stored, secret).is_ok()
            {
                let counter = v
                    .get("counter")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                return Ok(Some(FirstSigned {
                    segment,
                    offset,
                    counter,
                }));
            }
        }
    }
    Ok(None)
}

/// A v3.5.1 log's first record: counter 1 chained from "genesis".
fn starts_at_genesis(path: &Path) -> io::Result<bool> {
    Ok(segments::read_first_line(path)?
        .and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .is_some_and(|v| v["counter"] == 1 && v["prev_entry_hash"] == "genesis"))
}

/// Decide the plan. `identified`: the log holds an identity or open record.
pub(super) fn classify(
    path: &Path,
    secret: &[u8],
    key_id: &str,
    identified: bool,
) -> io::Result<Plan> {
    if secret.is_empty() {
        return Ok(Plan::Nothing);
    }
    match load(path, Some(secret), key_id) {
        Anchor::Known(s) if s.announced => return Ok(Plan::Nothing),
        Anchor::Known(s) => return Ok(Plan::Owed(s)),
        Anchor::Broken(f) => return Ok(Plan::Raise(f)),
        Anchor::NoSecret | Anchor::Absent => {}
    }
    let found = first_signed(path, secret)?;
    let hwm = std::fs::read(sibling(path, "hwm")).ok();
    let keyed_hwm = hwm
        .as_deref()
        .and_then(|raw| segments::parse_hwm(raw, secret, key_id))
        .is_some_and(|(_, has_mac)| has_mac);
    let sealed = !segments::list_segments(path)?.is_empty();
    // v3.5.1 signed but wrote no `.hwm`, no identity record, no segments.
    let v3_shape = !identified && hwm.is_none() && !sealed;
    Ok(match found {
        Some(first) if v3_shape && starts_at_genesis(path)? => Plan::Migrate(first),
        Some(first) if v3_shape => Plan::Unanchored(first),
        Some(_) => Plan::Rebuild { signed_found: true },
        None if keyed_hwm => Plan::Rebuild {
            signed_found: false,
        },
        None => Plan::FirstStart,
    })
}

/// Hex sha256 of each [`CHUNK`] of `file`'s first `len` bytes.
fn chunks_of(file: &Path, len: u64) -> io::Result<Vec<String>> {
    (0..len.div_ceil(CHUNK))
        .map(|i| {
            let start = i * CHUNK;
            digest(file, start, (start + CHUNK).min(len)).ok_or_else(|| {
                io::Error::other(format!(
                    "audit log: {} shrank while digested",
                    file.display()
                ))
            })
        })
        .collect()
}

/// Freeze every kept file below (`seq`, `offset`).
pub(super) fn legacy_below(path: &Path, seq: u64, offset: u64) -> io::Result<Vec<LegacyFile>> {
    let mut out = Vec::new();
    for (s, file) in kept(path)? {
        let len = match s.cmp(&seq) {
            std::cmp::Ordering::Less => std::fs::metadata(&file)?.len(),
            std::cmp::Ordering::Equal if offset > 0 => offset,
            _ => continue,
        };
        out.push(LegacyFile {
            seq: s,
            len,
            chunks: chunks_of(&file, len)?,
        });
    }
    Ok(out)
}

/// The end of the log as a position: the active file's seq and length, or
/// the seq a new active file gets when there is none.
pub(super) fn end_of(path: &Path) -> io::Result<(u64, u64)> {
    let sealed = segments::list_segments(path)?;
    let next = segments::next_seq(&sealed)?;
    match std::fs::metadata(path) {
        Ok(m) if m.len() > 0 => Ok((segments::active_segment_seq(path, next), m.len())),
        Ok(_) => Ok((next, 0)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((next, 0)),
        Err(e) => Err(e),
    }
}

/// The sidecar a plan writes, or `None` when it writes none.
pub(super) fn body_for(plan: &Plan, path: &Path, log_id: &str) -> io::Result<Option<SigStart>> {
    let open = |seq, offset, counter, unanchored, announced| -> io::Result<SigStart> {
        Ok(SigStart {
            log_id: log_id.to_string(),
            state: State::Open,
            segment_seq: seq,
            offset,
            counter,
            legacy: legacy_below(path, seq, offset)?,
            unanchored,
            announced,
        })
    };
    Ok(match plan {
        Plan::Nothing | Plan::Owed(_) | Plan::Raise(_) => None,
        Plan::Rebuild { .. } => Some(SigStart {
            log_id: log_id.to_string(),
            state: State::Closed,
            segment_seq: 0,
            offset: 0,
            counter: 0,
            legacy: Vec::new(),
            unanchored: false,
            announced: false,
        }),
        Plan::Migrate(f) => Some(open(f.segment, f.offset, f.counter, false, false)?),
        Plan::Unanchored(f) => Some(open(f.segment, f.offset, f.counter, true, false)?),
        Plan::FirstStart => {
            let (seq, offset) = end_of(path)?;
            Some(open(seq, offset, 0, false, true)?)
        }
    })
}

/// Publish `body` as the sidecar: a temp file, synced, renamed over, the
/// directory synced. Rust opens files on Windows with delete sharing, so a
/// reader holding the old file does not block the rename.
pub(super) fn publish(path: &Path, body: &SigStart, secret: &[u8], key_id: &str) -> io::Result<()> {
    use std::io::Write;
    let bytes = encode(body, secret, key_id)?;
    let tmp = sibling(path, "sigstart.tmp");
    let mut f = std::fs::File::create(&tmp).map_err(segments::ctx("create", &tmp))?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    let to = sibling(path, "sigstart");
    std::fs::rename(&tmp, &to).map_err(segments::ctx("rename", &to))?;
    segments::sync_dir(path)
}

/// The record an owed event writes, and its metric's name.
pub(super) fn event_of(
    body: &SigStart,
    signed_found: Option<bool>,
) -> (
    &'static str,
    Vec<(&'static str, serde_json::Value)>,
    &'static str,
) {
    let at = vec![
        ("segment_seq", body.segment_seq.into()),
        ("offset", body.offset.into()),
        ("counter", body.counter.into()),
    ];
    match (body.state, body.unanchored) {
        (State::Closed, _) => (
            EV_REBUILT,
            vec![("signed_found", signed_found.unwrap_or(true).into())],
            "mcp_audit_sigstart_rebuilt_total",
        ),
        (State::Open, true) => (EV_UNANCHORED, at, "mcp_audit_sigstart_unanchored_total"),
        (State::Open, false) => (EV_MIGRATED, at, "mcp_audit_sigstart_migrated_total"),
    }
}

/// Housekeeping events, named under the segment prefix so callers cannot
/// write them (round 2 HI2).
pub(crate) const EV_REBUILT: &str = "audit_segment_sigstart_rebuilt";
pub(crate) const EV_MIGRATED: &str = "audit_segment_sigstart_migrated";
pub(crate) const EV_UNANCHORED: &str = "audit_segment_sigstart_unanchored";
pub(crate) const EV_INVALID: &str = "audit_segment_sigstart_invalid";

/// The announce phase, after segment recovery (round 3 J3): write the
/// record the plan owes through `write`, then mark the sidecar announced.
/// A crash between leaves `announced: false`, so the next open retries; a
/// duplicate record is allowed.
pub(super) fn announce(
    plan: &Plan,
    written: Option<&SigStart>,
    path: &Path,
    secret: &[u8],
    key_id: &str,
    mut write: impl FnMut(&str, Vec<(&'static str, serde_json::Value)>) -> io::Result<()>,
) -> io::Result<()> {
    if let Plan::Raise(f) = plan {
        tracing::warn!(
            fault = f.as_str(),
            "audit log: signing anchor does not verify; kept as evidence"
        );
        telemetry_metrics::counter!("mcp_audit_sigstart_invalid_total").increment(1);
        return write(EV_INVALID, vec![("fault", f.as_str().into())]);
    }
    let signed_found = match plan {
        Plan::Rebuild { signed_found } => Some(*signed_found),
        _ => None,
    };
    let owed = match (plan, written) {
        (Plan::Owed(s), _) => s,
        (_, Some(s)) if !s.announced => s,
        _ => return Ok(()),
    };
    let (event, fields, metric) = event_of(owed, signed_found);
    tracing::warn!(event, "audit log: signing anchor set");
    telemetry_metrics::counter!(metric).increment(1);
    write(event, fields)?;
    let mut done = owed.clone();
    done.announced = true;
    publish(path, &done, secret, key_id)
}
