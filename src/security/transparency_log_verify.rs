// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Chain verification across sealed segments and the active file (D6 2.5),
//! and the readers that follow segments (session lookup, signed-entry scan).
//!
//! Each file is read through the existing 256 MiB bound, one at a time. The
//! per-entry checks (counter + 1, `prev_entry_hash`, recomputed hash, HMAC)
//! run unchanged across the seams; the seam checks sit on top.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::anchor::succ;
use super::rotation::{
    EV_EXPIRED, EV_HWM_MISSING, EV_OPENED, EV_SEALED, EV_TORN, HWM_MISSING_AT, TORN_COMMITTED,
};
use super::segments::{self, HighWater};

// The session reader, which shares this file's listing and test hooks.
#[path = "transparency_log_session.rs"]
mod session;
// The per-record checks a verify pass runs, beside the stream that drives them.
#[path = "transparency_log_checks.rs"]
mod checks;
use super::{MAX_AUDIT_READ_BYTES, TransparencyLogConfig, bounded_read_to_string};
pub use session::show_session_entries;

/// Result of a chain-integrity verification pass.
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// `true` when every entry in the log passed all checks. Without a
    /// secret those checks are hash-only: a caller verifying without the key
    /// must also refuse on [`Self::signed_entry_seen`].
    pub ok: bool,
    /// Number of entries checked.
    pub entries_checked: usize,
    /// Counter of the first invalid entry (`None` when `ok == true`).
    pub error_at_counter: Option<u64>,
    /// Human-readable description of the first failure.
    pub error_message: Option<String>,
    /// Files streamed: sealed segments plus the active file.
    pub segments_checked: usize,
    /// Segments deleted by retention and anchored by an expiry record.
    pub segments_expired: usize,
    /// Findings that do not fail the verdict (archive mode, a trailing seal).
    pub warnings: Vec<String>,
    /// An entry this pass parsed carried a signature (any `sig` key). Set
    /// before an entry is checked, so a returned result whose chain failed
    /// still reports it (a read error returns no result at all): a caller
    /// verifying without the key refuses on it, whatever another, earlier
    /// read of the log found.
    pub signed_entry_seen: bool,
}

/// Whether tail completeness is checked against `<path>.hwm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// The live log: a missing, torn or lower `.hwm` fails.
    Live,
    /// A copied set (`audit verify --archive`): tail completeness is reported
    /// as unchecked; every chain, seam and expiry check still fails as usual.
    Archive,
}

/// Verify the hash chain across every segment (no HMAC check), live mode.
///
/// Does **not** authenticate the per-entry HMAC `sig`; use
/// [`verify_log_signed`] when a shared secret is configured (MIK-6700).
/// [`VerifyResult::signed_entry_seen`] says whether it skipped any.
///
/// # Errors
///
/// A segment cannot be read, or an entry is not valid JSON.
pub fn verify_log(path: &Path) -> io::Result<VerifyResult> {
    verify_segments(path, &TransparencyLogConfig::default(), VerifyMode::Live)
}

/// As [`verify_log`], also authenticating each `sig` (and the `.hwm` MAC)
/// when `config` has a non-empty `shared_secret` (MIK-6700 HMAC.1).
///
/// # Errors
///
/// A segment cannot be read, or an entry is not valid JSON.
pub fn verify_log_signed(path: &Path, config: &TransparencyLogConfig) -> io::Result<VerifyResult> {
    verify_segments(path, config, VerifyMode::Live)
}

/// Every file of the log, oldest first: sealed segments, then the active
/// file when present, each with the segment number it should hold.
fn log_files(path: &Path) -> io::Result<Vec<(Option<u64>, PathBuf)>> {
    let sealed = segments::list_segments(path)?;
    let mut files: Vec<(Option<u64>, PathBuf)> =
        sealed.into_iter().map(|s| (Some(s.seq), s.path)).collect();
    if path.exists() {
        files.push((None, path.to_path_buf()));
    }
    Ok(files)
}

/// Whether `entry` is signed: it carries a `sig` field, whatever its value.
/// Presence, not a valid-looking value, so a null, empty or garbled `sig`
/// still counts and cannot downgrade a signed log to hash-only. The one rule
/// `audit verify` and SIEM export share for refusing a signed log they hold
/// no key for (MIK-8374).
pub(crate) fn is_signed_entry(entry: &Value) -> bool {
    entry.get("sig").is_some()
}

/// Whether any segment of the log holds a signed entry, so `audit verify`
/// refuses a silent hash-only pass over a signed log (MIK-6700 review).
/// A rotation mid-scan can move a segment out from under both its listed
/// names, so "none signed" stands only over a listing that held still; a
/// changed listing, or a listed file gone, reads once more, as the session
/// reader does.
///
/// # Errors
///
/// A segment cannot be read, or the log rotated under both reads.
pub fn log_contains_signed_entry(path: &Path) -> io::Result<bool> {
    let mut attempt = 0;
    loop {
        let files = log_files(path)?;
        #[cfg(test)]
        fire(&LISTED);
        let read = holds_signed_entry(&files);
        let stable = seqs(&files) == seqs(&log_files(path)?);
        match read {
            // A signed entry read is signed, whatever moved since.
            Ok(true) => return Ok(true),
            Ok(false) if stable => return Ok(false),
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        if attempt == 1 {
            return Err(changed_under_reader("signed-entry scan"));
        }
        attempt += 1;
    }
}

/// Whether any of `files` holds a signed entry.
fn holds_signed_entry(files: &[(Option<u64>, PathBuf)]) -> io::Result<bool> {
    for (_, file) in files {
        let content = bounded_read_to_string(file, MAX_AUDIT_READ_BYTES)?;
        let signed = content.lines().any(|raw| {
            serde_json::from_str::<Value>(raw.trim()).is_ok_and(|e| is_signed_entry(&e))
        });
        if signed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The segment numbers a listing names, oldest first.
fn seqs(files: &[(Option<u64>, PathBuf)]) -> Vec<Option<u64>> {
    files.iter().map(|(s, _)| *s).collect()
}

/// A log that rotated under a reader twice in a row: busy, retry.
fn changed_under_reader(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        format!("log changed during {what} (a live rotation); retry"),
    )
}

/// The log's files, or `NotFound` when there is nothing to read at all.
fn existing_log_files(path: &Path) -> io::Result<Vec<(Option<u64>, PathBuf)>> {
    let files = log_files(path)?;
    if files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no audit log or sealed segment at {}", path.display()),
        ));
    }
    Ok(files)
}

/// Verify the whole log at `path`: every segment as one stream, seams,
/// expiry anchors and (live mode) tail completeness against `.hwm`. Runs
/// even when the active file is absent. Restarts once if a live rotation
/// changes the segment list mid-stream.
///
/// # Errors
///
/// A segment cannot be read, or an entry is not valid JSON.
pub(crate) fn verify_segments(
    path: &Path,
    config: &TransparencyLogConfig,
    mode: VerifyMode,
) -> io::Result<VerifyResult> {
    verify_pinned(path, config, mode, None)
}

/// As [`verify_segments`], also against `pin`, an anchor (MIK-7713).
pub(super) fn verify_pinned(
    path: &Path,
    config: &TransparencyLogConfig,
    mode: VerifyMode,
    pin: Option<&HighWater>,
) -> io::Result<VerifyResult> {
    let secret = config.shared_secret.as_bytes();
    let changed = || changed_under_reader("verification");
    let mut attempt = 0;
    loop {
        #[cfg(test)]
        PASSES.with(|c| c.set(c.get() + 1));
        #[cfg(test)]
        BEFORE_STREAM.with(|h| {
            let taken = h.borrow_mut().take();
            if let Some(f) = taken {
                f();
            }
        });
        // `.hwm` is written after its record, so reading it first means a live
        // append can only leave the stream ahead of it, never behind.
        let hw = segments::read_hwm(path, secret, &config.key_id);
        // Listed after `.hwm` is read, on every pass: a log wiped between
        // passes is `NotFound`, never a clean result.
        let files = existing_log_files(path)?;
        #[cfg(test)]
        LISTED.with(|h| {
            let taken = h.borrow_mut().take();
            if let Some(f) = taken {
                f();
            }
        });
        let result = Stream::new(if secret.is_empty() {
            None
        } else {
            Some(secret)
        })
        .run(&files, hw.as_ref(), mode, pin);
        let files_after = log_files(path)?;
        // A `.hwm` written during the pass (a new log's first append) is a
        // moved log too: the records read may be newer than the missing mark.
        let hwm_appeared =
            hw.is_none() && segments::read_hwm(path, secret, &config.key_id).is_some();
        let stable = seqs(&files) == seqs(&files_after) && !hwm_appeared;
        match result {
            // A file listed a moment ago vanished: a rotation renamed it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
            Ok(result) if stable => return Ok(result),
            Ok(_) => {}
        }
        if attempt == 1 {
            // Twice in a row the log moved under the reader: that is a busy
            // log, not evidence of tampering.
            return Err(changed());
        }
        attempt += 1;
    }
}

/// A one-shot test hook.
#[cfg(test)]
type HookSlot = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

/// Run and clear a one-shot test hook.
#[cfg(test)]
fn fire(hook: &'static std::thread::LocalKey<HookSlot>) {
    let taken = hook.with(|h| h.borrow_mut().take());
    if let Some(f) = taken {
        f();
    }
}

#[cfg(test)]
thread_local! {
    /// Runs once after a pass lists the files, before it reads them.
    pub(crate) static LISTED: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    /// Runs once before a pass lists and streams the files.
    pub(crate) static BEFORE_STREAM: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    /// Runs once after the last file is streamed: the tests append here to
    /// prove `.hwm` is read before the stream, not after it.
    pub(crate) static AFTER_STREAM: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    /// Reader passes on this thread, so a test can count rescans.
    pub(crate) static PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One verification pass over the ordered files.
struct Stream<'a> {
    secret: Option<&'a [u8]>,
    /// Counter and hash of the last verified record; `None` seeds genesis.
    prev: Option<(u64, String)>,
    result: VerifyResult,
    /// Expiry records seen: segment -> (`last_counter`, `final_hash`).
    expiries: BTreeMap<u64, (u64, String)>,
    /// The oldest survivor's link to an expired segment, checked at the end
    /// because its anchoring expiry record lives in a newer segment.
    anchor: Option<(u64, String, u64)>,
    /// The oldest survivor opens with an open record: this log went through
    /// segment handling, so `.hwm` is expected even with no sealed sibling
    /// left (#2242).
    opened_oldest: bool,
    /// The oldest survivor opens segment 0 at genesis with counter 1: a log
    /// holding only that record crashed before its first `.hwm` (#2275).
    genesis_open: bool,
    /// Earliest counter at which a restart found `.hwm` missing (#2294).
    hwm_missing: Option<u64>,
    /// `.hwm`'s counter, and the entry hash of the record walked there
    /// (MIK-7712): the mark names a record, not only a count.
    mark_counter: Option<u64>,
    at_mark: Option<String>,
    /// The anchor's counter, the hash walked there, and the expired
    /// boundary the oldest survivor verifiably links to (MIK-7713).
    pin_counter: Option<u64>,
    at_pin: Option<String>,
    boundary: Option<(u64, String)>,
}

type Verdict = Result<(), (Option<u64>, String)>;

fn field_u64(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(Value::as_u64)
}

fn field_str<'v>(v: &'v Value, k: &str) -> Option<&'v str> {
    v.get(k).and_then(Value::as_str)
}

fn missing(line: usize, what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("line {line}: missing '{what}'"),
    )
}

impl<'a> Stream<'a> {
    fn new(secret: Option<&'a [u8]>) -> Self {
        Self {
            secret,
            prev: None,
            result: VerifyResult::default(),
            expiries: BTreeMap::new(),
            anchor: None,
            opened_oldest: false,
            genesis_open: false,
            hwm_missing: None,
            mark_counter: None,
            at_mark: None,
            pin_counter: None,
            at_pin: None,
            boundary: None,
        }
    }

    fn run(
        mut self,
        files: &[(Option<u64>, PathBuf)],
        hw: Option<&HighWater>,
        mode: VerifyMode,
        pin: Option<&HighWater>,
    ) -> io::Result<VerifyResult> {
        self.mark_counter = hw.map(|h| h.counter);
        self.pin_counter = pin.map(|p| p.counter);
        let verdict = match self.stream(files)? {
            Ok(()) => self.finish(files, hw, mode, pin),
            failed => failed,
        };
        match verdict {
            Ok(()) => self.result.ok = true,
            Err((at, msg)) => {
                self.result.error_at_counter = at;
                self.result.error_message = Some(msg);
            }
        }
        Ok(self.result)
    }

    /// Parse one line, and note a signature on it before any check can
    /// reject the entry, so a failed chain still reports it.
    fn read_entry(&mut self, raw: &str, file: &Path, ln: usize) -> io::Result<Value> {
        let entry: Value = serde_json::from_str(raw.trim()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: line {}: invalid JSON: {e}", file.display(), ln + 1),
            )
        })?;
        self.result.signed_entry_seen |= is_signed_entry(&entry);
        Ok(entry)
    }

    fn stream(&mut self, files: &[(Option<u64>, PathBuf)]) -> io::Result<Verdict> {
        let newest_sealed = files.iter().filter_map(|(s, _)| *s).next_back();
        // The previous file: its segment, path, and the seal it ended with.
        let mut before: Option<(u64, &Path, Option<u64>)> = None;
        for (index, (seq, file)) in files.iter().enumerate() {
            // With sealed siblings the active file must be the next segment;
            // with none left (retention or the disk-full path took them) its
            // open record names it, and the expiry anchor pins the link.
            let expected = match (seq, newest_sealed) {
                (Some(s), _) => *s,
                (None, Some(n)) => match succ(n, None) {
                    Ok(next) => next,
                    Err(e) => return Ok(Err(e)),
                },
                (None, None) => segments::active_segment_seq(file, 0),
            };
            let content = bounded_read_to_string(file, MAX_AUDIT_READ_BYTES)?;
            let mut sealed_here: Option<u64> = None;
            for (ln, raw) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                let entry = self.read_entry(raw, file, ln)?;
                let counter =
                    field_u64(&entry, "counter").ok_or_else(|| missing(ln + 1, "counter"))?;
                if let Some(next) = sealed_here {
                    return Ok(Err((
                        Some(counter),
                        format!(
                            "{}: record {counter} follows the seal naming segment {next}",
                            file.display()
                        ),
                    )));
                }
                if ln == 0
                    && let Err(e) =
                        self.first_record(&entry, counter, index, expected, file, before)
                {
                    return Ok(Err(e));
                }
                if let Err(e) = self.check_entry(&entry, counter, ln)? {
                    return Ok(Err(e));
                }
                match field_str(&entry, "event") {
                    Some(EV_SEALED) => {
                        let next = field_u64(&entry, "next_segment_seq")
                            .map_or_else(|| succ(expected, Some(counter)), Ok);
                        match next {
                            Ok(next) => sealed_here = Some(next),
                            Err(e) => return Ok(Err(e)),
                        }
                    }
                    Some(EV_HWM_MISSING) => self.note_hwm_missing(counter),
                    Some(EV_TORN)
                        if entry.get(TORN_COMMITTED).and_then(Value::as_bool) == Some(true) =>
                    {
                        self.note_hwm_missing(field_u64(&entry, HWM_MISSING_AT).unwrap_or(counter));
                    }
                    Some(EV_OPENED) => {
                        if let Some(at) = field_u64(&entry, HWM_MISSING_AT) {
                            self.note_hwm_missing(at);
                        }
                    }
                    Some(EV_EXPIRED) => {
                        if let (Some(k), Some(lc), Some(fh)) = (
                            field_u64(&entry, "segment_seq"),
                            field_u64(&entry, "last_counter"),
                            field_str(&entry, "final_hash"),
                        ) {
                            self.expiries.insert(k, (lc, fh.to_string()));
                        }
                    }
                    _ => {}
                }
            }
            if seq.is_none() && sealed_here.is_some() {
                self.result.warnings.push(format!(
                    "{} ends with a seal record: a rotation was interrupted",
                    file.display()
                ));
            }
            self.result.segments_checked += 1;
            before = Some((expected, file.as_path(), sealed_here));
        }
        #[cfg(test)]
        AFTER_STREAM.with(|hook| {
            let taken = hook.borrow_mut().take();
            if let Some(f) = taken {
                f();
            }
        });
        if let Some((seq, file, None)) = before
            && files.last().is_some_and(|(s, _)| s.is_some())
        {
            return Ok(Err((
                None,
                format!(
                    "segment {seq} ({}) is not sealed and the active log is missing",
                    file.display()
                ),
            )));
        }
        Ok(Ok(()))
    }
}
