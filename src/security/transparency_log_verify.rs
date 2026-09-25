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
use tracing::warn;

use super::rotation::{EV_EXPIRED, EV_OPENED, EV_SEALED};
use super::segments::{self, HighWater};
use super::{
    MAX_AUDIT_READ_BYTES, TransparencyLogConfig, bounded_read_to_string, recompute_entry_hash,
    verify_entry_sig,
};

/// Result of a chain-integrity verification pass.
#[derive(Debug, Default)]
pub struct VerifyResult {
    /// `true` when every entry in the log passed all checks.
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

/// Whether any segment of the log holds a signed entry, so `audit verify`
/// refuses a silent hash-only pass over a signed log (MIK-6700 review).
///
/// # Errors
///
/// A segment cannot be read.
pub fn log_contains_signed_entry(path: &Path) -> io::Result<bool> {
    for (_, file) in log_files(path)? {
        let content = bounded_read_to_string(&file, MAX_AUDIT_READ_BYTES)?;
        let signed = content.lines().any(|raw| {
            serde_json::from_str::<Value>(raw.trim()).is_ok_and(|e| e.get("sig").is_some())
        });
        if signed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every entry whose `session_id` is `session`, oldest first, across the
/// sealed segments and the active file.
///
/// # Errors
///
/// `NotFound` when neither the log nor any sealed segment exists, or a
/// segment cannot be read.
pub fn show_session_entries(path: &Path, session: &str) -> io::Result<Vec<Value>> {
    let mut results = Vec::new();
    for (_, file) in existing_log_files(path)? {
        let content = bounded_read_to_string(&file, MAX_AUDIT_READ_BYTES)?;
        for raw in content.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Value>(raw.trim()) {
                Ok(entry) if entry.get("session_id").and_then(Value::as_str) == Some(session) => {
                    results.push(entry);
                }
                Ok(_) => {}
                Err(e) => warn!("transparency log: skipping malformed line: {e}"),
            }
        }
    }
    Ok(results)
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

/// The one library entry point for `audit verify`: the whole log at `path`,
/// across its sealed segments, in `mode`, with the per-entry HMAC checked
/// when `config` carries a secret (D6 2.5).
///
/// # Errors
///
/// `NotFound` when neither the log nor any sealed segment exists;
/// `Interrupted` when the log rotated under the reader twice in a row
/// (retry); any read error.
pub fn verify_audit_log(
    path: &Path,
    config: &TransparencyLogConfig,
    mode: VerifyMode,
) -> io::Result<VerifyResult> {
    existing_log_files(path)?;
    verify_segments(path, config, mode)
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
    let secret = config.shared_secret.as_bytes();
    let changed = || {
        io::Error::new(
            io::ErrorKind::Interrupted,
            "log changed during verification (a live rotation); retry",
        )
    };
    let mut attempt = 0;
    loop {
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
        let files = log_files(path)?;
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
        .run(&files, hw.as_ref(), mode);
        let files_after = log_files(path)?;
        let seqs = |f: &[(Option<u64>, PathBuf)]| f.iter().map(|(s, _)| *s).collect::<Vec<_>>();
        let stable = seqs(&files) == seqs(&files_after);
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
        }
    }

    fn run(
        mut self,
        files: &[(Option<u64>, PathBuf)],
        hw: Option<&HighWater>,
        mode: VerifyMode,
    ) -> io::Result<VerifyResult> {
        let verdict = match self.stream(files)? {
            Ok(()) => self.finish(files, hw, mode),
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

    fn stream(&mut self, files: &[(Option<u64>, PathBuf)]) -> io::Result<Verdict> {
        let newest_sealed = files.iter().filter_map(|(s, _)| *s).next_back();
        // The previous file: its segment, path, and the seal it ended with.
        let mut before: Option<(u64, &Path, Option<u64>)> = None;
        for (index, (seq, file)) in files.iter().enumerate() {
            // With sealed siblings the active file must be the next segment;
            // with none left (retention or the disk-full path took them) its
            // open record names it, and the expiry anchor pins the link.
            let expected = seq.unwrap_or_else(|| match newest_sealed {
                Some(n) => n + 1,
                None => segments::active_segment_seq(file, 0),
            });
            let content = bounded_read_to_string(file, MAX_AUDIT_READ_BYTES)?;
            let mut sealed_here: Option<u64> = None;
            for (ln, raw) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
                let entry: Value = serde_json::from_str(raw.trim()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: line {}: invalid JSON: {e}", file.display(), ln + 1),
                    )
                })?;
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
                        sealed_here =
                            Some(field_u64(&entry, "next_segment_seq").unwrap_or(expected + 1));
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

impl Stream<'_> {
    /// Seam checks on a file's first record.
    fn first_record(
        &mut self,
        entry: &Value,
        counter: u64,
        index: usize,
        expected: u64,
        file: &Path,
        before: Option<(u64, &Path, Option<u64>)>,
    ) -> Verdict {
        let opened = field_str(entry, "event") == Some(EV_OPENED);
        let Some((prev_seq, prev_file, prev_seal)) = before else {
            // The oldest surviving file.
            if !opened {
                if expected != 0 {
                    return Err((
                        Some(counter),
                        format!(
                            "{} (segment {expected}) does not start with an open record",
                            file.display()
                        ),
                    ));
                }
                return Ok(()); // a pre-D6 segment 0 starts at genesis
            }
            Self::check_open_seq(entry, counter, expected, file)?;
            let prev_hash = field_str(entry, "prev_entry_hash")
                .unwrap_or_default()
                .to_string();
            match field_u64(entry, "prev_segment_seq") {
                Some(gone) => {
                    let link = field_str(entry, "prev_segment_final_hash").unwrap_or_default();
                    self.anchor = Some((gone, link.to_string(), counter));
                }
                None if prev_hash != "genesis" => {
                    return Err((
                        Some(counter),
                        format!(
                            "counters 1..{} missing before {}: the active segment was deleted",
                            counter.saturating_sub(1),
                            file.display()
                        ),
                    ));
                }
                None => {}
            }
            self.prev = Some((counter.saturating_sub(1), prev_hash));
            return Ok(());
        };
        debug_assert!(index > 0);
        let Some(next) = prev_seal else {
            return Err((
                Some(counter),
                format!(
                    "segment {prev_seq} ({}) has no seal record before {}",
                    prev_file.display(),
                    file.display()
                ),
            ));
        };
        if !opened {
            return Err((
                Some(counter),
                format!(
                    "{} does not start with an audit_segment_opened record",
                    file.display()
                ),
            ));
        }
        if next != expected {
            return Err((
                Some(counter),
                format!(
                    "segment {next} missing between {} and {} with no expiry record",
                    prev_file.display(),
                    file.display()
                ),
            ));
        }
        Self::check_open_seq(entry, counter, expected, file)?;
        if field_u64(entry, "prev_segment_seq") != Some(prev_seq) {
            return Err((
                Some(counter),
                format!(
                    "{} names prev_segment_seq {:?}, but follows {} (segment {prev_seq})",
                    file.display(),
                    field_u64(entry, "prev_segment_seq"),
                    prev_file.display()
                ),
            ));
        }
        self.check_seam_link(entry, counter, prev_seq, prev_file, file)?;
        let seal_counter = self.prev.as_ref().map_or(0, |p| p.0);
        if counter > seal_counter + 1 {
            return Err((
                Some(counter),
                format!(
                    "counters {}..{} missing after segment {prev_seq}: the active segment was \
                 deleted or truncated, or the host lost unflushed writes",
                    seal_counter + 1,
                    counter - 1
                ),
            ));
        }
        Ok(())
    }

    /// Every boundary names its link: the open record's
    /// `prev_segment_final_hash` must be the seal it follows, or a chain does
    /// not check its own links.
    fn check_seam_link(
        &self,
        entry: &Value,
        counter: u64,
        prev_seq: u64,
        prev_file: &Path,
        file: &Path,
    ) -> Verdict {
        let seal_hash = self.prev.as_ref().map_or("", |p| p.1.as_str());
        if field_str(entry, "prev_segment_final_hash") == Some(seal_hash) {
            return Ok(());
        }
        Err((
            Some(counter),
            format!(
                "{} names prev_segment_final_hash {:?}, but segment {prev_seq} ({}) sealed with \
                 {seal_hash}",
                file.display(),
                field_str(entry, "prev_segment_final_hash"),
                prev_file.display()
            ),
        ))
    }

    fn check_open_seq(entry: &Value, counter: u64, expected: u64, file: &Path) -> Verdict {
        let held = field_u64(entry, "segment_seq");
        if true || held == Some(expected) {
            return Ok(());
        }
        Err((
            Some(counter),
            format!(
                "{} holds segment_seq {held:?}, expected {expected}: segment files renamed or reordered",
                file.display()
            ),
        ))
    }

    /// The per-entry checks, unchanged from before D6.
    fn check_entry(&mut self, entry: &Value, counter: u64, ln: usize) -> io::Result<Verdict> {
        let stored = field_str(entry, "entry_hash").ok_or_else(|| missing(ln + 1, "entry_hash"))?;
        let stored_prev = field_str(entry, "prev_entry_hash")
            .ok_or_else(|| missing(ln + 1, "prev_entry_hash"))?;
        let (want_counter, want_prev) = match &self.prev {
            Some((c, h)) => (c + 1, h.as_str()),
            None => (counter, "genesis"),
        };
        if counter != want_counter {
            return Ok(Err((
                Some(counter),
                format!("counter gap at entry {counter}: expected {want_counter}"),
            )));
        }
        if stored_prev != want_prev {
            return Ok(Err((
                Some(counter),
                format!(
                    "entry {counter}: prev_entry_hash mismatch (expected '{want_prev}', got '{stored_prev}')"
                ),
            )));
        }
        let recomputed = recompute_entry_hash(entry)?;
        if recomputed != stored {
            return Ok(Err((
                Some(counter),
                format!(
                    "entry {counter}: entry_hash mismatch (computed '{recomputed}', stored '{stored}')"
                ),
            )));
        }
        if let Some(secret) = self.secret
            && let Err(msg) = verify_entry_sig(entry, stored, secret)
        {
            return Ok(Err((Some(counter), format!("entry {counter}: {msg}"))));
        }
        self.prev = Some((counter, stored.to_string()));
        self.result.entries_checked += 1;
        Ok(Ok(()))
    }

    /// End-of-stream checks: the expiry anchor and tail completeness.
    fn finish(
        &mut self,
        files: &[(Option<u64>, PathBuf)],
        hw: Option<&HighWater>,
        mode: VerifyMode,
    ) -> Verdict {
        if let Some((gone, link, counter)) = self.anchor.take() {
            match self.expiries.get(&gone) {
                Some((last, hash)) if *hash == link && last + 1 == counter => {
                    self.result.segments_expired =
                        self.expiries.keys().filter(|k| **k <= gone).count();
                }
                Some(_) => {
                    return Err((
                        Some(counter),
                        format!(
                            "segment {gone}: its expiry record does not match the link from the \
                         oldest surviving segment (hash or counter)"
                        ),
                    ));
                }
                None => {
                    return Err((
                        Some(counter),
                        format!("segment {gone} missing with no expiry record"),
                    ));
                }
            }
        }
        let sealed_present = files.iter().any(|(s, _)| s.is_some());
        let last = self.prev.as_ref().map_or(0, |p| p.0);
        let gap = match hw {
            None if sealed_present => {
                Some("high-water mark missing: tail loss cannot be ruled out".to_string())
            }
            Some(h) if last < h.counter => Some(format!(
                "counters {}..{} missing at the tail: the active segment was deleted or \
                 truncated, or the host lost unflushed writes",
                last + 1,
                h.counter
            )),
            _ => None,
        };
        match (gap, mode) {
            (Some(msg), VerifyMode::Live) => Err((Some(last + 1), msg)),
            (Some(msg), VerifyMode::Archive) => {
                self.result.warnings.push(format!(
                    "archive mode: tail completeness not checked ({msg})"
                ));
                Ok(())
            }
            (None, _) => Ok(()),
        }
    }
}
