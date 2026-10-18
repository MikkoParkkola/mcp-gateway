// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The record checks of an audit-log verify pass: a file's first-record
//! seams, each entry's chain and signature, and the verdict at the end of the
//! stream (the tail against `.hwm`, the anchor).

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::super::anchor::{Walked, check_anchor};
use super::super::{recompute_entry_hash, verify_entry_sig};
use super::{
    EV_HWM_MISSING, EV_OPENED, HighWater, Stream, Verdict, VerifyMode, field_str, field_u64,
    missing, succ,
};

impl Stream<'_> {
    /// Seam checks on a file's first record.
    pub(super) fn first_record(
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
            return self.first_record_oldest(entry, counter, expected, file);
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
        let after_seal = succ(seal_counter, Some(seal_counter))?;
        if counter > after_seal {
            return Err((
                Some(counter),
                format!(
                    "counters {}..{} missing after segment {prev_seq}: the active segment was \
                 deleted or truncated, or the host lost unflushed writes",
                    after_seal,
                    counter - 1
                ),
            ));
        }
        Ok(())
    }

    /// Seam checks on the oldest surviving file's first record.
    fn first_record_oldest(
        &mut self,
        entry: &Value,
        counter: u64,
        expected: u64,
        file: &Path,
    ) -> Verdict {
        if field_str(entry, "event") != Some(EV_OPENED) {
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
        self.opened_oldest = true;
        Self::check_open_seq(entry, counter, expected, file)?;
        let prev_hash = field_str(entry, "prev_entry_hash")
            .unwrap_or_default()
            .to_string();
        match field_u64(entry, "prev_segment_seq") {
            Some(gone) => {
                let link = field_str(entry, "prev_segment_final_hash").unwrap_or_default();
                // The chain must continue from the boundary it links to,
                // as at every internal seam.
                if link != prev_hash {
                    return Err((
                        Some(counter),
                        format!(
                            "segment {expected} opens with prev_entry_hash {prev_hash} but \
                             links to final hash {link}"
                        ),
                    ));
                }
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
            None => self.genesis_open = counter == 1,
        }
        self.prev = Some((counter.saturating_sub(1), prev_hash));
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
        if held == Some(expected) {
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
    pub(super) fn check_entry(
        &mut self,
        entry: &Value,
        counter: u64,
        ln: usize,
    ) -> io::Result<Verdict> {
        let stored = field_str(entry, "entry_hash").ok_or_else(|| missing(ln + 1, "entry_hash"))?;
        let stored_prev = field_str(entry, "prev_entry_hash")
            .ok_or_else(|| missing(ln + 1, "prev_entry_hash"))?;
        let (want_counter, want_prev) = match &self.prev {
            Some((c, h)) => match succ(*c, Some(*c)) {
                Ok(next) => (next, h.as_str()),
                Err(e) => return Ok(Err(e)),
            },
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
        if self.mark_counter == Some(counter) {
            self.at_mark = Some(stored.to_string());
        }
        if self.pin_counter == Some(counter) {
            self.at_pin = Some(stored.to_string());
        }
        self.prev = Some((counter, stored.to_string()));
        self.result.entries_checked += 1;
        Ok(Ok(()))
    }

    pub(super) fn note_hwm_missing(&mut self, at: u64) {
        self.hwm_missing = Some(self.hwm_missing.map_or(at, |e| e.min(at)));
    }

    /// End-of-stream checks: the expiry anchor and tail completeness.
    pub(super) fn finish(
        &mut self,
        files: &[(Option<u64>, PathBuf)],
        hw: Option<&HighWater>,
        mode: VerifyMode,
        pin: Option<&HighWater>,
    ) -> Verdict {
        if let Some((gone, link, counter)) = self.anchor.take() {
            match self.expiries.get(&gone) {
                Some((last, hash)) if *hash == link && succ(*last, Some(*last))? == counter => {
                    self.result.segments_expired =
                        self.expiries.keys().filter(|k| **k <= gone).count();
                    self.boundary = Some((*last, link));
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
        if let Some(at) = self.hwm_missing {
            let msg = format!(
                "{EV_HWM_MISSING} at counter {at}: a restart found the high-water mark \
                 missing or a record it could not verify, so tail loss or an edit before \
                 it cannot be ruled out"
            );
            match mode {
                VerifyMode::Live => return Err((Some(at), msg)),
                VerifyMode::Archive => self.result.warnings.push(format!("archive mode: {msg}")),
            }
        }
        if let Some(pin) = pin {
            let walked = Walked {
                last: self.prev.as_ref().map(|p| p.0),
                at_pin: self.at_pin.as_deref(),
                boundary: self.boundary.as_ref().map(|(c, h)| (*c, h.as_str())),
                signed: self.secret.is_some(),
            };
            check_anchor(pin, &walked)?;
        }
        let sealed_present = files.iter().any(|(s, _)| s.is_some());
        let last = self.prev.as_ref().map_or(0, |p| p.0);
        // Disk-full expiry can take the last sealed segment, so the open
        // record is the evidence then. An active cut to empty leaves none and
        // reads as a fresh log; only an external anchor catches that (#2276).
        // A cut back to the genesis open record alone is the same case: it
        // matches a crash before the first `.hwm`, so it is exempt (#2275).
        // A loss is located after the tail; a replaced record at the mark is
        // located at the mark, where the evidence of tampering sits (MIK-7838).
        let gap = match hw {
            None if sealed_present || (self.opened_oldest && !(self.genesis_open && last == 1)) => {
                Some((
                    succ(last, Some(last))?,
                    "high-water mark missing: tail loss cannot be ruled out".to_string(),
                ))
            }
            Some(h) if last < h.counter => Some((
                last + 1,
                format!(
                    "counters {}..{} missing at the tail: the active segment was deleted or \
                     truncated, or the host lost unflushed writes",
                    last + 1,
                    h.counter
                ),
            )),
            Some(h) if self.at_mark.as_ref().is_some_and(|at| *at != h.entry_hash) => Some((
                h.counter,
                format!(
                    "high-water mark hash mismatch at counter {}: the record there is not \
                     the one the mark recorded",
                    h.counter
                ),
            )),
            _ => None,
        };
        match (gap, mode) {
            (Some((at, msg)), VerifyMode::Live) => Err((Some(at), msg)),
            (Some((_, msg)), VerifyMode::Archive) => {
                self.result.warnings.push(format!(
                    "archive mode: tail completeness not checked ({msg})"
                ));
                Ok(())
            }
            (None, _) => Ok(()),
        }
    }
}
