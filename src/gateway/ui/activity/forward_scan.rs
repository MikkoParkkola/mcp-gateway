// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One segment read forward from an offset, a line at a time, within a byte
//! budget. A record within the log's cap is always read whole, even past the
//! budget, so no call ends inside a record. A run with no newline within the
//! cap is skipped up to its next newline, one budget per call.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::security::transparency_log::pager::ASSEMBLY_WINDOW;

/// Where a scan is between lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// At the start of a line.
    Boundary,
    /// Inside a run with no newline within the cap; it is discarded up to
    /// its next newline.
    SkipToNewline,
}

/// A whole record's bytes, newline included, by place and hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Anchor {
    pub(super) start: u64,
    pub(super) len: u64,
    pub(super) sha256: [u8; 32],
}

impl Anchor {
    /// Whether `file` still holds these bytes here. Returns the bytes read.
    pub(super) fn holds(&self, file: &File) -> io::Result<(bool, u64)> {
        let mut bytes = Vec::new();
        let mut f = file;
        f.seek(SeekFrom::Start(self.start))?;
        let n = len64(f.take(self.len).read_to_end(&mut bytes)?);
        Ok((n == self.len && hash(&bytes) == self.sha256, n))
    }
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// What the next line was.
#[derive(Debug)]
pub(super) enum Step {
    /// A JSON record with a counter.
    Record { entry: Value, anchor: Anchor },
    /// A whole line that is not a record, or the end of a skipped run.
    Unreadable,
    /// The budget is spent; the scan stops between lines or inside a run.
    Budget,
    /// No whole line remains: the end of the file, or a partial append.
    End,
}

/// One segment's forward scan.
pub(super) struct Scan {
    file: File,
    pub(super) offset: u64,
    pub(super) mode: Mode,
    /// Bytes this scan consumed.
    pub(super) read: u64,
    budget: u64,
}

impl Scan {
    pub(super) fn new(file: File, offset: u64, mode: Mode, budget: u64) -> Self {
        Self {
            file,
            offset,
            mode,
            read: 0,
            budget,
        }
    }

    /// Up to `limit` bytes from the offset, through the next newline.
    fn line(&self, limit: u64) -> io::Result<Vec<u8>> {
        let mut f = &self.file;
        f.seek(SeekFrom::Start(self.offset))?;
        let mut buf = Vec::new();
        BufReader::new(f.take(limit)).read_until(b'\n', &mut buf)?;
        Ok(buf)
    }

    pub(super) fn next(&mut self) -> io::Result<Step> {
        loop {
            if self.read >= self.budget {
                return Ok(Step::Budget);
            }
            match self.mode {
                Mode::SkipToNewline => {
                    let buf = self.line(self.budget - self.read)?;
                    if buf.is_empty() {
                        return Ok(Step::End);
                    }
                    self.consume(buf.len());
                    if buf.ends_with(b"\n") {
                        self.mode = Mode::Boundary;
                        return Ok(Step::Unreadable);
                    }
                }
                Mode::Boundary => {
                    let buf = self.line(ASSEMBLY_WINDOW)?;
                    if !buf.ends_with(b"\n") {
                        if len64(buf.len()) < ASSEMBLY_WINDOW {
                            return Ok(Step::End);
                        }
                        // Over the cap: never a record.
                        self.consume(buf.len());
                        self.mode = Mode::SkipToNewline;
                        continue;
                    }
                    let start = self.offset;
                    self.consume(buf.len());
                    let record = serde_json::from_slice::<Value>(&buf[..buf.len() - 1])
                        .ok()
                        .filter(|e| e.get("counter").and_then(Value::as_u64).is_some());
                    return Ok(match record {
                        Some(entry) => Step::Record {
                            entry,
                            anchor: Anchor {
                                start,
                                len: len64(buf.len()),
                                sha256: hash(&buf),
                            },
                        },
                        None => Step::Unreadable,
                    });
                }
            }
        }
    }

    fn consume(&mut self, n: usize) {
        let n = len64(n);
        self.offset += n;
        self.read += n;
    }
}
