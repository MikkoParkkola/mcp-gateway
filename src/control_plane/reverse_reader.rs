//! Newest-first line reader over an append-only log.
//!
//! The audit log is written oldest-first, but every read of it wants the newest
//! events. Reading the whole file to reverse it makes a page cost what the log
//! costs; this reader instead walks backwards in fixed blocks so a page costs
//! what the page costs.
//!
//! It carries no policy: it does not know what a record means, which records
//! match a filter, or when a caller has enough. It yields byte ranges, newest
//! first, within a byte allowance it never exceeds.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Bytes pulled from disk per backwards step.
const BLOCK: usize = 64 * 1024;

/// Why a reverse scan stopped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReverseStop {
    /// Offset 0 was reached: every line in the captured region was yielded.
    StartOfFile,
    /// The read allowance ran out before a further line could be assembled.
    AllowanceSpent,
}

/// One step of a reverse scan.
#[derive(Debug)]
pub(crate) enum ReverseStep {
    /// A newline-terminated line and the offset it starts at.
    Record {
        /// Byte offset of the line's first byte.
        start: u64,
        /// Line content, without its terminating newline.
        bytes: Vec<u8>,
    },
    /// No further line was produced; the reason distinguishes "done" from
    /// "ran out of budget".
    Stop(ReverseStop),
    /// A single line exceeded `max_record` without a newline. The caller must
    /// surface this rather than paging forever over a line it cannot read.
    Oversized {
        /// Exclusive end offset of the region the oversized line sits in.
        end: u64,
    },
}

/// A backwards, block-at-a-time line reader over a fixed region of a file.
///
/// The region end is captured once at construction, so a concurrent append is
/// invisible to this reader and a walk sees one consistent view of the log.
pub(crate) struct ReverseBlockReader {
    file: File,
    /// Start offset of the buffered, not-yet-yielded content.
    lo: u64,
    /// Exclusive end of the unyielded region. `file[hi-1]` is the newline that
    /// terminates the next line to yield (or `hi == lo` when nothing remains).
    hi: u64,
    /// `file[lo..hi-1]`: the unyielded content, newline-terminator excluded.
    buf: Vec<u8>,
    /// Remaining bytes this reader may still pull from disk.
    allowance: u64,
    /// Largest single line this reader will assemble.
    max_record: u64,
    /// Bytes pulled from disk so far.
    consumed: u64,
}

impl ReverseBlockReader {
    /// Open a reverse reader over `file[..end]`.
    ///
    /// `end` is the captured region end (the file length for a fresh read, a
    /// cursor boundary for a resumed one). An unterminated tail at `end` is a
    /// half-written append, not a record: it is skipped, never yielded.
    ///
    /// # Errors
    ///
    /// Errors on any I/O failure while positioning or reading.
    pub(crate) fn new(
        mut file: File,
        end: u64,
        allowance: u64,
        max_record: u64,
    ) -> std::io::Result<Self> {
        let mut reader = Self {
            lo: end,
            hi: end,
            buf: Vec::new(),
            allowance,
            max_record,
            consumed: 0,
            file: {
                file.seek(SeekFrom::Start(0))?;
                file
            },
        };
        reader.trim_trailing_fragment()?;
        Ok(reader)
    }

    /// Bytes read from disk so far. This is the reader's whole cost.
    pub(crate) fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Yield the next line, newest first.
    ///
    /// # Errors
    ///
    /// Errors on any I/O failure while reading a block.
    pub(crate) fn next_line(&mut self) -> std::io::Result<ReverseStep> {
        loop {
            if let Some(step) = self.take_buffered() {
                return Ok(step);
            }
            // No newline in the buffer: whatever is here is one unfinished
            // line that will only grow. Past the cap it can never be assembled,
            // and paging over it would hand back a cursor that never advances.
            if self.buf.len() as u64 > self.max_record {
                return Ok(ReverseStep::Oversized { end: self.hi });
            }
            if self.lo == 0 {
                return Ok(self.drain_first_line());
            }
            if !self.fill_block()? {
                return Ok(ReverseStep::Stop(ReverseStop::AllowanceSpent));
            }
        }
    }

    /// Split off the newest complete line already in `buf`, if there is one.
    fn take_buffered(&mut self) -> Option<ReverseStep> {
        let cut = self.buf.iter().rposition(|b| *b == b'\n')?;
        let bytes = self.buf.split_off(cut + 1);
        self.buf.pop(); // drop the newline itself
        let start = self.lo + cut as u64 + 1;
        Some(self.emit(start, bytes))
    }

    /// At offset 0 the remaining buffer is the oldest line: it has no preceding
    /// newline, so `take_buffered` can never claim it.
    fn drain_first_line(&mut self) -> ReverseStep {
        if self.buf.is_empty() {
            return ReverseStep::Stop(ReverseStop::StartOfFile);
        }
        let bytes = std::mem::take(&mut self.buf);
        self.emit(0, bytes)
    }

    /// Yield one assembled line, or reject it for exceeding `max_record`.
    ///
    /// The cap is enforced here, on the whole record, so that whether a record
    /// is oversized never depends on where a block boundary happened to fall.
    fn emit(&mut self, start: u64, bytes: Vec<u8>) -> ReverseStep {
        let end = self.hi;
        self.hi = start;
        if bytes.len() as u64 > self.max_record {
            return ReverseStep::Oversized { end };
        }
        ReverseStep::Record { start, bytes }
    }

    /// Prepend one more block of the file to `buf`.
    ///
    /// Returns `false` when the allowance cannot fund another read.
    fn fill_block(&mut self) -> std::io::Result<bool> {
        let want = BLOCK.min(usize::try_from(self.lo).unwrap_or(BLOCK));
        let want = u64::try_from(want).unwrap_or(0).min(self.allowance);
        if want == 0 {
            return Ok(false);
        }
        let len = usize::try_from(want).unwrap_or(0);
        let start = self.lo - want;
        let mut block = vec![0u8; len];
        self.file.seek(SeekFrom::Start(start))?;
        self.file.read_exact(&mut block)?;
        self.allowance -= want;
        self.consumed += want;
        self.lo = start;
        block.extend_from_slice(&self.buf);
        self.buf = block;
        Ok(true)
    }

    /// Drop any bytes after the captured region's final newline: a tail with no
    /// terminator is an append in progress. Called once, at construction.
    fn trim_trailing_fragment(&mut self) -> std::io::Result<()> {
        loop {
            if let Some(cut) = self.buf.iter().rposition(|b| *b == b'\n') {
                self.buf.truncate(cut);
                self.hi = self.lo + cut as u64 + 1;
                return Ok(());
            }
            if self.lo == 0 || !self.fill_block()? {
                self.buf.clear();
                self.hi = self.lo;
                return Ok(());
            }
        }
    }
}
