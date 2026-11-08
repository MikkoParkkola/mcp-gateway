// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A forward line reader with a strict byte limit: every byte its buffer pulls
//! from the file passes a `Take`-style limit set to the budget, so total bytes
//! read never exceed it, read-ahead included. Used by the look-above and the
//! receipt's forward scan.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Take};

use crate::security::transparency_log::pager::ASSEMBLY_WINDOW;

/// The buffer's size: one fill is at most this, and is charged whole.
const READ_AHEAD: u64 = 64 * 1024;

/// What the next line was.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Next {
    /// A whole line, without its newline.
    Line(Vec<u8>),
    /// The budget ended the read, on a line boundary or inside a line (whose
    /// bytes are not returned).
    Budget,
    /// No whole line remains: the end of the file, or a partial append.
    End,
}

pub(super) struct Forward {
    reader: BufReader<Take<File>>,
    budget: u64,
    /// Where the read began, and the file's length then: a budget that ends
    /// exactly at the end of the file ended nothing.
    start: u64,
    file_len: u64,
}

impl Forward {
    /// Read from `offset` of `file`, at most `budget` bytes.
    pub(super) fn open(mut file: File, offset: u64, budget: u64) -> io::Result<Self> {
        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::Start(offset))?;
        let capacity = usize::try_from(budget.min(READ_AHEAD)).unwrap_or(1).max(1);
        Ok(Self {
            reader: BufReader::with_capacity(capacity, file.take(budget)),
            budget,
            start: offset,
            file_len,
        })
    }

    pub(super) fn next_line(&mut self) -> io::Result<Next> {
        let mut buf = Vec::new();
        (&mut self.reader)
            .take(ASSEMBLY_WINDOW)
            .read_until(b'\n', &mut buf)?;
        if buf.last() == Some(&b'\n') {
            buf.pop();
            return Ok(Next::Line(buf));
        }
        let cut = self.pulled() >= self.budget && self.start + self.pulled() < self.file_len;
        // ponytail: a line over the record cap ends the read as Budget; the
        // logger never writes one, so it is never a delivery to find.
        let over_cap = u64::try_from(buf.len()).unwrap_or(u64::MAX) >= ASSEMBLY_WINDOW;
        Ok(if cut || over_cap {
            Next::Budget
        } else {
            Next::End
        })
    }

    /// Bytes pulled from the file so far, counted at the limited reader.
    pub(super) fn pulled(&self) -> u64 {
        self.budget - self.reader.get_ref().limit()
    }
}
