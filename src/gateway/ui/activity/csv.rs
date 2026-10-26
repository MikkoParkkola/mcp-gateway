// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity CSV export: RFC 4180 quoting, a spreadsheet formula guard on
//! every cell, and a closing `#end` line so a cut file never reads as whole.

use std::fmt::Write as _;

/// Why an export stopped before the log's end, if it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Truncated {
    None,
    Rows,
    Bytes,
    Scan,
}

impl Truncated {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rows => "rows",
            Self::Bytes => "bytes",
            Self::Scan => "scan",
        }
    }
}

/// Builds one CSV export, header first.
pub(super) struct CsvWriter {
    out: String,
    rows: usize,
}

impl CsvWriter {
    pub(super) fn new(header: &[&str]) -> Self {
        let mut w = Self {
            out: String::new(),
            rows: 0,
        };
        w.line(header);
        w
    }

    /// Append one data row.
    pub(super) fn row(&mut self, cells: &[&str]) {
        self.line(cells);
        self.rows += 1;
    }

    /// The finished file, ending `#end rows=<n> truncated=<state>`.
    pub(super) fn finish(mut self, truncated: Truncated) -> String {
        let _ = write!(
            self.out,
            "#end rows={} truncated={}\r\n",
            self.rows,
            truncated.as_str()
        );
        self.out
    }

    fn line(&mut self, cells: &[&str]) {
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            push_cell(&mut self.out, c);
        }
        self.out.push_str("\r\n");
    }
}

/// One cell, quoted when it holds a quote, comma, CR or LF.
fn push_cell(out: &mut String, cell: &str) {
    if cell.contains(['"', ',', '\r', '\n']) {
        out.push('"');
        out.push_str(&cell.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(cell);
    }
}

#[cfg(test)]
#[path = "csv_tests.rs"]
mod tests;
