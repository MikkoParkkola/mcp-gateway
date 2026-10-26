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

/// One cell. Only text is guarded: a number is written as a number, so a
/// negative latency or cost still sums in a spreadsheet.
#[derive(Debug, Clone, Copy)]
pub(super) enum Cell<'a> {
    Text(&'a str),
    Int(i64),
    Float(f64),
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
        let header: Vec<Cell<'_>> = header.iter().map(|h| Cell::Text(h)).collect();
        w.line(&header);
        w
    }

    /// Append one data row.
    pub(super) fn row(&mut self, cells: &[Cell<'_>]) {
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

    fn line(&mut self, cells: &[Cell<'_>]) {
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            match *c {
                Cell::Text(t) => push_cell(&mut self.out, t),
                // A number never needs quoting and must never be guarded.
                Cell::Int(n) => {
                    let _ = write!(self.out, "{n}");
                }
                Cell::Float(x) => {
                    let _ = write!(self.out, "{x}");
                }
            }
        }
        self.out.push_str("\r\n");
    }
}

/// Characters a spreadsheet reads as the start of a formula.
const FORMULA_LEADS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// One cell: a leading `'` when it would start a formula, then quoted when it
/// holds a quote, comma, CR or LF.
fn push_cell(out: &mut String, cell: &str) {
    let guarded;
    let cell = if cell.starts_with(FORMULA_LEADS) {
        guarded = format!("'{cell}");
        guarded.as_str()
    } else {
        cell
    };
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
