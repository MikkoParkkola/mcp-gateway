// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{Cell, CsvWriter, Truncated};

/// Export one row with `server` and `tool` set to `value`.
fn export(value: &str) -> String {
    let mut w = CsvWriter::new(&["counter", "server", "tool"]);
    w.row(&[Cell::Int(1), Cell::Text(value), Cell::Text(value)]);
    w.finish(Truncated::None)
}

#[test]
fn formula_lead_characters_get_a_leading_quote_in_server_and_tool() {
    for lead in ["=", "+", "-", "@", "\t", "\r"] {
        let value = format!("{lead}HYPERLINK(\"x\")");
        let file = export(&value);
        let data = file.lines().nth(1).unwrap_or_default();
        // Both caller-spelled cells: guarded, then quoted (each holds a quote).
        let guarded = format!("\"'{}\"", value.replace('"', "\"\""));
        assert_eq!(
            data,
            format!("1,{guarded},{guarded}"),
            "lead {lead:?} not guarded in both cells"
        );
    }
}

#[test]
fn rfc4180_quoting_of_quotes_commas_and_newlines() {
    let mut w = CsvWriter::new(&["a", "b", "c", "d"]);
    w.row(&[
        Cell::Text("plain"),
        Cell::Text("has,comma"),
        Cell::Text("has \"quote\""),
        Cell::Text("two\nlines"),
    ]);
    let file = w.finish(Truncated::None);
    assert_eq!(
        file,
        "a,b,c,d\r\nplain,\"has,comma\",\"has \"\"quote\"\"\",\"two\nlines\"\r\n#end rows=1 truncated=none\r\n"
    );
}

#[test]
fn file_ends_with_row_count_and_truncation_state() {
    for (t, s) in [
        (Truncated::None, "none"),
        (Truncated::Rows, "rows"),
        (Truncated::Bytes, "bytes"),
        (Truncated::Scan, "scan"),
    ] {
        let mut w = CsvWriter::new(&["a"]);
        w.row(&[Cell::Int(1)]);
        w.row(&[Cell::Int(2)]);
        let file = w.finish(t);
        assert!(
            file.ends_with(&format!("\r\n#end rows=2 truncated={s}\r\n")),
            "{file:?}"
        );
    }
}

#[test]
fn a_lead_character_inside_a_cell_is_left_alone() {
    let file = export("a=b");
    assert_eq!(file.lines().nth(1), Some("1,a=b,a=b"));
}

#[test]
fn numbers_are_never_guarded_and_text_always_is() {
    let mut w = CsvWriter::new(&["latency_ms", "cost", "tool"]);
    w.row(&[Cell::Int(-5), Cell::Float(-0.25), Cell::Text("-1+cmd")]);
    let file = w.finish(Truncated::None);
    assert_eq!(file.lines().nth(1), Some("-5,-0.25,'-1+cmd"));
}
