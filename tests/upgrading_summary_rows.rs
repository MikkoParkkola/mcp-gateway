// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/UPGRADING-4.0.md`: every numbered item has a row in the summary table,
//! and every row has an item.
//!
//! The summary ("What changed") is what an operator reads first; an item with
//! no row is a breaking change they never see. Three items (53, 58, 63) merged
//! with a section and no row, so the check is mechanical now rather than a
//! reviewer's memory.

use std::collections::BTreeSet;

const DOC: &str = include_str!("../docs/UPGRADING-4.0.md");

/// The item numbers in the summary table: the `| N |` rows between the
/// `## What changed` heading and the next `## ` heading. Scoped to that block
/// so a numbered row in some other table cannot stand in for a summary row.
fn summary_rows(doc: &str) -> BTreeSet<u32> {
    let mut in_summary = false;
    let mut rows = BTreeSet::new();
    for line in doc.lines() {
        if line.starts_with("## ") {
            in_summary = line.trim() == "## What changed";
            continue;
        }
        if !in_summary {
            continue;
        }
        let Some(rest) = line.strip_prefix('|') else {
            continue;
        };
        let cell = rest.split('|').next().unwrap_or("").trim();
        if let Ok(n) = cell.parse::<u32>() {
            assert!(rows.insert(n), "item {n} has two summary rows");
        }
    }
    rows
}

/// The item numbers with a section: every `## N. ` heading.
fn sections(doc: &str) -> BTreeSet<u32> {
    let mut found = BTreeSet::new();
    for line in doc.lines() {
        let Some(rest) = line.strip_prefix("## ") else {
            continue;
        };
        let Some((number, _)) = rest.split_once(". ") else {
            continue;
        };
        if let Ok(n) = number.parse::<u32>() {
            assert!(found.insert(n), "item {n} has two sections");
        }
    }
    found
}

#[test]
fn every_numbered_item_has_a_summary_row_and_every_row_an_item() {
    let rows = summary_rows(DOC);
    let sections = sections(DOC);
    for known in [1, 54, 58, 63] {
        assert!(
            sections.contains(&known) && rows.contains(&known),
            "item {known} is in the file; the parser must see its section and row"
        );
    }
    assert!(
        sections.len() > 10 && rows.len() > 10,
        "the parser found {} sections and {} rows; it no longer matches the file's shape",
        sections.len(),
        rows.len()
    );
    let missing_rows: Vec<_> = sections.difference(&rows).collect();
    let missing_sections: Vec<_> = rows.difference(&sections).collect();
    assert!(
        missing_rows.is_empty() && missing_sections.is_empty(),
        "docs/UPGRADING-4.0.md: items with a section but no `| N |` row in \
         \"What changed\": {missing_rows:?}; rows with no `## N.` section: \
         {missing_sections:?}"
    );
}

/// The two parsers, on a fixture, so a green real-file check cannot be a
/// parser that silently finds nothing (the size floor above guards the same
/// thing on the real file). The fixture carries the real file's awkward
/// shapes: a two-digit heading, prose inside the summary block, and a
/// numbered row in another table.
#[test]
fn the_parsers_see_rows_and_sections_where_they_are() {
    let doc = "## What changed\n\n| # | Change | Action |\n|---|---|---|\n| 1 | a | b |\n\
               | 54 | c | d |\n\nNumbers 18-20 are intentionally unused.\n\n## 1. One\n\n\
               text\n\n| 9 | not a summary row | x |\n\n## 54. Fifty-four\n\n\
               ## After upgrading\n";
    assert_eq!(summary_rows(doc), BTreeSet::from([1, 54]));
    assert_eq!(sections(doc), BTreeSet::from([1, 54]));
}

#[test]
#[should_panic(expected = "item 3 has two summary rows")]
fn a_duplicated_row_is_refused() {
    summary_rows("## What changed\n\n| 3 | a | b |\n| 3 | c | d |\n");
}

#[test]
#[should_panic(expected = "item 4 has two sections")]
fn a_duplicated_section_is_refused() {
    sections("## 4. One\n\n## 4. Again\n");
}
