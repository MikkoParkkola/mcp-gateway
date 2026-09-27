// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `docs/UPGRADING-4.0.md`: every numbered item has a row in the summary table,
//! and every row has an item.
//!
//! The summary ("What changed") is what an operator reads first; an item with
//! no row is a breaking change they never see. Three items (53, 58, 63) merged
//! with a section and no row, so the check is mechanical now rather than a
//! reviewer's memory.

use std::collections::{BTreeMap, BTreeSet};

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

/// The highest item number published so far. Item numbers are public
/// identifiers and never renumbered, so deleting the last item (row and
/// section together) must fail too, not just shrink the range.
const PUBLISHED_MAX: u32 = 70;

/// The Change cell of every summary row, by item number.
fn summary_cells(doc: &str) -> BTreeMap<u32, String> {
    let mut in_summary = false;
    let mut cells = BTreeMap::new();
    for line in doc.lines() {
        if line.starts_with("## ") {
            in_summary = line.trim() == "## What changed";
            continue;
        }
        let Some(rest) = line.strip_prefix('|').filter(|_| in_summary) else {
            continue;
        };
        let mut parts = rest.split('|').map(str::trim);
        if let Ok(n) = parts.next().unwrap_or("").parse::<u32>() {
            cells.insert(n, parts.next().unwrap_or("").to_string());
        }
    }
    cells
}

/// A row that stands for a number with no section of its own.
fn is_gap_row(cell: &str) -> bool {
    cell == "Never assigned" || cell.starts_with("Reserved: ") || cell.starts_with("Withdrawn")
}

/// Every number from 1 to the highest has one row; a number with a section
/// has an ordinary row, and a number without one has a gap row.
fn check_numbering(doc: &str, floor: u32) -> Result<(), String> {
    let rows = summary_rows(doc);
    let sections = sections(doc);
    let cells = summary_cells(doc);
    let max = rows
        .iter()
        .chain(&sections)
        .copied()
        .max()
        .unwrap_or(0)
        .max(floor);
    let mut problems = Vec::new();
    for n in 1..=max {
        match (cells.get(&n), sections.contains(&n)) {
            (None, true) => problems.push(format!("item {n} has a section and no summary row")),
            (None, false) => problems.push(format!("number {n} has neither a row nor a section")),
            (Some(cell), true) if is_gap_row(cell) => {
                problems.push(format!("item {n} has a section but its row says `{cell}`"));
            }
            (Some(cell), false) if !is_gap_row(cell) => problems.push(format!(
                "item {n} has a row and no section; mark it `Never assigned` or `Reserved: ...`"
            )),
            _ => {}
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[test]
fn every_number_has_a_row_and_every_gap_is_explained() {
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
    if let Err(problems) = check_numbering(DOC, PUBLISHED_MAX) {
        panic!("docs/UPGRADING-4.0.md: {problems}");
    }
}

#[test]
fn numbering_rules_on_fixtures() {
    let head = "## What changed\n\n| # | Change | Action |\n|---|---|---|\n";
    let ok = format!(
        "{head}| 1 | a | b |\n| 2 | Never assigned | None |\n| 3 | Reserved: lands with #9 | None yet |\n| 4 | d | e |\n\n## 1. A\n\n## 4. D\n"
    );
    assert_eq!(check_numbering(&ok, 4), Ok(()));
    let reserved_with_section = ok.replace("## 4. D", "## 3. C\n\n## 4. D");
    assert!(
        check_numbering(&reserved_with_section, 4)
            .unwrap_err()
            .contains("item 3 has a section")
    );
    let plain_without_section = ok.replace("| 2 | Never assigned |", "| 2 | b |");
    assert!(
        check_numbering(&plain_without_section, 4)
            .unwrap_err()
            .contains("item 2 has a row and no section")
    );
    let missing_row = ok.replace("| 2 | Never assigned | None |\n", "");
    assert!(
        check_numbering(&missing_row, 4)
            .unwrap_err()
            .contains("number 2 has neither")
    );
    let last_deleted = ok
        .replace("| 4 | d | e |\n", "")
        .replace("\n## 4. D\n", "\n");
    assert!(
        check_numbering(&last_deleted, 4)
            .unwrap_err()
            .contains("number 4 has neither")
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

/// Item numbers written as `1-4, 6, 11 and 58` in `text`.
fn numbers_in(text: &str) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let cleaned = text.replace(" and ", ", ").replace(" or ", ", ");
    for part in cleaned.split(',').map(str::trim) {
        if let Some((a, b)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                out.extend(a..=b);
            }
        } else if let Ok(n) = part.parse::<u32>() {
            out.insert(n);
        }
    }
    out
}

/// The text between `after` and the next `until` in the intro.
fn intro_span(after: &str, until: &str) -> &'static str {
    let intro = DOC.split("## What changed").next().unwrap();
    let start = intro
        .find(after)
        .unwrap_or_else(|| panic!("intro lost `{after}`"))
        + after.len();
    let rest = &intro[start..];
    &rest[..rest
        .find(until)
        .unwrap_or_else(|| panic!("intro lost `{until}`"))]
}

/// Entries of the `NOTICE_4_0_0_ITEMS` slice, counted from the source text:
/// each entry starts on its own line indented four spaces, as a string
/// literal or a `super::...::ITEM` constant; continuation lines start at
/// column 0 and comments are skipped.
fn notice_entries_in_source() -> usize {
    let src = include_str!("../src/commands/upgrade_notice_items.rs");
    let body = src
        .split("NOTICE_4_0_0_ITEMS: &[&str] = &[")
        .nth(1)
        .expect("slice");
    let body = &body[..body.find("\n];").expect("slice end")];
    body.lines()
        .filter(|l| l.starts_with("    \"") || l.starts_with("    super::"))
        .count()
}

/// The intro's lists: the two refuses-start lists agree, every listed number
/// is a real section, the notice list is as long as the notice the binary
/// prints, and every section is either in the notice list or explained in
/// the no-notice paragraph.
#[test]
fn intro_lists_cover_every_item() {
    let sections = sections(DOC);
    let refuses = numbers_in(intro_span("unless one of items ", " refuses it"));
    let bold = numbers_in(intro_span("**Items ", " refuse the gateway's start"));
    assert_eq!(refuses, bold, "the two refuses-start lists differ");
    assert!(
        refuses.len() >= 21,
        "the refuses-start list shrank to {refuses:?}"
    );
    let notice = numbers_in(intro_span("notice to stderr listing\nitems ", " below"));
    assert_eq!(
        notice.len(),
        notice_entries_in_source(),
        "the intro's notice list and NOTICE_4_0_0_ITEMS differ in length"
    );
    let explained = intro_span("The rest of the list has no startup notice.", "**Items ");
    let no_notice = numbers_after_item(explained);
    let both: Vec<_> = notice.intersection(&no_notice).collect();
    assert!(
        both.is_empty(),
        "items listed both with a startup notice and without one: {both:?}"
    );
    for n in refuses.iter().chain(&notice).chain(&no_notice) {
        assert!(
            sections.contains(n),
            "the intro lists item {n}, which has no section"
        );
    }
    let unexplained: Vec<_> = sections
        .iter()
        .filter(|n| !notice.contains(n) && !no_notice.contains(n))
        .collect();
    assert!(
        unexplained.is_empty(),
        "items with no startup notice and no reason in the intro: {unexplained:?}"
    );
}

/// Every number written after "item" or "items" in `text`, through lists
/// such as `12, 13 and 16` or `1-4`.
fn numbers_after_item(text: &str) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let mut listing = false;
    for word in text.split_whitespace() {
        let word = word.trim_end_matches(['.', ',', ';', ':']);
        if word.eq_ignore_ascii_case("item") || word.eq_ignore_ascii_case("items") {
            listing = true;
            continue;
        }
        if !listing {
            continue;
        }
        let found = numbers_in(word);
        if !found.is_empty() {
            out.extend(found);
        } else if word != "and" && word != "or" {
            listing = false;
        }
    }
    out
}

#[test]
fn item_lists_parse() {
    assert_eq!(
        numbers_after_item(
            "Items 5 and 9 are x. Item 10 y, and so does item 21. Items 1-3,\n7 or 8 z"
        ),
        BTreeSet::from([1, 2, 3, 5, 7, 8, 9, 10, 21])
    );
}

/// The body of section `n`, heading excluded.
fn section_body(doc: &str, n: u32) -> &str {
    let heading = format!("\n## {n}. ");
    let start = doc
        .find(&heading)
        .unwrap_or_else(|| panic!("no section {n}"));
    let body = &doc[start + heading.len()..];
    &body[..body.find("\n## ").unwrap_or(body.len())]
}

/// Items a later item changed, and the item that changed them. A reader who
/// lands on the older item must be pointed at the newer one.
const SUPERSEDED: &[(u32, u32)] = &[
    (10, 65),
    (17, 51),
    (21, 25),
    (22, 25),
    (33, 44),
    (40, 41),
    (43, 49),
];

#[test]
fn superseded_items_point_at_their_successor() {
    for &(old, new) in SUPERSEDED {
        let note = format!("> Superseded in part by item {new}:");
        assert!(
            section_body(DOC, old).contains(&note),
            "item {old} must carry `{note}`"
        );
    }
    let sections = sections(DOC);
    for n in &sections {
        let body = section_body(DOC, *n);
        for later in numbers_after_item(
            &body
                .lines()
                .filter(|l| l.starts_with("> Superseded in part by item"))
                .map(|l| l.trim_start_matches("> Superseded in part by "))
                .collect::<Vec<_>>()
                .join(" "),
        ) {
            assert!(
                later > *n && sections.contains(&later),
                "item {n} names item {later} as superseding it; it must be a later item"
            );
        }
    }
}

/// The walkthrough section.
fn walkthrough() -> &'static str {
    let start = DOC
        .find("\n## Upgrading from 3.5.x: a walkthrough\n")
        .expect("walkthrough section");
    let body = &DOC[start + 1..];
    &body[..body[3..].find("\n## ").map_or(body.len(), |i| i + 3)]
}

/// Every `mcp-gateway` command in the walkthrough's code blocks parses with
/// the real CLI, and every rehearsal check it cites exists in the script CI
/// runs.
#[test]
fn walkthrough_commands_and_checks_are_real() {
    use clap::Parser as _;
    let mut commands = Vec::new();
    let mut in_fence = false;
    for line in walkthrough().lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            let line = line.split(" #").next().unwrap_or(line);
            for part in line.split('|') {
                if let Some(at) = part.find("mcp-gateway ") {
                    commands.push(part[at..].trim().to_string());
                }
            }
        }
    }
    assert!(commands.len() >= 4, "found only {commands:?}");
    for command in &commands {
        if let Err(e) = mcp_gateway::cli::Cli::try_parse_from(command.split_whitespace()) {
            panic!("walkthrough command `{command}` does not parse: {e}");
        }
    }
    let script = include_str!("../scripts/release/nfr_upgrade_1_rehearsal.sh");
    let mut cited = 0;
    for piece in walkthrough().split('[').skip(1) {
        let inner = piece.split(']').next().unwrap_or("");
        for id in inner
            .split(',')
            .map(str::trim)
            .filter(|id| id.starts_with("PHASE"))
        {
            cited += 1;
            assert!(
                script.contains(&format!("record \"{id}\" \"PASS\"")),
                "walkthrough cites rehearsal check {id}, which the script does not record"
            );
        }
    }
    assert!(cited >= 10, "found only {cited} rehearsal checks cited");
}
