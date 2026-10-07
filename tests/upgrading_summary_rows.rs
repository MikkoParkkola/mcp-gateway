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
const PUBLISHED_MAX: u32 = 100;

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

/// Columns every summary row must fill. A breaking change is weighed by what
/// it takes away; the row has to say what the reader gets back and what to do,
/// not only what changed.
const REQUIRED_COLUMNS: [&str; 2] = ["What you gain", "Action needed"];

/// The summary header names every required column, and every numbered row has
/// the header's cell count with each required cell non-empty.
fn check_columns(doc: &str) -> Result<(), String> {
    let mut in_summary = false;
    let mut header: Option<Vec<&str>> = None;
    let mut problems = Vec::new();
    for line in doc.lines() {
        if line.starts_with("## ") {
            in_summary = line.trim() == "## What changed";
            continue;
        }
        if !in_summary || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let Some(head) = &header else {
            header = Some(cells);
            continue;
        };
        let Ok(n) = cells[0].parse::<u32>() else {
            continue; // the |---| separator
        };
        if cells.len() != head.len() {
            problems.push(format!(
                "item {n} has {} cells, the header {}",
                cells.len(),
                head.len()
            ));
            continue;
        }
        for column in REQUIRED_COLUMNS {
            if let Some(i) = head.iter().position(|h| *h == column)
                && cells[i].is_empty()
            {
                problems.push(format!("item {n} has an empty `{column}` cell"));
            }
        }
    }
    let Some(head) = header else {
        return Err("no summary table under `## What changed`".into());
    };
    for column in REQUIRED_COLUMNS {
        if !head.contains(&column) {
            problems.insert(0, format!("the summary header has no `{column}` column"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[test]
fn every_summary_row_says_what_you_gain_and_what_to_do() {
    if let Err(problems) = check_columns(&GUIDE) {
        panic!("docs/UPGRADING-4.0.md: {problems}");
    }
}

#[test]
fn column_rules_on_fixtures() {
    let ok = "## What changed\n\n| # | Change | What you gain | Action needed |\n|---|---|---|---|\n\
              | 1 | a | g | b |\n| 2 | Never assigned | None — number never assigned | None |\n\n## 1. A\n";
    assert_eq!(check_columns(ok), Ok(()));
    let old_header =
        "## What changed\n\n| # | Change | Action needed |\n|---|---|---|\n| 1 | a | b |\n";
    assert!(
        check_columns(old_header)
            .unwrap_err()
            .contains("no `What you gain` column")
    );
    assert!(
        check_columns(&ok.replace("| 1 | a | g | b |", "| 1 | a |  | b |"))
            .unwrap_err()
            .contains("item 1 has an empty `What you gain` cell")
    );
    assert!(
        check_columns(&ok.replace("| 1 | a | g | b |", "| 1 | a | g |  |"))
            .unwrap_err()
            .contains("item 1 has an empty `Action needed` cell")
    );
    assert!(
        check_columns(&ok.replace("| 1 | a | g | b |", "| 1 | a | b |"))
            .unwrap_err()
            .contains("item 1 has 3 cells, the header 4")
    );
    assert!(
        check_columns(&ok.replace("| 1 | a | g | b |", "| 1 | a | g | b | x |"))
            .unwrap_err()
            .contains("item 1 has 5 cells, the header 4")
    );
    assert!(
        check_columns(&ok.replace("| Action needed |", "| Action |"))
            .unwrap_err()
            .contains("no `Action needed` column")
    );
    // Columns are found by name, so their order is free.
    let reordered = ok
        .replace("| Change | What you gain |", "| What you gain | Change |")
        .replace("| 1 | a | g |", "| 1 | g | a |");
    assert_eq!(check_columns(&reordered), Ok(()));
    assert!(check_columns("## What changed\n\nno table\n").is_err());
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

/// The guide, line endings normalised: a Windows checkout reads it with CRLF.
static GUIDE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| DOC.replace("\r\n", "\n"));

/// What a startup marker's clause says the item does at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Clause {
    PrintsNotice,
    NoNotice,
    RefusesToStart,
    FailsBackend,
    FailsCapabilityFile,
}

impl Clause {
    /// The clause's words, and its place in a marker: notice first, then the
    /// refusal, then a failed backend, then a failed capability file.
    const ALL: [(Self, &'static str, u8); 5] = [
        (Self::PrintsNotice, "prints a notice", 0),
        (Self::NoNotice, "no notice", 0),
        (Self::RefusesToStart, "refuses to start", 1),
        (Self::FailsBackend, "fails a backend", 2),
        (Self::FailsCapabilityFile, "fails a capability file", 3),
    ];
}

/// The marker every item section starts with: its startup behaviour.
const MARKER: &str = "**Startup:** ";

/// Parse a marker's text (after `**Startup:** `) into its clauses.
///
/// Each item states its own startup behaviour in its own section, so adding an
/// item touches only that section and its summary row. The intro used to list
/// item numbers for each behaviour, and every change that added an item edited
/// the same intro lines, so each merge conflicted with every open change.
fn parse_marker(text: &str) -> Result<Vec<Clause>, String> {
    let mut clauses = Vec::new();
    let mut last_place = None;
    for part in text.split("; ") {
        let (clause, place, rest) = Clause::ALL
            .iter()
            .find_map(|&(clause, words, place)| {
                part.strip_prefix(words).map(|rest| (clause, place, rest))
            })
            .ok_or_else(|| format!("unrecognised clause {part:?}"))?;
        match rest.strip_prefix(", ") {
            Some(detail) if detail.trim().is_empty() => {
                return Err(format!("empty text after the comma in {part:?}"));
            }
            Some(_) => {}
            None if rest.is_empty() => {}
            None => return Err(format!("text must follow a comma in {part:?}")),
        }
        if part.contains(';') {
            return Err(format!("free text may not contain ';': {part:?}"));
        }
        if last_place.is_some_and(|last| place <= last) {
            return Err(format!("clause out of order or repeated: {part:?}"));
        }
        last_place = Some(place);
        clauses.push(clause);
    }
    let effect = clauses.iter().any(|c| {
        matches!(
            c,
            Clause::RefusesToStart | Clause::FailsBackend | Clause::FailsCapabilityFile
        )
    });
    let notice = clauses
        .iter()
        .any(|c| matches!(c, Clause::PrintsNotice | Clause::NoNotice));
    if !notice && !effect {
        return Err(format!("no notice clause and no refusal in {text:?}"));
    }
    Ok(clauses)
}

/// Item `n`'s marker text: the first non-blank line after its heading.
fn marker_of(doc: &str, n: u32) -> Result<&str, String> {
    let line = section_body(doc, n)
        .lines()
        .skip(1)
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    line.strip_prefix(MARKER)
        .ok_or_else(|| format!("item {n} does not start with `{MARKER}`: {line:?}"))
}

#[test]
fn every_section_starts_with_a_valid_startup_marker() {
    let mut refusing = 0;
    for n in sections(&GUIDE) {
        let text = marker_of(&GUIDE, n).unwrap_or_else(|e| panic!("{e}"));
        let clauses = parse_marker(text).unwrap_or_else(|e| panic!("item {n}: {e}"));
        let body = section_body(&GUIDE, n);
        assert_eq!(
            body.matches(MARKER).count(),
            1,
            "item {n} has more than one startup marker"
        );
        refusing += usize::from(clauses.contains(&Clause::RefusesToStart));
    }
    assert!(
        refusing > 0,
        "no item refuses the start: the parser found nothing"
    );
}

#[test]
fn marker_grammar() {
    for ok in [
        "prints a notice",
        "no notice",
        "no notice, a reason",
        "refuses to start",
        "prints a notice; refuses to start, only for a bad `MODE`",
        "no notice, decided per backend; fails a backend, with one warning",
        "no notice, decided per capability file; fails a capability file, with an error",
    ] {
        assert!(
            parse_marker(ok).is_ok(),
            "{ok:?} must parse: {:?}",
            parse_marker(ok)
        );
    }
    for bad in [
        "",
        "prints notices",
        "refuses to start; prints a notice",
        "prints a notice; no notice",
        "fails a backend; fails a backend",
        "no notice,",
        "no notice, ",
        "no noticeX",
        "no notice, a; b",
    ] {
        assert!(parse_marker(bad).is_err(), "{bad:?} must be refused");
    }
}

/// The intro names no item: behaviour lives in each item's own marker.
#[test]
fn intro_enumerates_no_items() {
    let intro = GUIDE.split("## What changed").next().unwrap();
    assert!(
        !intro.lines().any(|l| l.starts_with("- Item ")),
        "the intro lists items again"
    );
    let named = numbers_after_item(intro);
    assert!(named.is_empty(), "the intro names items {named:?}");
    for pointer in [
        "the items below",
        "listed under the bold heading",
        "The rest of the list",
    ] {
        assert!(
            !intro.contains(pointer),
            "the intro still points at a list: {pointer:?}"
        );
    }
}

/// Every item that existed when the markers replaced the intro lists keeps the
/// classification the intro gave it. Frozen: items added later are not in it.
#[test]
fn migrated_markers_match_the_frozen_classification() {
    let fixture = include_str!("fixtures/upgrading_startup_markers_4_0.txt").replace("\r\n", "\n");
    let mut seen = BTreeSet::new();
    for line in fixture.lines().filter(|l| !l.starts_with('#')) {
        let (n, expected) = line.split_once('\t').expect("N<TAB>marker");
        let n: u32 = n.parse().expect("item number");
        assert!(seen.insert(n), "item {n} is in the fixture twice");
        let actual = marker_of(&GUIDE, n).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(actual, expected, "item {n}'s startup marker changed");
    }
    assert!(
        seen.len() >= 74,
        "the frozen classification lost items: {}",
        seen.len()
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
    (35, 96),
    (54, 96),
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

/// #2266: the owner rule has its own item, and it says who is accepted and the fix.
#[test]
fn owner_rule_item_has_a_row_a_section_and_the_fix() {
    assert!(
        summary_rows(DOC).contains(&96),
        "item 96 has no summary row"
    );
    let body = section_body(DOC, 96);
    for want in [
        "chown 1001",
        "chmod 600",
        "root",
        "Kubernetes",
        "Docker Compose",
    ] {
        assert!(body.contains(want), "item 96 must mention `{want}`");
    }
}
