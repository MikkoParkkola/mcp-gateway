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

// MIK-8185: pending `upgrading.d/` fragments, and supersession by title.
#[path = "common/upgrading_fragments.rs"]
mod fragments;
use fragments::{SectionKey, pending_titles, resolve_successor, successor_name};

/// Which guide the checks read. CI sets `UPGRADING_DOC` to the guide with every
/// pending `upgrading.d/` fragment assembled (MIK-8185), so a fragment that
/// would break a check at release breaks its own PR instead.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DocSource {
    /// The committed guide, compiled in.
    Committed,
    /// A guide on disk: the release-preparation dry run.
    Assembled(std::path::PathBuf),
}

/// The source `UPGRADING_DOC`'s value selects. Takes the value, not the
/// environment, so both branches are tested without setting a variable.
fn doc_source(var: Option<std::ffi::OsString>) -> DocSource {
    match var {
        Some(path) if !path.is_empty() => DocSource::Assembled(path.into()),
        _ => DocSource::Committed,
    }
}

/// The guide text for `source`, line endings normalised: a Windows checkout
/// reads it with CRLF.
fn read_doc(source: &DocSource) -> String {
    match source {
        DocSource::Committed => DOC.replace("\r\n", "\n"),
        DocSource::Assembled(path) => std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("UPGRADING_DOC={}: {e}", path.display()))
            .replace("\r\n", "\n"),
    }
}

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
    let rows = summary_rows(&GUIDE);
    let sections = sections(&GUIDE);
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
    if let Err(problems) = check_numbering(&GUIDE, PUBLISHED_MAX) {
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

/// The guide, line endings normalised: a Windows checkout reads it with CRLF.
static GUIDE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| read_doc(&doc_source(std::env::var_os("UPGRADING_DOC"))));

/// The startup marker's grammar, shared with `scripts/release/upgrading_fragments.py`
/// through one file (MIK-8246): the marker prefix, the clauses, and the test
/// vectors both suites run.
#[derive(serde::Deserialize)]
struct Grammar {
    marker: String,
    clauses: Vec<ClauseSpec>,
    valid: Vec<String>,
    invalid: Vec<InvalidVector>,
}

/// One clause: its words, its place in a marker (notice first, then the
/// refusal, then a failed backend, then a failed capability file) and its role.
#[derive(Debug, serde::Deserialize)]
struct ClauseSpec {
    words: String,
    place: u8,
    role: String,
    #[serde(default)]
    needs_notice_field: bool,
}

/// A marker text the grammar refuses, and the token of the rule that refuses it.
#[derive(serde::Deserialize)]
struct InvalidVector {
    text: String,
    reason: String,
}

static GRAMMAR: std::sync::LazyLock<Grammar> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../scripts/release/upgrading-startup-grammar.json"
    ))
    .expect("scripts/release/upgrading-startup-grammar.json is valid")
});

/// Parse a marker's text (after the grammar's marker prefix) into its clauses.
/// An error starts with the reason token the grammar file names for the rule.
///
/// Each item states its own startup behaviour in its own section, so adding an
/// item touches only that section and its summary row. The intro used to list
/// item numbers for each behaviour, and every change that added an item edited
/// the same intro lines, so each merge conflicted with every open change.
fn parse_marker(text: &str) -> Result<Vec<&'static ClauseSpec>, String> {
    let mut clauses = Vec::new();
    let mut last_place = None;
    for part in text.split("; ") {
        let (clause, rest) = GRAMMAR
            .clauses
            .iter()
            .find_map(|c| part.strip_prefix(c.words.as_str()).map(|rest| (c, rest)))
            .ok_or_else(|| format!("unknown_clause: unrecognised clause {part:?}"))?;
        match rest.strip_prefix(", ") {
            Some(detail) if detail.trim().is_empty() => {
                return Err(format!(
                    "empty_detail: empty text after the comma in {part:?}"
                ));
            }
            Some(_) => {}
            None if rest.is_empty() => {}
            None => {
                return Err(format!(
                    "detail_needs_comma: text must follow a comma in {part:?}"
                ));
            }
        }
        if part.contains(';') {
            return Err(format!(
                "semicolon_in_text: free text may not contain ';': {part:?}"
            ));
        }
        if last_place.is_some_and(|last| clause.place <= last) {
            return Err(format!("order: clause out of order or repeated: {part:?}"));
        }
        last_place = Some(clause.place);
        clauses.push(clause);
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
    line.strip_prefix(GRAMMAR.marker.as_str()).ok_or_else(|| {
        format!(
            "item {n} does not start with `{}`: {line:?}",
            GRAMMAR.marker
        )
    })
}

#[test]
fn every_section_starts_with_a_valid_startup_marker() {
    let mut refusing = 0;
    for n in sections(&GUIDE) {
        let text = marker_of(&GUIDE, n).unwrap_or_else(|e| panic!("{e}"));
        let clauses = parse_marker(text).unwrap_or_else(|e| panic!("item {n}: {e}"));
        let body = section_body(&GUIDE, n);
        assert_eq!(
            body.matches(GRAMMAR.marker.as_str()).count(),
            1,
            "item {n} has more than one startup marker"
        );
        refusing += usize::from(clauses.iter().any(|c| c.role == "refusal"));
    }
    assert!(
        refusing > 0,
        "no item refuses the start: the parser found nothing"
    );
}

/// The shared vectors: both parsers accept every `valid` text and refuse every
/// `invalid` one for the rule its reason token names.
#[test]
fn marker_grammar() {
    for ok in &GRAMMAR.valid {
        assert!(
            parse_marker(ok).is_ok(),
            "{ok:?} must parse: {:?}",
            parse_marker(ok)
        );
    }
    for bad in &GRAMMAR.invalid {
        let err = parse_marker(&bad.text).expect_err(&format!("{:?} must be refused", bad.text));
        assert!(
            err.contains(&bad.reason),
            "{:?} must be refused for {}: {err}",
            bad.text,
            bad.reason
        );
    }
}

#[test]
fn grammar_table_is_well_formed() {
    let words: BTreeSet<_> = GRAMMAR.clauses.iter().map(|c| c.words.as_str()).collect();
    assert_eq!(words.len(), GRAMMAR.clauses.len(), "clause words repeat");
    for c in &GRAMMAR.clauses {
        assert!(
            ["notice", "refusal", "failure"].contains(&c.role.as_str()),
            "{:?} has role {:?}",
            c.words,
            c.role
        );
    }
    let places: BTreeSet<_> = GRAMMAR.clauses.iter().map(|c| c.place).collect();
    assert_eq!(places, BTreeSet::from([0, 1, 2, 3]));
    let flagged = GRAMMAR.clauses.iter().filter(|c| c.needs_notice_field);
    assert_eq!(
        flagged.count(),
        1,
        "exactly one clause needs the notice field"
    );
    assert_eq!(GRAMMAR.marker, "**Startup:** ");
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
const SUPERSEDED: &[(u32, SectionKey)] = &[
    (10, SectionKey::Number(65)),
    (17, SectionKey::Number(51)),
    (21, SectionKey::Number(25)),
    (22, SectionKey::Number(25)),
    (33, SectionKey::Number(44)),
    (40, SectionKey::Number(41)),
    (43, SectionKey::Number(49)),
    (35, SectionKey::Number(96)),
    (54, SectionKey::Number(96)),
];

#[test]
fn superseded_items_point_at_their_successor() {
    for &(old, new) in SUPERSEDED {
        let note = match new {
            SectionKey::Number(n) => format!("> Superseded in part by item {n}:"),
            SectionKey::Title(t) => format!("> Superseded in part by {t}:"),
        };
        assert!(
            section_body(&GUIDE, old).contains(&note),
            "item {old} must carry `{note}`"
        );
    }
    let sections = sections(&GUIDE);
    for n in &sections {
        let body = section_body(&GUIDE, *n);
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
        // MIK-8185: a successor still in `upgrading.d/` is named by its title.
        let pending = pending_titles();
        for line in body.lines() {
            let Some(rest) = line.strip_prefix("> Superseded in part by ") else {
                continue;
            };
            if rest.starts_with("item") {
                continue;
            }
            let name = successor_name(rest, &GUIDE, &pending);
            resolve_successor(&GUIDE, &pending, *n, name).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}

/// The walkthrough section.
fn walkthrough() -> &'static str {
    let start = GUIDE
        .find("\n## Upgrading from 3.5.x: a walkthrough\n")
        .expect("walkthrough section");
    let body = &GUIDE[start + 1..];
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
        summary_rows(&GUIDE).contains(&96),
        "item 96 has no summary row"
    );
    let body = section_body(&GUIDE, 96);
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
