// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8185: the guide checks' view of pending `upgrading.d/` fragments,
//! the guide source `UPGRADING_DOC` selects, and supersession by title.
//! Included by `tests/upgrading_summary_rows.rs`, whose helpers it uses.

use super::{DOC, DocSource, MARKER, doc_source, parse_marker, read_doc, sections};

/// The successor a `> Superseded in part by <name>: ...` note names. A title
/// may itself contain `:`, so the longest known title (numbered or pending)
/// followed by `:` wins; a name matching no title ends at the first `:`.
pub(super) fn successor_name<'a>(rest: &'a str, doc: &str, pending: &[String]) -> &'a str {
    let numbered = doc.lines().filter_map(|l| {
        l.strip_prefix("## ")?
            .split_once(". ")
            .map(|(_, t)| t.trim())
    });
    numbered
        .chain(pending.iter().map(String::as_str))
        .filter(|t| rest.strip_prefix(t).is_some_and(|r| r.starts_with(':')))
        .max_by_key(|t| t.len())
        .map_or_else(
            || rest.split_once(':').map_or(rest, |(name, _)| name).trim(),
            |t| &rest[..t.len()],
        )
}

#[test]
fn a_successor_title_may_contain_a_colon() {
    let doc = "## 1. One\n\n## 3. OAuth: issuer credentials\n";
    let pending = vec!["Cap: search -C".to_string()];
    assert_eq!(
        successor_name("OAuth: issuer credentials: the rest", doc, &pending),
        "OAuth: issuer credentials"
    );
    assert_eq!(
        successor_name("Cap: search -C: why", doc, &pending),
        "Cap: search -C"
    );
    assert_eq!(
        successor_name("Nothing known: why", doc, &pending),
        "Nothing known"
    );
    // Overlapping titles: the longer one that fits wins, not the first listed.
    let overlap = "## 4. OAuth: issuer\n\n## 5. OAuth: issuer credentials\n";
    assert_eq!(
        successor_name("OAuth: issuer credentials: why", overlap, &[]),
        "OAuth: issuer credentials"
    );
    assert_eq!(
        successor_name("OAuth: issuer: why", overlap, &[]),
        "OAuth: issuer"
    );
}

/// Titles of the pending fragments the checks see: none when `UPGRADING_DOC`
/// names an assembled guide, which already holds them as numbered items.
pub(super) fn pending_titles() -> Vec<String> {
    if doc_source(std::env::var_os("UPGRADING_DOC")) != DocSource::Committed {
        return Vec::new();
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("upgrading.d");
    pending_fragments(&dir)
        .iter()
        .filter_map(|(_, text)| text.lines().find_map(|l| l.strip_prefix("## ")))
        .map(|t| t.trim().to_string())
        .collect()
}

/// MIK-8185: `UPGRADING_DOC` selects the assembled guide; unset, the committed one.
#[test]
fn doc_source_follows_upgrading_doc() {
    assert_eq!(doc_source(None), DocSource::Committed);
    assert_eq!(
        doc_source(Some("/tmp/assembled.md".into())),
        DocSource::Assembled("/tmp/assembled.md".into())
    );
    assert_eq!(doc_source(Some("".into())), DocSource::Committed);
}

/// MIK-8185: an assembled guide is read from disk, CRLF normalised; the
/// committed one is the compiled-in file.
#[test]
fn read_doc_reads_the_selected_guide() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("UPGRADING-4.0.md");
    std::fs::write(&path, "# Assembled\r\n\r\n## 1. One\r\n").expect("write");
    assert_eq!(
        read_doc(&DocSource::Assembled(path)),
        "# Assembled\n\n## 1. One\n"
    );
    assert_eq!(read_doc(&DocSource::Committed), DOC.replace("\r\n", "\n"));
}

/// The pending `upgrading.d/` fragments, by file name, CRLF normalised. None in
/// a tree without the directory.
pub(super) fn pending_fragments(dir: &std::path::Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, String)> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|e| e == "md")
        })
        .map(|name| {
            let text = std::fs::read_to_string(dir.join(&name))
                .unwrap_or_else(|e| panic!("upgrading.d/{name}: {e}"))
                .replace("\r\n", "\n");
            (name, text)
        })
        .collect();
    found.sort();
    found
}

/// A fragment's startup marker text: the first non-blank line after its one
/// `## ` title, which must start with `**Startup:** `.
pub(super) fn fragment_marker<'a>(name: &str, text: &'a str) -> Result<&'a str, String> {
    let mut after_title = text.lines().skip_while(|l| !l.starts_with("## ")).skip(1);
    let line = after_title.find(|l| !l.trim().is_empty()).unwrap_or("");
    line.strip_prefix(MARKER)
        .ok_or_else(|| format!("upgrading.d/{name}: the first line after the title must start with `{MARKER}`: {line:?}"))
}

/// MIK-8185: every pending fragment's marker obeys the same grammar as a
/// numbered item's, so a fragment cannot carry a marker the guide would refuse.
#[test]
fn every_pending_fragment_has_a_valid_startup_marker() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("upgrading.d");
    for (name, text) in pending_fragments(&dir) {
        let marker = fragment_marker(&name, &text).unwrap_or_else(|e| panic!("{e}"));
        parse_marker(marker).unwrap_or_else(|e| panic!("upgrading.d/{name}: {e}"));
    }
}

#[test]
fn fragment_markers_on_fixtures() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(
        dir.path().join("3700.md"),
        "---\r\nchange: c\r\naction: a\r\n---\r\n## T\r\n\r\n**Startup:** refuses to start\r\n",
    )
    .expect("write");
    std::fs::write(dir.path().join(".frozen-max"), "3\n").expect("write");
    std::fs::write(dir.path().join(".gitkeep"), "").expect("write");
    let found = pending_fragments(dir.path());
    assert_eq!(found.len(), 1, "only *.md files are fragments: {found:?}");
    assert_eq!(found[0].0, "3700.md");
    assert_eq!(
        fragment_marker(&found[0].0, &found[0].1),
        Ok("refuses to start")
    );
    let late = "---\nchange: c\naction: a\n---\n## T\n\nProse.\n\n**Startup:** no notice\n";
    let err = fragment_marker("3701.md", late).unwrap_err();
    assert!(err.contains("upgrading.d/3701.md"), "{err}");
    let bad = fragment_marker(
        "3702.md",
        "---\nchange: c\naction: a\n---\n## T\n\n**Startup:** prints notices\n",
    )
    .and_then(|m| parse_marker(m).map(|_| m));
    assert!(bad.is_err(), "a bad clause must be refused");
    assert!(pending_fragments(&dir.path().join("absent")).is_empty());
}

/// What a supersession note names: an item number, or (for an entry still in
/// `upgrading.d/`, which has no number yet) its title.
#[derive(Debug, Clone, Copy)]
pub(super) enum SectionKey {
    Number(u32),
    #[allow(dead_code)]
    Title(&'static str),
}

/// Check that `name` (the text between `Superseded in part by ` and `:`) names
/// an item later than `from`: `item N` with N > from and a section, or the
/// title of a later numbered item or of a pending fragment (always later).
pub(super) fn resolve_successor(
    doc: &str,
    fragment_titles: &[String],
    from: u32,
    name: &str,
) -> Result<(), String> {
    let later = |n: u32| {
        if n > from {
            Ok(())
        } else {
            Err(format!(
                "item {from} names item {n} as superseding it; it must be a later item"
            ))
        }
    };
    if let Some(n) = name
        .strip_prefix("item ")
        .and_then(|n| n.parse::<u32>().ok())
    {
        return if sections(doc).contains(&n) {
            later(n)
        } else {
            Err(format!(
                "item {from} names item {n}, and there is no item {n}"
            ))
        };
    }
    for line in doc.lines() {
        if let Some((n, title)) = line.strip_prefix("## ").and_then(|r| r.split_once(". "))
            && title.trim() == name
            && let Ok(n) = n.parse::<u32>()
        {
            return later(n);
        }
    }
    if fragment_titles.iter().any(|t| t == name) {
        return Ok(()); // a pending entry is numbered after every committed one
    }
    Err(format!(
        "item {from} names `{name}`, which is no item or pending entry"
    ))
}

#[test]
fn successors_resolve_by_number_or_title() {
    let doc = "## 1. One\n\n## 3. Three\n\n## Upgrading from 3.5.x: a walkthrough\n";
    let pending = vec!["Alpha".to_string()];
    for (from, name) in [(1, "item 3"), (1, "Three"), (3, "Alpha")] {
        assert_eq!(
            resolve_successor(doc, &pending, from, name),
            Ok(()),
            "{from} -> {name}"
        );
    }
    for (from, name, why) in [
        (3, "item 1", "later"),
        (3, "One", "later"),
        (1, "item 2", "no item 2"),
        (1, "Nope", "no item or pending entry"),
    ] {
        let err = resolve_successor(doc, &pending, from, name).unwrap_err();
        assert!(err.contains(why), "{from} -> {name}: {err}");
    }
}
