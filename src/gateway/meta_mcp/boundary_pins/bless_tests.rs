// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The bless mode: with a ticket, a failing multiset check also appends the
//! rows it lists to add into `<name>.d/<ticket>.tsv`, and still fails. These
//! rows pass the ticket as a parameter against throwaway trees; none of them
//! sets the environment variable.

use std::path::Path;

use super::{BLESS_VAR, Bless, DIR, bless_from, delta_or_bless, pin_table_at};

const HEADER: &str = "# key\tnote";

/// A throwaway crate tree whose table `t` holds `rows` under [`HEADER`], with
/// `fragment` as `t.d/9977.tsv` when given (its bytes exactly).
fn tree(rows: &[&str], fragment: Option<&str>) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("a throwaway tree");
    let tables = root.path().join(DIR);
    std::fs::create_dir_all(tables.join("t.d")).expect("the table folders");
    let mut base = format!("{HEADER}\n");
    for row in rows {
        base.push_str(row);
        base.push('\n');
    }
    std::fs::write(tables.join("t.tsv"), base).expect("the base table");
    if let Some(bytes) = fragment {
        std::fs::write(tables.join("t.d").join("9977.tsv"), bytes).expect("a held fragment");
    }
    root
}

/// The check on table `t` under `root` for the `want` rows, blessed into
/// ticket 9977 when `bless` is set.
fn check(root: &Path, want: &[&str], bless: bool) -> Option<String> {
    let table = pin_table_at(root, "t");
    let pinned: Vec<(&Path, &str)> = table
        .rows()
        .iter()
        .map(|(file, row)| (file.as_path(), row.as_str()))
        .collect();
    let computed: Vec<String> = want.iter().map(|row| (*row).to_owned()).collect();
    let target = bless.then_some(Bless {
        root,
        ticket: "9977",
    });
    delta_or_bless("t", &computed, &pinned, target)
}

/// The fragment `t.d/9977.tsv` under `root`, or `None` when absent.
fn fragment(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join(DIR).join("t.d").join("9977.tsv")).ok()
}

fn base(root: &Path) -> String {
    std::fs::read_to_string(root.join(DIR).join("t.tsv")).expect("the base table")
}

/// R1: no bless, no write. A missing row fails as it always has and no
/// fragment appears.
#[test]
fn r1_without_a_ticket_nothing_is_written() {
    let root = tree(&["alpha"], None);
    let failure = check(root.path(), &["alpha", "beta"], false).expect("a missing row fails");
    assert!(failure.contains("rows to add (1;"), "{failure}");
    assert_eq!(fragment(root.path()), None);
}

/// R2: blessed, the missing row goes into the ticket's new fragment under
/// the base's header, and the run still fails; re-read, the same check
/// passes and writes nothing more. The base table never changes.
#[test]
fn r2_a_blessed_check_writes_the_rows_to_add_and_still_fails() {
    let root = tree(&["alpha"], None);
    let before = base(root.path());
    let failure = check(root.path(), &["alpha", "beta"], true).expect("a blessed run still fails");
    assert!(
        failure.contains("blessed: 1 rows written into t.d/9977.tsv"),
        "{failure}"
    );
    assert_eq!(
        fragment(root.path()).as_deref(),
        Some("# key\tnote\nbeta\n")
    );
    assert_eq!(
        check(root.path(), &["alpha", "beta"], true),
        None,
        "the next run passes"
    );
    assert_eq!(
        fragment(root.path()).as_deref(),
        Some("# key\tnote\nbeta\n")
    );
    assert_eq!(base(root.path()), before);
}

/// R2r: blessing adds a failure, never removes one. A row to remove still
/// fails the run after the row to add was written and re-read.
#[test]
fn r2r_a_row_to_remove_still_fails_a_blessed_run() {
    let root = tree(&["alpha", "stale"], None);
    check(root.path(), &["alpha", "beta"], true).expect("the first run fails");
    let again = check(root.path(), &["alpha", "beta"], true).expect("the removal still fails");
    assert!(again.contains("rows to remove (1)"), "{again}");
    assert!(!again.contains("rows to add"), "{again}");
}

/// R2d: a row the check wants twice is written twice, as its multiset
/// count says, and the re-read table then matches.
#[test]
fn r2d_a_repeated_row_is_written_as_often_as_it_is_missing() {
    let root = tree(&["alpha"], None);
    let want = ["alpha", "beta", "beta"];
    let failure = check(root.path(), &want, true).expect("the blessed run fails");
    assert!(failure.contains("blessed: 2 rows written"), "{failure}");
    assert_eq!(
        fragment(root.path()).as_deref(),
        Some("# key\tnote\nbeta\nbeta\n")
    );
    assert_eq!(check(root.path(), &want, true), None);
    // One copy already pinned and two wanted: exactly the missing one is
    // written, not the wanted count.
    let root = tree(&["alpha", "beta"], None);
    check(root.path(), &want, true).expect("the blessed run fails");
    assert_eq!(
        fragment(root.path()).as_deref(),
        Some("# key\tnote\nbeta\n")
    );
}

/// R2f: when the fragment cannot be written (the bless root is a plain file,
/// so no folder can be made under it), the run still fails with its
/// comparison, says the bless failed, and never claims rows were written.
#[test]
fn r2f_a_failed_write_keeps_the_failure_and_says_so() {
    let root = tree(&["alpha"], None);
    let blocked = root.path().join("a-plain-file");
    std::fs::write(&blocked, "no folder can be made here").expect("a plain file");
    let table = pin_table_at(root.path(), "t");
    let pinned: Vec<(&Path, &str)> = table
        .rows()
        .iter()
        .map(|(file, row)| (file.as_path(), row.as_str()))
        .collect();
    let target = Bless {
        root: &blocked,
        ticket: "9977",
    };
    let computed = ["alpha".to_owned(), "beta".to_owned()];
    let failure =
        delta_or_bless("t", &computed, &pinned, Some(target)).expect("the run still fails");
    assert!(failure.contains("rows to add (1;"), "{failure}");
    assert!(failure.contains("bless failed: cannot write"), "{failure}");
    assert!(!failure.contains("blessed:"), "{failure}");
}

/// R5: an existing fragment keeps every byte; the one missing row is
/// appended once. R5b: when its last line has no newline, one is added first.
#[test]
fn r5_an_existing_fragment_is_only_appended_to() {
    for (held, after) in [
        ("gamma\tkept by hand\n", "gamma\tkept by hand\nbeta\n"),
        ("gamma\tkept by hand", "gamma\tkept by hand\nbeta\n"),
    ] {
        let root = tree(&["alpha"], Some(held));
        let want = ["alpha", "gamma\tkept by hand", "beta"];
        check(root.path(), &want, true).expect("the blessed run fails");
        assert_eq!(
            fragment(root.path()).as_deref(),
            Some(after),
            "held {held:?}"
        );
        assert_eq!(check(root.path(), &want, true), None, "held {held:?}");
    }
}

/// The header is copied only from a base whose first line is a `#` comment.
#[test]
fn a_base_with_no_header_gives_the_fragment_none() {
    let root = tempfile::tempdir().expect("a throwaway tree");
    let tables = root.path().join(DIR);
    std::fs::create_dir_all(&tables).expect("the table folder");
    std::fs::write(tables.join("t.tsv"), "alpha\n").expect("a base with no header");
    check(root.path(), &["alpha", "beta"], true).expect("the blessed run fails");
    assert_eq!(fragment(root.path()).as_deref(), Some("beta\n"));
}

/// R3 and R6: the ticket a value names. A value that names no fragment is
/// refused even when every table matches; a dashed part is a fragment name;
/// CI never blesses; with no value, CI runs as it always has.
#[test]
fn r3_r6_the_ticket_a_value_names() {
    let refused = bless_from(Some("abc"), None).expect_err("a value naming no fragment");
    assert!(
        refused.contains("abc") && refused.contains(BLESS_VAR),
        "{refused}"
    );
    assert_eq!(
        bless_from(Some("9977-1"), None),
        Ok(Some("9977-1".to_owned()))
    );
    assert_eq!(bless_from(Some("9977"), None), Ok(Some("9977".to_owned())));
    assert_eq!(bless_from(Some(""), None), Ok(None));
    assert_eq!(bless_from(None, Some("true")), Ok(None));
    let in_ci = bless_from(Some("9977"), Some("true")).expect_err("CI never blesses");
    assert!(in_ci.contains(BLESS_VAR) && in_ci.contains("CI"), "{in_ci}");
}

/// R7: the live wiring, read from the sources. The four live pin tests are
/// the only callers of `bless_ticket()`, each helper hands its own `bless`
/// parameter to `delta_or_bless`, and nothing calls the old name.
#[test]
fn r7_only_the_live_tests_read_the_switch() {
    let dir = super::crate_root().join(DIR);
    let source = |file: &str| std::fs::read_to_string(dir.join(file)).expect("a pin source");
    let code_lines = |text: &str, needle: &str| {
        text.lines()
            .map(str::trim_start)
            .filter(|line| !line.starts_with("//") && line.contains(needle))
            .count()
    };
    let (allows, framing) = (source("allow_pins.rs"), source("delivery_framing.rs"));
    assert_eq!(
        (
            code_lines(&allows, concat!("bless_", "ticket()")),
            code_lines(&framing, concat!("bless_", "ticket()"))
        ),
        (2, 2),
        "the four live tests, and nothing else, read the switch"
    );
    // Each call sits inside one of the four live tests by name: the nearest
    // `fn` line above it.
    let live = [
        "t1b_every_production_allow_of_the_ban_is_pinned",
        "t1a_every_classed_read_is_pinned",
        "every_generic_framing_site_is_inventoried",
        "every_refusal_site_is_classified",
    ];
    for text in [&allows, &framing] {
        let mut within = "";
        for line in text.lines().map(str::trim_start) {
            if let Some(rest) = line.strip_prefix("fn ") {
                within = rest.split('(').next().unwrap_or_default();
            }
            if !line.starts_with("//") && line.contains(concat!("bless_", "ticket()")) {
                assert!(live.contains(&within), "the switch is read inside {within}");
            }
        }
    }
    for text in [&allows, &framing] {
        for line in text.lines().filter(|line| line.contains("delta_or_bless(")) {
            assert!(
                line.contains(", bless)"),
                "a helper must pass its own bless: {line}"
            );
        }
    }
    let mut stack = vec![super::crate_root().join("src")];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder)
            .expect("a source folder")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
                let reader = matches!(
                    file.as_deref(),
                    Some("allow_pins.rs" | "delivery_framing.rs")
                );
                // fragments.rs only defines the reader: a call there (say, in
                // delta_or_bless) would bypass the helpers' parameter.
                let calls = text.lines().map(str::trim_start).any(|line| {
                    !line.starts_with("//")
                        && !line.contains("fn bless_ticket")
                        && line.contains(concat!("bless_", "ticket()"))
                });
                assert!(
                    reader || !calls,
                    "{} reads the bless switch",
                    path.display()
                );
                assert!(
                    !text.contains(concat!("multiset", "_delta(")),
                    "{} still calls the old check",
                    path.display()
                );
            }
        }
    }
}
