// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Loader contracts using isolated files, plus the checked-in baseline.

use std::fs;
use std::path::{Path, PathBuf};

use super::ui_access_matrix_rows::{Attributes, Loaded, load_from, rows};

const OLD_ROW_COUNT: usize = 10890;
const BODY: &str = "refused\tde6b55925ef7\tshared refusal body\n";
const PLAIN: &str = "/ui/api/status\tGET\tplain\tAdminKey\t200\n";
const NAMED: &str = "/ui/api/status\tGET\tplain\tNoKey\t401:@refused\n";

struct Fixture {
    _root: tempfile::TempDir,
    dir: PathBuf,
    bodies: PathBuf,
}

impl Fixture {
    fn new(files: &[(&str, &str)], bodies: &str) -> Self {
        let root = tempfile::tempdir().expect("create isolated fixture");
        let dir = root.path().join("ui_access_matrix.d");
        let bodies_path = root.path().join("ui_access_matrix_bodies.tsv");
        fs::create_dir(&dir).expect("create fragment directory");
        for (slug, contents) in files {
            fs::write(dir.join(format!("{slug}.tsv")), contents).expect("write fragment");
        }
        fs::write(&bodies_path, bodies).expect("write body definitions");
        Self {
            _root: root,
            dir,
            bodies: bodies_path,
        }
    }

    fn load(&self) -> Result<Loaded, String> {
        load_from(&self.dir, &self.bodies)
    }
}

#[test]
fn rejects_a_slug_that_differs_from_the_file_name() {
    let fixture = Fixture::new(&[("wrong", PLAIN)], "");
    assert_eq!(
        fixture.load().unwrap_err(),
        "wrong.tsv:1: path /ui/api/status has slug status, expected wrong"
    );
}

#[test]
fn rejects_an_undefined_body_name() {
    let fixture = Fixture::new(&[("status", NAMED)], "");
    assert_eq!(
        fixture.load().unwrap_err(),
        "status.tsv:1: undefined body @refused"
    );
}

#[test]
fn rejects_a_named_body_used_by_no_row() {
    let fixture = Fixture::new(&[("status", PLAIN)], BODY);
    assert_eq!(
        fixture.load().unwrap_err(),
        "ui_access_matrix_bodies.tsv:1: body @refused is unused"
    );
}

#[test]
fn rejects_an_inline_digest_equal_to_a_named_body() {
    // Use the name first so an unused-body error cannot mask this failure.
    let contents = format!("{NAMED}/ui/api/status\tGET\tplain\tAuthOff\t403:de6b55925ef7\n");
    let fixture = Fixture::new(&[("status", &contents)], BODY);
    assert_eq!(
        fixture.load().unwrap_err(),
        "status.tsv:2: inline digest de6b55925ef7 must use @refused"
    );
}

#[test]
fn rejects_a_duplicate_row_in_one_file() {
    // Identity is the first four cells, even when the two answers differ.
    for answer in ["200", "403:0123456789ab"] {
        let contents = format!("{PLAIN}/ui/api/status\tGET\tplain\tAdminKey\t{answer}\n");
        let fixture = Fixture::new(&[("status", &contents)], "");
        assert_eq!(
            fixture.load().unwrap_err(),
            "status.tsv:2: duplicate row /ui/api/status\tGET\tplain\tAdminKey"
        );
    }
}

#[test]
fn rejects_a_line_without_exactly_five_tab_cells() {
    for (line, cells) in [
        ("/ui/api/status\tGET\tplain\tAdminKey\n", 4),
        ("/ui/api/status\tGET\tplain\tAdminKey\t200\textra\n", 6),
    ] {
        let fixture = Fixture::new(&[("status", line)], "");
        assert_eq!(
            fixture.load().unwrap_err(),
            format!("status.tsv:1: expected 5 tab-separated cells, got {cells}")
        );
    }
}

#[test]
fn parses_each_header_attribute_and_defaults_absent_attributes_to_false() {
    for (header, attributes) in [
        ("", Attributes::default()),
        (
            "#@ scoped\n",
            Attributes {
                scoped: true,
                ..Attributes::default()
            },
        ),
        (
            "#@ store_writes\n",
            Attributes {
                store_writes: true,
                ..Attributes::default()
            },
        ),
        (
            "#@ store_reads\n",
            Attributes {
                store_reads: true,
                ..Attributes::default()
            },
        ),
    ] {
        let fixture = Fixture::new(&[("status", &format!("{header}{PLAIN}"))], "");
        let loaded = fixture.load().expect("valid header");
        assert_eq!(loaded.files.len(), 1);
        let file = &loaded.files[0];
        assert_eq!(file.slug, "status");
        assert_eq!(file.path, "/ui/api/status");
        assert_eq!(file.attributes, attributes);
        let expected = ["/ui/api/status", "GET", "plain", "AdminKey", "200"].map(String::from);
        assert_eq!(file.rows, vec![expected]);
    }
}

#[test]
fn expands_a_named_body_under_different_statuses() {
    let contents = format!("{NAMED}/ui/api/status\tGET\tplain\tAuthOff\t403:@refused\n");
    let fixture = Fixture::new(&[("status", &contents)], BODY);
    let loaded = fixture.load().expect("named body expands");
    assert_eq!(loaded.files[0].rows[0][4], "401:de6b55925ef7");
    assert_eq!(loaded.files[0].rows[1][4], "403:de6b55925ef7");
    assert_eq!(loaded.bodies["refused"].digest, "de6b55925ef7");
    assert_eq!(loaded.bodies["refused"].meaning, "shared refusal body");
}

#[test]
fn ignores_a_plain_comment_line() {
    let contents = format!("# ordinary comment, not five tab cells\n{PLAIN}");
    let fixture = Fixture::new(&[("status", &contents)], "");
    let loaded = fixture.load().expect("comment ignored");
    assert_eq!(loaded.files[0].rows.len(), 1);
    assert_eq!(loaded.files[0].attributes, Attributes::default());
}

#[test]
fn keeps_an_attribute_line_instead_of_discarding_it_as_a_comment() {
    let contents = format!("# ordinary comment\n#@ scoped\n{PLAIN}");
    let fixture = Fixture::new(&[("status", &contents)], "");
    let loaded = fixture.load().expect("attribute retained");
    assert_eq!(loaded.files[0].rows.len(), 1);
    assert!(loaded.files[0].attributes.scoped);
}

#[test]
fn accepts_dashboard_nested_and_parameterized_route_slugs() {
    let fixture = Fixture::new(
        &[
            (
                "backends___name_",
                "/ui/api/backends/{name}\tGET\tplain\tAdminKey\t200\n",
            ),
            ("__dashboard", "/dashboard\tGET\tplain\tAdminKey\t200\n"),
            (
                "activity__export",
                "/ui/api/activity/export\tGET\tplain\tAdminKey\t200:tool_0\n",
            ),
        ],
        "",
    );
    let loaded = fixture.load().expect("valid slug transformations");
    let slugs: Vec<_> = loaded.files.iter().map(|file| file.slug.as_str()).collect();
    assert_eq!(
        slugs,
        ["__dashboard", "activity__export", "backends___name_"]
    );
    assert_eq!(loaded.files[1].rows[0][4], "200:tool_0");
}

#[test]
fn real_directory_expands_to_the_original_row_count() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/router");
    let dir = root.join("ui_access_matrix.d");
    let bodies = root.join("ui_access_matrix_bodies.tsv");
    assert_eq!(
        fs::read_dir(&dir).expect("real directory exists").count(),
        47
    );
    assert!(
        !fs::read_to_string(&bodies)
            .expect("real bodies exist")
            .is_empty()
    );
    let loaded = load_from(&dir, &bodies).expect("real fragments load");
    assert_eq!(loaded.files.len(), 47);
    assert_eq!(
        loaded
            .files
            .iter()
            .map(|file| file.rows.len())
            .sum::<usize>(),
        OLD_ROW_COUNT
    );
    assert!(
        loaded
            .files
            .iter()
            .flat_map(|file| &file.rows)
            .all(|row| !row[4].contains('@'))
    );
    // This API must include every feature's rows; consumers apply their filters.
    assert!(loaded.files.iter().any(|file| file.path == "/ui/api/costs"));
    assert_eq!(rows(), loaded);
}

#[test]
fn rendered_block_reloads_equal_with_headers_and_body_names_intact() {
    let contents = format!("#@ scoped\n#@ store_writes\n#@ store_reads\n{NAMED}{PLAIN}");
    let fixture = Fixture::new(&[("status", &contents)], BODY);
    let loaded = fixture.load().expect("source loads");
    let file = &loaded.files[0];
    let block = loaded.render_block(file);
    assert_eq!(block, contents);
    assert!(!block.contains("de6b55925ef7"));
    let replay = Fixture::new(&[(&file.slug, &block)], BODY);
    assert_eq!(replay.load().expect("rendered block reloads"), loaded);
}

#[test]
fn rejects_a_fragment_without_rows() {
    let fixture = Fixture::new(&[("status", "#@ scoped\n")], "");
    assert_eq!(
        fixture.load().unwrap_err(),
        "status.tsv:1: fragment has no rows"
    );
}

#[test]
fn rejects_an_unknown_attribute_instead_of_silently_dropping_it() {
    let fixture = Fixture::new(&[("status", &format!("#@ scope\n{PLAIN}"))], "");
    assert_eq!(
        fixture.load().unwrap_err(),
        "status.tsv:1: unknown attribute scope"
    );
}

#[test]
fn a_shared_body_edit_and_an_independent_route_addition_compose() {
    let fixture = Fixture::new(&[("status", NAMED)], BODY);
    let original = fixture.load().unwrap();
    let changed_body = BODY.replace("de6b55925ef7", "0123456789ab");
    assert_eq!(changed_body.lines().count(), 1);
    fs::write(&fixture.bodies, &changed_body).unwrap();
    let edited = fixture.load().unwrap();
    assert_eq!(edited.files[0].rows[0][4], "401:0123456789ab");
    // The body change requires no fragment edits, including newly added routes.
    assert_eq!(
        fs::read_to_string(fixture.dir.join("status.tsv")).unwrap(),
        NAMED
    );
    let new_route = NAMED.replace("/ui/api/status", "/ui/api/new-route");
    fs::write(fixture.dir.join("new-route.tsv"), &new_route).unwrap();
    let together = fixture.load().unwrap();
    assert_eq!(together.files.len(), 2);
    assert!(
        together
            .files
            .iter()
            .all(|file| file.rows[0][4] == "401:0123456789ab")
    );
    // Apply the two independent changes in the other order, too.
    let reverse = Fixture::new(&[("status", NAMED), ("new-route", &new_route)], BODY);
    assert!(
        reverse
            .load()
            .unwrap()
            .files
            .iter()
            .all(|file| { file.rows[0][4] == original.files[0].rows[0][4] })
    );
    fs::write(&reverse.bodies, changed_body).unwrap();
    assert_eq!(reverse.load().unwrap(), together);
}
