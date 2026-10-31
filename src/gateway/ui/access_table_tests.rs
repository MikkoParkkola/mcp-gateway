// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The access table against what it describes: every route and method the
//! router answers has exactly one row, every row names a route the listener
//! owns, and the page and tab inventory is the shell's own.

use std::collections::BTreeSet;

use super::{PAGES, ROWS, TABS, Verb};
use crate::gateway::routes;

/// The (path, verb) pairs the router answers, read from the pinned matrix:
/// every cell an admin key gets that is not 405, for a registered verb; plus
/// the live stream, which the matrix cannot probe (its body never ends).
fn registered() -> BTreeSet<(String, Verb)> {
    let stream = (routes::UI_STREAM.to_string(), Verb::Get);
    include_str!("../router/ui_access_matrix.tsv")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('\t').collect();
            let [path, method, _shape, caller, answer] = cells.as_slice() else {
                panic!("a matrix line has five cells: {l:?}");
            };
            let method = method
                .parse::<axum::http::Method>()
                .unwrap_or_else(|_| panic!("a matrix method parses: {l:?}"));
            let verb = Verb::of(&method)?;
            (*caller == "AdminKey" && *answer != "405" && method != axum::http::Method::HEAD)
                .then(|| (path.to_string(), verb))
        })
        .filter(|(path, _)| cfg!(feature = "cost-governance") || path != routes::UI_COSTS)
        .chain(std::iter::once(stream))
        .collect()
}

#[test]
fn every_registered_pair_has_exactly_one_row() {
    let rows: Vec<(String, Verb)> = ROWS
        .iter()
        .map(|r| (r.path.to_string(), r.method))
        .collect();
    let unique: BTreeSet<(String, Verb)> = rows.iter().cloned().collect();
    assert_eq!(rows.len(), unique.len(), "a (path, method) has two rows");
    let registered = registered();
    let missing: Vec<_> = registered.difference(&unique).collect();
    let extra: Vec<_> = unique.difference(&registered).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "rows the router answers without: {missing:?}; rows for nothing it answers: {extra:?}"
    );
}

#[test]
fn every_row_names_an_owned_route() {
    for row in ROWS {
        assert!(
            routes::OWNED.contains(&row.path),
            "{} is not a listener route",
            row.path
        );
    }
}

#[test]
fn every_page_but_a_feature_off_one_has_a_row() {
    for page in PAGES {
        let has_row = ROWS.iter().any(|r| r.tabs.iter().any(|&(p, _)| p == page));
        let costs_off = page.id() == "costs" && !cfg!(feature = "cost-governance");
        assert_eq!(has_row, !costs_off, "{}", page.id());
    }
}

/// The quoted ids of `const <name> = [ [id, label], ... ];` in the shell
/// script, with an id written `'a' + 'b'` joined.
fn shell_ids(script: &str, name: &str) -> Vec<String> {
    let start = script
        .find(&format!("const {name} = ["))
        .unwrap_or_else(|| panic!("the shell declares {name}"));
    let body = &script[start..];
    let body = &body[body.find('[').expect("an array") + 1..body.find("];").expect("its end")];
    body.split("],")
        .filter_map(|entry| {
            let id = entry.trim().trim_start_matches('[').split(',').next()?;
            let joined: String = id
                .split('+')
                .map(|part| part.trim().trim_matches('\''))
                .collect();
            (!joined.is_empty()).then_some(joined)
        })
        .collect()
}

#[test]
fn the_page_and_tab_inventory_is_the_shells() {
    let (_, script) = super::super::shell::ASSETS
        .iter()
        .find(|(name, _)| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("js"))
        })
        .expect("the shell script is an asset");
    let script = std::str::from_utf8(script).expect("the script is UTF-8");
    let pages: Vec<&str> = PAGES.iter().map(|p| p.id()).collect();
    let tabs: Vec<&str> = TABS.iter().map(|t| t.id()).collect();
    assert_eq!(shell_ids(script, "NAV"), pages);
    assert_eq!(shell_ids(script, "TABS"), tabs);
}
