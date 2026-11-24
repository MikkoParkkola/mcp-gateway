// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The access table against what it describes: every route and method the
//! router answers has exactly one row, every row names a route the listener
//! owns, and the page and tab inventory is the shell's own.

use std::collections::BTreeSet;

use super::{PAGES, ROWS, TABS, Verb};
use crate::gateway::router::ui_access_matrix_test_rows;
use crate::gateway::routes;

/// The (path, verb) pairs the router answers, read from the pinned matrix:
/// every cell an admin key gets that is not 405, for a registered verb; plus
/// the live stream, which the matrix cannot probe (its body never ends).
fn registered() -> BTreeSet<(String, Verb)> {
    let stream = (routes::UI_STREAM.to_string(), Verb::Get);
    ui_access_matrix_test_rows::rows()
        .files
        .into_iter()
        .flat_map(|file| file.rows)
        .filter_map(|row| {
            let [path, method, _shape, caller, answer] = &row;
            let method = method
                .parse::<axum::http::Method>()
                .unwrap_or_else(|_| panic!("a matrix method parses: {row:?}"));
            let verb = Verb::of(&method)?;
            (*caller == "AdminKey" && *answer != "405" && method != axum::http::Method::HEAD)
                .then(|| (path.clone(), verb))
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

/// To do, Access and Policies: each tab is backed by exactly the routes its
/// page calls for it, and only the three reads decide whether a tab opens.
#[test]
fn the_three_new_pages_are_backed_by_the_routes_they_call() {
    use super::Page::{Access, Policies, ToDo};
    use super::Tab::{Actions, Settings, Status};
    use Verb::{Delete, Get, Post};
    let backing: [((super::Page, super::Tab), &[(&str, Verb)]); 9] = [
        ((ToDo, Status), &[(routes::UI_DECISIONS, Get)]),
        ((ToDo, Actions), &[]),
        ((ToDo, Settings), &[]),
        ((Access, Status), &[(routes::UI_KEYS, Get)]),
        ((Access, Actions), &[(routes::UI_KEYS_NAME, Delete)]),
        ((Access, Settings), &[(routes::UI_KEYS, Post)]),
        ((Policies, Status), &[(routes::UI_POLICIES, Get)]),
        ((Policies, Actions), &[]),
        (
            (Policies, Settings),
            &[
                (routes::UI_POLICIES, Get),
                (routes::UI_SETTINGS_DIFF, Post),
                (routes::UI_SETTINGS, Post),
            ],
        ),
    ];
    for ((page, tab), want) in backing {
        let got: BTreeSet<(&str, Verb)> = ROWS
            .iter()
            .filter(|r| r.tabs.contains(&(page, tab)))
            .map(|r| (r.path, r.method))
            .collect();
        let want: BTreeSet<(&str, Verb)> = want.iter().copied().collect();
        assert_eq!(got, want, "{} {}", page.id(), tab.id());
    }
    let loads: BTreeSet<(&str, Verb)> = ROWS
        .iter()
        .filter(|r| {
            r.load
                && r.tabs
                    .iter()
                    .any(|&(p, _)| [ToDo, Access, Policies].contains(&p))
        })
        .map(|r| (r.path, r.method))
        .collect();
    let want = BTreeSet::from([
        (routes::UI_DECISIONS, Get),
        (routes::UI_KEYS, Get),
        (routes::UI_POLICIES, Get),
    ]);
    assert_eq!(loads, want, "the load rows of the three pages");
}

/// The rows those pages no longer read back no tab, and still ask what they
/// asked before: the guard reads a row's need, never its tabs.
#[test]
fn rows_left_without_a_tab_keep_their_need() {
    use super::AdminShape::{AdminRequired, Forbidden};
    use super::CpCheck::{Action, FromBody, Read};
    use super::Need::{Admin, ControlPlane};
    use crate::control_plane::ControlPlaneAction::{MutateGrant, MutatePolicy};
    use Verb::{Get, Post};
    let emptied: [(&str, Verb, super::Need); 8] = [
        (routes::UI_REFUSALS, Get, Admin(Forbidden)),
        (routes::UI_DEAD_LETTERS, Get, Admin(AdminRequired)),
        (routes::UI_DEAD_LETTERS_REPLAY, Post, Admin(AdminRequired)),
        (routes::UI_DEAD_LETTER_REPLAY, Post, Admin(AdminRequired)),
        (routes::UI_CONTROL_PLANE, Get, ControlPlane(Read)),
        (
            routes::UI_CONTROL_PLANE_GRANTS,
            Post,
            ControlPlane(Action(MutateGrant)),
        ),
        (
            routes::UI_CONTROL_PLANE_POLICIES,
            Post,
            ControlPlane(Action(MutatePolicy)),
        ),
        (
            routes::UI_CONTROL_PLANE_DECISIONS,
            Post,
            ControlPlane(FromBody(&[MutateGrant, MutatePolicy])),
        ),
    ];
    for (path, method, need) in emptied {
        let row = ROWS
            .iter()
            .find(|r| r.path == path && r.method == method)
            .unwrap_or_else(|| panic!("a row for {path} {method:?}"));
        assert!(
            row.tabs.is_empty() && !row.load,
            "{path} {method:?} still backs {:?} (load: {})",
            row.tabs,
            row.load
        );
        assert_eq!(row.need, need, "{path} {method:?} changed its need");
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
        // The shell script by its name: other screens ship their own scripts
        // (gateway.*.js sorts before shell.*.js in the table).
        .find(|(name, _)| {
            name.starts_with("shell.")
                && std::path::Path::new(name)
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
