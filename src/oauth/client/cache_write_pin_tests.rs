// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pins, the backstop to the grant proof's type: a token loaded from storage
//! enters the cache only through `cache_loaded`, which checks the install's
//! issuer under the install-key lock, and the grant proof is built only by its
//! two constructors. Every other write to the cache is listed here: a token
//! just issued (a login, a refresh, a client-credentials grant, a confirmed
//! sign-in), an emptied cache, or a test seed. A new site fails a row until it
//! is classified.

use std::collections::BTreeSet;
use std::path::Path;

/// `(file under src/oauth/client, function)` allowed to write the cache.
const WRITERS: [(&str, &str); 10] = [
    ("sign_in.rs", "cache_loaded"),
    ("sign_in.rs", "rediscover_if_moved"),
    ("grants/authorize.rs", "adopt_installed"),
    ("grants.rs", "try_client_credentials"),
    ("grants.rs", "refresh_token"),
    ("grants.rs", "authorize_until_by"),
    ("grants.rs", "save_confirmed"),
    ("grants.rs", "age_token_for_test"),
    ("mod.rs", "drop_credentials_from_other_issuer"),
    ("mod.rs", "seed_token_for_test"),
];

/// Every non-test source under the client, as `(path relative to it, text)`.
fn sources(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("the client sources list") {
        let path = entry.expect("an entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.contains("tests") || name.contains("fixture") {
            continue;
        }
        if path.is_dir() {
            sources(root, &path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let file = path.strip_prefix(root).unwrap().to_string_lossy();
            let text = std::fs::read_to_string(&path).expect("a readable source");
            out.push((file.replace('\\', "/"), text));
        }
    }
}

/// The client's non-test sources.
fn client_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/oauth/client");
    let mut all = Vec::new();
    sources(&root, &root, &mut all);
    all
}

/// Every `(file, enclosing fn)` with a line holding `needle`.
fn sites(all: &[(String, String)], needle: &str) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for (file, text) in all {
        let mut current = String::from("-");
        for line in text.lines() {
            if let Some(at) = line.find("fn ") {
                let rest = &line[at + 3..];
                let end = rest
                    .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                if end > 0 && (at == 0 || !line.as_bytes()[at - 1].is_ascii_alphanumeric()) {
                    current = rest[..end].to_owned();
                }
            }
            if line.contains(needle) {
                found.insert((file.clone(), current.clone()));
            }
        }
    }
    found
}

fn pairs(list: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    list.iter()
        .map(|(file, function)| ((*file).to_owned(), (*function).to_owned()))
        .collect()
}

#[test]
fn a_loaded_token_is_cached_only_through_the_checked_step() {
    let all = client_sources();
    for (file, text) in &all {
        let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(
            squeezed.matches("current_token.write()").count(),
            text.matches("current_token.write()").count(),
            "{file}: a cache write split across lines, which this scan cannot place"
        );
    }
    let found = sites(&all, "current_token.write()");

    let allowed = pairs(&WRITERS);
    let unlisted: Vec<_> = found.difference(&allowed).collect();
    assert!(
        unlisted.is_empty(),
        "cache writes outside the listed sites: {unlisted:?}"
    );
    assert!(
        found.contains(&("sign_in.rs".to_owned(), "cache_loaded".to_owned())),
        "the scan finds the checked step itself: {found:?}"
    );
}

#[test]
fn the_grant_proof_is_built_only_by_its_checks() {
    let all = client_sources();
    assert_eq!(
        sites(&all, "GrantAllowed { _only_here"),
        pairs(&[
            ("sign_in.rs", "issuer_current"),
            ("sign_in.rs", "ui_sign_in")
        ]),
        "who builds the grant proof"
    );
    assert_eq!(
        sites(&all, "Self::ui_sign_in()"),
        pairs(&[("grants.rs", "authorize_for_ui")]),
        "who takes the web-UI grant proof"
    );
}
