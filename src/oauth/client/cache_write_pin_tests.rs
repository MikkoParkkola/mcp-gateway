// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pin: a token loaded from storage enters the cache only through
//! `cache_loaded`, which checks the install's issuer under the install-key
//! lock. Every other write to the cache is listed here: a token just issued
//! (a login, a refresh, a client-credentials grant, a confirmed sign-in), an
//! emptied cache, or a test seed. A new write site fails this row until it is
//! classified, so no path can cache a token of another issuer unchecked.

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

/// Every `(file, enclosing fn)` holding a cache write, in non-test sources.
fn writers(root: &Path, dir: &Path, out: &mut BTreeSet<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("the client sources list") {
        let path = entry.expect("an entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.contains("tests") || name.contains("fixture") {
            continue;
        }
        if path.is_dir() {
            writers(root, &path, out);
            continue;
        }
        if !name.ends_with(".rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a readable source");
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
            if line.contains("current_token.write()") {
                let file = path.strip_prefix(root).unwrap().to_string_lossy();
                out.insert((file.replace('\\', "/"), current.clone()));
            }
        }
    }
}

#[test]
fn a_loaded_token_is_cached_only_through_the_checked_step() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/oauth/client");
    let mut found = BTreeSet::new();
    writers(&root, &root, &mut found);
    let allowed: BTreeSet<(String, String)> = WRITERS
        .iter()
        .map(|(file, function)| ((*file).to_owned(), (*function).to_owned()))
        .collect();

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
