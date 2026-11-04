// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared credential generator: its output, its lack of state, and the
//! closed list of production code allowed to call it (MIK-9223 S1).

use std::path::{Path, PathBuf};

use crate::random_secret::random_secret;

#[test]
fn each_install_gets_its_own_credential() {
    assert_ne!(
        random_secret("mcpgw_"),
        random_secret("mcpgw_"),
        "a shared credential across installs is no credential"
    );
}

#[test]
fn the_credential_is_not_guessable() {
    let token = random_secret("mcpgw_");
    let body = token.strip_prefix("mcpgw_").expect("the prefix leads");
    // 32 random bytes, base64url without padding: exactly 43 characters.
    assert_eq!(body.len(), 43, "not 32 random bytes: {token}");
    assert!(
        body.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "not base64url: {token}"
    );
    assert_eq!(random_secret("").len(), 43, "an empty prefix adds nothing");
}

/// The twin-copy invariant, as clock.rs holds its own: no state in code.
#[test]
fn random_secret_rs_holds_no_shared_mutable_state() {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    for line in include_str!("random_secret.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
    {
        for (at, _) in line.match_indices("static") {
            let before = line[..at].chars().next_back();
            let after = line[at + "static".len()..].chars().next();
            assert!(
                before.is_some_and(|c| is_ident(c) || c == '\'') || after.is_some_and(is_ident),
                "a static item in random_secret.rs: {line}"
            );
        }
        for forbidden in [
            "Mutex",
            "RwLock",
            "Atomic",
            "OnceLock",
            "LazyLock",
            "thread_local",
        ] {
            assert!(
                !line.contains(forbidden),
                "shared mutable state ({forbidden}) in random_secret.rs: {line}"
            );
        }
    }
}

/// Every production source file under `src/`, relative and with '/'.
fn production_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    files
        .into_iter()
        .filter_map(|path| {
            let relative = path
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            let is_test = relative.split('/').any(|part| {
                part == "tests" || part.ends_with("_tests") || part.ends_with("_tests.rs")
            });
            if is_test {
                return None;
            }
            let text = std::fs::read_to_string(&path).ok()?;
            let code =
                crate::test_source_text::sanitize(&crate::test_source_text::production_text(&text));
            Some((relative, code))
        })
        .collect()
}

/// The production callers of `random_secret`, both crates (MIK-9223 G2):
/// `gateway init`'s admin token (binary), the auto bearer, the key server's
/// bearer, the dashboard's session values. The create route joins at S5 and
/// rotate in C2; any other caller fails here until it is reviewed and named.
const CALLERS: &[(&str, usize)] = &[
    ("src/commands/mod.rs", 1),
    ("src/config/features/auth.rs", 1),
    ("src/gateway/auth_dashboard.rs", 1),
    ("src/key_server/store.rs", 1),
];

#[test]
fn random_secret_is_called_only_where_listed() {
    let mut found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/random_secret.rs")
        .filter_map(|(file, code)| {
            let count = code.matches("random_secret(").count();
            (count > 0).then_some((file, count))
        })
        .collect();
    found.sort();
    let want: Vec<(String, usize)> = CALLERS
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        found, want,
        "a new caller of random_secret: review it and list it here"
    );
}

/// No other production code draws 32 random bytes and base64url-encodes
/// them: a second credential generator would escape the caller list.
#[test]
fn no_other_credential_generator_exists() {
    let generators: Vec<String> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/random_secret.rs")
        .filter(|(_, code)| {
            code.contains("[u8; 32] = rand::rng().random()") && code.contains("URL_SAFE_NO_PAD")
        })
        .map(|(file, _)| file)
        .collect();
    assert!(
        generators.is_empty(),
        "credential generators outside random_secret.rs: {generators:?}"
    );
}
