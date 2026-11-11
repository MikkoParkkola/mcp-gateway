// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared credential generator: its output, its lack of state, and the
//! closed list of production code allowed to call it.

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

/// The shared generator, like the clock, holds no mutable shared state.
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

/// The production callers of `random_secret` in the library:
/// `gateway init`'s admin token, the auto bearer, the key server's
/// bearer, the dashboard's session values, the OAuth client's PKCE verifier. The create route is listed; rotate joins in C2; any other caller fails here until it is reviewed and named.
/// Every production file that names `random_secret` as a whole word, with
/// how often: the shared generator's callers (2 each, since
/// `crate::random_secret::random_secret(` names it twice), the library's
/// `mod random_secret;`, and the personal-account journey's own
/// `random_secret()` (its definition, its import and its three calls), which
/// is not the shared generator. Any other naming, by path, `use`, alias,
/// grouped or glob import, adds a word and fails until reviewed.
const CALLERS: &[(&str, usize)] = &[
    ("src/commands/mod.rs", 2),
    ("src/config/features/auth.rs", 2),
    ("src/gateway/auth_dashboard.rs", 2),
    ("src/gateway/ui/keys_create.rs", 2),
    ("src/key_server/store.rs", 2),
    ("src/lib.rs", 1),
    ("src/oauth/client/mod.rs", 2),
    ("src/personal_accounts/journey/mod.rs", 1),
    ("src/personal_accounts/journey/ops.rs", 4),
];

/// `random_secret` as a whole word: `random_secret_tests` and
/// `is_random_secret` are other identifiers.
fn whole_words(code: &str) -> usize {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices("random_secret")
        .filter(|(at, word)| {
            !code[..*at].ends_with(ident) && !code[at + word.len()..].starts_with(ident)
        })
        .count()
}

#[test]
fn random_secret_is_called_only_where_listed() {
    let mut found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/random_secret.rs")
        .filter_map(|(file, code)| {
            // Comments and string literals are blanked in `code`.
            let count = whole_words(&code);
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

/// The counts above hold only while every caller names the generator in
/// full. An alias (`random_secret as mint`), a glob (`random_secret::*`) or
/// a grouped import (`random_secret::{..}`) would let a listed file call it
/// any number of times under another name with its count unchanged, so none
/// is allowed in production code (rustfmt fixes the spacing these match).
#[test]
fn random_secret_is_never_imported_under_another_name() {
    let imports: Vec<(String, &str)> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/random_secret.rs")
        .flat_map(|(file, code)| {
            ["random_secret as", "random_secret::*", "random_secret::{"]
                .into_iter()
                .filter(move |form| code.contains(form))
                .map(move |form| (file.clone(), form))
        })
        .collect();
    assert!(
        imports.is_empty(),
        "call crate::random_secret::random_secret( in full: {imports:?}"
    );
}

/// The randomness entry points a generator can draw from, in any spelling
/// this codebase uses.
const RNG_ENTRY_POINTS: &[&str] = &[
    "rand::rng()",
    "rand::random",
    "thread_rng",
    "OsRng",
    "SystemRandom",
    "getrandom",
    "fill_bytes",
    "rand::fill",
];

/// Production files that both draw random bytes and use base64url, each
/// reviewed as not being a second credential generator. A new such file
/// fails until it calls `random_secret` or is reviewed and listed here.
const RANDOM_BASE64URL_REVIEWED: &[(&str, &str)] = &[
    (
        "src/a2a/delegation.rs",
        "a 128-bit cancel token whose RNG failure is recoverable",
    ),
    (
        "src/events/client.rs",
        "a verification challenge the subscriber echoes, never a credential",
    ),
    (
        "src/gateway/ui/activity/cursor.rs",
        "an HMAC key; base64url encodes the signed body, not random bytes",
    ),
    (
        "src/gateway/ui/backends/signin_flow.rs",
        "a 16-byte sign-in attempt id",
    ),
    (
        "src/oauth/client/mod.rs",
        "16-byte state and client ids; its PKCE verifier calls random_secret",
    ),
    (
        "src/personal_accounts/journey/mod.rs",
        "its own generator with a recoverable RNG error (a register row)",
    ),
    (
        "src/protocol/continuation/keyring.rs",
        "AEAD key material; base64url encodes the encrypted continuation envelope",
    ),
];

/// A file-level tripwire, not a proof: a production file that names one of
/// the RNG entry points above AND uses base64url must be reviewed and listed.
/// It does not see hex or standard-base64 generators, RNG names brought in by
/// `use`, or a second site inside a listed file; the enforced replacement is
/// clippy `disallowed-methods` on the RNG APIs, tracked separately.
#[test]
fn no_other_credential_generator_exists() {
    let mut found: Vec<String> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/random_secret.rs")
        .filter(|(_, code)| {
            code.contains("URL_SAFE") && RNG_ENTRY_POINTS.iter().any(|rng| code.contains(rng))
        })
        .map(|(file, _)| file)
        .collect();
    found.sort();
    let want: Vec<String> = RANDOM_BASE64URL_REVIEWED
        .iter()
        .map(|(file, _)| (*file).to_owned())
        .collect();
    assert_eq!(
        found, want,
        "random bytes and base64url outside random_secret.rs: call it, or review the file and list it"
    );
}
