// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared credential generator: its output, its lack of state, and the
//! closed list of production code allowed to call it.

use std::path::Path;

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
/// The personal-account journey takes its state, binding and verifier from
/// here with an empty prefix: the 43-character base64url form its own
/// generator produced before it moved onto this one.
#[test]
fn an_empty_prefix_is_43_base64url_characters() {
    let secret = random_secret("");
    assert_eq!(secret.len(), 43, "{secret}");
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "{secret}"
    );
}

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
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    crate::test_source_files::rust_files(&root.join("src"), &mut files);
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
/// how often: the shared generator's callers (2 per call, since
/// `crate::random_secret::random_secret(` names it twice; the personal-account
/// journey's three secrets make 6) and the library's `mod random_secret;`.
/// Any other naming, by path, `use`, alias, grouped or glob import, adds a
/// word and fails until reviewed.
const CALLERS: &[(&str, usize)] = &[
    ("src/cli_support/init.rs", 2),
    ("src/config/features/auth.rs", 2),
    ("src/gateway/auth_dashboard.rs", 2),
    ("src/gateway/ui/cli_login/attempts.rs", 2),
    ("src/gateway/ui/keys_create.rs", 2),
    ("src/key_server/store.rs", 2),
    ("src/lib.rs", 1),
    ("src/oauth/client/mod.rs", 2),
    ("src/personal_accounts/journey/ops.rs", 6),
];

/// `word` as a whole word: for `random_secret`, `random_secret_tests` and
/// `is_random_secret` are other identifiers.
fn whole_words(code: &str, word: &str) -> usize {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(word)
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
            let count = whole_words(&code, "random_secret");
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

/// Every production file that names `ids::new_v4`, with how often: each one
/// is `crate::ids::new_v4()`, naming a record, request, task or temp file
/// (tokio's `TcpSocket::new_v4` is another function). An id must never become a credential, so a new caller fails
/// here until it is reviewed and listed.
const ID_CALLERS: &[(&str, usize)] = &[
    ("src/a2a/client.rs", 1),
    ("src/a2a/types.rs", 1),
    ("src/attestation/signer.rs", 1),
    ("src/backend/ops.rs", 2),
    ("src/capability/executor/cli_run.rs", 1),
    ("src/capability/executor/jsonrpc.rs", 1),
    ("src/capability/executor/mod.rs", 2),
    ("src/chains/executor.rs", 1),
    ("src/config_persistence_journal_v2_drain.rs", 1),
    ("src/config_reload/grant_audit.rs", 1),
    ("src/events/backend_source.rs", 1),
    ("src/events/lease.rs", 1),
    ("src/events/upstream_session_notes.rs", 2),
    ("src/events/webhook_source.rs", 1),
    ("src/gateway/input_bridge.rs", 1),
    ("src/gateway/meta_mcp/chain_interim.rs", 2),
    ("src/gateway/oauth/jwks.rs", 1),
    ("src/gateway/proxy.rs", 3),
    ("src/gateway/streaming.rs", 1),
    ("src/gateway/trace.rs", 1),
    ("src/gateway/ui/cli_login/attempts.rs", 1),
    ("src/gateway/webhooks/mod.rs", 1),
    ("src/heartbeat.rs", 1),
    ("src/identity_grants/journal.rs", 1),
    ("src/identity_propagation/mod.rs", 1),
    ("src/identity_propagation/token_exchange.rs", 1),
    ("src/key_server/store.rs", 1),
    ("src/protocol/continuation/ledger.rs", 2),
    ("src/protocol/continuation/payload.rs", 1),
    ("src/protocol/tasks.rs", 1),
    ("src/security/transparency_log_identity.rs", 1),
    ("src/transport/notification_sink.rs", 1),
    ("src/transport/websocket.rs", 1),
];

#[test]
fn ids_new_v4_is_called_only_where_listed() {
    let mut found: Vec<(String, usize)> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/ids.rs")
        .filter_map(|(file, code)| {
            let count = whole_words(&code, "ids::new_v4");
            (count > 0).then_some((file, count))
        })
        .collect();
    found.sort();
    let want: Vec<(String, usize)> = ID_CALLERS
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        found, want,
        "a new caller of crate::ids::new_v4: review it and list it here"
    );
}

/// The id counts hold only while every caller names `ids::new_v4` in full:
/// importing the function itself, an alias, a glob or a grouped import would
/// let a listed file call it uncounted.
#[test]
fn ids_new_v4_is_never_imported_under_another_name() {
    let imports: Vec<(String, &str)> = production_sources()
        .into_iter()
        .filter(|(file, _)| file != "src/ids.rs")
        .flat_map(|(file, code)| {
            [
                "ids::new_v4;",
                "ids::new_v4 as",
                "::ids::*",
                "::ids::{",
                " ids::*",
                " ids::{",
            ]
            .into_iter()
            .filter(move |form| code.contains(form))
            .map(move |form| (file.clone(), form))
        })
        .collect();
    assert!(
        imports.is_empty(),
        "call crate::ids::new_v4( in full: {imports:?}"
    );
}

/// Both caller pins count names, so a binding such as
/// `let mint = crate::random_secret::random_secret;`, or the function passed
/// on as a value, would let a listed file call it any number of times with
/// its count unchanged: every production occurrence of either generator is a
/// direct call.
#[test]
fn the_pinned_generators_are_only_called_directly() {
    let mut values = Vec::new();
    for (file, code) in production_sources() {
        for name in ["random_secret::random_secret", "ids::new_v4"] {
            for (at, _) in code.match_indices(name) {
                if !code[at + name.len()..].trim_start().starts_with('(') {
                    values.push(format!("{file}: {name}"));
                }
            }
        }
    }
    assert!(
        values.is_empty(),
        "call it directly, never as a value or an import: {values:?}"
    );
}

/// The entropy crates in Cargo.lock at the versions the clippy.toml list was
/// enumerated against, each with every package that depends on it: a version
/// bump, or a new dependent (which can turn on a feature such as uuid's v7),
/// fails until the list is re-enumerated and this table reviewed.
const ENTROPY_LOCK: &[(&str, &str, &[&str])] = &[
    (
        "getrandom",
        "0.2.17",
        &["jsonwebtoken", "rand_core", "redox_users", "ring"],
    ),
    (
        "getrandom",
        "0.3.4",
        &[
            "ahash",
            "governor",
            "jsonschema",
            "jsonschema-value",
            "rand_core",
            "referencing",
            "tempfile",
        ],
    ),
    (
        "getrandom",
        "0.4.3",
        &["jobserver", "quinn-proto", "rand", "uuid"],
    ),
    (
        "rand",
        "0.10.3",
        &["mcp-gateway", "quinn-proto", "tungstenite", "uuid"],
    ),
    ("rand", "0.9.5", &["governor", "metrics-util"]),
    ("rand_chacha", "0.9.0", &["rand"]),
    (
        "rand_core",
        "0.10.1",
        &["chacha20", "getrandom", "rand", "rand_pcg"],
    ),
    ("rand_core", "0.6.4", &["signature"]),
    (
        "rand_core",
        "0.9.5",
        &["rand", "rand_chacha", "rand_xoshiro"],
    ),
    ("rcgen", "0.14.10", &["mcp-gateway"]),
    (
        "ring",
        "0.17.14",
        &[
            "mcp-gateway",
            "quinn-proto",
            "rcgen",
            "rustls-webpki",
            "x509-parser",
        ],
    ),
    ("uuid", "1.28.0", &["mcp-gateway", "tower-http"]),
];

/// The gateway's own declarations of the entropy crates it calls, as written
/// in Cargo.toml: a feature added here fails until the list is reviewed.
const ENTROPY_DECLARED: [&str; 4] = [
    r#"uuid = { version = "1.23", features = ["v4", "fast-rng"] }"#,
    r#"rand = "0.10""#,
    r#"ring = "0.17""#,
    r#"rcgen = { version = "0.14", features = ["pem", "x509-parser"] }"#,
];

/// Every version of the entropy crates in `lock` with its dependents: a
/// dependency entry names `name version`, or `name` alone when only one
/// version of it is locked.
fn entropy_lock(lock: &str) -> Vec<(String, String, Vec<String>)> {
    let names: Vec<&str> = ENTROPY_LOCK.iter().map(|(name, _, _)| *name).collect();
    let packages: Vec<(String, String, Vec<String>)> = lock
        .split("[[package]]")
        .skip(1)
        .map(|block| {
            let field = |key: &str| {
                block
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix(key)?
                            .strip_prefix(" = \"")?
                            .strip_suffix('"')
                    })
                    .unwrap_or_default()
                    .to_string()
            };
            let deps = block
                .split_once("dependencies = [")
                .map_or(String::new(), |(_, rest)| {
                    rest.split(']').next().unwrap_or_default().to_string()
                })
                .lines()
                .filter_map(|l| {
                    let entry = l.trim().trim_end_matches(',').trim_matches('"');
                    let mut words = entry.split_whitespace();
                    let name = words.next()?;
                    Some(
                        words
                            .next()
                            .map_or(name.to_string(), |v| format!("{name} {v}")),
                    )
                })
                .collect();
            (field("name"), field("version"), deps)
        })
        .collect();
    let mut rows: Vec<(String, String, Vec<String>)> = packages
        .iter()
        .filter(|(name, _, _)| names.contains(&name.as_str()))
        .map(|(name, version, _)| {
            let only = packages.iter().filter(|(n, _, _)| n == name).count() == 1;
            let exact = format!("{name} {version}");
            let mut dependents: Vec<String> = packages
                .iter()
                .filter(|(_, _, deps)| deps.iter().any(|d| *d == exact || (only && d == name)))
                .map(|(n, _, _)| n.clone())
                .collect();
            dependents.sort();
            dependents.dedup();
            (name.clone(), version.clone(), dependents)
        })
        .collect();
    rows.sort();
    rows
}

#[test]
fn the_entropy_crates_are_pinned() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let mut want: Vec<(String, String, Vec<String>)> = ENTROPY_LOCK
        .iter()
        .map(|(name, version, deps)| {
            let deps = deps.iter().map(|d| (*d).to_string()).collect();
            ((*name).to_string(), (*version).to_string(), deps)
        })
        .collect();
    want.sort();
    assert_eq!(
        entropy_lock(&lock),
        want,
        "an entropy crate moved: re-enumerate the clippy.toml list against it, then update this table"
    );
    // cargo rewrites the manifest in a packaged crate; the lock is the same.
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml");
    if !manifest.starts_with("# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO") {
        for line in ENTROPY_DECLARED {
            assert!(
                manifest.lines().any(|l| l.trim() == line),
                "Cargo.toml no longer declares {line}: review the entropy list"
            );
        }
    }
}

/// The credential output pin: digest and approval fields kept out of
/// serializers and text output.
#[path = "credential_output_tests.rs"]
mod credential_output;

/// The root clippy list's free functions, owned by a module path rather than
/// a type or trait, as (module, name).
fn banned_free_functions() -> Vec<(&'static str, &'static str)> {
    include_str!("gateway/meta_mcp/boundary_pins/root_ban_span.toml")
        .lines()
        .filter_map(|path| {
            let (module, name) = path.rsplit_once("::")?;
            let owner = module.rsplit("::").next()?;
            (!owner.starts_with(char::is_uppercase)).then_some((module, name))
        })
        .collect()
}

/// The banned free functions a `use` in `code` imports: directly, aliased,
/// in a group, or by a glob of their module. Imported, one runs as a
/// single-segment call (`random()`) that the allow inventory does not count.
fn imported_free_functions(code: &str) -> Vec<String> {
    let free = banned_free_functions();
    let mut found = Vec::new();
    for (at, _) in code.match_indices("use ") {
        let line_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
        let before = code[line_start..at].trim();
        if !(before.is_empty() || before == "pub" || before.starts_with("pub(")) {
            continue;
        }
        let Some(end) = code[at..].find(';') else {
            continue;
        };
        let compact: String = code[at + 4..at + end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let compact = compact.trim_start_matches("::");
        for (module, name) in &free {
            let direct = compact == format!("{module}::{name}")
                || compact.starts_with(&format!("{module}::{name}as"));
            let glob = compact == format!("{module}::*");
            let grouped = compact
                .strip_prefix(&format!("{module}::{{"))
                .is_some_and(|items| {
                    items.trim_end_matches('}').split(',').any(|item| {
                        item == *name || item == "*" || item.starts_with(&format!("{name}as"))
                    })
                });
            if direct || glob || grouped {
                found.push(format!("{module}::{name}"));
            }
        }
    }
    found
}

/// The import ban sees each spelling, and leaves trait imports alone.
#[test]
fn the_import_ban_sees_each_spelling() {
    for code in [
        "use rand::random;",
        "use rand::random as draw;",
        "use rand::{random, RngExt};",
        "use rand::*;",
        "pub(crate) use ring::rand::generate;",
    ] {
        assert!(!imported_free_functions(code).is_empty(), "missed: {code}");
    }
    for code in [
        "use rand::RngExt as _;",
        "use ring::rand::SecureRandom as _;",
        "use rand::seq::SliceRandom;",
    ] {
        assert!(imported_free_functions(code).is_empty(), "flagged: {code}");
    }
}

/// No production file imports a banned free function: each is called by its
/// full path, which the allow inventory counts.
#[test]
fn no_banned_free_function_is_imported() {
    let imports: Vec<String> = production_sources()
        .into_iter()
        .flat_map(|(file, code)| {
            imported_free_functions(&code)
                .into_iter()
                .map(move |name| format!("{file}: {name}"))
        })
        .collect();
    assert!(
        imports.is_empty(),
        "call it by its full path, never imported: {imports:?}"
    );
}
