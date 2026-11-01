// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `discover --write`'s adoption: literal values go to the secret store and
//! only references reach the config, a refused server is skipped with its
//! reasons and no value, and no entry is deleted once a saved file may name
//! it.

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use super::*;
use crate::config::{Config, TransportConfig};
use crate::discovery::{DiscoveredServer, DiscoverySource, ServerMetadata};
use crate::secret_store::{FilesStore, SecretStore, Vault, unused_entries};

fn server(name: &str, env: &[(&str, &str)]) -> DiscoveredServer {
    let mut server = DiscoveredServer::new(
        name.to_string(),
        String::new(),
        DiscoverySource::ClaudeDesktop,
        TransportConfig::Stdio {
            command: "npx".to_string(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata::default(),
    );
    server.env = env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect::<HashMap<_, _>>()
        .into_iter()
        .collect();
    server
}

fn opened(dir: &Path) -> Opened {
    (
        Vault::with_lock(dir, dir.join("vault.lock")),
        Arc::new(FilesStore::new(dir)),
    )
}

/// Entries in the store that no config names: every entry, here.
fn entries(dir: &Path) -> usize {
    let store = FilesStore::new(dir);
    let stores: [&dyn SecretStore; 1] = [&store];
    unused_entries(
        &Vault::with_lock(dir, dir.join("vault.lock")),
        &stores,
        &BTreeSet::new(),
    )
    .expect("listing")
    .len()
}

/// The value the gateway reads for `reference`, through its own reader.
fn read_reference(reference: &str) -> String {
    assert!(reference.starts_with("file:"), "{reference}");
    crate::config::secret_ref::SecretRef::parse(reference)
        .resolve("test", &Config::default().env_overlay())
        .expect("the reference resolves")
}

#[test]
fn d16_a_literal_goes_to_the_store_and_only_its_reference_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let mut found = server("tool", &[("API_KEY", "sk-test")]);
    found.headers = [("Authorization".to_string(), "Bearer sk-header".to_string())]
        .into_iter()
        .collect();

    let adoption = adopt_with(&mut config, &[found], || Ok(opened(dir.path()))).expect("adopts");
    adoption.settle(&Ok(()));

    let backend = &config.backends["tool"];
    let written = &backend.env["API_KEY"];
    assert_ne!(written, "sk-test");
    assert_eq!(read_reference(written), "sk-test");
    assert_eq!(
        read_reference(&backend.headers["Authorization"]),
        "Bearer sk-header"
    );
    let yaml = crate::yaml::to_string(&config).expect("yaml");
    assert!(!yaml.contains("sk-test"), "{yaml}");
}

/// d9c: a client value that looks like a gateway reference is the client's
/// literal; it is stored as those bytes, never kept as a reference.
#[test]
fn d9c_a_reference_shaped_literal_is_stored_as_its_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let literal = "file:/nonexistent/mcp-gateway-b3/token";
    let found = server("tool", &[("API_KEY", literal)]);

    adopt_with(&mut config, &[found], || Ok(opened(dir.path())))
        .expect("adopts")
        .settle(&Ok(()));

    let written = &config.backends["tool"].env["API_KEY"];
    assert_ne!(written, literal);
    assert_eq!(read_reference(written), literal);
}

#[test]
fn a_template_and_an_empty_value_are_copied_and_no_store_is_opened() {
    let mut config = Config::default();
    let found = server(
        "tool",
        &[
            ("TOKEN", "${TOKEN}"),
            ("AUTH", "Bearer ${T}"),
            ("EMPTY", ""),
        ],
    );
    let opens = Cell::new(0);

    adopt_with(&mut config, &[found], || {
        opens.set(opens.get() + 1);
        Err("no store".to_string())
    })
    .expect("adopts")
    .settle(&Ok(()));

    assert_eq!(opens.get(), 0, "a store was opened with nothing to save");
    let env = &config.backends["tool"].env;
    assert_eq!(env["TOKEN"], "${TOKEN}");
    assert_eq!(env["AUTH"], "Bearer ${T}");
    assert_eq!(env["EMPTY"], "");
}

/// d7 and the skip ruling: the capabilities name, an invalid name and a
/// refused find are skipped with their codes; the rest is written.
#[test]
fn d7_a_refused_server_is_skipped_with_its_reasons_and_no_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let capabilities = config.capabilities.name.clone();
    let mut client_only = server("client-only", &[("API_KEY", "zq-never-shown")]);
    client_only.uncarried = vec!["env.API_KEY".to_string()];
    let servers = [
        server(&capabilities, &[]),
        server("x/y", &[]),
        client_only,
        server("good", &[("K", "zq-stored")]),
    ];

    let adoption = adopt_with(&mut config, &servers, || Ok(opened(dir.path()))).expect("adopts");

    assert_eq!(
        adoption.outcomes,
        [
            Outcome::Skipped {
                name: capabilities.clone(),
                reasons: vec![("capabilities_name", "name".to_string())],
                skip: Skip::ByRule,
            },
            Outcome::Skipped {
                name: "x/y".to_string(),
                reasons: vec![("invalid_name", "name".to_string())],
                skip: Skip::Refused,
            },
            Outcome::Skipped {
                name: "client-only".to_string(),
                reasons: vec![("needs_client_only_secret", "env.API_KEY".to_string())],
                skip: Skip::Refused,
            },
            Outcome::Adopted {
                name: "good".to_string()
            },
        ]
    );
    let shown = describe_skipped(&adoption.outcomes);
    assert!(
        shown.contains("needs_client_only_secret (env.API_KEY)"),
        "{shown}"
    );
    assert!(!shown.contains("zq-"), "{shown}");
    adoption.settle(&Ok(()));
    let names: Vec<&String> = config.backends.keys().collect();
    assert_eq!(names, ["good"]);
}

#[test]
fn when_every_server_is_skipped_nothing_is_written_or_stored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let mut refused = server("refused", &[("API_KEY", "zq-never-shown")]);
    refused.uncarried = vec!["env.API_KEY".to_string()];

    let Err(message) = adopt_with(&mut config, &[refused, server("a b", &[])], || {
        Ok(opened(dir.path()))
    }) else {
        panic!("a write with nothing adoptable succeeded");
    };

    assert!(
        message.contains("no discovered server could be adopted"),
        "{message}"
    );
    assert!(message.contains("invalid_name (name)"), "{message}");
    assert!(!message.contains("zq-"), "{message}");
    assert!(config.backends.is_empty());
    assert!(!dir.path().join("secrets").exists());
}

#[test]
fn a_value_the_store_cannot_keep_skips_its_server_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    // One byte over the files store's limit.
    let huge = "x".repeat(64 * 1024);
    let servers = [
        server("big", &[("A", "zq-small"), ("B", huge.as_str())]),
        server("fine", &[("K", "zq-kept")]),
    ];

    let adoption = adopt_with(&mut config, &servers, || Ok(opened(dir.path()))).expect("adopts");

    assert_eq!(
        adoption.outcomes[0],
        Outcome::Skipped {
            name: "big".to_string(),
            reasons: vec![("value_too_large", "env.B".to_string())],
            skip: Skip::Refused,
        }
    );
    adoption.settle(&Ok(()));
    let names: Vec<&String> = config.backends.keys().collect();
    assert_eq!(names, ["fine"]);
    assert_eq!(entries(dir.path()), 1, "only the adopted server's value");
}

#[test]
fn an_unopenable_store_writes_nothing() {
    let mut config = Config::default();
    let found = server("tool", &[("A", "zq-small")]);

    let Err(message) = adopt_with(&mut config, &[found], || {
        Err("secrets.store (keychain) refused: locked".to_string())
    }) else {
        panic!("adopted without a store");
    };

    assert!(message.contains("secrets.store"), "{message}");
    assert!(config.backends.is_empty());
}

/// A later server of a name already offered is skipped: the first wins, and
/// no entry is made for a backend the file would not name.
#[test]
fn a_repeated_name_is_skipped_and_stores_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let servers = [
        server("tool", &[("K", "zq-first")]),
        server("tool", &[("K", "zq-second")]),
    ];

    let adoption = adopt_with(&mut config, &servers, || Ok(opened(dir.path()))).expect("adopts");

    assert_eq!(
        adoption.outcomes[1],
        Outcome::Skipped {
            name: "tool".to_string(),
            reasons: vec![("duplicate_name", "name".to_string())],
            skip: Skip::Refused,
        }
    );
    adoption.settle(&Ok(()));
    assert_eq!(entries(dir.path()), 1);
    assert_eq!(
        read_reference(&config.backends["tool"].env["K"]),
        "zq-first"
    );
}

/// Every refusal names its field only: no URL, argument or path reaches the
/// warning, whichever rule refused.
#[test]
fn no_refusal_shows_a_url_or_an_argument() {
    let mut url = server("remote", &[]);
    url.transport = TransportConfig::Http {
        http_url: "https://zq-host.example/mcp?token=zq-query".to_string(),
        streamable_http: None,
        protocol_version: None,
    };
    let mut args = server("local", &[]);
    if let TransportConfig::Stdio { command, cwd, .. } = &mut args.transport {
        *command = "npx ${zq-arg}".to_string();
        *cwd = Some("zq-relative/dir".to_string());
    }
    let mut template = server("template", &[("KEY", "zq-${SUFFIX}")]);
    template.uncarried = vec!["args[1]".to_string()];
    let mut config = Config::default();

    let Err(message) = adopt_with(&mut config, &[url, args, template], || {
        Err("unused".to_string())
    }) else {
        panic!("a refused server was adopted");
    };

    assert!(message.contains("credential_in_url (url)"), "{message}");
    assert!(
        message.contains("needs_client_only_secret (command)"),
        "{message}"
    );
    assert!(
        message.contains("needs_client_only_secret (cwd)"),
        "{message}"
    );
    assert!(
        message.contains("needs_client_only_secret (args[1]), literal_in_template (env.KEY)"),
        "sorted by field: {message}"
    );
    assert!(!message.contains("zq-"), "{message}");
}

/// r4 F4: once the edit returned, a panic (printing the comments note after
/// the save, say) keeps the entries: the saved file may name them.
#[test]
fn f4_a_panic_after_the_edit_keeps_the_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let found = server("tool", &[("API_KEY", "sk-test")]);
    let adoption = adopt_with(&mut config, &[found], || Ok(opened(dir.path()))).expect("adopts");

    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _held = adoption;
        panic!("after the save");
    }));

    assert!(unwound.is_err());
    assert_eq!(entries(dir.path()), 1, "the entry was deleted on unwind");
}

/// The writer's last fallible step is the atomic rename, so any error means
/// the file was not replaced and nothing names the entries.
#[test]
fn a_failed_save_removes_the_entries_and_a_saved_one_keeps_them() {
    for (saved, kept) in [
        (Err("Failed to replace config: disk full".to_string()), 0),
        (Err("Not saved: it would drop comments".to_string()), 0),
        (Ok(()), 1),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = Config::default();
        let found = server("tool", &[("API_KEY", "sk-test")]);

        adopt_with(&mut config, &[found], || Ok(opened(dir.path())))
            .expect("adopts")
            .settle(&saved);

        assert_eq!(entries(dir.path()), kept, "{saved:?}");
    }
}

#[test]
fn a_skipped_field_is_escaped_for_the_terminal() {
    let shown = describe_skipped(&[Outcome::Skipped {
        name: "a\u{202e}b".to_string(),
        reasons: vec![("needs_client_only_secret", "env.K\u{1b}[31m".to_string())],
        skip: Skip::Refused,
    }]);
    assert!(!shown.contains('\u{202e}'), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
}

/// `shown` escapes exactly the characters that can hide, reorder or break
/// terminal text, and keeps everything else, a Windows path included.
#[test]
fn shown_escapes_hidden_characters_and_keeps_the_rest() {
    let rows = [
        ("plain-name_1.0", "plain-name_1.0"),
        ("C:\\Users\\me\\mcp.json", "C:\\Users\\me\\mcp.json"),
        ("ünïcødé 名前", "ünïcødé 名前"),
        ("a\u{1b}[31mb", "a\\u{1b}[31mb"),
        ("a\u{202e}b", "a\\u{202e}b"),
        ("a\u{200b}b", "a\\u{200b}b"),
        ("a\nb\rc\td", "a\\u{a}b\\u{d}c\\u{9}d"),
        ("a\u{2028}b\u{2029}c", "a\\u{2028}b\\u{2029}c"),
        ("a\u{7f}b\u{85}c", "a\\u{7f}b\\u{85}c"),
        // Only a backslash that begins `\u{` is doubled.
        ("a\\u{1b}b", "a\\\\u{1b}b"),
        ("C:\\u\\x\\{y}", "C:\\u\\x\\{y}"),
    ];
    for (raw, expected) in rows {
        assert_eq!(shown(raw).to_string(), expected, "{raw:?}");
        assert_eq!(shows_unchanged(raw), raw == expected, "{raw:?}");
    }
}

/// A name that spells an escape out never reads like one `shown` wrote.
#[test]
fn a_spelled_out_escape_is_told_apart_from_a_real_one() {
    let real = shown("tool\u{1b}x").to_string();
    let spelled = shown("tool\\u{1b}x").to_string();
    assert_eq!(real, "tool\\u{1b}x");
    assert_eq!(spelled, "tool\\\\u{1b}x");
    assert_ne!(real, spelled);
}

/// Backslash runs before an escape are doubled whole, so no two names print
/// alike: an odd run before `u{` is an escape `shown` wrote, an even one is
/// literal text.
#[test]
fn backslash_runs_never_make_two_names_print_alike() {
    let names = [
        "a\u{1b}",    // a real ESC
        "a\\u{1b}",   // the text \u{1b}
        "a\\\u{1b}",  // a backslash, then a real ESC
        "a\\\\u{1b}", // the text \\u{1b}
    ];
    let printed: Vec<String> = names.iter().map(|n| shown(n).to_string()).collect();
    assert_eq!(
        printed,
        ["a\\u{1b}", "a\\\\u{1b}", "a\\\\\\u{1b}", "a\\\\\\\\u{1b}"]
    );
    // A path's lone backslashes stay single.
    assert_eq!(shown("C:\\Users\\me").to_string(), "C:\\Users\\me");
}

/// The skip warning keeps its quotes around an escaped name.
#[test]
fn a_skip_warning_quotes_the_escaped_name() {
    let shown_skip = describe_skipped(&[Outcome::Skipped {
        name: "a\u{1b}b".to_string(),
        reasons: vec![("invalid_name", "name".to_string())],
        skip: Skip::Refused,
    }]);
    assert_eq!(shown_skip, "\"a\\u{1b}b\": invalid_name (name)");
}

/// A run whose only find is left out by rule (the gateway's own entry,
/// named like `capabilities.name`) imports nothing and succeeds; no store is
/// opened.
#[test]
fn a_run_skipped_only_by_rule_succeeds_with_nothing_adopted() {
    let mut config = Config::default();
    let own = config.capabilities.name.clone();
    let servers = [server(&own, &[])];
    let adoption = adopt_with(&mut config, &servers, || {
        panic!("no store is opened when nothing is adopted")
    })
    .expect("a by-rule skip is not a failure");
    assert_eq!(
        adoption.outcomes,
        [Outcome::Skipped {
            name: own,
            reasons: vec![("capabilities_name", "name".to_string())],
            skip: Skip::ByRule,
        }]
    );
    assert!(config.backends.is_empty());
}

/// A refusal with nothing adopted fails the run, by-rule skips beside it
/// or not, and the message names every skipped server.
#[test]
fn a_refusal_with_nothing_adopted_fails_the_run() {
    let mut config = Config::default();
    let own = config.capabilities.name.clone();
    let servers = [server(&own, &[]), server("x/y", &[])];
    let error = adopt_with(&mut config, &servers, || {
        panic!("no store is opened when nothing is adopted")
    })
    .err()
    .expect("a refusal with nothing adopted fails");
    assert!(error.contains("nothing was written"), "{error}");
    assert!(error.contains("invalid_name"), "{error}");
    assert!(error.contains("capabilities_name"), "{error}");
    assert!(config.backends.is_empty());
}
