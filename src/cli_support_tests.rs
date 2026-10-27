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

fn read_reference(reference: &str) -> String {
    let path = reference.strip_prefix("file:").expect("a files reference");
    std::fs::read_to_string(path).expect("the secret file")
}

#[test]
fn d16_a_literal_goes_to_the_store_and_only_its_reference_is_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    let found = server("tool", &[("API_KEY", "sk-test")]);

    let adoption = adopt_with(&mut config, &[found], || Ok(opened(dir.path()))).expect("adopts");
    adoption.settle(&Ok(()));

    let written = &config.backends["tool"].env["API_KEY"];
    assert_ne!(written, "sk-test");
    assert_eq!(read_reference(written), "sk-test");
    let yaml = serde_yaml_ng::to_string(&config).expect("yaml");
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
            },
            Outcome::Skipped {
                name: "x/y".to_string(),
                reasons: vec![("invalid_name", "name".to_string())],
            },
            Outcome::Skipped {
                name: "client-only".to_string(),
                reasons: vec![("needs_client_only_secret", "env.API_KEY".to_string())],
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
fn a_store_refusal_writes_nothing_and_leaves_no_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = Config::default();
    // Over the files store's limit, after a value it would take.
    let huge = "x".repeat(64 * 1024);
    let found = server("tool", &[("A", "zq-small"), ("B", huge.as_str())]);

    let Err(message) = adopt_with(&mut config, &[found], || Ok(opened(dir.path()))) else {
        panic!("an oversized value was stored");
    };

    assert!(message.contains("secrets.store"), "{message}");
    assert!(!message.contains("zq-small"), "{message}");
    assert!(config.backends.is_empty());
    assert_eq!(entries(dir.path()), 0);
}

#[test]
fn an_unopenable_store_writes_nothing() {
    let mut config = Config::default();
    let found = server("tool", &[("A", "zq-small")]);

    let refused = adopt_with(&mut config, &[found], || {
        Err("secrets.store (keychain) refused: locked".to_string())
    });

    assert!(refused.is_err());
    assert!(config.backends.is_empty());
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

#[test]
fn a_failed_save_keeps_the_entries_unless_it_was_refused_before_writing() {
    for (saved, kept) in [
        (
            Err("Failed to write gateway.yaml: disk full".to_string()),
            1,
        ),
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
    }]);
    assert!(!shown.contains('\u{202e}'), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
}
