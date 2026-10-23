// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8783.AUTO.7, the family guard for settings-automatic-first: the
//! loader's retired and removed key lists (src/config/strict_keys.rs) and the
//! list `mcp-gateway upgrade` deletes (src/commands/retired_config_keys.rs)
//! name the same keys. The two live in different crates (the library and the
//! binary), so the guard reads both sources rather than widening either.

use std::collections::BTreeSet;

use regex::Regex;

fn source(rel: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The text of `const NAME: ... = &[ ... ];`, up to its closing `];`.
fn block<'a>(text: &'a str, name: &str) -> &'a str {
    let head = format!("const {name}: ");
    let start = text
        .find(&head)
        .unwrap_or_else(|| panic!("no const {name}"));
    let rest = &text[start..];
    // The earlier of the two closings: a one-row list ends `)];` on its own line.
    let end = [rest.find("\n];"), rest.find(")];")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or_else(|| panic!("{name} has no end"));
    &rest[..end]
}

/// Every `&["a", "b"]` path in `text`, dotted.
fn paths(text: &str) -> BTreeSet<String> {
    let path = Regex::new(r#"&\[((?:"[^"]+",?\s*)+)\]"#).expect("regex");
    let seg = Regex::new(r#""([^"]+)""#).expect("regex");
    path.captures_iter(text)
        .map(|c| {
            seg.captures_iter(&c[1])
                .map(|s| s[1].to_owned())
                .collect::<Vec<_>>()
                .join(".")
        })
        .collect()
}

/// The loader's three lists, as dotted paths (`backends.*.<key>` for the
/// backend ones).
fn loader() -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let text = source("src/config/strict_keys.rs");
    let backend_key = Regex::new(r#"\(\s*"([a-z_]+)",\s*\n"#).expect("regex");
    let backend = backend_key
        .captures_iter(block(&text, "REMOVED_BACKEND_KEYS"))
        .map(|c| format!("backends.*.{}", &c[1]))
        .collect();
    (
        paths(block(&text, "RETIRED_KEYS")),
        paths(block(&text, "REMOVED_KEYS")),
        backend,
    )
}

/// `upgrade`'s list, split by what the loader does with each key.
fn upgrade() -> (BTreeSet<String>, BTreeSet<String>) {
    let text = source("src/commands/retired_config_keys.rs");
    let row = Regex::new(r"\((&\[[^\]]+\]),\s*OnLoad::(Warns|Refuses)\)").expect("regex");
    let (mut warns, mut refuses) = (BTreeSet::new(), BTreeSet::new());
    for c in row.captures_iter(block(&text, "REMOVED")) {
        let key = paths(&c[1]).into_iter().next().expect("one path per row");
        if &c[2] == "Warns" {
            warns.insert(key)
        } else {
            refuses.insert(key)
        };
    }
    (warns, refuses)
}

/// Each side's extras.
fn gaps(left: &BTreeSet<String>, right: &BTreeSet<String>) -> (Vec<String>, Vec<String>) {
    (
        left.difference(right).cloned().collect(),
        right.difference(left).cloned().collect(),
    )
}

const RETIRED_SETTINGS: [&str; 7] = [
    "capabilities.stale_check_secs",
    "cache.enabled",
    "failsafe.retry.enabled",
    "failsafe.circuit_breaker.enabled",
    "auth.client_circuit_breaker.enabled",
    "security.signature_chain.max_links",
    "server.protocol_revision_window",
];

/// T1.1: three pairs, each equal; the seven settings are retired keys.
#[test]
fn the_loader_and_upgrade_retire_the_same_keys() {
    let (retired, removed, backend) = loader();
    let (warns, refuses) = upgrade();
    // The reader must have found something: an empty parse equals an empty parse.
    assert!(
        retired.contains("meta_mcp.cache_tools") && removed.contains("marketplace"),
        "{retired:?} {removed:?}"
    );
    assert!(backend.contains("backends.*.idle_timeout"), "{backend:?}");
    let none = (vec![], vec![]);
    assert_eq!(
        gaps(&retired, &warns),
        none,
        "RETIRED_KEYS vs upgrade's Warns"
    );
    let plain: BTreeSet<String> = refuses
        .iter()
        .filter(|k| !k.starts_with("backends."))
        .cloned()
        .collect();
    let wild: BTreeSet<String> = refuses
        .iter()
        .filter(|k| k.starts_with("backends."))
        .cloned()
        .collect();
    assert_eq!(
        gaps(&removed, &plain),
        none,
        "REMOVED_KEYS vs upgrade's Refuses"
    );
    assert_eq!(
        gaps(&backend, &wild),
        none,
        "REMOVED_BACKEND_KEYS vs upgrade's backends.* Refuses"
    );
    for key in RETIRED_SETTINGS {
        assert!(retired.contains(key), "{key} must be a retired key");
    }
}

/// T1.2: the reader and the comparison name a key missing on either side.
#[test]
fn the_registry_comparison_names_a_missing_key() {
    let text = "const REMOVED: &[(&[&str], OnLoad)] = &[\n    (&[\"a\", \"b\"], OnLoad::Warns),\n    (&[\"c\"], OnLoad::Warns),\n];\n";
    let all = paths(block(text, "REMOVED"));
    assert_eq!(all, BTreeSet::from(["a.b".to_owned(), "c".to_owned()]));
    let short = BTreeSet::from(["a.b".to_owned()]);
    assert_eq!(gaps(&all, &short), (vec!["c".to_owned()], vec![]));
    assert_eq!(gaps(&short, &all), (vec![], vec!["c".to_owned()]));
}
