// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which names a lock refusal may quote: only names inside npm's registry
//! grammar, so a package cannot choose the words of its own refusal.

use super::*;

/// R20's locks: a root plus one entry, the entry's own fields given.
fn lock_with(key: &str, entry: Value) -> Value {
    json!({"lockfileVersion": 3, "packages": {"": {}, key: entry}})
}

const TARBALL: &str = "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz";

/// R20, kills "a package-chosen name is quoted unchecked": each slot (the
/// entry's key, a peer, a dependency) holding a name outside npm's grammar
/// reads as "the package" or "a dependency", while a registry name is quoted.
#[test]
fn r20_only_registry_names_are_quoted_in_a_lock_refusal() {
    let text = |lock: &Value| check_lock(lock).expect_err("refused").to_string();
    let key = lock_with(
        "node_modules/x y<b>",
        json!({"resolved": "https://elsewhere/x.tgz"}),
    );
    assert_eq!(
        text(&key),
        "this command cannot be previewed: the install holds the package, which is not from the \
         registry; the server can still be added without a preview"
    );
    let peer = lock_with(
        "node_modules/ok",
        json!({"resolved": TARBALL, "peerDependencies": {"x y<b>": "file:../x"}}),
    );
    assert_eq!(
        text(&peer),
        "this command cannot be previewed: the install holds a dependency of node_modules/ok, which \
         is not from the registry; the server can still be added without a preview"
    );
    let dep = lock_with(
        "node_modules/ok",
        json!({"resolved": TARBALL, "dependencies": {"x y<b>": "git+https://x"}}),
    );
    assert_eq!(
        text(&dep),
        "this command cannot be previewed: the install holds a dependency of node_modules/ok, which \
         is not from the registry; the server can still be added without a preview"
    );
    let good = lock_with(
        "node_modules/ok",
        json!({"resolved": TARBALL, "dependencies": {"@a/ok-1": "github:a/b"}}),
    );
    assert_eq!(
        text(&good),
        "this command cannot be previewed: the install holds @a/ok-1 of node_modules/ok, which is \
         not from the registry; the server can still be added without a preview"
    );
}

/// R20's grammar, both sides of each bound: 214 characters pass and 215 do
/// not; a scope needs both halves; capitals are not registry names.
#[test]
fn r20_the_name_grammar_has_its_bounds() {
    assert!(npm_name_ok(&"a".repeat(214)));
    assert!(!npm_name_ok(&"a".repeat(215)));
    assert!(npm_name_ok("@s/n"));
    assert!(!npm_name_ok("@s/"));
    assert!(!npm_name_ok("s/n"));
    assert!(!npm_name_ok("@/n"));
    assert!(!npm_name_ok("A"));
    assert!(npm_name_ok("ok-1.x_y~z"));
}
