// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which names a lock refusal may quote: only names inside npm's registry
//! grammar, so a package cannot choose the words of its own refusal.

use super::*;

/// R20's locks: a root plus one entry, the entry's own fields given.
fn lock_with(key: &str, entry: Value) -> Value {
    let mut lock = json!({"lockfileVersion": 3, "packages": {"": {}}});
    lock["packages"][key] = entry;
    lock
}

const TARBALL: &str = "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz";

/// R20, kills "a package-chosen name is quoted unchecked": each slot (the
/// entry's key, a peer, a dependency) holding a name outside npm's grammar
/// reads as "the package" or "a dependency", while a registry name is quoted.
#[test]
fn r20_only_registry_names_are_quoted_in_a_lock_refusal() {
    // Each case pins what its refusal must say (which slot, and never the bad
    // name), not the sentence around it.
    let ok = "node_modules/ok";
    let slots = [
        (
            lock_with(
                "node_modules/x y<b>",
                json!({"resolved": "https://elsewhere/x.tgz"}),
            ),
            "the package",
        ),
        (
            lock_with(
                ok,
                json!({"resolved": TARBALL, "peerDependencies": {"x y<b>": "file:../x"}}),
            ),
            "a dependency of node_modules/ok",
        ),
        (
            lock_with(
                ok,
                json!({"resolved": TARBALL, "dependencies": {"x y<b>": "git+https://x"}}),
            ),
            "a dependency of node_modules/ok",
        ),
        (
            lock_with(
                ok,
                json!({"resolved": TARBALL, "dependencies": {"@a/ok-1": "github:a/b"}}),
            ),
            "@a/ok-1 of node_modules/ok",
        ),
    ];
    for (lock, who) in slots {
        let text = check_lock(&lock).expect_err("refused").to_string();
        assert!(
            text.contains(&format!("the install holds {who}, which")) && !text.contains("x y<b>"),
            "the refusal should name {who:?} and never the bad name: {text}"
        );
        // The frame every command refusal carries: what failed, and that the
        // server can still be added.
        assert!(
            text.starts_with("this command cannot be previewed: ")
                && text.ends_with("; the server can still be added without a preview"),
            "the refusal lost its frame: {text}"
        );
    }
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
