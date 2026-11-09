// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The read token's shape rows: the judge may hold one token type of one
//! shape, and build a token only as an argument of its one read chain, on its
//! real firewall, in `assess`, outside async code. Each fixture is the
//! accepted judge with one change, so it reports exactly that change.

use super::*;

/// The accepted judge: the token type, its test-only constructor and the
/// one read chain.
const BASE: &str = r"
    use crate::security::firewall::Firewall;
    use std::cell::Cell;
    /// Only the judge builds one.
    pub(crate) struct ReadsToken(std::cell::Cell<()>);
    #[cfg(test)]
    pub(crate) fn test_token() -> ReadsToken {
        ReadsToken(Cell::new(()))
    }
    fn assess(firewall: &Firewall, key: Option<&str>) {
        let reservation = key.and_then(|k| {
            firewall
                .reads(&ReadsToken(Cell::new(())))
                .reserve(&ReadsToken(Cell::new(())), k, 1, 2, true)
        });
    }
";

/// Everything the judge checks report for `source`: unsupported items and
/// token findings, sorted.
fn findings(source: &str) -> Vec<String> {
    let file = syn::parse_file(source).expect("the fixture parses");
    let mut found = Entries {
        taken: taken_names(&file.items),
        ..Entries::default()
    };
    entries(&file, &mut found);
    let mut all = found.unsupported;
    all.extend(token_findings(&file));
    all.sort();
    all
}

#[test]
fn the_real_token_shape_is_accepted() {
    assert_eq!(findings(BASE), Vec::<String>::new());
    // A grouped import of the real firewall type is the same binding.
    let grouped = BASE.replace(
        "use crate::security::firewall::Firewall;",
        "use crate::security::firewall::{Firewall, FirewallConfig};",
    );
    assert_ne!(grouped, BASE, "the edit matched nothing");
    assert_eq!(findings(&grouped), Vec::<String>::new());
}

/// Every fixture is BASE with one edit; each reports exactly its finding.
// One table holds every refused shape, so each expected finding reads against
// the same accepted judge; splitting it would hide that.
#[test]
#[allow(clippy::too_many_lines)]
fn the_token_check_refuses_each_other_shape() {
    let chain = "firewall\n                .reads(&ReadsToken(Cell::new(())))\n                .reserve(&ReadsToken(Cell::new(())), k, 1, 2, true)";
    let decl = "pub(crate) struct ReadsToken(std::cell::Cell<()>);";
    let assess = "fn assess(firewall: &Firewall, key: Option<&str>) {";
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "a second struct",
            format!("{BASE}\nstruct Other;"),
            "struct Other",
        ),
        (
            "a visible field",
            BASE.replace(
                decl,
                "pub(crate) struct ReadsToken(pub(crate) std::cell::Cell<()>);",
            ),
            "struct ReadsToken",
        ),
        (
            "a derive",
            BASE.replace(decl, &format!("#[derive(Clone)]\n{decl}")),
            "struct ReadsToken",
        ),
        (
            "a unit struct",
            BASE.replace(decl, "pub(crate) struct ReadsToken;"),
            "struct ReadsToken",
        ),
        (
            "a Copy payload",
            BASE.replace(decl, "pub(crate) struct ReadsToken(());"),
            "struct ReadsToken",
        ),
        (
            "a private struct",
            BASE.replace(decl, "struct ReadsToken(std::cell::Cell<()>);"),
            "struct ReadsToken",
        ),
        (
            "a gated fn returning a token",
            format!(
                "{BASE}\npub(crate) fn give(firewall: &Firewall) -> ReadsToken {{\n\
                 let Some(both) = judging(firewall) else {{ return ReadsToken(Cell::new(())); }};\n\
                 ReadsToken(Cell::new(()))\n}}"
            ),
            "a token outside the read chain in give",
        ),
        (
            "a bound token",
            BASE.replace(
                assess,
                &format!("{assess}\n        let t = ReadsToken(Cell::new(()));"),
            ),
            "a token outside the read chain in assess",
        ),
        (
            "a second chain",
            BASE.replace(assess, &format!("{assess}\n        let again = {chain};")),
            "more than one read chain",
        ),
        (
            "a foreign receiver",
            BASE.replace(
                "fn assess(firewall: &Firewall,",
                "fn assess(firewall: &Other,",
            ),
            "a read chain on other than a Firewall parameter in assess",
        ),
        (
            "an alias building tokens",
            format!(
                "{BASE}\nuse self::ReadsToken as Capability;\n\
                 pub(crate) fn give(firewall: &Firewall) -> Capability {{\n\
                 let Some(both) = judging(firewall) else {{ return Capability(Cell::new(())); }};\n\
                 Capability(Cell::new(()))\n}}"
            ),
            "an alias of ReadsToken",
        ),
        (
            "a self-rename through a group",
            format!("{BASE}\nuse self::ReadsToken::{{self as Capability}};"),
            "an alias of ReadsToken",
        ),
        (
            "a glob over the token",
            format!("{BASE}\nuse self::ReadsToken::*;"),
            // A glob may also bring in a `Firewall`, so it is refused on both counts.
            "Firewall bound other than by its import + an alias of ReadsToken",
        ),
        (
            "a raw-spelled alias",
            format!("{BASE}\nuse self::r#ReadsToken as Capability;"),
            "an alias of ReadsToken",
        ),
        (
            "an alias inside a fn",
            format!(
                "{BASE}\nfn helper() -> usize {{\n\
                 use self::ReadsToken as Capability;\n\
                 0\n}}"
            ),
            "an item inside helper",
        ),
        (
            "an alias inside an inline module",
            format!("{BASE}\nmod hidden {{\n    use super::ReadsToken as Capability;\n}}"),
            "mod hidden",
        ),
        (
            "a macro that builds a token",
            format!(
                "{BASE}\nfn helper() -> usize {{\n\
                 make!();\n\
                 0\n}}"
            ),
            "a macro in helper",
        ),
        (
            "a const holding the constructor",
            format!("{BASE}\nconst MAKE: fn(Cell<()>) -> ReadsToken = ReadsToken;"),
            "a token outside the read chain outside a fn",
        ),
        (
            "a generic Firewall shadowing the import",
            BASE.replace("fn assess(", "fn assess<Firewall: Clone>("),
            "a generic assess",
        ),
        (
            "a chain outside assess",
            BASE.replace("fn assess(", "fn judged("),
            "a read chain outside assess in judged",
        ),
        (
            "a let shadowing firewall",
            BASE.replace(
                assess,
                &format!("{assess}\n        let firewall = Foreign;"),
            ),
            "a binding shadows firewall in assess",
        ),
        (
            "a closure parameter shadowing firewall",
            BASE.replace("key.and_then(|k| {", "key.and_then(|firewall| {"),
            "a binding shadows firewall in assess",
        ),
        (
            "a match arm shadowing firewall",
            BASE.replace(
                assess,
                &format!("{assess}\n        match key {{ Some(firewall) => {{}} None => {{}} }}"),
            ),
            "a binding shadows firewall in assess",
        ),
        (
            "a rebound Firewall",
            BASE.replace(
                "use crate::security::firewall::Firewall;",
                "use crate::security::other::Thing as Firewall;",
            ),
            "Firewall bound other than by its import",
        ),
        (
            "a second Firewall binding",
            format!("{BASE}\nuse other::Firewall;"),
            "Firewall bound other than by its import",
        ),
        (
            "an async assess",
            BASE.replace("fn assess(", "async fn assess("),
            "a read chain in async code in assess",
        ),
        (
            "an async block",
            BASE.replace("key.and_then(|k| {", "key.and_then(|k| async {"),
            "a read chain in async code in assess",
        ),
        (
            "an async closure",
            BASE.replace("key.and_then(|k| {", "key.and_then(async |k| {"),
            "a read chain in async code in assess",
        ),
        (
            "a test-only item with another attribute",
            format!("{BASE}\n#[cfg(test)]\n#[inline]\nfn helper() {{}}"),
            "an attribute on helper",
        ),
        (
            "no read chain",
            BASE.replace(chain, "firewall.tenant_guard()"),
            "no read chain",
        ),
    ];
    let mut wrong = Vec::new();
    for (label, source, want) in &cases {
        assert_ne!(source, BASE, "{label}: the edit matched nothing");
        let got = findings(source);
        // A fixture with more than one finding lists them sorted, joined by " + ".
        let want: Vec<&str> = want.split(" + ").collect();
        if got != want {
            wrong.push(format!("{label}: got {got:?}, want {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
