// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The finder's own rows.

use super::*;

/// The scan's own row: a new raw read of the flag is found, and a read of the
/// accessor is not.
#[test]
fn the_scan_finds_a_new_raw_admin_read() {
    let files = file_of("let a = client.admin; let b = client.admin_standing();");
    assert_eq!(
        found_in(&files).get(&(".admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// The two reads a field-access needle cannot see: a struct pattern that
/// binds the flag (with or without a new name, or ignoring it) and a direct
/// `CallerStanding::Admin`. Struct update syntax is a write and is not found.
#[test]
fn the_scan_finds_a_destructured_read_and_a_direct_admin_standing() {
    let cells = [
        ("let Caller { admin, .. } = client;", 1),
        ("let Caller { name, admin: flag, .. } = client;", 1),
        ("match c { Self { admin: _, .. } => {} }", 1),
        ("Caller { admin: true, ..base }", 0),
    ];
    for (text, want) in cells {
        let files = file_of(text);
        assert_eq!(
            found_in(&files)
                .get(&("{ admin, .. }", "src/new.rs".to_owned()))
                .copied()
                .unwrap_or(0),
            want,
            "{text}"
        );
    }
    let files = file_of("let s = CallerStanding::Admin;");
    assert_eq!(
        found_in(&files).get(&("CallerStanding::Admin", "src/new.rs".to_owned())),
        Some(&1)
    );
}

/// Every accessor that reads a standing is a reader too: each one picks
/// `Gateway` or `InScope`, so each call is inventoried with the one it reads.
#[test]
fn the_scan_finds_every_standing_accessor() {
    for (text, needle) in [
        ("if c.is_gateway_admin() {}", "is_gateway_admin"),
        ("let s = c.admin_standing();", "admin_standing"),
        (
            "client.map_or(None, AuthenticatedClient::admin_standing)",
            "admin_standing",
        ),
        ("if caller.admin.is_gateway() {}", "is_gateway()"),
        ("if is_admin(Some(c)) {}", "is_admin("),
        ("let g = BackendGrant::for_ui(Some(c));", "::for_ui("),
    ] {
        let files = file_of(text);
        assert_eq!(
            found_in(&files).get(&(needle, "src/new.rs".to_owned())),
            Some(&1),
            "{text}"
        );
    }
}

/// A fixture as a source file: wrapped in an item so a parser accepts it.
fn file_of(body: &str) -> Vec<(String, String)> {
    vec![(
        "src/new.rs".to_owned(),
        format!("fn fixture() {{ {body} }}"),
    )]
}

/// How many times `needle` is found in the one fixture file.
fn found(files: &[(String, String)], needle: &'static str) -> usize {
    found_in(files)
        .get(&(needle, "src/new.rs".to_owned()))
        .copied()
        .unwrap_or(0)
}

/// A raw identifier names the same field: `c.r#admin` reads the flag.
#[test]
fn the_scan_finds_a_raw_identifier_read() {
    assert_eq!(found(&file_of("let a = c.r#admin;"), ".admin"), 1);
}

/// A struct pattern that names every field binds the flag as surely as one
/// with `..`, outside a macro and inside one.
#[test]
fn the_scan_finds_a_full_field_pattern() {
    for body in [
        "let Small { admin, name } = s;",
        "let _ = matches!(s, Small { admin, name });",
        "assert_matches!(s, Small { admin, name });",
        "check!(s => Small { name, admin });",
    ] {
        assert_eq!(found(&file_of(body), "{ admin, .. }"), 1, "{body}");
    }
}

/// An accessor imported under another name is still that accessor: each
/// call counts, and the use line itself does not. (The text finder counts the
/// name once, in the use line, so two calls tell the finders apart.)
#[test]
fn the_scan_resolves_a_renamed_accessor() {
    let renamed = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::authz::admin_standing as standing;\n\
         fn fixture() { let _ = standing(true, &[]); let _ = standing(false, &[]); }"
            .to_owned(),
    )];
    assert_eq!(found(&renamed, "admin_standing"), 2);
}

/// Comments, string literals and definitions read nothing.
#[test]
fn the_scan_ignores_comments_strings_and_definitions() {
    let files = vec![(
        "src/new.rs".to_owned(),
        "// c.admin\n/// c.admin\nfn is_gateway_admin() {}\nfn fixture() { let _ = \"c.admin\"; }"
            .to_owned(),
    )];
    assert_eq!(found(&files, ".admin"), 0);
    assert_eq!(found(&files, "is_gateway_admin"), 0);
}

/// A raw identifier in a macro no parser takes, and a bare variant through a
/// glob import or a rename, are each one read. (Two reads through the rename:
/// the text finder counts its use line once.)
#[test]
fn the_scan_finds_readers_in_token_walks_globs_and_renamed_variants() {
    assert_eq!(found(&file_of("check!(s => c.r#admin);"), ".admin"), 1);
    let glob = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::router::authorization::CallerStanding::*;\n\
         fn fixture(s: CallerStanding) { match s { Admin => {} _ => {} } }"
            .to_owned(),
    )];
    assert_eq!(found(&glob, "CallerStanding::Admin"), 1);
    let renamed = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::router::authorization::CallerStanding::Admin as Elevated;\n\
         fn fixture(s: CallerStanding) { match s { Elevated => {} _ => {} }; let _ = matches!(s, Elevated); }"
            .to_owned(),
    )];
    assert_eq!(found(&renamed, "CallerStanding::Admin"), 2);
}

/// Imports reach into a macro no parser takes and chain through each other:
/// a renamed variant or type in a token walk, and a rename of a rename, are
/// each one read; a name already monitored is not counted twice.
#[test]
fn the_scan_resolves_imports_in_token_walks_and_through_chains() {
    let file = |uses: &str, body: &str| {
        vec![(
            "src/new.rs".to_owned(),
            format!("{uses}\nfn fixture() {{ {body} }}"),
        )]
    };
    let standing = "use crate::gateway::router::authorization::CallerStanding";
    for (uses, body) in [
        (
            format!("{standing}::Admin as Elevated;"),
            "check!(s => Elevated);",
        ),
        (format!("{standing} as S;"), "check!(s => S::Admin);"),
        (
            format!("{standing} as S;\nuse S::Admin as Elevated;"),
            "let x = Elevated;",
        ),
        (
            format!("{standing} as S;\nuse S::Admin as Elevated;"),
            "check!(s => Elevated);",
        ),
        (
            "use crate::gateway::router::authorization::CallerStanding::*;".to_owned(),
            "check!(s => Admin);",
        ),
    ] {
        assert_eq!(
            found(&file(&uses, body), "CallerStanding::Admin"),
            1,
            "{uses} {body}"
        );
    }
    let direct = file(
        "use crate::gateway::authz::is_gateway_admin;",
        "check!(s => is_gateway_admin);",
    );
    assert_eq!(found(&direct, "is_gateway_admin"), 1, "counted once");
    let renamed = file(
        "use crate::gateway::authz::admin_standing as standing;",
        "check!(s => standing(c));",
    );
    assert_eq!(
        found(&renamed, "admin_standing"),
        1,
        "a renamed accessor in a token walk"
    );
}

/// A reader in an attribute's value or arguments is a read; a file that does
/// not parse, and one local name bound to two paths one of which is
/// monitored, each fail named; a namespaced `matches!` is parsed like the
/// bare one.
#[test]
fn the_scan_reads_attributes_and_names_what_it_cannot_vouch_for() {
    assert_eq!(
        found(&file_of("#[audit = c.r#admin] let a = 1;"), ".admin"),
        1,
        "an attribute value"
    );
    assert_eq!(
        found(&file_of("#[audit(c.admin)] let a = 1;"), ".admin"),
        1,
        "attribute arguments"
    );
    assert_eq!(
        found(
            &file_of("let _ = std::matches!(s, Small { admin, .. });"),
            "{ admin, .. }"
        ),
        1,
        "a namespaced matches!"
    );
    let broken = vec![("src/new.rs".to_owned(), "fn fixture( {".to_owned())];
    assert_eq!(found(&broken, "<does not parse>"), 1, "an unparsed file");
    let conflict = vec![(
        "src/new.rs".to_owned(),
        "mod a { use crate::gateway::authz::is_gateway_admin as check; }\n\
         mod b { use std::mem::drop as check; }\n\
         fn fixture() { check(c); }"
            .to_owned(),
    )];
    assert_eq!(
        found(&conflict, "<conflicting import>"),
        1,
        "a monitored conflict"
    );
}

/// A monitored function taken as a value, or a monitored method called
/// through its type, is a read as surely as a call: each counts once.
#[test]
fn the_scan_finds_callable_readers_taken_as_values() {
    for (body, key) in [
        (
            "let f = CallerStanding::of_client; f(client);",
            "CallerStanding::of_client(",
        ),
        (
            "use crate::gateway::authz::resolve_role; let f = resolve_role; f(k);",
            "resolve_role(",
        ),
        (
            "use crate::gateway::ui::is_admin; let _ = keys.iter().map(is_admin);",
            "is_admin(",
        ),
        (
            "let _ = AdminStanding::is_gateway(standing);",
            "is_gateway()",
        ),
        ("let _ = Thing::for_ui;", "::for_ui("),
        (
            "let _ = CallerStanding::of_client(c);",
            "CallerStanding::of_client(",
        ),
    ] {
        assert_eq!(found(&file_of(body), key), 1, "{body}");
    }
    assert_eq!(
        found(&file_of("let is_admin = true; if is_admin {}"), "is_admin("),
        0,
        "a local named like a reader, never called, is not one"
    );
    let defined = vec![(
        "src/new.rs".to_owned(),
        "fn resolve_role() {}\nfn fixture() { let f = resolve_role; }".to_owned(),
    )];
    assert_eq!(
        found(&defined, "resolve_role("),
        1,
        "a function the file defines, taken as a value"
    );
}

/// The same forms are found in a macro no parser takes as in parsed syntax:
/// a file-defined callable taken as a bare value, and a name that matches one
/// key as written and another through an import (each key once). A file whose
/// imports are too many to resolve fails named, never silently.
#[test]
fn the_token_walk_matches_parsed_syntax_and_a_capped_expansion_fails_named() {
    let defined = vec![(
        "src/new.rs".to_owned(),
        "fn resolve_role() {}\nfn fixture() { check!(s => resolve_role); }".to_owned(),
    )];
    assert_eq!(
        found(&defined, "resolve_role("),
        1,
        "a file-defined callable in a token walk"
    );
    let both = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::router::authorization::CallerStanding::of_client as is_admin;\n\
         fn fixture() { check!(s => is_admin(c)); }"
            .to_owned(),
    )];
    assert_eq!(found(&both, "is_admin("), 1, "the name as written");
    assert_eq!(
        found(&both, "CallerStanding::of_client("),
        1,
        "and what it imports"
    );
    let mut globs = String::new();
    for i in 0..70 {
        globs.push_str("use crate::m");
        globs.push_str(&i.to_string());
        globs.push_str("::*;\n");
    }
    let crowded = vec![(
        "src/new.rs".to_owned(),
        format!(
            "{globs}use crate::gateway::authz::admin_standing as standing;\n\
             fn fixture() {{ let _ = standing(true, &[]); }}"
        ),
    )];
    assert_eq!(
        found(&crowded, "<import expansion capped>"),
        1,
        "named, not silent"
    );
    let cycle = vec![(
        "src/new.rs".to_owned(),
        "use b as a;\nuse a as b;\nfn fixture() { let _ = a(1); check!(s => b(2)); }".to_owned(),
    )];
    assert_eq!(
        found(&cycle, "<import expansion capped>"),
        1,
        "a cycle of renames ends, failing named"
    );
    let two_scopes = vec![(
        "src/new.rs".to_owned(),
        "mod one { use A::Admin as A; }\n\
         mod two { use crate::gateway::router::authorization::CallerStanding as A; }\n\
         fn fixture() { let _ = A; }"
            .to_owned(),
    )];
    assert_eq!(
        found(&two_scopes, "<import expansion capped>"),
        1,
        "a name bound in two scopes that would need expanding twice fails named, not silently"
    );
    let same_name = vec![(
        "src/new.rs".to_owned(),
        "mod guard { pub fn guard() {} }\nuse guard::guard;\nfn fixture() { guard(); }".to_owned(),
    )];
    let all = found_in(&same_name);
    assert!(
        all.keys().all(|(_, file)| file != "src/new.rs"),
        "a function imported from a module of the same name expands once: {all:?}"
    );
}

/// A variant matched by its qualified path is a read, in a match arm, a
/// `let .. else` and an `if let`, as surely as in an expression.
#[test]
fn the_scan_finds_a_qualified_variant_in_a_pattern() {
    for body in [
        "match s { CallerStanding::Admin => {} _ => {} }",
        "let CallerStanding::Admin = s else { return; };",
        "if let CallerStanding::Admin = s {}",
    ] {
        assert_eq!(found(&file_of(body), "CallerStanding::Admin"), 1, "{body}");
    }
}

// Guard rows: green on the text finder too, they pin the new finder's handling.

/// An unrelated import under a monitored name does not hide a real call.
#[test]
fn an_unrelated_alias_does_not_hide_a_real_accessor_call() {
    let shadowed = vec![(
        "src/new.rs".to_owned(),
        "mod other { use std::mem::drop as is_admin; }\n\
         fn fixture() { let _ = is_admin(Some(c)); }"
            .to_owned(),
    )];
    assert_eq!(found(&shadowed, "is_admin("), 1);
}

/// A reader in a `matches!` guard is a read.
#[test]
fn the_scan_finds_a_reader_in_a_matches_guard() {
    assert_eq!(
        found(
            &file_of("let _ = matches!(c, Some(x) if x.admin);"),
            ".admin"
        ),
        1
    );
}

/// The optional-client predicate is a free fn sharing the
/// method's name, so the existing whole-segment needle counts every call and
/// reference to it, and nothing else. A near name is a different segment.
#[test]
fn the_free_predicate_counts_under_its_key() {
    let files = vec![(
        "src/new.rs".to_owned(),
        "use crate::gateway::auth::is_gateway_admin;\n\
         fn fixture() {\n\
             let a = crate::gateway::auth::is_gateway_admin(c);\n\
             let b = is_gateway_admin(c);\n\
             let d = o.map(is_gateway_admin);\n\
         }"
        .to_owned(),
    )];
    let all = found_in(&files);
    assert_eq!(found(&files, "is_gateway_admin"), 3, "{all:?}");
    assert_eq!(all.len(), 1, "counted under no other key: {all:?}");
    for (text, want) in [
        ("let a = is_gateway_admin_opt(c);", 0),
        ("let a = my_is_gateway_admin(c);", 0),
        ("let a = r#is_gateway_admin(c);", 1),
    ] {
        assert_eq!(found(&file_of(text), "is_gateway_admin"), want, "{text}");
    }
}
