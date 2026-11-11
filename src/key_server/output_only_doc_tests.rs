// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The doc tests on `VerifiedIdentity` and `TemporaryToken` say neither type
//! is read from bytes nor written out. A `compile_fail` block proves that only
//! while it fails for the missing trait and nothing else: stable rustdoc does
//! not check the error code, so a typo in the type's path would also fail it,
//! and it would pass. Each type's compiling twin reads the same type through
//! the same path, so the path is proven right where the failures name it.

/// The code lines of the doc test opened by `fence` just above
/// `pub struct {name}`, with `///` removed; `nth` counts fences of that kind.
fn doc_test(source: &str, name: &str, fence: &str, nth: usize) -> Vec<String> {
    let doc = source
        .split(&format!("\npub struct {name} {{"))
        .next()
        .and_then(|before| before.rsplit("\n\n").next())
        .expect("the struct and its doc comment");
    let body = doc
        .split(fence)
        .nth(nth)
        .and_then(|rest| rest.split("/// ```\n").next())
        .unwrap_or_else(|| panic!("{name}: doc test {fence:?} #{nth}"));
    body.lines()
        .map(|line| line.trim_start_matches("///").trim().to_owned())
        .collect()
}

const FAILING: &str = "/// ```compile_fail,E0277\n";

#[test]
fn each_output_only_type_is_neither_read_nor_written_and_reads_through_its_path() {
    for (source, name, path, arg, passing_fence, reads) in [
        (
            include_str!("oidc/verified.rs"),
            "VerifiedIdentity",
            "mcp_gateway::key_server::oidc::VerifiedIdentity",
            "identity",
            "/// Reading it through its accessors compiles:\n///\n/// ```\n",
            "identity.subject()",
        ),
        (
            include_str!("store.rs"),
            "TemporaryToken",
            "mcp_gateway::key_server::TemporaryToken",
            "token",
            "/// Reading its fields compiles:\n///\n/// ```\n",
            "&token.jti",
        ),
    ] {
        let read = doc_test(source, name, FAILING, 1);
        let write = doc_test(source, name, FAILING, 2);
        let passing = doc_test(source, name, passing_fence, 1);
        assert_eq!(
            read,
            [
                format!("fn read(bytes: &str) -> {path} {{"),
                read[1].clone(),
                "}".to_owned(),
            ],
            "{name}: the first failing test reads one value of the type"
        );
        assert!(read[1].starts_with("serde_json::from_str(bytes)"), "{name}");
        assert_eq!(
            write,
            [
                format!("fn write({arg}: &{path}) -> String {{"),
                write[1].clone(),
                "}".to_owned(),
            ],
            "{name}: the second failing test writes one value of the type"
        );
        assert!(write[1].starts_with("serde_json::to_string("), "{name}");
        assert_eq!(passing.len(), 3, "{name}: one read in the twin");
        assert!(
            passing[0].contains(&format!("({arg}: &{path})")),
            "{name}: the twin takes the same type by the same path: {passing:?}"
        );
        assert_eq!(passing[1], reads, "{name}: the twin reads it");
    }
}
