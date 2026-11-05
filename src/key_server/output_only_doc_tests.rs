// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The output-only doc tests on `VerifiedIdentity` and `TemporaryToken`
//! prove their point only while each `compile_fail` block fails for the
//! missing `Deserialize` (E0277) on the very type its compiling twin writes
//! out. A typo in the path would fail it for another reason, and it would
//! pass.

const FAILING: &str = "/// ```compile_fail,E0277\n";
const PASSING: &str = "/// Writing one out compiles:\n///\n/// ```\n";

/// The code lines of the doc test opened by `fence` just above
/// `pub struct {name}`, with `///` removed.
fn doc_test(source: &str, name: &str, fence: &str) -> Vec<String> {
    let doc = source
        .split(&format!("\npub struct {name} {{"))
        .next()
        .and_then(|before| before.rsplit("\n\n").next())
        .expect("the struct and its doc comment");
    let body = doc
        .split(fence)
        .nth(1)
        .and_then(|rest| rest.split("/// ```\n").next())
        .unwrap_or_else(|| panic!("{name}: doc test {fence:?}"));
    body.lines()
        .map(|line| line.trim_start_matches("///").trim().to_owned())
        .collect()
}

#[test]
fn each_output_only_type_fails_to_read_and_writes_out() {
    for (source, name, path, arg) in [
        (
            include_str!("oidc.rs"),
            "VerifiedIdentity",
            "mcp_gateway::key_server::oidc::VerifiedIdentity",
            "identity",
        ),
        (
            include_str!("store.rs"),
            "TemporaryToken",
            "mcp_gateway::key_server::TemporaryToken",
            "token",
        ),
    ] {
        let failing = doc_test(source, name, FAILING);
        let passing = doc_test(source, name, PASSING);
        assert_eq!(
            failing,
            [
                format!("fn read(bytes: &str) -> {path} {{"),
                failing[1].clone(),
                "}".to_owned(),
            ],
            "{name}: the failing test reads one value of the type"
        );
        assert!(
            failing[1].starts_with("serde_json::from_str(bytes)"),
            "{name}"
        );
        assert_eq!(
            passing,
            [
                format!("fn write({arg}: &{path}) -> String {{"),
                passing[1].clone(),
                "}".to_owned(),
            ],
            "{name}: the twin writes the same type out"
        );
        assert!(passing[1].starts_with("serde_json::to_string("), "{name}");
    }
}
