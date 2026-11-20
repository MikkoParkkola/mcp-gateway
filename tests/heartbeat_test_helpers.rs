// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D11 of the heartbeat test plan: every helper in `common/gateway_bin.rs`
//! that builds a gateway command sets `DO_NOT_TRACK=1` on it, so a
//! release-profile test run's spawned gateway never sends a heartbeat.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use gateway_bin::Inherit;

/// The builders, written out (A8): a new `pub fn ... -> Command` in the
/// helper file must join this list, or the completeness check fails by name.
const BUILDERS: [&str; 5] = [
    "command",
    "command_with_env_home",
    "test_binary_with_only_env",
    "isolated_with_env_home",
    "wrapped",
];

/// The one builder that launches no gateway: it re-runs this test binary as a
/// row child with only the named variables, so it carries no gateway setting.
const NOT_A_GATEWAY: &str = "test_binary_with_only_env";

/// The value the built command sets for `DO_NOT_TRACK`, if it sets one.
fn dnt(command: &std::process::Command) -> Option<String> {
    command
        .get_envs()
        .find(|(name, _)| *name == "DO_NOT_TRACK")
        .and_then(|(_, value)| value.map(|v| v.to_string_lossy().into_owned()))
}

/// The `pub fn` names in `source` whose signature (up to its body) returns a
/// `Command`, however the signature is wrapped.
fn builders_in(source: &str) -> Vec<String> {
    source
        .match_indices("pub fn ")
        .filter(|(i, _)| *i == 0 || source[..*i].ends_with('\n'))
        .filter_map(|(i, m)| {
            let rest = &source[i + m.len()..];
            let signature = &rest[..rest.find('{')?];
            signature.contains("-> Command").then(|| {
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect()
            })
        })
        .collect()
}

/// D11. Each builder's command carries `DO_NOT_TRACK=1`, under both inherit
/// modes; the reader returns nothing for a command that does not set it.
#[test]
fn each_gateway_helper_sets_dnt() {
    // Controls first, so a red run proves them on today's tree: the reader
    // returns None for a command that sets nothing, the scan finds a wrapped
    // signature and skips a non-builder, and the helper file defines exactly
    // the builders listed.
    assert_eq!(dnt(&std::process::Command::new("true")), None);
    let planted =
        "pub fn path() -> &'static str {\n}\npub fn planted(\n    a: u8,\n) -> Command {\n}\n";
    assert_eq!(builders_in(planted), ["planted"]);
    assert_eq!(
        builders_in(include_str!("common/gateway_bin.rs")),
        BUILDERS,
        "the builders gateway_bin defines"
    );
    let home = tempfile::tempdir().expect("home");
    let env_home = tempfile::tempdir().expect("env home");
    for inherit in [Inherit::Environment, Inherit::Nothing] {
        let built = [
            ("command", gateway_bin::command(home.path(), inherit)),
            (
                "command_with_env_home",
                gateway_bin::command_with_env_home(home.path(), env_home.path(), inherit),
            ),
            (
                "isolated_with_env_home",
                gateway_bin::isolated_with_env_home(
                    // Only its environment is read; the program never runs.
                    std::process::Command::new("never-run"),
                    home.path(),
                    env_home.path(),
                    inherit,
                ),
            ),
            (
                "wrapped",
                gateway_bin::wrapped(&["sh", "-c", "exec \"$0\" \"$@\""], home.path(), inherit),
            ),
        ];
        let names: Vec<&str> = built.iter().map(|(name, _)| *name).collect();
        let gateway_builders: Vec<&str> = BUILDERS
            .into_iter()
            .filter(|name| *name != NOT_A_GATEWAY)
            .collect();
        assert_eq!(names, gateway_builders);
        for (name, command) in &built {
            assert_eq!(
                dnt(command).as_deref(),
                Some("1"),
                "{name} under {inherit:?}"
            );
        }
    }
}
