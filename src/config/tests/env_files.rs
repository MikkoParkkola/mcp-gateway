// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Env-file overlay resolution and substitution scanning.

use super::*;

// -------------------------------------------------------------------------
// MIK-7256 — env files on a failed load (§P2 failing tests)
//
// Written against `docs/design/mik-7256-env-files-on-a-failed-load.md` and the
// rows in `docs/design/mik-7256-test-plan.md`. The design's types do not exist
// yet, so these are expected to fail to COMPILE until implementation lands.
//
// The design states that expansion must reach its home "through an injected
// resolver rather than calling `dirs::home_dir()` inline" (design:314-315) but
// does not name the seam. These tests name it `config::HomeResolver`, with
// `fn home_dir(&self, so_far: &EnvOverlay) -> Option<PathBuf>`. The `so_far`
// parameter is not decoration: startup applies each file before expanding the
// next, so a resolver that cannot see the overlay under construction cannot
// reproduce production's sequential semantics, which is the property
// ENVFILE.19c exists to pin. Rename freely at implementation time.
// -------------------------------------------------------------------------

/// A [`HomeResolver`] that always answers with one directory, for the rows that
/// only need `HOME` pointed somewhere writable.
struct FixedHome(std::path::PathBuf);

impl HomeResolver for FixedHome {
    fn home_dir(&self, _so_far: &EnvOverlay) -> Option<std::path::PathBuf> {
        Some(self.0.clone())
    }
}

/// ENVFILE.19 — an `env_files` entry spelled `~/<file>` with `HOME` pointed at a
/// temp dir: the overlay OPENS the path startup recorded and reads the same
/// pairs.
///
/// Phrased as opening a recorded path rather than resolving one, because a row
/// that says "resolves" can go green on an overlay that re-expands and happens
/// to agree. Tilde expansion is a supported spelling today
/// (`src/config/mod.rs:290-298`); an overlay that skipped it would silently stop
/// rotating those files, and nothing else in the plan would go red.
#[test]
fn envfile_19_the_overlay_opens_the_tilde_path_startup_recorded() {
    // GIVEN: a home directory holding one env file, named by a `~/...` entry
    let home = tempfile::tempdir().unwrap();
    let env_path = home.path().join("rotating.env");
    write_owner_only(&env_path, "MCP_GW_TEST_ENVFILE19_KEY=startup-value-19\n").unwrap();

    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("gateway.yaml");
    write_owner_only(&cfg_path, "env_files:\n  - \"~/rotating.env\"\n").unwrap();

    // WHEN: startup evaluates the config through an injected home
    let startup =
        Config::load_evaluated_with_home(Some(&cfg_path), &FixedHome(home.path().to_path_buf()))
            .unwrap();

    // THEN: the path startup RECORDED is the expanded one, not the `~` spelling
    assert_eq!(
        startup.env_paths.as_paths(),
        std::slice::from_ref(&env_path),
        "startup must record the absolute path it opened"
    );

    // AND: the overlay carries the pairs read from that same file
    assert_eq!(
        startup
            .overlay
            .resolve("MCP_GW_TEST_ENVFILE19_KEY")
            .as_deref(),
        Some("startup-value-19"),
        "the overlay must carry the pairs of the file startup opened"
    );
}

/// ENVFILE.19d — `HOME` unset and `HOME` empty, each in its own CHILD PROCESS.
///
/// A child per variant because the case mutates a PROCESS-wide variable: an
/// in-process version races every other test the runner schedules beside it,
/// while the oracle it compares against is read in a different environment than
/// the one under test. Absent and empty are the same input to `dirs`, which
/// falls back rather than returning the empty value
/// (`dirs-sys-0.5.0/src/lib.rs:33-37`) — testing only the unset spelling lets an
/// implementation that special-cases one and not the other pass.
#[test]
fn envfile_19d_home_unset_and_home_empty_both_resolve_to_the_dirs_fallback() {
    for variant in ["unset", "empty"] {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "config::tests::envfile_19d_child_resolves_against_dirs_home_dir",
            "--ignored",
            "--nocapture",
        ]);
        cmd.env("MCP_GW_TEST_ENVFILE19D_VARIANT", variant);
        if variant == "unset" {
            cmd.env_remove("HOME");
        } else {
            cmd.env("HOME", "");
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "child for HOME={variant} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        // Printed only after both child assertions pass, so a child that
        // silently ran zero tests cannot be read as a pass.
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("ENVFILE.19d child ok"),
            "child for HOME={variant} did not run the case"
        );
    }
}

/// ENVFILE.13 on the path a running gateway actually takes: the reload layers
/// the new overlay over the one in force, so a line deleted from an env file
/// only stops resolving if that layering does not carry it forward.
#[test]
fn a_key_deleted_from_an_env_file_stops_resolving_after_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join("gateway.env");
    let cfg_path = dir.path().join("gateway.yaml");
    write_owner_only(
        &cfg_path,
        format!("env_files:\n  - '{}'\n", env_path.display()),
    )
    .unwrap();
    write_owner_only(&env_path, "MCP_GW_TEST_DELETED_KEY=first\n").unwrap();

    // GIVEN: a startup that resolved the key from the file
    let startup = Config::load_evaluated(Some(&cfg_path)).unwrap();
    assert_eq!(
        startup
            .overlay
            .resolve("MCP_GW_TEST_DELETED_KEY")
            .as_deref(),
        Some("first"),
        "startup must resolve the key the env file assigns"
    );

    // WHEN: the line is deleted and the config is reloaded against the overlay
    // in force, exactly as `config_reload` does it
    write_owner_only(&env_path, "MCP_GW_TEST_OTHER_KEY=second\n").unwrap();
    let reloaded = Config::load_with_overlay(Some(&cfg_path), &startup.env_paths).unwrap();

    // THEN: the deleted line's value is gone, and the surviving line is not
    assert_eq!(
        reloaded.overlay.resolve("MCP_GW_TEST_DELETED_KEY"),
        None,
        "a deleted assignment must not survive the reload that removed it"
    );
    assert_eq!(
        reloaded.overlay.resolve("MCP_GW_TEST_OTHER_KEY").as_deref(),
        Some("second"),
        "the reload must still apply the file's remaining assignments"
    );
}

/// ENVFILE.12: a substitution naming a key the env files themselves define is
/// a reload hazard, because `dotenvy` expands it against the process
/// environment and nothing writes that environment any more. The scanner has
/// to tell a live substitution from a token the parser would never expand.
#[test]
fn a_substitution_naming_a_defined_key_is_detected_and_a_quoted_one_is_not() {
    use std::collections::BTreeSet;
    let defined: BTreeSet<String> = ["BASE".to_string()].into_iter().collect();
    let dir = tempfile::tempdir().unwrap();

    let cases = [
        ("URL=${BASE}/v1\n", Some("BASE"), "a braced substitution"),
        ("URL=$BASE/v1\n", Some("BASE"), "an unbraced substitution"),
        ("URL=x${BASE}y\n", Some("BASE"), "a substitution mid-value"),
        ("# URL=${BASE}\n", None, "a whole-line comment"),
        ("URL='${BASE}'\n", None, "a single-quoted value"),
        ("URL=\\${BASE}\n", None, "an escaped substitution"),
        ("URL=${OTHER}\n", None, "a key the files do not define"),
        ("URL=plain\n", None, "no substitution at all"),
        ("URL=plain # ${BASE}\n", None, "a trailing comment"),
        (
            "URL='prefix'$BASE\n",
            Some("BASE"),
            "a substitution after a closing single quote",
        ),
        (
            "URL=\"${BASE}\" # ${BASE}\n",
            Some("BASE"),
            "a substitution inside double quotes",
        ),
    ];

    for (index, (body, expected, what)) in cases.iter().enumerate() {
        let path = dir.path().join(format!("case{index}.env"));
        write_owner_only(&path, body).unwrap();
        assert_eq!(
            super::env_overlay::substitution_naming_defined_key(
                &std::fs::read_to_string(&path).unwrap(),
                &defined,
            )
            .as_deref(),
            *expected,
            "{what} was classified wrongly"
        );
    }
}

/// ENVFILE.13: `dotenvy` separates the optional `export` prefix from the key
/// with ANY whitespace — `parse_line` reads the key, then `skip_whitespace`,
/// before looking for the `=` (`dotenvy-0.15.7/src/parse.rs:48-58`). So
/// `export\tKEY=v` is valid and defines `KEY`. Stripping only the literal
/// `"export "` recorded the key as `export\tKEY`, left `KEY` looking
/// undefined, and refused a later `${KEY}` the same file does define — the
/// gateway would not start on a file dotenvy reads without complaint.
#[test]
fn an_export_prefix_is_stripped_whatever_whitespace_follows_it() {
    use std::collections::BTreeSet;
    let defined: BTreeSet<String> = ["KEY".to_string(), "export".to_string()]
        .into_iter()
        .collect();

    // Each case carries the key `dotenvy` actually takes from its first line.
    // Without that column the cases only prove the scanner agrees with itself,
    // and the whole point of the prefix rule is that it agrees with the parser
    // that will later read the same file.
    let cases = [
        (
            "export\tKEY=v\nURL=${KEY}\n",
            "KEY",
            None,
            "a tab after export",
        ),
        (
            "export   KEY=v\nURL=${KEY}\n",
            "KEY",
            None,
            "several spaces after export",
        ),
        (
            "export KEY=v\nURL=${KEY}\n",
            "KEY",
            None,
            "one space after export",
        ),
        (
            "export KEY=v\r\nURL=${KEY}\r\n",
            "KEY",
            None,
            "CRLF line endings",
        ),
        // `export` is a legal key in its own right; treating it as a prefix
        // here would define nothing and let the substitution through.
        (
            "export=v\nURL=${export}\n",
            "export",
            None,
            "export as the key itself",
        ),
        // No whitespace follows, so this is not the prefix and the key is
        // `exportKEY` -- `KEY` really is undefined here.
        (
            "exportKEY=v\nURL=${KEY}\n",
            "exportKEY",
            Some("KEY"),
            "no whitespace after export",
        ),
    ];

    for (body, parsed_key, expected, what) in cases {
        let parsed: Vec<String> = dotenvy::from_read_iter(std::io::Cursor::new(body.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("dotenvy must parse the {what} fixture: {e}"))
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            parsed.first().map(String::as_str),
            Some(parsed_key),
            "dotenvy takes a different key from {what}, so this case proves nothing"
        );

        assert_eq!(
            super::env_overlay::substitution_naming_defined_key(body, &defined).as_deref(),
            expected,
            "{what} was classified wrongly"
        );
    }
}

/// dotenvy substitutes from the process environment before the buffer it is
/// reading (dotenvy 0.15.7 `parse.rs:265`), so a fixture whose referenced key
/// the test runner happens to export would expand to the runner's value. Fail
/// with that cause named rather than with a confusing expansion mismatch.
fn assert_not_in_process_env(key: &str) {
    assert!(
        std::env::var_os(key).is_none(),
        "{key} is set in the process environment, which dotenvy reads before the file"
    );
}

/// Measured against `dotenvy` rather than assumed: a substitution it expands
/// but the scanner cannot see is a reload that silently changes meaning, which
/// is the whole thing the refusal exists to prevent.
///
/// Two shapes the scanner used to miss. A braced name runs to the closing
/// brace, and `dotenvy` accepts a `.` in a key, so `${BASE.URL}` is one dotted
/// name rather than `BASE` followed by junk. And an unbalanced quote joins the
/// physical lines that follow into one value, so a reference on a continuation
/// line is expanded like any other.
#[test]
fn the_scanner_sees_every_substitution_dotenvy_expands() {
    let cases = [
        (
            "BASE.URL",
            "BASE.URL=upstream\nURL=${BASE.URL}/v1\n",
            "URL",
            "upstream/v1",
            "REF=${BASE.URL}/v1\n",
        ),
        (
            "OTHER",
            "OTHER=middle\nK=\"first\n${OTHER}\nlast\"\n",
            "K",
            "first\nmiddle\nlast",
            "REF=\"first\n${OTHER}\nlast\"\n",
        ),
        ("A", "A=x\nK=$A_B\n", "K", "x_B", "REF=$A_B\n"),
    ];

    for (key, same_file, expanded_key, expanded_value, other_file) in cases {
        assert_not_in_process_env(key);
        let parsed: std::collections::HashMap<String, String> =
            dotenvy::from_read_iter(std::io::Cursor::new(same_file.as_bytes()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("dotenvy must parse the {key} fixture: {e}"))
                .into_iter()
                .collect();
        assert_eq!(
            parsed.get(expanded_key).map(String::as_str),
            Some(expanded_value),
            "dotenvy must expand the {key} reference, or this case proves nothing"
        );

        let defined = [key.to_string()].into_iter().collect();
        assert_eq!(
            super::env_overlay::substitution_naming_defined_key(other_file, &defined).as_deref(),
            Some(key),
            "the scanner must name the {key} reference dotenvy just expanded"
        );
    }
}

/// `Env::prefixed(..)` parsed each value before handing it to Figment, and
/// `Figment::extract` does not coerce a string into a number or a bool. A
/// provider that stores raw strings therefore breaks every non-string field an
/// operator can override, which is silent until deserialisation fails.
#[test]
fn overlay_env_parses_values_the_way_the_figment_env_provider_did() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("typed.env");
    write_owner_only(
        &path,
        "MCP_GATEWAY_SERVER__PORT=9090\nMCP_GATEWAY_SERVER__ENABLED=true\n",
    )
    .expect("write env file");

    let overlay = EnvOverlay::from_paths(std::slice::from_ref(&path));
    let data = OverlayEnv::new(&overlay).data().expect("provider data");
    let server = data
        .get(&Profile::Default)
        .and_then(|dict| dict.get("server"))
        .and_then(Value::as_dict)
        .expect("the nested server dictionary");

    assert!(
        matches!(server.get("port"), Some(Value::Num(..))),
        "a numeric override must reach Figment as a number: {:?}",
        server.get("port")
    );
    assert!(
        matches!(server.get("enabled"), Some(Value::Bool(..))),
        "a boolean override must reach Figment as a bool: {:?}",
        server.get("enabled")
    );
}

/// `Env` reads the process environment through `vars_os`, so a non-UTF-8
/// variable belonging to some other part of the system is lossily converted.
/// `std::env::vars` panics on the same input, which would abort a load over a
/// variable the gateway never reads.
// Unix-only: builds a non-UTF-8 env value from raw bytes (OsStringExt); Windows env strings are UTF-16.
#[cfg(unix)]
#[test]
fn overlay_env_survives_a_non_utf8_process_variable() {
    use std::os::unix::ffi::OsStringExt as _;

    let overlay = EnvOverlay::none();
    let vars = OverlayEnv::new(&overlay).merged_vars(
        [
            (
                std::ffi::OsString::from_vec(vec![b'X', 0xff]),
                std::ffi::OsString::from("value"),
            ),
            (
                std::ffi::OsString::from("MCP_GATEWAY_SERVER__PORT"),
                std::ffi::OsString::from_vec(vec![0xff, b'9']),
            ),
        ]
        .into_iter(),
    );

    assert!(
        vars.contains_key("MCP_GATEWAY_SERVER__PORT"),
        "a lossily converted value must still be offered to Figment: {vars:?}"
    );
}

/// The other half of the scanner's contract with `dotenvy`: a reference it
/// would not expand must not refuse a reload. An over-report costs an operator
/// a working reload and is invisible until they try one.
///
/// Every case is measured the same way as its positive sibling — the fixture
/// is parsed first, and the assertion is that `dotenvy` left the reference
/// alone.
#[test]
fn the_scanner_ignores_what_dotenvy_leaves_alone() {
    let cases = [
        // An unbraced name is alphanumeric, so this expands the undefined `A`
        // and leaves `_B` literal: `A_B` is never read.
        ("A_B", "A_B=x\nK=$A_B\n", "K", "_B"),
        // A trailing comment begins after a tab as readily as after a space.
        ("A", "A=x\nK=v\t# $A\n", "K", "v"),
        // A single-quoted region is inert.
        ("A", "A=x\nK='${A}'\n", "K", "${A}"),
    ];

    // The first case expands `A`, which the file never assigns, so an `A` in
    // the process environment would fill it. No case reads another name: an
    // exported `A_B` is never read and must not fail the test.
    assert_not_in_process_env("A");
    for (key, file, unexpanded_key, unexpanded_value) in cases {
        let parsed: std::collections::HashMap<String, String> =
            dotenvy::from_read_iter(std::io::Cursor::new(file.as_bytes()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap_or_else(|e| panic!("dotenvy must parse the {key} fixture: {e}"))
                .into_iter()
                .collect();
        assert_eq!(
            parsed.get(unexpanded_key).map(String::as_str),
            Some(unexpanded_value),
            "dotenvy must leave the {key} reference unexpanded, or this case proves nothing"
        );

        let defined = [key.to_string()].into_iter().collect();
        assert_eq!(
            super::env_overlay::substitution_naming_defined_key(file, &defined),
            None,
            "the scanner must not refuse a reload over a reference dotenvy ignores: {file:?}"
        );
    }
}

/// A rewrite round-trips the file. An `MCP_GATEWAY_*` override reaching the
/// struct would be serialised back out on the next write, planting in the
/// config a value the operator only ever set in an env file — the same defect
/// as a persisted secret, arriving through the prefix instead of through
/// `env:`.
#[test]
fn a_literal_load_leaves_an_env_file_override_out_of_the_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_path = dir.path().join("override.env");
    write_owner_only(&env_path, "MCP_GATEWAY_SERVER__PORT=9090\n").expect("write env file");
    let config_path = dir.path().join("config.yaml");
    write_owner_only(
        &config_path,
        format!(
            "env_files:\n  - {}\nserver:\n  port: 8080\n",
            env_path.display()
        ),
    )
    .expect("write config");

    let resolved = Config::load(Some(&config_path)).expect("resolved load");
    assert_eq!(
        resolved.server.port, 9090,
        "the override must still reach a running gateway, or this case proves nothing"
    );

    let literal = Config::load_literal(Some(&config_path)).expect("literal load");
    assert_eq!(
        literal.server.port, 8080,
        "a rewrite path must see the port the file spells, not the one the env file overrides"
    );

    crate::gateway::test_helpers::write_config_fixture(&config_path, &literal).expect("rewrite");
    let rewritten = std::fs::read_to_string(&config_path).expect("read back");
    assert!(
        !rewritten.contains("9090"),
        "the rewrite must not persist an env-file override: {rewritten}"
    );
    // Asserting only the absence would also pass for a rewrite that lost the
    // port and the env-file list entirely, which is data loss wearing the same
    // output as a correct write.
    assert!(
        rewritten.contains("8080"),
        "the rewrite must keep the port the file spells: {rewritten}"
    );
    assert!(
        rewritten.contains(&env_path.display().to_string()),
        "the rewrite must keep the env-file list the config declares: {rewritten}"
    );
}

/// A file that supplies a key and then substitutes it resolves within its own
/// buffer, so the startup guard must let it through.
///
/// The guard compares against the keys *every* env file owns. Before this, a
/// file's own earlier assignment made its later reference look like the silent
/// cross-file read the guard exists to refuse, and a configuration that loads
/// exactly as written could not start the gateway.
#[test]
fn a_file_substituting_a_key_it_defined_itself_is_not_refused() {
    // dotenvy substitutes from the process environment before the buffer
    // (dotenvy 0.15.7 `parse.rs:265`), so a common name such as `BASE`
    // exported by whatever runs the tests replaces the file's own value and
    // fails the precondition below. Namespaced keys keep the fixture hermetic,
    // and the check names the cause if one is ever set anyway.
    const BASE: &str = "MCP_GW_TEST_SAME_FILE_BASE";
    const ENDPOINT: &str = "MCP_GW_TEST_SAME_FILE_ENDPOINT";
    assert_not_in_process_env(BASE);
    let file = format!("{BASE}=https://api.invalid-test\n{ENDPOINT}=${{{BASE}}}/v1\n");

    let parsed: std::collections::HashMap<String, String> =
        dotenvy::from_read_iter(std::io::Cursor::new(file.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("dotenvy must parse the fixture")
            .into_iter()
            .collect();
    assert_eq!(
        parsed.get(ENDPOINT).map(String::as_str),
        Some("https://api.invalid-test/v1"),
        "dotenvy must expand the same-file reference, or this case proves nothing"
    );

    let defined = [BASE.to_string(), ENDPOINT.to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        super::env_overlay::substitution_naming_defined_key(&file, &defined),
        None,
        "a reference the same file already supplied is not a cross-file read"
    );
}

/// The other half: a reference to a key this file never assigns is still
/// refused, so the fix above did not simply switch the guard off.
#[test]
fn a_reference_to_a_key_another_file_owns_is_still_refused() {
    let file = "ENDPOINT=${BASE}/v1\n";
    let defined = ["BASE".to_string(), "ENDPOINT".to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        super::env_overlay::substitution_naming_defined_key(file, &defined).as_deref(),
        Some("BASE"),
        "a key supplied only by another env file does not resolve here"
    );
}
