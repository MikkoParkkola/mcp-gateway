// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A server's optional owner (`backends.<name>.owner`): loaded through the
//! real pipeline (strict keys, then validation), trimmed when read, at most
//! 200 characters, no control character anywhere.

use super::{BackendConfig, Config};

/// `Config::load` of a file with one backend `svc` whose mapping carries
/// `extra` (YAML lines, already indented).
fn load(extra: &str) -> anyhow::Result<Config> {
    load_text(&format!(
        "backends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n{extra}"
    ))
}

fn load_text(text: &str) -> anyhow::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, text).expect("write config");
    Config::load(Some(&path)).map_err(anyhow::Error::from)
}

/// A YAML double-quoted owner line for `value`, escaping as YAML does.
fn owner_line(value: &str) -> String {
    format!(
        "    owner: {}\n",
        serde_json::to_string(value).expect("json string")
    )
}

fn refused_naming_owner(result: anyhow::Result<Config>, case: &str) {
    let error = match result {
        Ok(_) => panic!("{case}: loaded, expected a refusal"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        error.contains("backends.svc.owner"),
        "{case}: the refusal names the key: {error}"
    );
}

/// O1, O5: a backend loads without `owner`, with one (the strict key list
/// accepts it), and with an explicit `null`; a non-string is refused.
#[test]
fn o1_a_backend_loads_with_or_without_an_owner() {
    let without = load("").expect("loads without an owner");
    assert_eq!(without.backends["svc"].owner(), None);
    let with = load(&owner_line("Team Payments")).expect("loads with an owner");
    assert_eq!(with.backends["svc"].owner(), Some("Team Payments"));
    let null = load("    owner: null\n").expect("an explicit null loads");
    assert_eq!(null.backends["svc"].owner(), None);
    assert!(load("    owner: 5\n").is_err(), "a number is not an owner");
}

/// O2: the owner is read trimmed; empty or all-space reads as none.
#[test]
fn o2_the_owner_reads_trimmed() {
    for (written, read) in [("  Ana  ", Some("Ana")), ("   ", None), ("", None)] {
        let config = load(&owner_line(written)).expect("loads");
        assert_eq!(config.backends["svc"].owner(), read, "{written:?}");
    }
}

/// O3, O3b: at most 200 characters once trimmed, counted as characters, not
/// bytes; surrounding space does not count.
#[test]
fn o3_at_most_two_hundred_characters_once_trimmed() {
    let at_limit = "é".repeat(200);
    load(&owner_line(&at_limit)).expect("200 two-byte characters load");
    load(&owner_line(&format!("  {at_limit}  "))).expect("surrounding space does not count");
    refused_naming_owner(load(&owner_line(&"é".repeat(201))), "201 characters");
    refused_naming_owner(
        load(&owner_line(&format!("  {}  ", "x".repeat(201)))),
        "201 characters inside spaces",
    );
}

/// O4, O4b: a control character anywhere is refused, a C1 control included,
/// and one that trimming would remove too; on a disabled backend and with
/// the firewall off as well (the check is unconditional).
#[test]
fn o4_a_control_character_anywhere_is_refused() {
    for value in [
        "a\nb", "a\tb", "a\u{7}b", "\nAna", "Ana\t", "\n", "a\u{85}b",
    ] {
        refused_naming_owner(load(&owner_line(value)), &format!("{value:?}"));
        refused_naming_owner(
            load(&format!("{}    enabled: false\n", owner_line(value))),
            &format!("{value:?} on a disabled backend"),
        );
        refused_naming_owner(
            load_text(&format!(
                "security:\n  firewall:\n    enabled: false\nbackends:\n  svc:\n    http_url: \"http://127.0.0.1:9/mcp\"\n{}",
                owner_line(value)
            )),
            &format!("{value:?} with the firewall off"),
        );
    }
}

/// O8: a backend without an owner serialises with no `owner` key.
#[test]
fn o8_no_owner_serialises_no_key() {
    let value = crate::yaml::to_value(&BackendConfig::default()).expect("serialises");
    let mapping = value.as_mapping().expect("a mapping");
    assert!(
        mapping.keys().all(|k| k.as_str() != Some("owner")),
        "{mapping:?}"
    );
}
