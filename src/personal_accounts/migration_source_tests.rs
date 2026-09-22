// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 §5.3c.1, §10.2 and §10.5 — the refusals that stop a
//! missing, substituted or malformed 3.x source becoming a silent zero.
//!
//! TWO-DIRECTIONAL THROUGHOUT. Every refusal is paired with the nearest source
//! that MUST still read: one differing byte of mode, one symlink instead of the
//! file it points at, one character of JSON. A suite of refusals alone passes
//! for a reader that refuses everything, and a reader that refuses everything
//! migrates nothing.

use std::path::{Path, PathBuf};

use super::{SourceRefusal, read_legacy_source};

const RECORD: &str = r#"{
  "access_token": "legacy-3x-access-token",
  "token_type": "Bearer",
  "refresh_token": "legacy-3x-refresh-token",
  "expires_at": 4102444800,
  "scope": "read write"
}"#;

/// Write a file at the mode `TokenStorage::save` uses on write.
fn seed(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("seed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    path
}

/// THE POSITIVE CONTROL for every refusal below. A well-formed private 3.x
/// record reads, fields and all.
#[test]
fn a_private_well_formed_3_x_record_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed(dir.path(), "aaaaaaaaaaaaaaaa_tokens.json", RECORD, 0o600);
    let token = read_legacy_source(&path).expect("a 0600 regular file with valid JSON must read");
    assert_eq!(token.access_token, "legacy-3x-access-token");
    assert_eq!(
        token.refresh_token.as_deref(),
        Some("legacy-3x-refresh-token")
    );
    assert_eq!(token.scope.as_deref(), Some("read write"));
}

/// §5.3c.1 — an absent source REFUSES, and names the path and the override.
///
/// This is the loud refusal. Without it a resolved filename that does not exist
/// reads as "nothing to migrate", which reaches the user as every backend
/// asking to re-authorise — indistinguishable from the migration never running.
#[test]
fn an_absent_source_refuses_naming_the_path_and_the_override() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bbbbbbbbbbbbbbbb_tokens.json");
    let refusal = read_legacy_source(&path).expect_err("an absent source must refuse");
    assert_eq!(
        refusal,
        SourceRefusal::Missing {
            path: path.display().to_string()
        }
    );
    // The message is the whole point of the refusal: a user who sees it must be
    // able to act without reading the design.
    let shown = refusal.to_string();
    assert!(
        shown.contains(&path.display().to_string()),
        "the refusal must name the exact path it looked for: {shown}"
    );
    assert!(
        shown.contains("--legacy-backend-name"),
        "the refusal must name the override AS THE FLAG A USER TYPES. It named \
         the config-key spelling until a real run showed the message, which is \
         the surface change quietly downgrading the error: {shown}"
    );
}

/// §10.5 — a symlink at the resolved path REFUSES, even to a valid 0600 record.
///
/// The filename is predictable from config anyone who can read it can read, and
/// `fs::read_to_string` follows symlinks. A party who can write into the source
/// directory could otherwise have migration seal THEIR token into the declared
/// principal's account. `symlink_metadata` is what makes this detectable:
/// plain `metadata` reports the target's type and mode and would call this a
/// private regular file.
#[cfg(unix)]
#[test]
fn a_symlink_at_the_resolved_path_refuses_even_to_a_valid_record() {
    let dir = tempfile::tempdir().unwrap();
    let real = seed(dir.path(), "planted_tokens.json", RECORD, 0o600);
    // Control: the target itself reads, so the refusal below is about the link
    // and not about the content behind it.
    assert!(read_legacy_source(&real).is_ok());

    let link = dir.path().join("cccccccccccccccc_tokens.json");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    assert_eq!(
        read_legacy_source(&link).expect_err("a symlink must refuse"),
        SourceRefusal::NotPrivate {
            path: link.display().to_string()
        },
        "a substituted source is refused however valid the bytes behind it are"
    );
}

/// §10.5 — a group- or world-readable credential file REFUSES.
///
/// 0644 is the mode a file acquires when something other than
/// `TokenStorage::save` wrote it, and a credential readable by anyone else is
/// not the file 3.x left behind.
#[cfg(unix)]
#[test]
fn a_group_readable_source_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed(dir.path(), "dddddddddddddddd_tokens.json", RECORD, 0o644);
    assert_eq!(
        read_legacy_source(&path).expect_err("a group-readable source must refuse"),
        SourceRefusal::NotPrivate {
            path: path.display().to_string()
        }
    );
}

/// §10.5 — a directory at the resolved path REFUSES rather than panicking.
#[test]
fn a_directory_at_the_resolved_path_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("eeeeeeeeeeeeeeee_tokens.json");
    std::fs::create_dir(&path).expect("mkdir");
    assert!(matches!(
        read_legacy_source(&path).expect_err("a directory must refuse"),
        SourceRefusal::NotPrivate { .. }
    ));
}

/// §10.2 — a malformed record leaks NOTHING of its contents.
///
/// The sentinel sits in a field of the wrong type, which is the shape whose
/// `serde_json` `Display` embeds the offending input — "invalid type: string
/// \"…\", expected u64". `oauth/storage.rs:215` logs exactly that error, which
/// is why migration does not go through it. Here the refusal must carry the
/// position and the path, and no fragment of the file.
#[test]
fn a_malformed_record_reports_position_only_and_never_its_contents() {
    const SENTINEL: &str = "SENTINEL-REFRESH-TOKEN-MUST-NOT-APPEAR";
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        r#"{{
  "access_token": "legacy-3x-access-token",
  "expires_at": "{SENTINEL}"
}}"#
    );
    let path = seed(dir.path(), "ffffffffffffffff_tokens.json", &body, 0o600);

    let refusal = read_legacy_source(&path).expect_err("a wrong-typed field must refuse");
    let shown = refusal.to_string();
    assert!(
        !shown.contains(SENTINEL),
        "the refusal must not carry file contents: {shown}"
    );
    assert!(
        !format!("{refusal:?}").contains(SENTINEL),
        "nor may its Debug rendering, which is what a tracing field would print"
    );
    assert!(
        matches!(refusal, SourceRefusal::Unparseable { line, column, .. } if line == 3 && column > 0),
        "and it must still say WHERE, or the user cannot fix the file: {shown}"
    );
}

/// The other direction of the leak test: the sentinel IS in the file, so a
/// reader that reported contents would have had something to report.
///
/// Without this, the test above passes for a reader that returns an empty
/// string for every error — which would leak nothing and say nothing.
#[test]
fn the_leak_test_is_not_vacuous_the_sentinel_is_really_in_the_file() {
    const SENTINEL: &str = "SENTINEL-REFRESH-TOKEN-MUST-NOT-APPEAR";
    let dir = tempfile::tempdir().unwrap();
    let body = format!(r#"{{"access_token": "a", "expires_at": "{SENTINEL}"}}"#);
    let path = seed(dir.path(), "gggggggggggggggg_tokens.json", &body, 0o600);
    assert!(
        std::fs::read_to_string(&path).unwrap().contains(SENTINEL),
        "control: the sentinel must be on disk for its absence downstream to mean anything"
    );
    // And serde itself WOULD have embedded it, which is the leak being avoided.
    let raw = serde_json::from_str::<crate::oauth::TokenInfo>(&body)
        .expect_err("the wrong-typed field must fail to parse");
    assert!(
        raw.to_string().contains(SENTINEL),
        "control: serde_json's own Display embeds the offending input, which is \
         exactly why the refusal must not render it"
    );
}

/// Truncated JSON refuses at its position, not as a missing file.
#[test]
fn truncated_json_refuses_as_unparseable_not_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed(
        dir.path(),
        "hhhhhhhhhhhhhhhh_tokens.json",
        r#"{"access_token": "a""#,
        0o600,
    );
    assert!(
        matches!(
            read_legacy_source(&path).expect_err("broken JSON must refuse"),
            SourceRefusal::Unparseable { .. }
        ),
        "a present but broken file is a different refusal from an absent one, \
         and conflating them is what TokenStorage::load does"
    );
}
