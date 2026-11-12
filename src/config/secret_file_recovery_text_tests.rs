// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The refusal text for a recovery file, every kind, read on every platform,
//! and the callers of the recovery and config guarded reads.

use super::SecretFile;

/// No owner, mode or ACL fix; the untrusted, move-aside guidance.
fn assert_recovery_guidance(kind: &str, text: &str) {
    let lower = text.to_lowercase();
    for advice in [
        "icacls",
        "/grant",
        "/reset",
        "/setowner",
        "takeown",
        "chown",
        "chmod",
        "fix: ",
    ] {
        assert!(!lower.contains(advice), "{kind} advises {advice:?}: {text}");
    }
    assert!(lower.contains("untrusted"), "{kind}: {text}");
    assert!(lower.contains("move both files aside"), "{kind}: {text}");
}

/// Every refusal kind the guard gives a journal or staged original: the
/// Windows DACL, not UTF-8, not a regular file, and on Unix each mode rule
/// and a foreign owner. Another class keeps its usual fix.
#[test]
fn every_recovery_file_refusal_gives_the_guidance_and_no_fix() {
    let path = std::path::Path::new("/gw/.gateway.yaml.replace-journal");
    let what = SecretFile::RecoveryFile;
    let head = r"Refusing to load replace journal or staged original C:\gw\x";
    let found = r#"[ForeignSid("S-1-1-0"), NotProtected]"#;
    let acl = super::acl_refusal_text(what, head, found, || unreachable!("no repair"));
    assert!(acl.starts_with(head) && acl.contains(found), "{acl}");
    let kinds = [
        ("windows dacl", acl),
        ("not utf-8", super::not_utf8_message(what, path)),
        ("fifo", super::not_regular_message(what, path, "FIFO")),
    ]
    .into_iter()
    .chain(mode_refusals(what, path));
    for (kind, text) in kinds {
        assert!(text.contains(what.noun()), "{kind} lost the facts: {text}");
        assert_recovery_guidance(kind, &text);
        // The guidance itself, word for word, ends every kind's text.
        assert!(
            text.ends_with(super::RECOVERY_FILE_FIX),
            "{kind} does not end with the recovery guidance: {text}"
        );
    }
}

/// The recovery guidance, word for word: any rewording goes back to
/// review.
#[test]
fn the_recovery_guidance_is_the_reviewed_text() {
    assert_eq!(
        super::RECOVERY_FILE_FIX,
        "Both the replace journal and its staged original are untrusted: another account \
         could have planted them with a matching digest. Leave their owner and mode alone, \
         because fixing them would make the next recovery restore them. Check gateway.yaml \
         against a known-good copy, move both files aside, then retry."
    );
}

/// The Unix mode and owner refusals of `what`, after checking another
/// class keeps its usual fix; none elsewhere.
#[cfg(unix)]
fn mode_refusals(what: SecretFile, path: &std::path::Path) -> Vec<(&'static str, String)> {
    use super::Refusal;
    /// Every Unix refusal kind with its name: the one list the row reads.
    const KINDS: [(&str, Refusal); 4] = [
        ("world", Refusal::World),
        ("group write", Refusal::GroupWrite),
        ("group read", Refusal::GroupReadOwned),
        ("foreign owner", Refusal::ForeignOwner),
    ];
    let config = super::refusal_message(SecretFile::Config, path, Refusal::World, (0o666, 0, 7), 0);
    assert!(
        config.contains("Fix: chmod 600"),
        "the config fix changed: {config}"
    );
    // No wildcard: a new kind fails to compile here, and the slot it is
    // given must then hold it in KINDS, or this check fails.
    let slot = |refusal: Refusal| match refusal {
        Refusal::World => 0,
        Refusal::GroupWrite => 1,
        Refusal::GroupReadOwned => 2,
        Refusal::ForeignOwner => 3,
    };
    // The exhaustive match gives a new kind a slot; KINDS must then name it,
    // or the slots stop being the full range of the list.
    let mut slots: Vec<usize> = KINDS.iter().map(|(_, refusal)| slot(*refusal)).collect();
    slots.sort_unstable();
    assert_eq!(
        slots,
        (0..KINDS.len()).collect::<Vec<_>>(),
        "the slots are not the full range"
    );
    for (index, (_, refusal)) in KINDS.iter().enumerate() {
        assert_eq!(slot(*refusal), index, "{refusal:?} is not in its slot");
    }
    KINDS
        .into_iter()
        .map(|(name, refusal)| {
            (
                name,
                super::refusal_message(what, path, refusal, (0o666, 0, 7), 0),
            )
        })
        .collect()
}

#[cfg(not(unix))]
fn mode_refusals(_: SecretFile, _: &std::path::Path) -> Vec<(&'static str, String)> {
    Vec::new()
}

/// The recovery-file check finds a journal and a staged original handed as
/// bare relative names, resolved against the base it is given (the working
/// directory in production), and does not take gateway.yaml for one. The
/// base is a temporary directory, so this test never changes the process's
/// working directory.
#[test]
fn a_bare_relative_recovery_file_is_found_against_its_base() {
    use crate::config_persistence::journal;
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&config, "x").expect("config");
    journal::stage_original(&config, b"x").expect("stage");
    journal::begin(&config, crate::hashing::sha256_hex(b"x")).expect("journal");
    let base = dir.path();
    for name in [
        ".gateway.yaml.replace-journal",
        ".gateway.yaml.replace-original",
    ] {
        assert!(
            super::is_recovery_file(base, std::path::Path::new(name)),
            "the bare name {name} was not found as a recovery file"
        );
    }
    assert!(!super::is_recovery_file(
        base,
        std::path::Path::new("gateway.yaml")
    ));
}

/// A test file by its name or a `tests` directory, never by a "test"
/// substring, which would exempt a production `latest.rs`.
fn is_test_file(rel: &std::path::Path) -> bool {
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    name.ends_with("_tests.rs")
        || name.ends_with("_test.rs")
        || rel
            .parent()
            .is_some_and(|dir| dir.iter().any(|segment| segment == "tests"))
}

#[test]
fn the_test_file_rule_skips_only_test_files() {
    use std::path::Path;
    for test in [
        "a/b_tests.rs",
        "b_test.rs",
        "config/tests/env_files.rs",
        "tests/x.rs",
    ] {
        assert!(is_test_file(Path::new(test)), "{test} is a test file");
    }
    for production in [
        "latest.rs",
        "contest/mod.rs",
        "config/testing.rs",
        "tests.rs",
    ] {
        assert!(
            !is_test_file(Path::new(production)),
            "{production} is not a test file"
        );
    }
}

/// The production files (test files left out) that call the recovery-class
/// and config-class guarded reads, pinned: only crash recovery's file calls
/// the recovery read, and the config read has a fixed set of calling files,
/// so a new calling file of either fails here and is a reviewed change. It
/// pins files, not the paths each call is handed.
#[test]
fn the_recovery_and_config_reads_have_their_known_callers() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let callers = |needle: &str| -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).expect("src").flatten() {
                let path = entry.path();
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                if path.is_dir() {
                    stack.push(path);
                } else if !is_test_file(path.strip_prefix(&src).expect("under src"))
                    && crate::test_source_text::production_text(&text).contains(needle)
                {
                    let rel = path.strip_prefix(&src).expect("under src");
                    found.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        found.sort();
        found
    };
    assert_eq!(
        callers("read_recovery_text("),
        [
            "config/secret_file.rs",
            "config_persistence_journal.rs",
            "config_persistence_journal_v2_drain.rs",
        ]
    );
    assert_eq!(
        callers("read_config_text("),
        [
            "config/secret_file.rs",
            "config_persistence.rs",
            "config_persistence_journal.rs",
            "config_reload/replace.rs",
            "config_reload/replace_audit.rs",
            // The settings preview reads gateway.yaml as the writer does,
            // without its lock; it writes nothing.
            "config_reload/ui_diff.rs",
        ]
    );
}
