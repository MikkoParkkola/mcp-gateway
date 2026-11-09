// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Docs rows for the hashed audit email: the upgrading note names what
//! changed and every operator-facing consequence; the key-server operator
//! doc states the limit for email-shaped subjects; the backup runbook names
//! the key file. Phrases are identifiers wherever one exists, so the rows
//! pin content, not wording.

const UPGRADING: &str = "upgrading.d/9386.md";
const OPERATOR_DOC: &str = "docs/MULTI_USER.md";
const RUNBOOK: &str = "docs/runbooks/backup-restore-and-keys.md";
const KEY_FILE: &str = "key-server-email-hmac.json";

fn read(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn lacks(text: &str, needles: &[&str]) -> Vec<String> {
    needles
        .iter()
        .filter(|n| !text.contains(**n))
        .map(|n| (*n).to_owned())
        .collect()
}

/// The upgrading note: the new field and key id, the key file and its
/// backup, the optional configured key and how to generate one, the audit
/// record's changed type, the audit log the key server now requires, the
/// email-shaped-subject limit with its warning, the IDNA limit, and rollback.
#[test]
fn the_upgrading_note_names_every_consequence() {
    let text = read(UPGRADING);
    let missing = lacks(
        &text,
        &[
            "email_hash",
            "email_hash_key_id",
            KEY_FILE,
            "audit_email_hmac_secret_ref",
            "openssl rand -hex 32",
            "SafeIdentity",
            "AuditEvent",
            "security.transparency_log.enabled",
            "pseudonym",
            "WARN",
            "IDNA",
            "rollback",
        ],
    );
    assert!(missing.is_empty(), "{UPGRADING} lacks {missing:?}");
}

/// The operator doc states the limit: subjects that are email addresses
/// stay as they are, with one warning per provider.
#[test]
fn the_operator_doc_states_the_email_subject_limit() {
    let text = read(OPERATOR_DOC);
    let missing = lacks(&text, &["email_hash", "email-shaped", "WARN"]);
    assert!(missing.is_empty(), "{OPERATOR_DOC} lacks {missing:?}");
}

/// The backup runbook names the key file and what losing it costs. (The
/// explicit reset arrives with the lookup part, which extends this row.)
#[test]
fn the_backup_runbook_names_the_email_hash_key_file() {
    let text = read(RUNBOOK);
    let missing = lacks(&text, &[KEY_FILE, "email_hash", "backup"]);
    assert!(missing.is_empty(), "{RUNBOOK} lacks {missing:?}");
}
