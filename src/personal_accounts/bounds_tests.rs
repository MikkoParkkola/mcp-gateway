// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{AccountError, EPOCH, KEY, alice, grant, open_token, seal_token, token_aad};

#[test]
fn s03_empty_aad_contexts_are_rejected_individually() {
    let account = alice();
    assert!(token_aad("current", "gateway-instance", EPOCH, &account).is_ok());
    for (key_id, instance, epoch) in [
        ("", "gateway-instance", EPOCH),
        ("current", "", EPOCH),
        ("current", "gateway-instance", ""),
    ] {
        assert_eq!(
            token_aad(key_id, instance, epoch, &account),
            Err(AccountError::InvalidConfiguration)
        );
    }
}

#[test]
fn s03_record_validation_matches_documented_limits() {
    let aad = token_aad("current", "gateway-instance", EPOCH, &alice()).unwrap();
    let original = grant();
    let mut boundary = original.clone();
    boundary.access_token = "a".repeat(65_536);
    boundary.refresh_token = Some("r".repeat(65_536));
    let envelope = seal_token("current", &KEY, &aad, &boundary).unwrap();
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(boundary));
    let mut without_refresh = original.clone();
    without_refresh.refresh_token = None;
    without_refresh.scopes.clear();
    let envelope = seal_token("current", &KEY, &aad, &without_refresh).unwrap();
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(without_refresh));

    for fault in [
        "empty_access",
        "large_access",
        "empty_refresh",
        "large_refresh",
        "short_generation",
        "long_generation",
        "uppercase_generation",
        "invalid_generation",
        "short_descriptor",
        "long_descriptor",
        "uppercase_descriptor",
        "invalid_descriptor",
        "zero_revision",
        "zero_epoch",
        "duplicate_scopes",
        "unsorted_scopes",
    ] {
        let mut record = original.clone();
        match fault {
            "empty_access" => record.access_token.clear(),
            "large_access" => record.access_token = "a".repeat(65_537),
            "empty_refresh" => record.refresh_token = Some(String::new()),
            "large_refresh" => record.refresh_token = Some("r".repeat(65_537)),
            "short_generation" => record.generation = "a".repeat(31),
            "long_generation" => record.generation = "a".repeat(33),
            "uppercase_generation" => record.generation = "A".repeat(32),
            "invalid_generation" => record.generation = "g".repeat(32),
            "short_descriptor" => record.descriptor_revision = "a".repeat(63),
            "long_descriptor" => record.descriptor_revision = "a".repeat(65),
            "uppercase_descriptor" => record.descriptor_revision = "A".repeat(64),
            "invalid_descriptor" => record.descriptor_revision = "g".repeat(64),
            "zero_revision" => record.token_revision = 0,
            "zero_epoch" => record.authorization_epoch = 0,
            "duplicate_scopes" => record.scopes = vec!["drive.read".into(), "drive.read".into()],
            "unsorted_scopes" => record.scopes = vec!["z".into(), "a".into()],
            _ => unreachable!(),
        }
        assert!(
            matches!(
                seal_token("current", &KEY, &aad, &record),
                Err(AccountError::NotAuthentic)
            ),
            "invalid record field {fault} must not be sealed"
        );
    }
    let envelope = seal_token("current", &KEY, &aad, &original).unwrap();
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(original));
}

#[test]
fn s03_plaintext_limit_accepts_exact_boundary_and_rejects_next_byte() {
    let aad = token_aad("current", "gateway-instance", EPOCH, &alice()).unwrap();
    let mut record = grant();
    record.client_id.clear();
    let initial_bytes = serde_json::to_vec(&record).unwrap().len();
    record.client_id = "p".repeat(262_144 - initial_bytes);
    assert_eq!(serde_json::to_vec(&record).unwrap().len(), 262_144);
    let envelope = seal_token("current", &KEY, &aad, &record).unwrap();
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(record.clone()));
    record.client_id.push('p');
    assert_eq!(serde_json::to_vec(&record).unwrap().len(), 262_145);
    assert!(matches!(
        seal_token("current", &KEY, &aad, &record),
        Err(AccountError::NotAuthentic)
    ));
}

#[test]
#[cfg(unix)]
fn s03_each_invalid_store_configuration_refuses_before_authority_creation() {
    use super::{PersonalAccountStore, config};

    let control = tempfile::tempdir().unwrap();
    let control_settings = config(control.path());
    drop(PersonalAccountStore::initialize(control_settings.clone()).unwrap());
    drop(PersonalAccountStore::open(control_settings).unwrap());
    for fault in [
        "empty_instance",
        "empty_key_id",
        "missing_current_key",
        "empty_retained_key_id",
        "short_key",
        "long_retained_key",
        "zero_entries",
        "zero_bytes",
        "overflow_bytes",
        "same_roots",
        "records_contain_authority",
        "authority_contains_records",
        "relative_records",
        "relative_authority",
        "parent_component",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut settings = config(root.path());
        match fault {
            "empty_instance" => settings.instance_id.clear(),
            "empty_key_id" => settings.current_key_id.clear(),
            "missing_current_key" => settings.keys.clear(),
            "empty_retained_key_id" => {
                settings.keys.insert(String::new(), KEY.to_vec());
            }
            "short_key" => {
                settings.keys.insert("current".into(), vec![0x51; 31]);
            }
            "long_retained_key" => {
                settings.keys.insert("previous".into(), vec![0x52; 33]);
            }
            "zero_entries" => settings.max_entries = 0,
            "zero_bytes" => settings.max_authority_bytes = 0,
            "overflow_bytes" => settings.max_authority_bytes = usize::MAX,
            "same_roots" => settings.authority_dir = settings.store_dir.clone(),
            "records_contain_authority" => {
                settings.authority_dir = settings.store_dir.join("authority");
            }
            "authority_contains_records" => {
                settings.store_dir = settings.authority_dir.join("records");
            }
            "relative_records" => settings.store_dir = "records".into(),
            "relative_authority" => settings.authority_dir = "authority".into(),
            "parent_component" => settings.store_dir = root.path().join("intermediate/../records"),
            _ => unreachable!(),
        }
        let observed = PersonalAccountStore::initialize(settings.clone());
        assert!(
            matches!(observed, Err(AccountError::InvalidConfiguration)),
            "configuration fault {fault} must fail the configuration boundary"
        );
        assert!(!settings.authority_dir.join("authority.json").exists());
    }
}
