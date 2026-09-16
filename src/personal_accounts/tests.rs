// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! First storage increment: S01/S02/S03 primitives and explicit initialization.
//! Lifecycle and public-route cases remain separate pending increments.

use super::storage::{open_token, seal_token, token_aad};
use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const KEY: [u8; 32] = [0x51; 32];
const EPOCH: &str = "0123456789abcdef0123456789abcdef";

fn alice() -> AccountKey {
    AccountKey {
        principal_authority: "https://identity.example".into(),
        principal_subject: "alice".into(),
        backend_id: "google-workspace".into(),
        resource: "https://www.googleapis.com/drive/v3".into(),
        oauth_issuer: "https://accounts.google.com".into(),
    }
}

fn grant() -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".into(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
        access_token: "synthetic-alice-access-private-material-9f3a71".into(),
        refresh_token: Some("synthetic-alice-refresh-private-material-8c9d21".into()),
        token_type: "Bearer".into(),
        // Storage must preserve expired tokens for the refresh service.
        expires_at: 0,
        provider_account_id: Some("synthetic-alice-provider-account-private-1a92".into()),
        client_id: "synthetic-google-client".into(),
    }
}

fn config(root: &std::path::Path) -> StoreConfig {
    let root = root
        .canonicalize()
        .expect("fixture root is an existing directory");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: BTreeMap::from([("current".into(), KEY.to_vec())]),
        max_entries: 10_000,
        max_authority_bytes: 16_777_216,
    }
}

#[test]
fn s01_account_key_matches_independent_full_sha256_vector() {
    // Golden computed independently from the published byte format, not by the
    // production encoder or a production constant on the expected side.
    assert_eq!(
        alice().digest(),
        Ok("05336cba800dd362bf06b017880035b23b43b8010f49674e8bc5b2c4a49fcd5a".into())
    );
}

#[test]
fn s01_every_account_axis_selects_a_different_key() {
    let original = alice();
    let baseline = original.digest().expect("valid account key");
    let mut variants = Vec::new();
    for axis in 0..5 {
        let mut changed = original.clone();
        match axis {
            0 => changed.principal_authority = "https://other-identity.example".into(),
            1 => changed.principal_subject = "bob".into(),
            2 => changed.backend_id = "other-backend".into(),
            3 => changed.resource = "https://www.googleapis.com/calendar/v3".into(),
            4 => changed.oauth_issuer = "https://other-issuer.example".into(),
            _ => unreachable!("five account axes"),
        }
        let digest = changed.digest().expect("valid changed account key");
        assert_ne!(digest, baseline, "account axis {axis} was omitted");
        variants.push(digest);
    }
    variants.sort();
    variants.dedup();
    assert_eq!(variants.len(), 5, "changed axes must not alias each other");
}

#[test]
fn s01_delimiter_ambiguous_and_unicode_distinct_fields_do_not_alias() {
    let mut left = alice();
    left.principal_authority = "a:b".into();
    left.principal_subject = "c".into();
    let mut right = left.clone();
    right.principal_authority = "a".into();
    right.principal_subject = "b:c".into();
    assert_ne!(
        left.digest().expect("valid left tuple"),
        right.digest().expect("valid right tuple"),
        "delimiter encoding is ambiguous"
    );
    left.principal_subject = "\u{00e9}".into();
    right = left.clone();
    right.principal_subject = "e\u{0301}".into();
    assert_ne!(
        left.digest().expect("valid left tuple"),
        right.digest().expect("valid right tuple"),
        "identity must not be normalized"
    );
}

#[test]
fn s01_empty_and_oversized_fields_refuse_but_boundary_is_valid() {
    for axis in 0..5 {
        for (replacement, valid) in [
            (String::new(), false),
            ("x".repeat(4096), true),
            ("x".repeat(4097), false),
            ("é".repeat(2048), true),
            ("é".repeat(2049), false),
        ] {
            let mut account = alice();
            let field = match axis {
                0 => &mut account.principal_authority,
                1 => &mut account.principal_subject,
                2 => &mut account.backend_id,
                3 => &mut account.resource,
                4 => &mut account.oauth_issuer,
                _ => unreachable!("five account axes"),
            };
            *field = replacement;
            if valid {
                assert!(account.digest().is_ok(), "valid boundary on axis {axis}");
            } else {
                assert_eq!(
                    account.digest(),
                    Err(AccountError::InvalidAccountKey),
                    "invalid boundary on axis {axis}"
                );
            }
        }
    }
}

#[test]
fn s03_token_aad_matches_independent_domain_and_tuple_vector() {
    let expected = hex::decode(concat!(
        "6d63702d676174657761792f6163636f756e742d746f6b656e2d6161642f7631",
        "00000014706572736f6e616c5f6163636f756e74732e7631",
        "0000000763757272656e74",
        "00000010676174657761792d696e7374616e6365",
        "000000203031323334353637383961626364656630313233343536373839616263646566",
        "0000001868747470733a2f2f6964656e746974792e6578616d706c65",
        "00000005616c696365",
        "00000010676f6f676c652d776f726b7370616365",
        "0000002368747470733a2f2f7777772e676f6f676c65617069732e636f6d2f64726976652f7633",
        "0000001b68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d"
    ))
    .expect("independent fixed AAD vector is hex");
    assert_eq!(
        token_aad("current", "gateway-instance", EPOCH, &alice()),
        Ok(expected)
    );
}

#[test]
fn s02_envelope_roundtrip_has_exact_public_shape_and_no_plaintext_secrets() {
    let record = grant();
    let aad = token_aad("current", "gateway-instance", EPOCH, &alice()).expect("valid context");
    let sealed = seal_token("current", &KEY, &aad, &record);
    assert!(sealed.is_ok(), "a valid grant must encrypt: {sealed:?}");
    let envelope = sealed.expect("asserted successful encryption");
    let value = serde_json::to_value(&envelope).expect("serialize envelope");
    let fields: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        ["ciphertext", "key_id", "nonce", "schema_version"].into()
    );
    assert_eq!(value["schema_version"], "personal_accounts.v1");
    assert_eq!(value["key_id"], "current");
    assert_eq!(STANDARD.decode(&envelope.nonce).unwrap().len(), 12);
    assert!(STANDARD.decode(&envelope.ciphertext).unwrap().len() >= 16);
    let encoded = serde_json::to_string(&value).unwrap();
    for secret in [
        &record.access_token,
        record.refresh_token.as_ref().unwrap(),
        record.provider_account_id.as_ref().unwrap(),
    ] {
        assert!(
            !encoded.contains(secret),
            "credential leaked to outer envelope"
        );
    }
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(record));
}

#[test]
fn s03_instance_epoch_and_each_principal_binding_reject_relocated_ciphertext() {
    let original = alice();
    let aad = token_aad("current", "gateway-instance", EPOCH, &original).unwrap();
    let sealed = seal_token("current", &KEY, &aad, &grant());
    assert!(sealed.is_ok(), "positive encryption control is required");
    let envelope = sealed.unwrap();
    assert!(
        open_token(&KEY, &aad, &envelope).is_ok(),
        "original context must open"
    );
    let mut contexts = vec![
        token_aad("current", "other-gateway-instance", EPOCH, &original).unwrap(),
        token_aad(
            "current",
            "gateway-instance",
            "ffffffffffffffffffffffffffffffff",
            &original,
        )
        .unwrap(),
    ];
    for axis in 0..5 {
        let mut changed = original.clone();
        let field = match axis {
            0 => &mut changed.principal_authority,
            1 => &mut changed.principal_subject,
            2 => &mut changed.backend_id,
            3 => &mut changed.resource,
            4 => &mut changed.oauth_issuer,
            _ => unreachable!("five account axes"),
        };
        field.push_str("-different");
        contexts.push(token_aad("current", "gateway-instance", EPOCH, &changed).unwrap());
    }
    for (axis, changed_aad) in contexts.iter().enumerate() {
        assert_eq!(
            open_token(&KEY, changed_aad, &envelope),
            Err(AccountError::NotAuthentic),
            "AAD axis {axis} was not authenticated"
        );
    }
    assert_eq!(
        open_token(&[0x52; 32], &aad, &envelope),
        Err(AccountError::NotAuthentic)
    );
}

#[test]
fn s02_reencrypting_same_record_uses_fresh_nonces() {
    let aad = token_aad("current", "gateway-instance", EPOCH, &alice()).unwrap();
    let record = grant();
    let first = seal_token("current", &KEY, &aad, &record);
    let second = seal_token("current", &KEY, &aad, &record);
    assert!(
        first.is_ok() && second.is_ok(),
        "both valid encryptions must succeed"
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_ne!(
        first.nonce, second.nonce,
        "record rewrite reused a GCM nonce"
    );
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_eq!(open_token(&KEY, &aad, &first), Ok(record.clone()));
    assert_eq!(open_token(&KEY, &aad, &second), Ok(record));
}

#[test]
#[cfg(unix)]
fn s03_explicit_initialization_creates_encrypted_authority_and_reopens() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    assert!(PersonalAccountStore::open(settings.clone()).is_err());
    assert!(
        !settings.store_dir.exists(),
        "startup must not create token state"
    );
    assert!(
        !settings.authority_dir.exists(),
        "startup silently initialized authority"
    );
    let initialized = PersonalAccountStore::initialize(settings.clone());
    assert!(
        initialized.is_ok(),
        "explicit empty-store initialization must succeed"
    );
    drop(initialized);
    let authority_path = settings.authority_dir.join("authority.json");
    let initial_metadata = std::fs::metadata(&authority_path).unwrap();
    assert_eq!(initial_metadata.permissions().mode() & 0o777, 0o600);
    let initial_modified = initial_metadata.modified().unwrap();
    let persisted = std::fs::read(&authority_path);
    assert!(
        persisted.is_ok(),
        "initialization must persist its authority"
    );
    let bytes = persisted.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("authority envelope JSON");
    let fields: std::collections::BTreeSet<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        ["ciphertext", "key_id", "nonce", "schema_version"].into()
    );
    assert_eq!(value["schema_version"], "personal_accounts.authority.v1");
    assert!(
        value["ciphertext"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(
        !String::from_utf8_lossy(&bytes).contains("gateway-instance"),
        "authority payload must be encrypted"
    );
    assert!(
        PersonalAccountStore::open(settings.clone()).is_ok(),
        "persisted authority must reopen; child-process restart is a later case"
    );
    assert!(
        PersonalAccountStore::initialize(settings.clone()).is_err(),
        "initialization must not replace existing authority"
    );
    assert_eq!(
        std::fs::read(settings.authority_dir.join("authority.json")).unwrap(),
        bytes,
        "failed reinitialization must preserve acknowledged authority bytes"
    );
    assert_eq!(
        std::fs::metadata(&authority_path)
            .unwrap()
            .modified()
            .unwrap(),
        initial_modified,
        "failed reinitialization must not rewrite even identical authority"
    );
    assert!(
        PersonalAccountStore::open(settings).is_ok(),
        "refused initialization must leave authority usable"
    );
}

#[test]
#[cfg(not(unix))]
fn s11_unsupported_platform_refuses_custody_without_creating_state() {
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    assert!(PersonalAccountStore::initialize(settings.clone()).is_err());
    assert!(PersonalAccountStore::open(settings.clone()).is_err());
    assert!(!settings.store_dir.exists());
    assert!(!settings.authority_dir.exists());
}

#[test]
fn s03_independent_aes256_gcm_vector_opens_exact_expired_payload() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/aes256_gcm.json")).unwrap();
    let envelope = serde_json::from_value(fixture["envelope"].clone()).unwrap();
    let record: GrantRecord = serde_json::from_value(fixture["record"].clone()).unwrap();
    let aad = hex::decode(fixture["aad_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        record,
        grant(),
        "independent fixture matches synthetic expired storage payload"
    );
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(record));
}

fn corrupted_envelopes(original: &serde_json::Value) -> Vec<(&'static str, serde_json::Value)> {
    let mut cases = Vec::new();
    for field in ["ciphertext", "nonce"] {
        let mut bytes = STANDARD.decode(original[field].as_str().unwrap()).unwrap();
        assert!(!bytes.is_empty());
        bytes[0] ^= 1;
        let mut changed = original.clone();
        changed[field] = STANDARD.encode(bytes).into();
        cases.push((field, changed));
    }
    for (field, value) in [
        ("schema_version", "unsupported-schema"),
        ("key_id", "other-key-id"),
        ("nonce", "!not-base64!"),
        ("ciphertext", "!not-base64!"),
        ("ciphertext", ""),
    ] {
        let mut changed = original.clone();
        changed[field] = value.into();
        cases.push((field, changed));
    }
    let mut changed = original.clone();
    changed["nonce"] = STANDARD.encode([0_u8; 11]).into();
    cases.push(("short nonce", changed));
    cases
}

#[test]
fn s03_every_token_envelope_field_rejects_tampering() {
    let aad = token_aad("current", "gateway-instance", EPOCH, &alice()).unwrap();
    let sealed = seal_token("current", &KEY, &aad, &grant());
    assert!(
        sealed.is_ok(),
        "valid encryption control before field mutation"
    );
    let envelope = sealed.unwrap();
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(grant()));
    let value = serde_json::to_value(&envelope).unwrap();
    for (field, altered) in corrupted_envelopes(&value) {
        let mutated = serde_json::from_value(altered).unwrap();
        assert_eq!(
            open_token(&KEY, &aad, &mutated),
            Err(AccountError::NotAuthentic),
            "tampered {field} must refuse"
        );
    }
    assert_eq!(open_token(&KEY, &aad, &envelope), Ok(grant()));
}

#[test]
#[cfg(unix)]
fn s03_authority_uses_aes256_gcm_and_rejects_wrong_keys_and_tampering() {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    let created = PersonalAccountStore::initialize(settings.clone());
    assert!(created.is_ok(), "valid authority control before mutation");
    drop(created);
    let path = settings.authority_dir.join("authority.json");
    let bytes = std::fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut ciphertext = STANDARD
        .decode(value["ciphertext"].as_str().unwrap())
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&ciphertext).contains("gateway-instance"),
        "decoded ciphertext must not be plaintext"
    );
    let nonce: [u8; 12] = STANDARD
        .decode(value["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    // Independent literal vector from the approved authority byte format;
    // never produced by a production AAD helper.
    let aad = hex::decode(concat!(
        "6d63702d676174657761792f6163636f756e742d617574686f726974792d6161642f7631",
        "0000001e706572736f6e616c5f6163636f756e74732e617574686f726974792e7631",
        "0000000763757272656e74",
        "00000010676174657761792d696e7374616e6365"
    ))
    .unwrap();
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
    let opened = key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&aad),
        &mut ciphertext,
    );
    assert!(
        opened.is_ok(),
        "authority must use actual AES256-GCM with specified AAD"
    );
    let payload: serde_json::Value = serde_json::from_slice(opened.unwrap()).unwrap();
    assert_eq!(payload["instance_id"], "gateway-instance");
    assert!(
        payload["entries"]
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    );
    let mut wrong_key = settings.clone();
    wrong_key.keys.insert("current".into(), vec![0x52; 32]);
    assert!(
        PersonalAccountStore::open(wrong_key).is_err(),
        "wrong authority key must refuse"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(PersonalAccountStore::open(settings.clone()).is_ok());
    let mut with_alias = settings.clone();
    with_alias.keys.insert("other-key-id".into(), KEY.to_vec());
    for (field, altered) in corrupted_envelopes(&value) {
        std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
        let result = PersonalAccountStore::open(with_alias.clone());
        let refused = result.is_err();
        drop(result);
        std::fs::write(&path, &bytes).unwrap();
        assert!(refused, "tampered authority {field} must refuse");
        assert!(
            PersonalAccountStore::open(settings.clone()).is_ok(),
            "restored authority must reopen after {field}"
        );
    }
}

#[test]
fn s02_grant_debug_omits_credentials_and_provider_identity() {
    let record = grant();
    let diagnostic = format!("{record:?}");
    for secret in [
        record.access_token.as_str(),
        record.refresh_token.as_deref().unwrap(),
        record.provider_account_id.as_deref().unwrap(),
    ] {
        assert!(!diagnostic.contains(secret), "credential leaked to Debug");
    }
    assert!(
        diagnostic.contains("GrantRecord"),
        "redacted diagnostic retains its type"
    );
}

#[cfg(target_os = "linux")]
#[path = "fifo_tests.rs"]
mod fifo;

#[cfg(unix)]
#[path = "store_tests.rs"]
mod store;

#[path = "bounds_tests.rs"]
mod bounds;

// Lookup authority-entry validation, kept separate from the frozen lookup
// packet so each source binding stays clear.
#[cfg(unix)]
#[path = "authority_tests.rs"]
mod authority;

#[cfg(unix)]
#[path = "wire_bound_tests.rs"]
mod wire_bound;

// Durable store operations. Separate modules keep each evidence packet bound to
// its own source, and store_tests.rs is already at its 800-line cap.
#[cfg(unix)]
#[path = "child_probe.rs"]
mod probe;

#[cfg(unix)]
#[path = "commit_tests.rs"]
mod commit;

#[cfg(unix)]
#[path = "fence_tests.rs"]
mod fence;

#[cfg(unix)]
#[path = "crash_tests.rs"]
mod crash;
