// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{AccountKey, AccountLookup, GrantRecord, PersonalAccountStore, StoreConfig, config};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

#[derive(serde::Deserialize)]
struct CommittedFixture {
    key_hex: String,
    instance_id: String,
    store_epoch: String,
    authority: String,
    record_files: BTreeMap<String, String>,
    cases: Vec<FixtureGrant>,
}

#[derive(serde::Deserialize)]
struct FixtureGrant {
    fields: [String; 5],
    digest: String,
    basename: String,
    record: GrantRecord,
}

#[derive(serde::Deserialize)]
struct LookupStatesFixture {
    states: Vec<StateFixture>,
    metadata_mismatches: Vec<MetadataFixture>,
    unsafe_pointers: Vec<PointerFixture>,
    unaccepted_ciphertext: UnacceptedFixture,
    absent_orphan: OrphanFixture,
    envelope_bounds: Vec<BoundVariant>,
}

/// One store per variant: a long configured key ID, a maximum-plaintext record
/// and an ordinary one. `OrphanFixture` is the shared record-plus-bytes shape.
#[derive(serde::Deserialize)]
struct BoundVariant {
    name: String,
    key_id: String,
    authority: String,
    max: OrphanFixture,
    ordinary: OrphanFixture,
}

/// An authentic record for a tuple the authority has never committed.
#[derive(serde::Deserialize)]
struct OrphanFixture {
    fields: [String; 5],
    digest: String,
    basename: String,
    record: GrantRecord,
    record_bytes: String,
}

#[derive(serde::Deserialize)]
struct StateFixture {
    state: String,
    authority: String,
}

#[derive(serde::Deserialize)]
struct MetadataFixture {
    field: String,
    record: GrantRecord,
    record_bytes: String,
    authority: String,
}

#[derive(serde::Deserialize)]
struct PointerFixture {
    basename: String,
    authority: String,
}

#[derive(serde::Deserialize)]
struct UnacceptedFixture {
    record: GrantRecord,
    record_bytes: String,
}

fn account_key(fields: &[String; 5]) -> AccountKey {
    AccountKey {
        principal_authority: fields[0].clone(),
        principal_subject: fields[1].clone(),
        backend_id: fields[2].clone(),
        resource: fields[3].clone(),
        oauth_issuer: fields[4].clone(),
    }
}

impl FixtureGrant {
    fn account_key(&self) -> AccountKey {
        account_key(&self.fields)
    }
}

fn committed_fixture() -> CommittedFixture {
    serde_json::from_str(include_str!("fixtures/committed_grants.json")).unwrap()
}

fn lookup_states_fixture() -> LookupStatesFixture {
    serde_json::from_str(include_str!("fixtures/lookup_states.json")).unwrap()
}

fn install_committed_fixture() -> (tempfile::TempDir, StoreConfig, CommittedFixture) {
    let fixture = committed_fixture();
    let root = tempfile::tempdir().unwrap();
    let settings = config(root.path());
    assert_eq!(settings.instance_id, fixture.instance_id);
    assert_eq!(
        settings.keys["current"],
        hex::decode(&fixture.key_hex).unwrap()
    );
    for dir in [&settings.store_dir, &settings.authority_dir] {
        std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
    }
    write_private(
        &settings.authority_dir.join("authority.json"),
        fixture.authority.as_bytes(),
    );
    for (basename, bytes) in &fixture.record_files {
        write_private(&settings.store_dir.join(basename), bytes.as_bytes());
    }
    (root, settings, fixture)
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// The shared settings with the long key ID added as an extra retained key:
/// `current` stays current, so a cap read off `current_key_id` cannot pass.
fn install_bound_fixture(variant: &BoundVariant) -> (tempfile::TempDir, StoreConfig) {
    let key = hex::decode(committed_fixture().key_hex).unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut settings = config(root.path());
    assert_ne!(settings.current_key_id, variant.key_id);
    settings.keys.insert(variant.key_id.clone(), key);
    for dir in [&settings.store_dir, &settings.authority_dir] {
        std::fs::DirBuilder::new().mode(0o700).create(dir).unwrap();
    }
    write_private(
        &settings.authority_dir.join("authority.json"),
        variant.authority.as_bytes(),
    );
    for grant in [&variant.max, &variant.ordinary] {
        write_private(
            &settings.store_dir.join(&grant.basename),
            grant.record_bytes.as_bytes(),
        );
    }
    (root, settings)
}

#[test]
fn s01_independent_committed_fixture_resolves_every_account_axis() {
    let (_root, settings, fixture) = install_committed_fixture();
    assert_eq!(fixture.cases.len(), 6);
    let store =
        PersonalAccountStore::open(settings).expect("independent valid authority must open");
    for case in &fixture.cases {
        let key = case.account_key();
        assert_eq!(key.digest(), Ok(case.digest.clone()));
        assert_eq!(
            store.lookup(&key),
            Ok(AccountLookup::Connected(case.record.clone())),
            "a changed account axis must return its own independently encrypted record"
        );
    }
    let mut absent = fixture.cases[0].account_key();
    absent.principal_subject = "unconnected-carla".into();
    assert_eq!(store.lookup(&absent), Ok(AccountLookup::Absent));
}

#[test]
fn s01_invalid_account_key_is_refused_not_reported_absent() {
    let (_root, settings, fixture) = install_committed_fixture();
    let store = PersonalAccountStore::open(settings).unwrap();
    // Well-formed but unconnected stays the genuine-absence control, so a
    // lookup that refuses every unknown identity cannot satisfy this test.
    let mut unconnected = fixture.cases[0].account_key();
    unconnected.principal_subject = "unconnected-carla".into();
    assert_eq!(store.lookup(&unconnected), Ok(AccountLookup::Absent));
    let oversized = "a".repeat(4097);
    for invalid in ["", oversized.as_str()] {
        for axis in 0..5 {
            let mut key = fixture.cases[0].account_key();
            match axis {
                0 => key.principal_authority = invalid.into(),
                1 => key.principal_subject = invalid.into(),
                2 => key.backend_id = invalid.into(),
                3 => key.resource = invalid.into(),
                4 => key.oauth_issuer = invalid.into(),
                _ => unreachable!("five account axes"),
            }
            assert_eq!(
                store.lookup(&key),
                Err(super::AccountError::InvalidAccountKey),
                "a malformed field {axis} must not be reported as connectable absence"
            );
        }
    }
}

#[test]
fn s01_never_committed_account_with_authentic_orphan_stays_absent() {
    let orphan = lookup_states_fixture().absent_orphan;
    let (_root, settings, fixture) = install_committed_fixture();
    let key = account_key(&orphan.fields);
    assert_eq!(key.digest(), Ok(orphan.digest.clone()));
    assert!(orphan.basename.starts_with(&orphan.digest));
    assert!(!fixture.record_files.contains_key(&orphan.basename));
    // The plant is authentic under its own account binding, so a refusal here
    // would come from the authority having no entry, never from an AEAD failure.
    let aad =
        super::storage::token_aad("current", &settings.instance_id, &fixture.store_epoch, &key)
            .unwrap();
    let envelope: super::storage::TokenEnvelope =
        serde_json::from_str(&orphan.record_bytes).unwrap();
    assert_eq!(
        super::storage::open_token(&settings.keys["current"], &aad, &envelope),
        Ok(orphan.record.clone()),
        "the planted candidate is a genuinely decryptable record for this tuple"
    );
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(settings.store_dir.join(&orphan.basename))
        .unwrap()
        .write_all(orphan.record_bytes.as_bytes())
        .unwrap();
    let store = PersonalAccountStore::open(settings).unwrap();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Absent),
        "a store_dir plant cannot enrol an account the authority never committed"
    );
    for case in &fixture.cases {
        assert_eq!(
            store.lookup(&case.account_key()),
            Ok(AccountLookup::Connected(case.record.clone())),
            "the plant does not disturb any committed account"
        );
    }
}

#[test]
fn s03_missing_referenced_record_is_storage_failure_not_absence() {
    let (_root, settings, fixture) = install_committed_fixture();
    let case = &fixture.cases[0];
    let key = case.account_key();
    let store = PersonalAccountStore::open(settings.clone()).unwrap();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(case.record.clone()))
    );
    let path = settings.store_dir.join(&case.basename);
    let original = std::fs::read(&path).unwrap();
    // An equally authentic but uncommitted candidate must not be adopted when
    // the exact authority pointer goes missing.
    let orphan = settings
        .store_dir
        .join(format!("{}-{}.json", case.digest, "e".repeat(32)));
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&orphan)
        .unwrap()
        .write_all(&original)
        .unwrap();
    assert_eq!(std::fs::read(&orphan).unwrap(), original);
    std::fs::remove_file(&path).unwrap();
    let observed = store.lookup(&key);
    let mut restored = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    restored.write_all(&original).unwrap();
    drop(restored);
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(case.record.clone()))
    );
    assert_eq!(observed, Err(super::AccountError::StorageUnavailable));
}

#[test]
fn s03_unreferenced_ciphertext_cannot_change_the_accepted_grant() {
    let (_root, settings, fixture) = install_committed_fixture();
    let case = &fixture.cases[0];
    let key = case.account_key();
    let store = PersonalAccountStore::open(settings.clone()).unwrap();
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(case.record.clone()))
    );
    let orphan = settings
        .store_dir
        .join(format!("{}-{}.json", case.digest, "f".repeat(32)));
    let foreign_record = &fixture.record_files[&fixture.cases[1].basename];
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&orphan)
        .unwrap()
        .write_all(foreign_record.as_bytes())
        .unwrap();
    assert!(orphan.is_file());
    drop(store);
    let reopened = PersonalAccountStore::open(settings).unwrap();
    assert_eq!(
        reopened.lookup(&key),
        Ok(AccountLookup::Connected(case.record.clone())),
        "only the independent manifest's accepted candidate is usable"
    );
}

#[test]
fn s13_tombstone_and_reconnect_states_ignore_retained_ciphertext() {
    let variants = lookup_states_fixture();
    assert_eq!(variants.states.len(), 2);
    // The tombstoned entry keeps no ciphertext pointer, so its state and version
    // must survive every disposition of the record file it no longer names.
    // "removed" and "corrupted" are equivalent falsifiers against the same fault
    // (an implementation that still reaches for `{digest}-*.json` after revoke);
    // both are kept because they diverge for the next slice's cleanup behavior,
    // and neither is counted as an independently caught mutant.
    for variant in variants.states {
        for disposition in ["retained", "removed", "corrupted"] {
            let (_root, settings, fixture) = install_committed_fixture();
            let case = &fixture.cases[0];
            let record_path = settings.store_dir.join(&case.basename);
            match disposition {
                // The old ciphertext is retained byte-for-byte. The independently
                // authenticated authority, not presence of a token file, decides state.
                "retained" => assert_eq!(
                    std::fs::read(&record_path).unwrap(),
                    fixture.record_files[&case.basename].as_bytes()
                ),
                "removed" => std::fs::remove_file(&record_path).unwrap(),
                "corrupted" => std::fs::write(&record_path, b"{ not an envelope").unwrap(),
                other => panic!("unexpected record disposition: {other}"),
            }
            std::fs::write(
                settings.authority_dir.join("authority.json"),
                variant.authority.as_bytes(),
            )
            .unwrap();
            let store = PersonalAccountStore::open(settings).unwrap();
            let version = super::GrantVersion {
                generation: case.record.generation.clone(),
                token_revision: case.record.token_revision,
                authorization_epoch: case.record.authorization_epoch,
                descriptor_revision: case.record.descriptor_revision.clone(),
            };
            let expected = match variant.state.as_str() {
                "revoked" => AccountLookup::Revoked(version),
                "reconnect_required" => AccountLookup::ReconnectRequired(version),
                other => panic!("unexpected fixture state: {other}"),
            };
            assert_eq!(
                store.lookup(&case.account_key()),
                Ok(expected),
                "{} state must not depend on the {disposition} record file",
                variant.state
            );
            let unrelated = &fixture.cases[1];
            assert_eq!(
                store.lookup(&unrelated.account_key()),
                Ok(AccountLookup::Connected(unrelated.record.clone())),
                "one tombstone cannot hide an unrelated connected account"
            );
        }
    }
}

#[test]
fn s03_authority_record_metadata_mismatch_fails_closed() {
    let variants = lookup_states_fixture();
    assert_eq!(
        variants
            .metadata_mismatches
            .iter()
            .map(|case| case.field.as_str())
            .collect::<Vec<_>>(),
        [
            "generation",
            "token_revision",
            "authorization_epoch",
            "descriptor_revision"
        ]
    );
    for variant in variants.metadata_mismatches {
        let (_root, settings, fixture) = install_committed_fixture();
        let case = &fixture.cases[0];
        let key = case.account_key();
        let aad =
            super::storage::token_aad("current", &settings.instance_id, &fixture.store_epoch, &key)
                .unwrap();
        let envelope: super::storage::TokenEnvelope =
            serde_json::from_str(&variant.record_bytes).unwrap();
        assert_eq!(
            super::storage::open_token(&settings.keys["current"], &aad, &envelope),
            Ok(variant.record.clone()),
            "the independent changed record is authentic and structurally valid"
        );
        let original = serde_json::to_value(&case.record).unwrap();
        let changed = serde_json::to_value(&variant.record).unwrap();
        let different: Vec<_> = original
            .as_object()
            .unwrap()
            .iter()
            .filter(|(field, value)| changed[*field] != **value)
            .map(|(field, _)| field.as_str())
            .collect();
        assert_eq!(different, [variant.field.as_str()]);
        std::fs::write(
            settings.store_dir.join(&case.basename),
            variant.record_bytes.as_bytes(),
        )
        .unwrap();
        std::fs::write(
            settings.authority_dir.join("authority.json"),
            variant.authority.as_bytes(),
        )
        .unwrap();
        // Either global validation on open or exact lookup may reject, but the
        // failure must be authenticated inconsistency, never absence or a grant.
        let observed = PersonalAccountStore::open(settings).and_then(|store| store.lookup(&key));
        assert_eq!(
            observed,
            Err(super::AccountError::NotAuthentic),
            "authority/record disagreement in {} must refuse disclosure",
            variant.field
        );
    }
}

#[test]
fn s03_record_filesystem_failures_are_not_absence() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    for fault in ["symlink", "public_permissions", "oversized", "directory"] {
        let (_root, settings, fixture) = install_committed_fixture();
        let case = &fixture.cases[0];
        let key = case.account_key();
        let store = PersonalAccountStore::open(settings.clone()).unwrap();
        assert_eq!(
            store.lookup(&key),
            Ok(AccountLookup::Connected(case.record.clone()))
        );
        let path = settings.store_dir.join(&case.basename);
        let backup = settings.store_dir.join("saved-valid-ciphertext");
        std::fs::rename(&path, &backup).unwrap();
        match fault {
            "symlink" => symlink(&backup, &path).unwrap(),
            "public_permissions" => {
                std::fs::copy(&backup, &path).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            "oversized" => std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(&vec![b'a'; 2 * 1024 * 1024])
                .unwrap(),
            "directory" => std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap(),
            _ => unreachable!(),
        }
        let observed = store.lookup(&key);
        if fault == "directory" {
            std::fs::remove_dir(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::rename(&backup, &path).unwrap();
        assert_eq!(
            store.lookup(&key),
            Ok(AccountLookup::Connected(case.record.clone()))
        );
        assert_eq!(
            observed,
            Err(super::AccountError::StorageUnavailable),
            "unsafe record file {fault} must refuse while restored data remains readable"
        );
    }
}

#[test]
fn s03_authenticated_unsafe_record_pointers_are_rejected() {
    let variants = lookup_states_fixture();
    let named = committed_fixture();
    // Name each vector, so a fixture edit cannot silently drop traversal,
    // absolute-path, foreign-digest, malformed-suffix or dot-segment coverage.
    assert_eq!(
        variants
            .unsafe_pointers
            .iter()
            .map(|pointer| pointer.basename.clone())
            .collect::<Vec<String>>(),
        [
            format!("../records/{}", named.cases[0].basename),
            format!("/untrusted/{}", named.cases[0].basename),
            format!(
                "{}{}",
                named.cases[1].digest,
                &named.cases[0].basename[64..]
            ),
            format!("{}-NOT-LOWERCASE-HEX.json", named.cases[0].digest),
            format!("./{}", named.cases[0].basename),
        ]
    );
    for variant in variants.unsafe_pointers {
        let (_root, settings, fixture) = install_committed_fixture();
        let case = &fixture.cases[0];
        // Same-fixture positive control: a blanket NotAuthentic implementation
        // cannot satisfy both this and the refusal below.
        let control = PersonalAccountStore::open(settings.clone()).unwrap();
        assert_eq!(
            control.lookup(&fixture.cases[1].account_key()),
            Ok(AccountLookup::Connected(fixture.cases[1].record.clone())),
            "the unmutated fixture still resolves an unrelated committed account"
        );
        drop(control);
        // For malformed single-component names, place the exact valid ciphertext
        // at the named path so a missing file or AEAD mismatch cannot mask a
        // skipped basename validator. Dot-segment paths already reach that data.
        if !variant.basename.contains('/') {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(settings.store_dir.join(&variant.basename))
                .unwrap()
                .write_all(fixture.record_files[&case.basename].as_bytes())
                .unwrap();
        }
        std::fs::write(
            settings.authority_dir.join("authority.json"),
            variant.authority.as_bytes(),
        )
        .unwrap();
        let observed = PersonalAccountStore::open(settings)
            .and_then(|store| store.lookup(&case.account_key()));
        assert_eq!(
            observed,
            Err(super::AccountError::NotAuthentic),
            "authenticated unsafe record pointer must reject before file selection"
        );
    }
}

#[test]
fn s03_authentic_unaccepted_ciphertext_is_rejected() {
    let variants = lookup_states_fixture();
    let variant = variants.unaccepted_ciphertext;
    let (_root, settings, fixture) = install_committed_fixture();
    let case = &fixture.cases[0];
    let key = case.account_key();
    let aad = super::storage::token_aad(
        "current",
        &settings.instance_id,
        "0123456789abcdef0123456789abcdef",
        &key,
    )
    .unwrap();
    let envelope: super::storage::TokenEnvelope =
        serde_json::from_str(&variant.record_bytes).unwrap();
    assert_eq!(
        super::storage::open_token(&settings.keys["current"], &aad, &envelope),
        Ok(variant.record.clone())
    );
    let mut expected = case.record.clone();
    expected.access_token = variant.record.access_token.clone();
    assert_ne!(expected.access_token, case.record.access_token);
    assert_eq!(
        expected, variant.record,
        "all authority metadata still agrees"
    );
    let store = PersonalAccountStore::open(settings.clone()).unwrap();
    let path = settings.store_dir.join(&case.basename);
    std::fs::write(&path, variant.record_bytes.as_bytes()).unwrap();
    let observed = store.lookup(&key);
    std::fs::write(&path, fixture.record_files[&case.basename].as_bytes()).unwrap();
    assert_eq!(
        observed,
        Err(super::AccountError::NotAuthentic),
        "an authentic same-version token still needs the exact accepted ciphertext digest"
    );
    assert_eq!(
        store.lookup(&key),
        Ok(AccountLookup::Connected(case.record.clone()))
    );
}

#[test]
fn s03_maximum_plaintext_record_reads_under_a_long_configured_key_id() {
    let bounds = lookup_states_fixture().envelope_bounds;
    assert_eq!(bounds.len(), 2);
    for variant in &bounds {
        // No configuration check caps a key ID, and escaping enlarges one more.
        assert!(
            serde_json::to_string(&variant.key_id).unwrap().len() - 2 >= 4096,
            "{} key id is long enough to matter",
            variant.name
        );
        let payload = serde_json::to_vec(&variant.max.record).unwrap().len();
        assert_eq!(payload, 262_144, "{} max payload", variant.name);
        let (_root, settings) = install_bound_fixture(variant);
        let store = PersonalAccountStore::open(settings).unwrap();
        // This control passing proves a refusal below is the envelope bound.
        assert_eq!(
            store.lookup(&account_key(&variant.ordinary.fields)),
            Ok(AccountLookup::Connected(variant.ordinary.record.clone())),
            "{} ordinary control must resolve",
            variant.name
        );
        assert_eq!(
            store.lookup(&account_key(&variant.max.fields)),
            Ok(AccountLookup::Connected(variant.max.record.clone())),
            "{} maximum-plaintext record must stay readable at {} envelope bytes",
            variant.name,
            variant.max.record_bytes.len()
        );
    }
}

// A record FIFO cannot be observed in-process: an implementation that opens it
// without O_NONBLOCK blocks forever, which is the defect under test. The bounded
// child process is the oracle. Linux-only, matching the existing authority FIFO
// regression; other platforms leave this path unexecuted, not passed.
#[cfg(target_os = "linux")]
const RECORD_CHILD_ROOT: &str = "MCP_ACCOUNTS_RECORD_FIFO_TEST_ROOT";
#[cfg(target_os = "linux")]
const RECORD_CHILD_TEST: &str = "personal_accounts::tests::store::record_lookup_child";

/// Private test-binary entrypoint; no daemon or real credentials are involved.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "private child entrypoint; exercised by the bounded record-FIFO regression"]
fn record_lookup_child() {
    use std::io::Write as _;

    let root =
        std::env::var_os(RECORD_CHILD_ROOT).expect("child requires its synthetic fixture root");
    let fixture = committed_fixture();
    let case = &fixture.cases[0];
    let key = case.account_key();
    let settings = config(std::path::Path::new(&root));
    println!("ACCOUNT_RECORD_READY");
    std::io::stdout().flush().unwrap();
    let outcome = match PersonalAccountStore::open(settings).map(|store| store.lookup(&key)) {
        Ok(Ok(AccountLookup::Connected(record))) if record == case.record => "CONNECTED".to_owned(),
        Ok(Ok(other)) => format!("STATE:{other:?}"),
        Ok(Err(error)) => format!("LOOKUP:{error:?}"),
        Err(error) => format!("OPEN:{error:?}"),
    };
    println!("ACCOUNT_RECORD_RESULT:{outcome}");
    std::io::stdout().flush().unwrap();
}

/// Always reap the owned child, including an implementation that never returns.
#[cfg(target_os = "linux")]
struct RecordProbe {
    child: std::process::Child,
    reader: Option<std::thread::JoinHandle<()>>,
    events: std::sync::mpsc::Receiver<String>,
}

#[cfg(target_os = "linux")]
impl Drop for RecordProbe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn probe_record_lookup(
    root: &std::path::Path,
) -> Result<String, std::sync::mpsc::RecvTimeoutError> {
    use std::io::BufRead as _;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            RECORD_CHILD_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env(RECORD_CHILD_ROOT, root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Inherited, so a child panic is visible in the log rather than being
        // silently indistinguishable from the blocking failure this bounds.
        .stderr(Stdio::inherit());
    if let Some(profile) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", profile);
    }
    let mut child = command.spawn().expect("spawn isolated record-lookup child");
    let output = child.stdout.take().unwrap();
    let (sender, events) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            let event = if line.contains("ACCOUNT_RECORD_READY") {
                "READY".to_owned()
            } else if let Some((_, result)) = line.split_once("ACCOUNT_RECORD_RESULT:") {
                result.trim().to_owned()
            } else {
                continue;
            };
            if sender.send(event).is_err() {
                break;
            }
        }
    });
    let probe = RecordProbe {
        child,
        reader: Some(reader),
        events,
    };
    assert_eq!(
        probe.events.recv_timeout(Duration::from_secs(10)),
        Ok("READY".to_owned()),
        "child readiness is a harness precondition"
    );
    probe.events.recv_timeout(Duration::from_secs(1))
}

#[cfg(target_os = "linux")]
#[test]
fn s03_fifo_record_refuses_promptly_without_blocking_lookup() {
    use std::os::unix::fs::FileTypeExt as _;

    let (root, settings, fixture) = install_committed_fixture();
    let case = &fixture.cases[0];
    // The parent never opens the store: both directory locks belong to the child.
    assert_eq!(
        probe_record_lookup(root.path()),
        Ok("CONNECTED".to_owned()),
        "the unmutated fixture must resolve through the child before any fault"
    );
    let path = settings.store_dir.join(&case.basename);
    let original = std::fs::read(&path).unwrap();
    let backup = settings.store_dir.join("saved-valid-ciphertext");
    std::fs::rename(&path, &backup).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("create actual FIFO in private fixture root");
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_fifo()
    );
    // Capture the result while the FIFO is present, then restore the untouched
    // ciphertext and prove it still reads before asserting the refusal.
    let observed = probe_record_lookup(root.path());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&backup, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(probe_record_lookup(root.path()), Ok("CONNECTED".to_owned()));
    assert_eq!(
        observed,
        Ok("LOOKUP:StorageUnavailable".to_owned()),
        "a record FIFO must refuse as physical-storage failure within one second of readiness"
    );
}
