// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6744.STORE.1 — the migration end to end.
//!
//! These are the criterion's own tests: a 3.x credential file goes in, a grant
//! the sole operator can look up comes out, and the 3.x file is untouched.
//!
//! EVERY NEGATIVE HERE RUNS A PROVEN-SUCCESSFUL MIGRATION FIRST. A suite that
//! only asserted "nothing was written" would pass for a migration that does
//! nothing at all, which is the defect class this repository has caught
//! repeatedly. So the positive leg is inside the same test, not in a sibling.

use std::path::{Path, PathBuf};

use super::{MigrationOutcome, MigrationRefusal, MigrationRequest, migrate_backend};
use crate::oauth::TokenStorage;
use crate::personal_accounts::config::{AccountDescriptor, DescriptorMode};
use crate::personal_accounts::identity::AccountDescriptor as KeyDescriptor;
use crate::personal_accounts::identity::{Principal, account_key};
use crate::personal_accounts::storage::migration_source::SourceRefusal;
use crate::personal_accounts::{AccountLookup, PersonalAccountStore, StoreConfig};

const BACKEND: &str = "workspace";
const RESOURCE: &str = "https://mcp.example.test/v1/mcp";
const ISSUER: &str = "https://auth.example.test";
const CLIENT: &str = "client-abc";
/// 2100-01-01, so a seeded grant is unexpired whenever this runs.
const FAR_FUTURE: u64 = 4_102_444_800;

const KEY: [u8; 32] = [0x51; 32];

fn store_config(root: &Path) -> StoreConfig {
    let root = root.canonicalize().expect("fixture root exists");
    StoreConfig {
        instance_id: "gateway-instance".into(),
        store_dir: root.join("records"),
        authority_dir: root.join("authority"),
        current_key_id: "current".into(),
        keys: std::collections::BTreeMap::from([("current".into(), KEY.to_vec())]),
        max_entries: 64,
        max_authority_bytes: 16_777_216,
    }
}

fn key_descriptor() -> KeyDescriptor {
    KeyDescriptor {
        descriptor_id: "workspace-personal".to_owned(),
        provider: "workspace".to_owned(),
        resource: RESOURCE.to_owned(),
        issuer: ISSUER.to_owned(),
    }
}

fn descriptor() -> AccountDescriptor {
    AccountDescriptor {
        mode: DescriptorMode::PersonalManaged,
        provider: "workspace".to_owned(),
        resource: Some(RESOURCE.to_owned()),
        issuer: Some(ISSUER.to_owned()),
        authorization_endpoint: None,
        token_endpoint: None,
        revocation_endpoint: None,
        client_id: Some(CLIENT.to_owned()),
        client_secret_ref: None,
        redirect_uri: None,
        scopes: Some(vec!["read".to_owned(), "write".to_owned()]),
        send_resource_parameter: Some(true),
        external_strategy: None,
    }
}

/// Literal 3.x token JSON, seeded as bytes rather than written through
/// `TokenStorage::save`, so this fixture states the 3.x layout itself: a test
/// that wrote and read through the same code would pass just as well if both
/// had moved together.
fn legacy_json() -> String {
    format!(
        r#"{{
  "access_token": "legacy-3x-access-token",
  "token_type": "Bearer",
  "refresh_token": "legacy-3x-refresh-token",
  "expires_at": {FAR_FUTURE},
  "scope": "read write"
}}"#
    )
}

struct Fixture {
    _root: tempfile::TempDir,
    settings: StoreConfig,
    store: PersonalAccountStore,
    legacy: TokenStorage,
    oauth_dir: PathBuf,
}

impl Fixture {
    /// An initialized store and a 3.x credential directory holding one record
    /// at the path the 3.x naming scheme resolves to.
    fn new() -> Self {
        Self::with_body(Some(legacy_json()))
    }

    fn with_body(body: Option<String>) -> Self {
        let root = tempfile::tempdir().expect("temp dir");
        let oauth_dir = root.path().join("oauth");
        std::fs::create_dir_all(&oauth_dir).expect("oauth dir");
        let legacy = TokenStorage::new(oauth_dir.clone()).expect("open 3.x store");
        if let Some(body) = body {
            let path = legacy.token_path(BACKEND, RESOURCE);
            std::fs::write(&path, body).expect("seed 3.x record");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
            }
        }
        let settings = store_config(root.path());
        let store =
            PersonalAccountStore::initialize(settings.clone()).expect("offline initialization");
        Self {
            _root: root,
            settings,
            store,
            legacy,
            oauth_dir,
        }
    }

    fn source_path(&self) -> PathBuf {
        self.legacy.token_path(BACKEND, RESOURCE)
    }

    fn request<'a>(
        descriptor: &'a AccountDescriptor,
        key: &'a KeyDescriptor,
        legacy_issuer: &'a str,
    ) -> MigrationRequest<'a> {
        MigrationRequest {
            key_descriptor: key,
            descriptor,
            bound_backend: BACKEND,
            legacy_backend_name: None,
            legacy_issuer,
            registered_client_id: None,
        }
    }

    fn migrate(&self) -> Result<MigrationOutcome, MigrationRefusal> {
        let descriptor = descriptor();
        let key = key_descriptor();
        migrate_backend(
            &self.store,
            &self.legacy,
            &Self::request(&descriptor, &key, ISSUER),
        )
    }

    /// Look the migrated grant up the way a request would: through the SAME
    /// key constructor the lease path uses, never a hand-assembled one.
    fn lookup(&self) -> AccountLookup {
        let key = key_descriptor();
        let account = account_key(Some(Principal::SoleOperator), &key).expect("sole-operator key");
        self.store.lookup(&account).expect("the store reads back")
    }
}

/// THE CRITERION. A 3.x credential migrates, and the sole operator can find it.
///
/// The lookup goes through `account_key(Some(Principal::SoleOperator), ..)` —
/// the same constructor a request uses — so this proves the grant lands at an
/// address a real caller resolves to, not merely that a record exists.
#[test]
fn a_3_x_credential_migrates_and_the_sole_operator_can_look_it_up() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.lookup(),
        AccountLookup::Absent,
        "control: nothing is present before the migration runs"
    );

    assert_eq!(fixture.migrate(), Ok(MigrationOutcome::Migrated));

    let AccountLookup::Connected(record) = fixture.lookup() else {
        panic!("a migrated grant must read back as connected");
    };
    assert_eq!(record.access_token, "legacy-3x-access-token");
    assert_eq!(
        record.refresh_token.as_deref(),
        Some("legacy-3x-refresh-token")
    );
    assert_eq!(record.scopes, vec!["read".to_owned(), "write".to_owned()]);
    assert_eq!(record.expires_at, FAR_FUTURE, "the real lifetime is kept");
    assert_eq!(record.client_id, CLIENT);
}

/// The 3.x source survives byte for byte, and is never re-keyed.
///
/// Both halves run AFTER a proven-successful migration, so neither can pass for
/// a migration that did nothing: the first assertion below would fail.
#[test]
fn the_3_x_source_survives_byte_for_byte_and_is_never_re_keyed() {
    let fixture = Fixture::new();
    let before = std::fs::read(fixture.source_path()).expect("seeded");

    assert_eq!(
        fixture.migrate(),
        Ok(MigrationOutcome::Migrated),
        "control: the non-destructive claim is about a migration that RAN"
    );

    assert_eq!(
        std::fs::read(fixture.source_path()).expect("still there"),
        before,
        "the 3.x file is opened read-only and never mutated"
    );
    // Nothing new appears in the credential directory: migration writes to the
    // per-principal store and never re-keys the old file under the 4.0.0 name.
    let entries: Vec<_> = std::fs::read_dir(&fixture.oauth_dir)
        .expect("readable")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "migration must not write a second credential file: {entries:?}"
    );
}

/// §5.3c.1 — a declared backend with NO 3.x file refuses loudly, naming the
/// override flag.
///
/// The silent alternative is the dangerous one: a resolved path that does not
/// exist otherwise reads as "nothing to migrate", which reaches the user as
/// every backend asking to re-authorise, indistinguishable from the migration
/// never having run. Deriving the backend name removes the typo route into
/// this; a rename, a moved home directory or a deleted file all still land
/// here, so the message has to carry the way out.
#[test]
fn a_declared_backend_with_no_3_x_file_refuses_loudly() {
    let fixture = Fixture::with_body(None);
    let refusal = fixture.migrate().expect_err("an absent source must refuse");
    let MigrationRefusal::Source(SourceRefusal::Missing { path }) = &refusal else {
        panic!("an absent source must refuse as Missing, got {refusal:?}");
    };
    assert_eq!(path, &fixture.source_path().display().to_string());

    let shown = refusal.to_string();
    assert!(
        shown.contains("legacy_backend_name"),
        "the refusal must name the override that fixes a rename: {shown}"
    );
    assert_eq!(
        fixture.lookup(),
        AccountLookup::Absent,
        "and nothing is written on the way to refusing"
    );
}

/// Re-running is safe: the second run fences instead of writing.
///
/// Idempotency is a property of the `Absent` guard rather than of a bookkeeping
/// file this design would otherwise have had to invent. The generation must be
/// identical across runs, because a second write would mint a new one.
#[test]
fn re_running_the_migration_fences_instead_of_writing_again() {
    let fixture = Fixture::new();
    assert_eq!(fixture.migrate(), Ok(MigrationOutcome::Migrated));
    let AccountLookup::Connected(first) = fixture.lookup() else {
        panic!("connected after the first run");
    };

    assert_eq!(
        fixture.migrate(),
        Ok(MigrationOutcome::AlreadyPresent),
        "the second run finds the account Connected, which is not Absent"
    );

    let AccountLookup::Connected(second) = fixture.lookup() else {
        panic!("still connected after the second run");
    };
    assert_eq!(
        first.generation, second.generation,
        "a fenced run writes nothing, so the generation cannot have moved"
    );
}

/// A credential the user deliberately revoked is never resurrected.
///
/// `Revoked` is not `Absent`, so the same guard that makes a re-run safe also
/// makes this safe, with no extra rule to get wrong.
#[test]
fn a_revoked_account_is_never_resurrected_by_a_migration() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.migrate(),
        Ok(MigrationOutcome::Migrated),
        "control: migrate once so there is something to revoke"
    );
    let key = key_descriptor();
    let account = account_key(Some(Principal::SoleOperator), &key).expect("sole-operator key");
    fixture.store.revoke(&account).expect("revoke");
    assert!(matches!(fixture.lookup(), AccountLookup::Revoked(_)));

    assert_eq!(
        fixture.migrate(),
        Ok(MigrationOutcome::AlreadyPresent),
        "a migration must not overwrite a revocation"
    );
    assert!(
        matches!(fixture.lookup(), AccountLookup::Revoked(_)),
        "and the account stays revoked"
    );
}

/// §6 — the migrated grant carries the 3.x file it came from.
///
/// This is what lets an auditor tell a grant the user consented to from one
/// written on their behalf, which matters because the residual risk this row
/// accepts is an attribution nobody can verify at migration time.
#[test]
fn a_migrated_grant_is_labelled_with_its_3_x_source() {
    let fixture = Fixture::new();
    assert_eq!(fixture.migrate(), Ok(MigrationOutcome::Migrated));

    let key = key_descriptor();
    let account = account_key(Some(Principal::SoleOperator), &key).expect("sole-operator key");
    let digest = account.digest().expect("digest");
    let authority = fixture.store.lock_authority();
    let entry = authority
        .as_ref()
        .expect("authority held")
        .entries
        .get(&digest)
        .expect("the migrated account has an entry");
    let expected = fixture
        .source_path()
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned);
    assert_eq!(
        entry.legacy_migration, expected,
        "the marker names the 3.x file this grant was migrated from"
    );
}

/// The migrated grant is DURABLE, not merely in memory.
///
/// A reopened store must still find it, or the migration has written something
/// that dies with the process that wrote it.
#[test]
fn a_migrated_grant_survives_reopening_the_store() {
    let fixture = Fixture::new();
    assert_eq!(fixture.migrate(), Ok(MigrationOutcome::Migrated));

    let key = key_descriptor();
    let account = account_key(Some(Principal::SoleOperator), &key).expect("sole-operator key");
    // The writer holds both directory locks, so it must be released before a
    // second opener can take them -- which is the store working as designed,
    // not an obstacle to route around.
    let Fixture {
        _root: root,
        settings,
        store,
        ..
    } = fixture;
    drop(store);
    let reopened = PersonalAccountStore::open(settings).expect("the authority reopens");
    assert!(
        matches!(reopened.lookup(&account), Ok(AccountLookup::Connected(_))),
        "an acknowledged migration is durable"
    );
    drop(root);
}
