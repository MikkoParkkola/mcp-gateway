// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway custody bootstrap: startup, lock ownership, explicit shutdown.
//!
//! TARGET PATH: `src/gateway/server/gateway_bootstrap_tests.rs`.
//!
//! WHAT THESE DRIVE. Only the gateway's own API — `Gateway::new_evaluated`,
//! `start_account_custody`, `account_custody`, `shutdown_account_custody`.
//! Nothing here calls `personal_accounts::start_custody` directly, on purpose:
//! that function will grow a provider argument when the real refresh adapter
//! lands, and a test bound to its current signature would have to be rewritten
//! then. Bound to the gateway API, these tests go green with no edit at all.
//!
//! WHAT IS GREEN TODAY, WHAT IS RED. The custody startup path is a refusing
//! scaffold: everything up to and including configuration resolution is real,
//! and it then refuses because the refresh provider type is uninhabited. So
//! `omitted_accounts_*` and `a_misconfigured_accounts_block_*` pass now, and
//! every test that requires a STARTED custody fails now — deliberately, and on
//! the assertion that names the missing behaviour rather than on a compile
//! error. `not_scaffold` turns the scaffold refusal into an explicit failure so
//! it can never be mistaken for a domain outcome; the one test that asserts the
//! scaffold marker itself says so in its name and is retired when custody runs.
//!
//! WHAT THEY DO NOT RE-ASSERT. The evaluated-config layer (`Config::accounts`
//! parsing, overlay resolution, `env:` reference preservation, redacted Debug)
//! is already pinned by `src/config/account_custody_tests.rs`, and the custody
//! worker's own drain/off-thread/single-flight contracts by
//! `src/personal_accounts/worker_tests.rs`. The fixture SHAPE is borrowed from
//! both; none of their assertions is repeated. What is new here is the gateway:
//! that it resolves, opens, owns, and releases.
//!
//! DETERMINISM. Every test owns a `TempDir`, so no two share a store. No sleep,
//! no global environment mutation, no shared static: the fixture key reaches the
//! gateway through an env FILE only, and nothing in this crate writes the
//! process environment — which is what makes its absence there assertable.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;

use super::Gateway;
use crate::config::{Config, LiveEnv};
use crate::personal_accounts::config::AccountsConfigError;
use crate::personal_accounts::{
    AccountError, AccountKey, AccountLookup, CustodyBootstrapError, CustodyError,
    CustodyStartError, GrantRecord, PersonalAccountStore, StoreConfig,
};

/// The store key, as bytes and as the base64 the env file carries.
const KEY: [u8; 32] = [0x51; 32];
const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
/// The same material one byte short: a configuration error, not a key.
const SHORT_KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUQ==";

/// Assigned by the fixture env file and by nothing else. A name unique to this
/// module, so "absent from the process environment" cannot be made true or
/// false by another test.
const KEY_VAR: &str = "GATEWAY_BOOTSTRAP_TEST_ACCOUNT_KEY";
const INSTANCE_ID: &str = "gateway-bootstrap";

/// Whether the fixture config carries an `accounts` block, and with what key.
///
/// An enum rather than an `Option<&str>` flag so the call site reads without
/// opening this signature.
enum Accounts<'a> {
    Omitted,
    Configured(&'a str),
}

struct Fixture {
    /// Held for the test's lifetime: dropping it removes the store.
    _root: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
}

impl Fixture {
    /// The store as the gateway will resolve it. Byte-identical to the YAML, so
    /// a test that seeds through this opens the same two locked directories the
    /// gateway does.
    fn store_config(&self) -> StoreConfig {
        StoreConfig {
            instance_id: INSTANCE_ID.to_string(),
            store_dir: self.root.join("store"),
            authority_dir: self.root.join("authority"),
            current_key_id: "current".to_string(),
            keys: BTreeMap::from([("current".to_string(), KEY.to_vec())]),
            max_entries: 10_000,
            max_authority_bytes: 16_777_216,
        }
    }

    /// Initialize the store and commit one connected grant, then release it.
    ///
    /// Returns the record, so a readback through the gateway is compared against
    /// what was actually written rather than against a second literal.
    fn seed(&self) -> GrantRecord {
        let record = grant();
        let store = PersonalAccountStore::initialize(self.store_config())
            .expect("the fixture store initializes offline");
        store
            .commit_grant(&alice(), &record)
            .expect("the fixture grant commits");
        drop(store);
        record
    }
}

/// A config file, an env file beside it, and nothing on disk for the store.
///
/// The env file is the ONLY place the key material appears; the config holds an
/// `env:` reference to it, exactly as a deployment does.
fn fixture(accounts: Accounts<'_>) -> Fixture {
    // Guards the hand-written base64 above: a mistyped constant would otherwise
    // make a key-length test pass for the wrong reason.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(KEY_B64)
        .expect("the fixture key is standard base64");
    assert_eq!(
        decoded,
        KEY.to_vec(),
        "the fixture key must be 32 0x51 bytes"
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(SHORT_KEY_B64)
            .expect("the short fixture key is standard base64")
            .len(),
        31,
        "the short key must be one byte short of the 32 the store requires"
    );

    let temp = tempfile::TempDir::new().expect("fixture root");
    // Canonicalized so the YAML, the seeding config and the lock paths are one
    // string. On macOS a temp root is a symlink, and comparing the two spellings
    // later is a distraction the test does not need.
    let root = temp
        .path()
        .canonicalize()
        .expect("the fixture root resolves");

    let env_path = root.join("accounts.env");
    std::fs::write(&env_path, format!("{KEY_VAR}={}\n", key_of(&accounts)))
        .expect("write the fixture env file");

    let body = match accounts {
        Accounts::Omitted => format!(
            "env_files:\n  - {}\nserver:\n  port: 18491\n",
            env_path.display()
        ),
        Accounts::Configured(_) => format!(
            "env_files:\n  - {}\nserver:\n  port: 18491\naccounts:\n  schema_version: accounts.v1\n  \
             enabled: true\n  deployment: single_process\n  instance_id: {INSTANCE_ID}\n  \
             store_dir: {}\n  authority_dir: {}\n  current_key_id: current\n  keys:\n    \
             current: env:{KEY_VAR}\n  limits:\n    store_entries: 10000\n    \
             authority_bytes: 16777216\n",
            env_path.display(),
            root.join("store").display(),
            root.join("authority").display(),
        ),
    };
    let config_path = root.join("config.yaml");
    std::fs::write(&config_path, body).expect("write the fixture config");

    Fixture {
        _root: temp,
        root,
        config_path,
    }
}

/// The env file always carries a key, so the omitted-accounts case proves the
/// gateway ignores it rather than failing to find it.
fn key_of<'a>(accounts: &'a Accounts<'a>) -> &'a str {
    match accounts {
        Accounts::Omitted => KEY_B64,
        Accounts::Configured(key) => key,
    }
}

fn alice() -> AccountKey {
    AccountKey {
        principal_authority: "https://identity.example".to_string(),
        principal_subject: "alice".to_string(),
        backend_id: "google-workspace-personal".to_string(),
        resource: "https://www.googleapis.com/drive/v3".to_string(),
        oauth_issuer: "https://accounts.google.com".to_string(),
    }
}

/// Unexpired on purpose: `resolve` then needs no provider round trip, which is
/// what lets these tests exercise real custody while the refresh adapter is
/// still missing.
fn grant() -> GrantRecord {
    GrantRecord {
        generation: "fedcba9876543210fedcba9876543210".to_string(),
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: "0".repeat(64),
        scopes: vec!["https://www.googleapis.com/auth/drive.readonly".to_string()],
        access_token: "synthetic-alice-access-private-material-9f3a71".to_string(),
        refresh_token: Some("synthetic-alice-refresh-private-material-8c9d21".to_string()),
        token_type: "Bearer".to_string(),
        expires_at: u64::MAX,
        provider_account_id: Some("synthetic-alice-provider-account-private-1a92".to_string()),
        client_id: "synthetic-google-client".to_string(),
    }
}

/// The production startup, exactly as `main.rs` will perform it.
async fn build(config_path: &Path) -> crate::Result<Gateway> {
    let (config, env) = evaluated(config_path);
    Gateway::new_evaluated(config, env, Some(config_path.to_path_buf())).await
}

/// The same startup with the custody step's own typed outcome preserved.
///
/// Not a shortcut around the constructor: `new_evaluated` is exactly these two
/// steps — the same overlay-aware construction, then the custody bring-up — and
/// every claim made through this pair is ALSO made end-to-end through `build` in
/// the same test. Building through `new_with_path` here would validate against
/// the process environment instead, where the fixture key does not exist.
async fn build_typed(config_path: &Path) -> (Gateway, Result<(), CustodyBootstrapError>) {
    let (config, env) = evaluated(config_path);
    let mut gateway = Gateway::new_with_env(config, env, Some(config_path.to_path_buf()))
        .await
        .expect("the fixture config builds an ordinary gateway");
    let outcome = gateway.start_account_custody().await;
    (gateway, outcome)
}

/// The startup evaluation, with its refusal preserved.
///
/// A config the loader refuses is refused HERE, before any gateway exists, so
/// the refusal is a value a test can assert on rather than a panic inside the
/// fixture.
fn load(config_path: &Path) -> crate::Result<(Config, Arc<LiveEnv>)> {
    let evaluated = Config::load_evaluated(Some(config_path))?;
    let env = Arc::new(LiveEnv::new(evaluated.overlay, evaluated.env_paths));
    Ok((evaluated.config, env))
}

/// As [`load`], for the fixtures that must evaluate.
fn evaluated(config_path: &Path) -> (Config, Arc<LiveEnv>) {
    load(config_path).expect("the fixture config evaluates")
}

/// The scaffold refusal is never a domain outcome.
///
/// Same contract as `worker_tests::refuse_scaffold`: a not-implemented answer
/// fails the test loudly instead of being read as "custody declined", which is
/// what stops a refusing stub from satisfying a behavioural assertion.
#[track_caller]
fn not_scaffold<T>(
    result: Result<T, CustodyBootstrapError>,
    what: &str,
) -> Result<T, CustodyBootstrapError> {
    match result {
        Err(CustodyBootstrapError::Start(CustodyStartError::RuntimeNotImplemented)) => {
            panic!("{what}: RuntimeNotImplemented is the refusing scaffold, not a domain outcome")
        }
        other => other,
    }
}

#[track_caller]
fn expect_connected(lookup: AccountLookup) -> GrantRecord {
    match lookup {
        AccountLookup::Connected(record) => record,
        other => panic!("expected a connected account, got {other:?}"),
    }
}

/// An omitted `accounts` block must leave startup exactly as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn omitted_accounts_starts_an_ordinary_gateway_with_no_custody() {
    let fx = fixture(Accounts::Omitted);

    let gateway = build(&fx.config_path)
        .await
        .expect("a config without an accounts block starts an ordinary gateway");
    assert!(
        gateway.account_custody().is_none(),
        "no accounts block must enable no custody: an omitted block is not a default store"
    );
    assert!(
        !fx.root.join("store").exists() && !fx.root.join("authority").exists(),
        "an omitted accounts block must not create a store directory"
    );
}

/// Resolution is real, and it happens BEFORE anything is opened.
///
/// The 31-byte key is refused by the configuration layer, at the public load a
/// deployment performs: the `env:` reference is resolved through the overlay,
/// the material is the wrong length, and startup stops there with no gateway
/// ever built. So this asserts the PUBLIC refusal and an untouched filesystem —
/// a config rejected this early cannot also be required to produce a later
/// custody outcome, and demanding one would be demanding a step that is
/// unreachable by construction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_misconfigured_accounts_block_is_refused_by_real_resolution() {
    let fx = fixture(Accounts::Configured(SHORT_KEY_B64));

    // Built rather than spelled out, so the assertion cannot drift from the
    // message the configuration layer actually renders.
    let expected = AccountsConfigError::KeyMaterial {
        key_id: "current".to_string(),
    }
    .to_string();
    let error = load(&fx.config_path).expect_err("a key that is not 32 bytes must refuse startup");
    assert!(
        matches!(&error, crate::Error::ConfigValidation(message) if *message == expected),
        "the refusal must be the configuration layer's own, named by key id only, got {error}"
    );
    assert!(
        !fx.root.join("store").exists() && !fx.root.join("authority").exists(),
        "a configuration refused before the open must not touch the filesystem"
    );
}

// RETIRED, exactly as its own header instructed: the scaffold-marker test
// `the_scaffold_refuses_at_the_provider_and_claims_no_locks` asserted
// `CustodyStartError::RuntimeNotImplemented` from a valid configuration, which
// is no longer producible — `start_account_custody` now brings a real provider
// and a real custody up. Its two live claims did not go with it: "a started
// gateway holds both locks" is the AC-1 test below, and "the process
// environment never carries the env-file key" is asserted in that same test and
// in the disabled-block test. `not_scaffold` is kept and still guards the two
// refusal tests, so a scaffold answer reappearing anywhere would fail loudly.

/// AC-1. A started gateway owns the EXISTING store and can read what is in it.
///
/// The readback is the key-preservation proof at this layer: the store was
/// sealed with 32 bytes the test wrote directly, the gateway received those
/// bytes only through an env file, and a wrong key cannot produce this record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_started_gateway_owns_the_existing_store_and_reads_its_seeded_grant() {
    let fx = fixture(Accounts::Configured(KEY_B64));
    let seeded = fx.seed();

    let gateway = build(&fx.config_path)
        .await
        .expect("a valid accounts block against an initialized store starts custody");
    let custody = gateway
        .account_custody()
        .expect("a configured accounts block must attach custody");

    let lease = custody
        .resolve(&alice())
        .await
        .expect("the seeded account resolves through the gateway's custody");
    assert_eq!(lease.account, alice());
    assert_eq!(lease.generation, seeded.generation);
    assert_eq!(lease.token_revision, seeded.token_revision);
    assert_eq!(lease.scopes, seeded.scopes);

    // Exactly one owner, and it is this gateway: the constructor returned only
    // after both exclusive locks were acquired.
    assert_eq!(
        PersonalAccountStore::open(fx.store_config())
            .err()
            .expect("a second owner must not open the store the gateway holds"),
        AccountError::StorageUnavailable,
        "a constructed gateway is ready only because it already holds both locks"
    );
    assert!(
        std::env::var(KEY_VAR).is_err(),
        "the key reached the store through the env overlay; the process environment is unchanged"
    );
}

/// AC-1, the other half: `open` is an open, never an initialize.
///
/// Without this a startup that quietly created a store would pass every other
/// test here — and would silently strand a deployment whose store directory was
/// mistyped, serving an empty custody instead of refusing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn construction_refuses_when_no_store_has_been_initialized() {
    let fx = fixture(Accounts::Configured(KEY_B64));

    let (gateway, outcome) = build_typed(&fx.config_path).await;
    let error = not_scaffold(outcome, "an uninitialized store")
        .expect_err("an absent store must refuse startup, not be created by it");
    assert!(
        matches!(
            error,
            CustodyBootstrapError::Start(CustodyStartError::Store(_))
        ),
        "the refusal must come from the real store boundary, got {error:?}"
    );
    assert!(gateway.account_custody().is_none());
    assert!(
        build(&fx.config_path).await.is_err(),
        "the production constructor must fail rather than start without a store"
    );

    // Nothing half-created was left behind: explicit offline initialization
    // still works, which it would not against a partially written authority.
    PersonalAccountStore::initialize(fx.store_config())
        .expect("a refused open must leave the directory initializable");
}

/// AC-2. A second gateway refuses while the first owns the locks.
///
/// The FIRST-OWNER CONTROL is the first assertion, not a courtesy: a startup
/// that always refused would satisfy the lock case below trivially. It must
/// succeed here, refuse there, and succeed again once the owner lets go — three
/// outcomes no constant answer can produce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_gateway_refuses_while_the_first_owns_the_locks() {
    let fx = fixture(Accounts::Configured(KEY_B64));
    fx.seed();

    let first = build(&fx.config_path)
        .await
        .expect("the first owner starts: this control is what makes the refusal below mean lock");
    assert!(first.account_custody().is_some());

    assert!(
        build(&fx.config_path).await.is_err(),
        "a second gateway must not start against a store another gateway holds"
    );
    let (second, outcome) = build_typed(&fx.config_path).await;
    assert_eq!(
        not_scaffold(outcome, "a second owner").expect_err("the second start refuses"),
        CustodyBootstrapError::Start(CustodyStartError::Store(AccountError::StorageUnavailable)),
        "the refusal is the real held lock, reported as the store's own error"
    );
    assert!(
        second.account_custody().is_none(),
        "a gateway that could not claim the store must not look half-available"
    );

    // The boundary was ownership, not a permanent failure: once the first
    // gateway releases the store, a new owner starts.
    first
        .shutdown_account_custody()
        .await
        .expect("the first owner releases its store");
    let third = build(&fx.config_path)
        .await
        .expect("a released store admits a new owner");
    assert!(third.account_custody().is_some());
}

/// AC-3. Explicit account shutdown drains, frees both locks, and refuses after.
///
/// The reopen happens WHILE the gateway is alive, which is what a no-op shutdown
/// cannot fake: without a real release the open below fails on the locks this
/// gateway is still holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_account_shutdown_frees_both_locks_while_the_gateway_stays_alive() {
    let fx = fixture(Accounts::Configured(KEY_B64));
    let seeded = fx.seed();

    let gateway = build(&fx.config_path).await.expect("custody starts");
    let custody = Arc::clone(
        gateway
            .account_custody()
            .expect("a configured accounts block must attach custody"),
    );
    custody
        .resolve(&alice())
        .await
        .expect("custody serves before shutdown");

    gateway
        .shutdown_account_custody()
        .await
        .expect("explicit account shutdown completes");

    // THE PROOF, with the gateway still alive and still holding its handle.
    let reopened = PersonalAccountStore::open(fx.store_config())
        .expect("account shutdown released both file locks");
    let durable = expect_connected(reopened.lookup(&alice()).expect("readback"));
    assert_eq!(
        durable.generation, seeded.generation,
        "releasing the store must not disturb what it holds"
    );
    drop(reopened);

    assert_eq!(
        custody
            .resolve(&alice())
            .await
            .expect_err("work after shutdown is refused"),
        CustodyError::ShuttingDown,
        "operations after an account shutdown refuse, never silently queue"
    );
    assert!(
        gateway.account_custody().is_some(),
        "the gateway keeps its handle after releasing the store: it is the handle that refuses"
    );

    gateway
        .shutdown_account_custody()
        .await
        .expect("account shutdown is idempotent");
}
// APPEND VERBATIM to the end of `src/gateway/server/gateway_bootstrap_tests.rs`.
// Eighth test; the existing seven are unchanged. No new imports: `fixture`,
// `Accounts`, `KEY_B64`, `KEY_VAR` and `build` are already in scope there.

/// A DISABLED accounts block starts an ordinary gateway, exactly as an omitted
/// one does.
///
/// RED TODAY, and on an assertion rather than a compile error: resolution
/// answers `NotEnabled` and `start_account_custody` currently propagates it, so
/// `build` fails on its own `expect` below. That is the behaviour this names —
/// `enabled: false` is an operator's decision to run WITHOUT custody, not a
/// misconfiguration, and a decline must claim nothing: no store, no lock, no
/// directories.
///
/// UNLIKE its siblings this does NOT retire on green. The disabled path never
/// reaches the refresh provider, so a real provider cannot change what it
/// asserts; and `the_scaffold_refuses_at_the_provider` cannot cover this case,
/// because a disabled block is refused before the provider is ever reached.
///
/// The fixture is the SAME store-only YAML every other configured test uses,
/// with one line flipped — so any difference in outcome is that flag and nothing
/// else. The flip is applied to the config FILE; the running process, its
/// environment and the env file are untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_accounts_block_starts_an_ordinary_gateway_with_no_custody() {
    let fx = fixture(Accounts::Configured(KEY_B64));

    // Anchored: a fixture that renames, reindents or duplicates this line must
    // move this test with it, instead of silently leaving an ENABLED block here
    // and turning the assertions below into a copy of the AC-1 test.
    const ENABLED: &str = "\n  enabled: true\n";
    let yaml = std::fs::read_to_string(&fx.config_path).expect("the fixture config is readable");
    assert_eq!(
        yaml.matches(ENABLED).count(),
        1,
        "the fixture must carry exactly one `enabled: true` line for this test to flip"
    );
    std::fs::write(
        &fx.config_path,
        yaml.replace(ENABLED, "\n  enabled: false\n"),
    )
    .expect("write the disabled fixture config");

    // No `seed()`: the store is never initialized, so "the directories are
    // absent" below is a claim about the gateway and not about the fixture.
    let gateway = build(&fx.config_path)
        .await
        .expect("a disabled accounts block starts an ordinary gateway; it does not refuse startup");
    assert!(
        gateway.account_custody().is_none(),
        "a disabled block must enable no custody: declined is not deferred"
    );
    assert!(
        !fx.root.join("store").exists() && !fx.root.join("authority").exists(),
        "a disabled accounts block must create no store: a decline claims nothing on disk"
    );
    assert!(
        std::env::var(KEY_VAR).is_err(),
        "a disabled block reads no key material; the process environment stays unchanged"
    );
}
