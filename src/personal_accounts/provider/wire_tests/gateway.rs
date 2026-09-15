// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway startup over the real wire.
//!
//! TARGET PATH: `src/personal_accounts/provider/wire_tests/gateway.rs`, wired by
//! `mod gateway;` in `wire_tests.rs`. PROPOSAL ONLY — not applied, not compiled.
//!
//! WHAT CHANGED FROM r1, AND WHY. r1 claimed an ordering proof from the WRONG
//! observation: after a startup that had already failed, it opened the store,
//! found the locks free, and read that as "the provider was awaited before the
//! store was opened". It is not. An implementation that opened the store FIRST
//! and dropped it on the refusal produces exactly the same free locks. The
//! absence of a lock after a failure says nothing about the order in which
//! things happened during it.
//!
//! THE REPAIR IS A BARRIER, NOT A STRONGER ASSERTION. The fixture parks the
//! FIRST request it receives inside the response path, after recording it and
//! before answering it. A real `Gateway` construction is spawned through the one
//! shared constructor. While that construction is DEMONSTRABLY suspended at that
//! recorded metadata fetch — demonstrable because the fixture announced the
//! parked request and has not answered it — this test opens the store itself and
//! takes its two exclusive file locks. That open SUCCEEDING is the ordering
//! evidence: at a moment provably inside the metadata fetch, the startup owned
//! nothing. A store-before-fetch implementation fails at that named checkpoint,
//! because its locks would already be held when the fetch parks.
//!
//! The witness is dropped BEFORE the response is released, so the test's own
//! lock is never what the startup contends with — the release half must not be
//! able to fail for the test's reason instead of the implementation's.
//!
//! The bad-metadata refusal stays, as its own test, asserting only what it can:
//! a document that was really fetched is really refused. It makes NO ordering
//! claim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::timeout;

use super::fixture::{CLIENT_ID, Fixture, json_200, metadata, responder, trusting_client};

/// A store key that exists only in the fixture env file.
const KEY: [u8; 32] = [0x51; 32];
const KEY_B64: &str = "UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=";
const KEY_VAR: &str = "PROVIDER_WIRE_TEST_ACCOUNT_KEY";
const INSTANCE_ID: &str = "provider-wire";
const ACCOUNT_ID: &str = "wire-fixture-account";

/// Bound on a whole startup, released barrier included. Above the client's own
/// 10s request timeout so a transport refusal is reported as the refusal it is,
/// rather than as this timeout firing first.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

struct GatewayFixture {
    _root: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
}

impl GatewayFixture {
    fn store_config(&self) -> crate::personal_accounts::StoreConfig {
        crate::personal_accounts::StoreConfig {
            instance_id: INSTANCE_ID.to_string(),
            store_dir: self.root.join("store"),
            authority_dir: self.root.join("authority"),
            current_key_id: "current".to_string(),
            keys: BTreeMap::from([("current".to_string(), KEY.to_vec())]),
            max_entries: 10_000,
            max_authority_bytes: 16_777_216,
        }
    }
}

/// A config file, an env file beside it, and one managed descriptor pointed at
/// `origin` — the fixture listener, reached by name over real TLS.
fn gateway_fixture(origin: &str) -> GatewayFixture {
    let temp = tempfile::TempDir::new().expect("fixture root");
    // macOS temp roots are symlinks; the store paths must be one spelling.
    let root = temp
        .path()
        .canonicalize()
        .expect("the fixture root resolves");
    let env_path = root.join("accounts.env");
    std::fs::write(&env_path, format!("{KEY_VAR}={KEY_B64}\n")).expect("write the env file");

    let body = format!(
        "env_files:\n  - {env}\nserver:\n  port: 18493\naccounts:\n  schema_version: accounts.v1\n  \
         enabled: true\n  deployment: single_process\n  instance_id: {INSTANCE_ID}\n  \
         store_dir: {store}\n  authority_dir: {authority}\n  current_key_id: current\n  keys:\n    \
         current: env:{KEY_VAR}\n  descriptors:\n    {ACCOUNT_ID}:\n      mode: personal_managed\n      \
         provider: wire-fixture\n      resource: https://api.wire-fixture.example/v1\n      \
         issuer: {origin}\n      authorization_endpoint: {origin}/authorize\n      \
         token_endpoint: {origin}/token\n      client_id: {CLIENT_ID}\n      \
         redirect_uri: https://callback.wire-fixture.example/oauth\n      scopes:\n        - \
         https://api.wire-fixture.example/scope.readonly\n      send_resource_parameter: false\n  \
         limits:\n    store_entries: 10000\n    authority_bytes: 16777216\n",
        env = env_path.display(),
        store = root.join("store").display(),
        authority = root.join("authority").display(),
    );
    let config_path = root.join("config.yaml");
    std::fs::write(&config_path, body).expect("write the fixture config");

    GatewayFixture {
        _root: temp,
        root,
        config_path,
    }
}

fn evaluated(config_path: &Path) -> (crate::config::Config, Arc<crate::config::LiveEnv>) {
    let evaluated = crate::config::Config::load_evaluated(Some(config_path))
        .expect("the fixture config evaluates");
    (
        evaluated.config,
        Arc::new(crate::config::LiveEnv::new(
            evaluated.overlay,
            evaluated.env_paths,
        )),
    )
}

/// The store this fixture's config names, opened for real: two exclusive file
/// locks, taken by this test. Its SUCCESS is the "nobody else owns it" witness
/// and its failure is the "somebody does" one — the same production call the
/// gateway's own startup makes, so neither answer can be a fixture artefact.
fn open_store(
    gw: &GatewayFixture,
) -> Result<crate::personal_accounts::PersonalAccountStore, crate::personal_accounts::AccountError>
{
    crate::personal_accounts::PersonalAccountStore::open(gw.store_config())
}

// ── 6. Startup awaits metadata BEFORE it owns the store ──────────────────────

/// AC: a Gateway with a managed descriptor is still holding NOTHING at a moment
/// provably inside its issuer-metadata fetch, and owns both store locks only
/// once that fetch has been answered and accepted.
///
/// Runs through the production constructor with the production transport TYPE —
/// the only injection is the test CA and the name override carried by the same
/// `GatewayProviderHttp` production builds (seam S4, one shared body).
///
/// FALSIFIER: an implementation that opened the store before fetching metadata
/// fails at `NAMED CHECKPOINT` below, because the parked fetch would then happen
/// with both file locks already held and this test's own open would be refused.
/// The r1 version of this test could not fail that way: it looked at the locks
/// after the flow had ended, when a store opened first and dropped on failure
/// looks identical to a store never opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_startup_awaits_metadata_before_it_owns_the_store() {
    let served = Arc::new(Mutex::new(String::new()));
    let (fixture, mut pause) = Fixture::start_paused({
        let served = Arc::clone(&served);
        responder(move |_| json_200(&served.lock().expect("served metadata").clone()))
    })
    .await;
    let origin = fixture.origin();
    *served.lock().expect("served metadata") = metadata(&origin, &origin);
    let gw = gateway_fixture(&origin);

    // The store exists before startup: `start_account_custody` opens, it never
    // initializes, and a missing store would refuse for the wrong reason.
    drop(
        crate::personal_accounts::PersonalAccountStore::initialize(gw.store_config())
            .expect("the fixture store initializes offline"),
    );

    let (config, env) = evaluated(&gw.config_path);
    let client = trusting_client(&fixture);
    let config_path = gw.config_path.clone();
    // Spawned so this test can act WHILE the constructor is suspended. Awaiting
    // it here instead would make every observation below post-hoc, which is the
    // r1 defect.
    let starting = tokio::spawn(async move {
        crate::gateway::Gateway::new_evaluated_with_account_http(
            config,
            env,
            Some(config_path),
            client,
        )
        .await
    });

    // ── Barrier: the startup is suspended inside a recorded metadata fetch. ──
    let parked = pause.wait_entered().await;
    assert_eq!(parked.method, "GET");
    assert!(
        parked.target.starts_with("/.well-known/"),
        "the parked request is the discovery fetch itself, got {}",
        parked.target
    );
    assert!(
        parked.header("authorization").is_none(),
        "discovery is an unauthenticated GET: no secret is read before a document is accepted"
    );

    // ── NAMED CHECKPOINT: unanswered fetch, unowned store. ──
    // The fixture has announced this request and has NOT answered it, so the
    // constructor cannot be past it. The store's two exclusive locks are free at
    // that instant, which a startup that opened the store first cannot produce.
    let witness = open_store(&gw).expect(
        "NAMED CHECKPOINT: while startup is suspended inside the metadata fetch the store must be \
         unowned — a store-before-fetch implementation fails HERE",
    );
    // Released BEFORE the response, so the startup never contends with this
    // test's own lock and the success half cannot fail for the test's reason.
    drop(witness);
    pause.release();

    let gateway = timeout(STARTUP_TIMEOUT, starting)
        .await
        .expect("the released constructor finished within the bound")
        .expect("the startup task did not panic")
        .expect("acceptable metadata over real TLS starts custody");
    assert!(
        gateway.account_custody().is_some(),
        "a started gateway attaches exactly one custody handle"
    );

    let fetched = fixture.requests();
    let discovery: BTreeSet<&str> = fetched.iter().map(|r| r.target.as_str()).collect();
    assert!(
        discovery.contains("/.well-known/oauth-authorization-server"),
        "the RFC 8414 location is tried first, got {discovery:?}"
    );
    assert!(
        fetched
            .iter()
            .all(|r| r.method == "GET" && r.header("authorization").is_none()),
        "every discovery request is an unauthenticated GET"
    );

    // ── And now it DOES own the store. ──
    assert_eq!(
        open_store(&gw)
            .err()
            .expect("a second owner must not open the store the gateway holds"),
        crate::personal_accounts::AccountError::StorageUnavailable,
        "the constructor returned only after both exclusive locks were taken"
    );
    gateway
        .shutdown_account_custody()
        .await
        .expect("explicit account shutdown releases the store");
    drop(open_store(&gw).expect("shutdown freed both file locks"));
    assert!(
        std::env::var(KEY_VAR).is_err(),
        "the key travelled through the env overlay; the process environment is untouched"
    );

    fixture.stop().await;
}

/// AC: a descriptor whose issuer metadata binds a DIFFERENT issuer refuses
/// startup, and refuses it about a document that really arrived over TLS.
///
/// SCOPE, STATED SO IT IS NOT MISREAD: this test proves a policy refusal on real
/// bytes. It asserts NOTHING about ordering. Free locks after a failed startup
/// are equally consistent with a store that was opened and dropped, which is why
/// the ordering claim lives in the barrier test above and only there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_startup_refuses_metadata_that_binds_another_issuer() {
    let served = Arc::new(Mutex::new(String::new()));
    let fixture = Fixture::start({
        let served = Arc::clone(&served);
        responder(move |_| json_200(&served.lock().expect("served metadata").clone()))
    })
    .await;
    let origin = fixture.origin();
    *served.lock().expect("served metadata") =
        metadata(&origin, "https://issuer-that-was-not-configured.example");
    let gw = gateway_fixture(&origin);
    drop(
        crate::personal_accounts::PersonalAccountStore::initialize(gw.store_config())
            .expect("the fixture store initializes offline"),
    );

    let (config, env) = evaluated(&gw.config_path);
    let refusal = crate::gateway::Gateway::new_evaluated_with_account_http(
        config,
        env,
        Some(gw.config_path.clone()),
        trusting_client(&fixture),
    )
    .await;
    assert!(
        refusal.is_err(),
        "a metadata document binding another issuer must refuse startup, not be accepted"
    );
    assert!(
        !fixture.requests().is_empty(),
        "the refusal is a POLICY refusal about a document that was really fetched"
    );

    fixture.stop().await;
}
