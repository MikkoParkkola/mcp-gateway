// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L3 and H2. Expected ids are `config_revision` over a literal part.
//! Nothing here calls attach or publish itself, and nothing sleeps.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::Gateway;
use super::warmstart::{WarmStartMode, WarmerGuard};
use crate::capability::{CapabilityBackend, CapabilityExecutor, CapabilityWatcher};
use crate::config::Config;
use crate::config_reload::LiveConfig;
use crate::config_reload::refusals::ReloadReporting;
use crate::config_reload::revision::{
    AppliedInputs, CapabilityPart, PartDigest, RawInputs, config_revision, part_digest,
};
use crate::gateway::webhooks::WebhookRegistry;

/// A row's look at one delivery, copied into the backend a startup builds.
type Observer = Arc<dyn Fn(&CapabilityBackend) + Send + Sync>;

fn yaml_bytes(name: &str) -> Vec<u8> {
    format!(
        "name: {name}\ndescription: served\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://example.com\n      path: /{name}\n"
    )
    .into_bytes()
}

fn write_good(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(format!("{name}.yaml")), bytes).expect("the capability file writes");
}

fn root_of(dir: &Path) -> String {
    dir.to_str().expect("the temp path is utf-8").to_owned()
}

/// The id of `part` alone, under the process record key. The part is a
/// literal; the key is the one startup installs, not a digest read back
/// from the catalogue.
fn id_of(key: &[u8; 32], part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        key,
        &AppliedInputs {
            capabilities: part.clone(),
            ..AppliedInputs::default()
        },
    )
}

/// The gateway.yaml bytes the attached `LiveConfig` started from; any fixed
/// bytes do, the rows compare ids built over the same ones.
const YAML: &[u8] = b"server:\n  port: 1\n";

/// A `LiveConfig` with the process's revision key and a startup revision whose
/// capability part is not loaded, as a real startup builds one: a delivery
/// into it changes its published revision.
fn keyed_live(config: &Config, key: [u8; 32]) -> Arc<LiveConfig> {
    Arc::new(
        LiveConfig::new(config.clone())
            .with_revision_key(key)
            .with_applied(RawInputs {
                gateway_yaml: YAML.to_vec(),
                capabilities: CapabilityPart::NotLoaded,
                ..RawInputs::default()
            }),
    )
}

/// The id that `LiveConfig` publishes once `part` reaches it.
fn live_id(key: &[u8; 32], part: &CapabilityPart<PartDigest>) -> String {
    config_revision(
        key,
        &AppliedInputs {
            gateway_yaml: part_digest(key, YAML),
            capabilities: part.clone(),
            ..AppliedInputs::default()
        },
    )
}

fn loaded(key: &[u8; 32], path: &str, bytes: &[u8]) -> CapabilityPart<PartDigest> {
    CapabilityPart::Loaded(vec![(path.to_string(), part_digest(key, bytes))])
}

fn revision_key_of_process() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

struct Started {
    backend: Arc<CapabilityBackend>,
    live: Arc<LiveConfig>,
    key: [u8; 32],
    _shutdown: tokio::sync::broadcast::Sender<()>,
    _watcher: Option<CapabilityWatcher>,
}

fn bind_one_shared_account(gateway: &mut Gateway) {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use crate::personal_accounts::config::{
        AccountDescriptor, AccountsConfig, AccountsLimits, DescriptorMode,
    };

    // `enabled` and a non-empty descriptor list is what makes the HTTP scan
    // run inline, before `start_capability_watcher` returns. `Shared` needs
    // no store, so this does not open one.
    gateway.config.accounts = Some(AccountsConfig {
        adapters: Vec::new(),
        hosted: None,
        schema_version: "accounts.v1".to_string(),
        enabled: true,
        deployment: "single_process".to_string(),
        instance_id: "capability-publish-tests".to_string(),
        store_dir: PathBuf::from("/synthetic/fixture/accounts/records"),
        authority_dir: PathBuf::from("/synthetic/fixture/accounts/authority"),
        current_key_id: "current".to_string(),
        keys: BTreeMap::from([(
            "current".to_string(),
            "env:FIXTURE_ACCOUNT_STORE_KEY".to_string(),
        )]),
        descriptors: Some(
            [(
                "shared".to_string(),
                AccountDescriptor {
                    mode: DescriptorMode::Shared,
                    provider: "fixture".to_string(),
                    resource: None,
                    issuer: None,
                    authorization_endpoint: None,
                    token_endpoint: None,
                    revocation_endpoint: None,
                    client_id: None,
                    client_secret_ref: None,
                    redirect_uri: None,
                    scopes: None,
                    send_resource_parameter: None,
                    external_strategy: None,
                    authorize_extra: None,
                },
            )]
            .into_iter()
            .collect(),
        ),
        limits: AccountsLimits::default(),
    });
}

async fn start_http(dirs: &[PathBuf], account_bound: bool, observer: Option<Observer>) -> Started {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = dirs.iter().map(|dir| dir.display().to_string()).collect();
    let mut gateway = Gateway::new(config).await.expect("the gateway builds");
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("the meta-mcp builds")
        .meta_mcp;
    if account_bound {
        bind_one_shared_account(&mut gateway);
    }
    if let Some(observer) = observer {
        // Copied into the backend `start_capability_watcher` constructs,
        // which happens before that call's first await.
        CapabilityBackend::install_next_delivery_observer(observer);
    }
    let webhooks = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        gateway.config.webhooks.clone(),
    )));
    let (shutdown, _) = tokio::sync::broadcast::channel(4);
    let watcher = gateway
        .start_capability_watcher(&meta, &webhooks, &shutdown)
        .await
        .expect("the capability step starts");
    let backend = meta.get_capabilities().expect("the catalogue is installed");
    if account_bound {
        // R22(a): the inline scan has published with nothing attached, so it
        // parked. Its part is held and readiness waits for attach.
        assert_eq!(
            backend.delivered_revisions().len(),
            1,
            "premise: the account-bound scan published before the step returned"
        );
        assert!(
            !backend.initial_scan_complete(),
            "a parked scan is not ready before attach"
        );
    }
    // As run does after this step, once LiveConfig is built and before the bind.
    let key = meta.record_key().config_revision_key();
    let live = keyed_live(&gateway.config, key);
    backend.attach_revision(Arc::clone(&live));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !backend.initial_scan_complete() {
        assert!(tokio::time::Instant::now() < deadline, "hung past 30s");
        tokio::task::yield_now().await;
    }
    Started {
        backend,
        live,
        key,
        _shutdown: shutdown,
        _watcher: watcher,
    }
}

async fn start_stdio(
    dir: &str,
    observer: Option<Observer>,
) -> (Arc<CapabilityBackend>, [u8; 32], Arc<LiveConfig>) {
    let mut config = Config::default();
    config.capabilities.enabled = true;
    config.capabilities.directories = vec![dir.to_string()];
    let gateway = Gateway::new(config).await.expect("the gateway builds");
    let meta = gateway
        .build_meta_mcp()
        .await
        .expect("the meta-mcp builds")
        .meta_mcp;
    if let Some(observer) = observer {
        CapabilityBackend::install_next_delivery_observer(observer);
    }
    let warmer = WarmerGuard::new(&gateway.backends, WarmStartMode::Stdio, None);
    let key = meta.record_key().config_revision_key();
    let live = keyed_live(&gateway.config, key);
    match tokio::time::timeout(
        Duration::from_secs(30),
        gateway.install_stdio_startup_catalogue(
            &meta,
            &live,
            None,
            &warmer,
            ReloadReporting::default(),
        ),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => panic!("stdio startup refused: {error}"),
        Err(elapsed) => panic!("hung past 30s: {elapsed}"),
    }
    let backend = meta.get_capabilities().expect("the catalogue is installed");
    (backend, key, live)
}

fn watch_delivery() -> (Arc<AtomicBool>, Arc<AtomicBool>, Observer) {
    let ran = Arc::new(AtomicBool::new(false));
    let lock_free = Arc::new(AtomicBool::new(false));
    let (ran_flag, free_flag) = (Arc::clone(&ran), Arc::clone(&lock_free));
    let observer = Arc::new(move |backend: &CapabilityBackend| {
        // Inside the delivery, not after it returned: a lock taken for the
        // publish and dropped before this runs would hide the fault.
        free_flag.store(backend.catalogue_write_free(), Ordering::SeqCst);
        ran_flag.store(true, Ordering::SeqCst);
    });
    (ran, lock_free, observer)
}

fn covered(
    backend: &CapabilityBackend,
    live: &LiveConfig,
    key: &[u8; 32],
    path: &str,
    bytes: &[u8],
    startup: &str,
) {
    // The running configuration itself, not only the handoff's record: its
    // published revision is the one over the loaded file.
    assert_eq!(
        live.applied_now()
            .published
            .expect("a revision is published")
            .revision
            .clone(),
        live_id(key, &loaded(key, path, bytes)),
        "{startup}: the LiveConfig publishes the covered revision"
    );
    assert_eq!(
        backend
            .delivered_revisions()
            .iter()
            .map(|(_, part)| id_of(key, part))
            .collect::<Vec<_>>(),
        vec![id_of(key, &loaded(key, path, bytes))],
        "{startup} reaches a covered part, with no extra call"
    );
    assert!(
        backend.initial_scan_complete(),
        "{startup}: readiness is true"
    );
    assert_eq!(
        backend.scan_completions(),
        1,
        "{startup}: readiness turned true exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_account_bound_http_startup_reaches_a_covered_part() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bytes = yaml_bytes("alpha");
    write_good(dir.path(), "alpha", &bytes);
    let root = root_of(dir.path());
    let started = Box::pin(start_http(&[dir.path().to_path_buf()], true, None)).await;
    covered(
        &started.backend,
        &started.live,
        &started.key,
        &format!("{root}/alpha.yaml"),
        &bytes,
        "account-bound HTTP",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_background_http_startup_reaches_a_covered_part() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bytes = yaml_bytes("alpha");
    write_good(dir.path(), "alpha", &bytes);
    let root = root_of(dir.path());
    let started = Box::pin(start_http(&[dir.path().to_path_buf()], false, None)).await;
    covered(
        &started.backend,
        &started.live,
        &started.key,
        &format!("{root}/alpha.yaml"),
        &bytes,
        "background HTTP",
    );
}

/// S1 at the publish point: an HTTP startup over two directories delivers
/// once, after both are loaded, a part naming both files. A publish per
/// directory would deliver twice, or deliver a part naming only the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s1_a_two_directory_startup_delivers_one_part_naming_both() {
    let (first, second) = (
        tempfile::tempdir().expect("a temp dir"),
        tempfile::tempdir().expect("a temp dir"),
    );
    let (alpha, beta) = (yaml_bytes("alpha"), yaml_bytes("beta"));
    write_good(first.path(), "alpha", &alpha);
    write_good(second.path(), "beta", &beta);
    let dirs = [first.path().to_path_buf(), second.path().to_path_buf()];
    let started = Box::pin(start_http(&dirs, false, None)).await;
    // The part is sorted by path, and the temp dirs' names order the two.
    let mut files = vec![
        (
            format!("{}/alpha.yaml", root_of(first.path())),
            part_digest(&started.key, &alpha),
        ),
        (
            format!("{}/beta.yaml", root_of(second.path())),
            part_digest(&started.key, &beta),
        ),
    ];
    files.sort();
    let both = CapabilityPart::Loaded(files);
    assert_eq!(
        started
            .backend
            .delivered_revisions()
            .iter()
            .map(|(_, part)| id_of(&started.key, part))
            .collect::<Vec<_>>(),
        vec![id_of(&started.key, &both)],
        "one delivery, naming both directories' files"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_stdio_startup_reaches_a_covered_part() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bytes = yaml_bytes("alpha");
    write_good(dir.path(), "alpha", &bytes);
    let root = root_of(dir.path());
    let (backend, key, live) = Box::pin(start_stdio(&root, None)).await;
    covered(
        &backend,
        &live,
        &key,
        &format!("{root}/alpha.yaml"),
        &bytes,
        "stdio",
    );
}

/// Every publish point delivers with no catalogue lock held. The delivery
/// is asserted first: an absent one fails, and a lock check that never ran
/// does not pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l3_every_publish_point_delivers_with_no_catalogue_lock_held() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bytes = yaml_bytes("alpha");
    write_good(dir.path(), "alpha", &bytes);
    let root = root_of(dir.path());

    let (http_ran, http_free, http_observer) = watch_delivery();
    let _http = Box::pin(start_http(
        &[dir.path().to_path_buf()],
        false,
        Some(http_observer),
    ))
    .await;

    let (stdio_ran, stdio_free, stdio_observer) = watch_delivery();
    let _stdio = Box::pin(start_stdio(&root, Some(stdio_observer))).await;

    let (reload_ran, reload_free, reload_observer) = watch_delivery();
    let backend = Arc::new(
        CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()))
            .with_revision_key(revision_key_of_process()),
    );
    backend.set_delivery_observer(reload_observer);
    let paths = [root.clone()];
    backend.register_directories(&paths);
    match tokio::time::timeout(Duration::from_secs(30), backend.reload()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => panic!("the reload refused: {error}"),
        Err(elapsed) => panic!("hung past 30s: {elapsed}"),
    }

    assert!(
        http_ran.load(Ordering::SeqCst),
        "HTTP scan: a delivery happened"
    );
    assert!(
        http_free.load(Ordering::SeqCst),
        "HTTP scan delivers with no catalogue lock held"
    );
    assert!(
        stdio_ran.load(Ordering::SeqCst),
        "stdio startup: a delivery happened"
    );
    assert!(
        stdio_free.load(Ordering::SeqCst),
        "stdio startup delivers with no catalogue lock held"
    );
    assert!(
        reload_ran.load(Ordering::SeqCst),
        "reload: a delivery happened"
    );
    assert!(
        reload_free.load(Ordering::SeqCst),
        "reload delivers with no catalogue lock held"
    );
}

/// Kills the mutant "the HTTP attach in `Gateway::run` deleted or moved". No
/// row can run `Gateway::run` (it binds a listener), so its position is pinned
/// in the production source: after the meta-mcp takes the `LiveConfig`, before
/// the listener binds, exactly once. Deleted, the scan's held part would never
/// reach the live config and nothing else would fail.
#[test]
fn h2_http_run_attaches_after_live_config_and_before_the_bind() {
    let code = crate::test_source_text::sanitize(&crate::test_source_text::production_text(
        include_str!("run.rs"),
    ));
    let set = code
        .find("meta_mcp.set_live_config(")
        .expect("run gives the meta-mcp its LiveConfig");
    let attach = code
        .find(".attach_revision(Arc::clone(&live_config))")
        .expect("run attaches the capability handoff to that LiveConfig");
    let bind = code
        .find("TcpListener::bind(")
        .expect("run binds its listener");
    assert!(
        set < attach && attach < bind,
        "the attach sits after the LiveConfig is set ({set}) and before the bind ({bind}), at {attach}"
    );
    assert_eq!(
        code.matches(".attach_revision(").count(),
        1,
        "run attaches once"
    );
}

/// Kills the mutant "the startup scan registers webhook routes after its
/// publish". The publish can make the scan ready, so a client that sees
/// readiness must find every capability's webhook route, as before revisions
/// were published. Pinned in the source for the reason the attach is: the
/// order inside one spawned step has no seam a row can hold.
#[test]
fn startup_registers_webhook_routes_before_the_publish_that_can_mark_ready() {
    let code = crate::test_source_text::sanitize(&crate::test_source_text::production_text(
        include_str!("run_steps.rs"),
    ));
    let routes = code
        .find(".register_capability(&cap)")
        .expect("the startup scan registers webhook routes");
    let publish = code
        .find(".publish_initial_scan(")
        .expect("the startup scan publishes its part");
    assert!(
        routes < publish,
        "webhook routes ({routes}) are registered before the publish ({publish})"
    );
    assert_eq!(
        code.matches(".register_capability(&cap)").count(),
        1,
        "one registration site"
    );
}
