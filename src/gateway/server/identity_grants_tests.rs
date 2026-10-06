// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup grant audit through the real startup helpers (MIK-7570.AUDIT.4,
//! cells T3, T4c, T5a, T5b, T6c, T9, T12, T13).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::super::{Gateway, build_control_plane_store, control_plane_base};
use super::{start_identity_grant_audit, stdio_identity_grants};
use crate::config::Config;
use crate::control_plane::store::AuditFilter;
use crate::control_plane::{ControlPlaneStore, GrantChangeVerb as V};
use crate::identity_grants::journal::{GrantChange, JournalVerb, apply_change, grant_digest};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile,
    write_identity_grants_file,
};

const TOKEN: &str = "grant-audit-start-token-0123456789abcdef";

fn row(grant_id: &str, reason: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("api_key".to_string(), "alice".to_string(), None),
        agent: GrantAgent::Any,
        capability: "cap".to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "p".to_string(),
        reason: reason.to_string(),
    }
}

fn add(new: IdentityGrant) -> GrantChange {
    Box::new(move |file: &mut IdentityGrantFile| {
        let id = new.grant_id.clone();
        file.grants.push(new);
        Ok((JournalVerb::Add, id))
    })
}

fn grants_path(dir: &Path) -> PathBuf {
    dir.join("grants.yaml")
}

fn store_dir(dir: &Path) -> PathBuf {
    dir.join("control-plane")
}

/// Auth and grants on, an explicit governance store under `dir`.
fn config(dir: &Path, auth: bool) -> Config {
    let mut config = Config::default();
    config.auth.enabled = auth;
    config.auth.bearer_token = Some(TOKEN.to_string());
    config.security.transparency_log.enabled = true;
    config.security.transparency_log.path = dir.join("audit.jsonl").to_string_lossy().into_owned();
    config.control_plane.store_dir = Some(store_dir(dir).to_string_lossy().into_owned());
    // The task store under the test's own directory, never the default under $HOME.
    config.tasks.store_dir = dir.join("tasks").to_string_lossy().into_owned();
    config.security.identity_grants.enabled = true;
    config.security.identity_grants.path = grants_path(dir).to_string_lossy().into_owned();
    config
}

/// One startup up to serving: load, open the store, run the grant audit.
struct Started {
    store: Option<Arc<dyn ControlPlaneStore>>,
    sink: Option<Arc<crate::config_reload::IdentityGrantSink>>,
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
}

impl Started {
    async fn run(config: Config) -> crate::Result<Self> {
        let base = control_plane_base(&config, None);
        let gateway = Gateway::new(config.clone()).await.expect("valid config");
        let meta = gateway.build_meta_mcp().await?.meta_mcp;
        let store = build_control_plane_store(&config, &base)?;
        let sink = start_identity_grant_audit(&config, &meta, store.as_ref(), &base.path).await?;
        Ok(Self { store, sink, meta })
    }

    /// `(verb, target)` of every grant record, oldest first.
    fn records(&self) -> Vec<(V, String)> {
        let store = self.store.as_ref().expect("a store is open");
        let mut events = store.read_audit(&AuditFilter::new(10_000)).unwrap().events;
        events.reverse();
        events
            .into_iter()
            .filter_map(|e| e.grant_change.map(|c| (c.verb, e.target_id)))
            .collect()
    }

    fn served(&self) -> Vec<IdentityGrant> {
        let (store, _) = self.meta.identity_grant_sink();
        store.read().values().cloned().collect()
    }
}

/// T3a: 2 active, 1 revoked, 1 expired: two `loaded`, then the closing
/// record with count 2; the served rows are the loaded ones (T13's base).
#[tokio::test]
async fn t3a_startup_snapshot_records_the_active_grants() {
    let dir = tempfile::tempdir().unwrap();
    let mut expired = row("g3", "r");
    expired.expires_at = Some("2001-01-01T00:00:00Z".parse().unwrap());
    let mut revoked = row("g4", "r");
    revoked.revoked_at = Some("2001-01-01T00:00:00Z".parse().unwrap());
    for r in [row("g1", "r"), row("g2", "r"), expired, revoked] {
        apply_change(&grants_path(dir.path()), true, add(r))
            .await
            .unwrap();
    }
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    let got = s.records();
    let snapshot: Vec<_> = got.iter().filter(|r| r.0 == V::Loaded).cloned().collect();
    assert_eq!(
        snapshot,
        vec![(V::Loaded, "g1".into()), (V::Loaded, "g2".into())]
    );
    assert_eq!(got.last().map(|r| r.0), Some(V::LoadedComplete), "{got:?}");
    assert_eq!(got.iter().filter(|r| r.0 == V::Add).count(), 4, "{got:?}");
}

/// T3b: zero grants still writes the closing record, count 0.
#[tokio::test]
async fn t3b_empty_grant_file_writes_a_zero_count() {
    let dir = tempfile::tempdir().unwrap();
    write_identity_grants_file(
        &grants_path(dir.path()),
        &IdentityGrantFile::new(Vec::new()),
    )
    .await
    .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    let store = s.store.as_ref().unwrap();
    let events = store.read_audit(&AuditFilter::new(10)).unwrap().events;
    let closing = events[0].grant_change.clone().expect("closing record");
    assert_eq!(closing.verb, V::LoadedComplete);
    assert_eq!(closing.count, Some(0));
}

/// T4c: an edit made while the gateway was stopped is recorded out-of-band
/// by the next startup, before its snapshot.
#[tokio::test]
async fn t4c_edit_while_stopped_is_out_of_band_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    drop(
        Box::pin(Started::run(config(dir.path(), true)))
            .await
            .unwrap(),
    );
    let edited = row("g1", "edited");
    write_identity_grants_file(
        &grants_path(dir.path()),
        &IdentityGrantFile::new(vec![edited.clone()]),
    )
    .await
    .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    let got = s.records();
    let oob = got.iter().position(|r| *r == (V::OutOfBand, "g1".into()));
    let last_start = got.iter().rposition(|r| r.0 == V::Loaded);
    assert!(oob.is_some() && oob < last_start, "{got:?}");
    assert_eq!(s.served(), vec![edited]);
}

/// T5a: auth on, grants on, and the default store cannot open: HTTP and
/// stdio both refuse to start, naming the governance audit log.
#[tokio::test]
async fn t5a_no_store_refuses_start_with_auth_and_grants() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let blocker = dir.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();
    let mut config = config(dir.path(), true);
    config.control_plane.store_dir = None;
    // The default base is `<config dir>/<stem>-control-plane`, under a file.
    let config_path = blocker.join("gateway.yaml");
    let base = control_plane_base(&config, Some(&config_path));

    let http = build_control_plane_store(&config, &base).map(|s| s.is_some());
    let err = http
        .expect_err("HTTP: started with grants unaudited")
        .to_string();
    assert!(err.contains("governance audit log"), "{err}");

    let gateway = Gateway::new(config.clone()).await.unwrap();
    let meta = gateway.build_meta_mcp().await.unwrap().meta_mcp;
    let stdio = stdio_identity_grants(&config, Some(&config_path), &meta).await;
    let err = stdio
        .map(|s| s.is_some())
        .expect_err("stdio: started unaudited")
        .to_string();
    assert!(err.contains("governance audit log"), "{err}");
}

/// T5b (control): auth off builds no store, no auditor and no state file.
#[tokio::test]
async fn t5b_auth_off_has_no_store_and_no_auditor() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), false)))
        .await
        .unwrap();
    assert!(s.store.is_none());
    assert!(!s.sink.as_ref().expect("grants on").has_auditor());
    assert!(
        !store_dir(dir.path())
            .join("grant-journal-state.json")
            .exists()
    );
    assert_eq!(s.served().len(), 1, "auth off still serves the grant file");
}

/// T9: the sink the startup helper builds carries an auditor.
#[tokio::test]
async fn t9_startup_sink_carries_an_auditor() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    assert!(s.sink.as_ref().expect("grants on").has_auditor());
}

/// T6c: a plan write that fails at startup serves no grants and writes no
/// snapshot.
#[tokio::test]
async fn t6c_unwritable_plan_at_startup_serves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    std::fs::create_dir_all(
        store_dir(dir.path())
            .join("grant-journal-state.json")
            .join("x"),
    )
    .unwrap();
    let s = Box::pin(Started::run(config(dir.path(), true)))
        .await
        .unwrap();
    assert!(s.served().is_empty(), "{:?}", s.served());
    assert!(!s.records().iter().any(|r| r.0 == V::LoadedComplete));
}

/// T13: the file changed between the initial load and the locked read: the
/// served rows are the `loaded` rows.
#[tokio::test]
async fn t13_served_rows_equal_the_loaded_rows() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let config = config(dir.path(), true);
    let base = control_plane_base(&config, None);
    let gateway = Gateway::new(config.clone()).await.unwrap();
    let meta = gateway.build_meta_mcp().await.unwrap().meta_mcp;
    let later = row("g2", "r");
    apply_change(&grants_path(dir.path()), true, add(later.clone()))
        .await
        .unwrap();
    let store = build_control_plane_store(&config, &base).unwrap();
    start_identity_grant_audit(&config, &meta, store.as_ref(), &base.path)
        .await
        .unwrap();
    let s = Started {
        store,
        sink: None,
        meta,
    };
    let loaded: Vec<String> = s
        .records()
        .into_iter()
        .filter(|r| r.0 == V::Loaded)
        .map(|r| r.1)
        .collect();
    let served: Vec<String> = s.served().into_iter().map(|g| g.grant_id).collect();
    assert_eq!(loaded, served);
    assert_eq!(served, vec!["g1".to_string(), "g2".to_string()]);
    let digest = grant_digest(&later);
    assert!(s.served().iter().any(|g| grant_digest(g) == digest));
}

fn governance_log(dir: &Path) -> String {
    std::fs::read_to_string(store_dir(dir).join("audit.jsonl")).unwrap_or_default()
}

/// T12 (HTTP): by the time the listener answers, the snapshot's closing
/// record is in the governance log.
#[tokio::test]
async fn t12_http_snapshot_precedes_the_listener() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let mut config = config(dir.path(), true);
    config.server.host = "127.0.0.1".to_string();
    // Port 0: the gateway reports the port it bound (MIK-7984).
    config.server.port = 0;
    config.tasks.store_dir = dir.path().join("tasks").to_string_lossy().into_owned();
    let mut gateway = Gateway::new(config)
        .await
        .unwrap()
        .with_data_dir(dir.path().to_path_buf());
    let bound = gateway.bound_port_for_test();
    let server = tokio::spawn(async move { Box::pin(gateway.run()).await });
    let up = tokio::time::timeout(Duration::from_secs(60), async {
        // A run that ends before binding drops the sender; `ended` reports it.
        let Ok(port) = bound.await else { return };
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
            && !server.is_finished()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let log = governance_log(dir.path());
    server.abort();
    // Only the abort may end it: a panic or a returned run is a failure.
    let ended = server.await;
    assert!(
        up.is_ok()
            && ended
                .as_ref()
                .is_err_and(tokio::task::JoinError::is_cancelled),
        "the HTTP gateway never bound: {ended:?}"
    );
    assert!(log.contains("loaded_complete"), "{log}");
}

/// T12 (stdio): the first response comes after the snapshot is logged.
#[tokio::test]
async fn t12_stdio_snapshot_precedes_the_first_response() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let gateway = Gateway::new(config(dir.path(), true))
        .await
        .unwrap()
        .with_data_dir(dir.path().to_path_buf());
    let (mut client, input) = tokio::io::duplex(64 * 1024);
    let (output, reader) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(async move { drop(gateway.run_stdio_on(input, output, None).await) });
    let init = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "grant-audit", "version": "0"}},
    });
    client
        .write_all(format!("{init}\n").as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    let mut reader = tokio::io::BufReader::new(reader);
    let read = tokio::time::timeout(Duration::from_secs(60), reader.read_line(&mut line)).await;
    let log = governance_log(dir.path());
    task.abort();
    drop(task.await);
    assert!(matches!(read, Ok(Ok(n)) if n > 0), "no initialize response");
    assert!(log.contains("loaded_complete"), "{log}");
}

/// T3c + T3d through the startup helper: a failed `loaded` or closing append
/// serves no grants.
#[tokio::test]
async fn t3cd_failed_snapshot_append_serves_nothing() {
    use std::sync::atomic::Ordering;
    // Two grants: appends 1-2 record the adds, 3-4 the `loaded`, 5 the close.
    for fail_at in [3, 5] {
        let dir = tempfile::tempdir().unwrap();
        for id in ["g1", "g2"] {
            apply_change(&grants_path(dir.path()), true, add(row(id, "r")))
                .await
                .unwrap();
        }
        let config = config(dir.path(), true);
        let gateway = Gateway::new(config.clone()).await.unwrap();
        let meta = Box::pin(gateway.build_meta_mcp()).await.unwrap().meta_mcp;
        let flaky = Arc::new(crate::config_reload::grant_audit_tests::FlakyStore::default());
        flaky.fail_from.store(fail_at, Ordering::SeqCst);
        let store: Arc<dyn ControlPlaneStore> = flaky.clone();
        std::fs::create_dir_all(store_dir(dir.path())).unwrap();
        let sink = start_identity_grant_audit(&config, &meta, Some(&store), &store_dir(dir.path()))
            .await
            .unwrap();
        let (live, _) = meta.identity_grant_sink();
        assert!(live.read().values().next().is_none(), "fail_at={fail_at}");
        // The refusal holds for the whole run: a later reload must not serve
        // rows that no snapshot recorded, even once the store works again.
        flaky.fail_from.store(0, Ordering::SeqCst);
        let ctx = crate::config_reload::ReloadContext::new(
            grants_path(dir.path()),
            Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(300),
        )
        .expect("the registry pairs with the config")
        .with_identity_grant_sink_opt(sink);
        let _ = ctx.reload_identity_grants().await;
        assert!(
            live.read().values().next().is_none(),
            "a reload after the failed snapshot served grants, fail_at={fail_at}"
        );
        assert!(
            !flaky.events().iter().any(|e| e
                .grant_change
                .as_ref()
                .is_some_and(|c| c.verb == V::LoadedComplete)),
            "fail_at={fail_at}"
        );
    }
}

/// `fail_on_error: false` tolerates a missing grant file at startup: the run
/// serves nothing but keeps its audited reload sink, so creating the file
/// later is picked up by a reload.
#[tokio::test]
async fn a_tolerated_missing_grant_file_still_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path(), true);
    config.security.identity_grants.fail_on_error = false;
    let s = Box::pin(Started::run(config.clone())).await.unwrap();
    let (live, _) = s.meta.identity_grant_sink();
    assert!(live.read().values().next().is_none());
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();

    let ctx = crate::config_reload::ReloadContext::new(
        grants_path(dir.path()),
        Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    )
    .expect("the registry pairs with the config")
    .with_identity_grant_sink_opt(s.sink.clone());
    let _ = ctx.reload_identity_grants().await;

    assert!(
        live.read().values().next().is_some(),
        "a reload after a tolerated startup read error served nothing"
    );
}

/// A reload with this run's grant sink, as the watcher and meta-tool run it.
async fn reload_with(config: &Config, sink: Option<Arc<crate::config_reload::IdentityGrantSink>>) {
    let ctx = crate::config_reload::ReloadContext::new(
        PathBuf::from(&config.security.identity_grants.path),
        Arc::new(crate::config_reload::LiveConfig::new(config.clone())),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    )
    .expect("the registry pairs with the config")
    .with_identity_grant_sink_opt(sink);
    let _ = ctx.reload_identity_grants().await;
}

/// The empty set served after a tolerated startup read error is the
/// baseline: a grant file then written directly (not through the CLI) reads
/// as `out_of_band` on the next reload.
#[tokio::test]
async fn a_direct_repair_after_a_tolerated_read_is_out_of_band() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = config(dir.path(), true);
    config.security.identity_grants.fail_on_error = false;
    let s = Box::pin(Started::run(config.clone())).await.unwrap();
    write_identity_grants_file(
        &grants_path(dir.path()),
        &IdentityGrantFile::new(vec![row("g1", "r")]),
    )
    .await
    .unwrap();

    reload_with(&config, s.sink.clone()).await;

    assert!(
        s.records().contains(&(V::OutOfBand, "g1".into())),
        "a direct repair was not recorded as out_of_band: {:?}",
        s.records()
    );
}

/// `fail_on_error: true` also governs the audited startup read: a grant file
/// that breaks after the first load refuses the start.
#[tokio::test]
async fn fail_on_error_applies_to_the_audited_startup_read() {
    let dir = tempfile::tempdir().unwrap();
    apply_change(&grants_path(dir.path()), true, add(row("g1", "r")))
        .await
        .unwrap();
    let mut config = config(dir.path(), true);
    config.security.identity_grants.fail_on_error = true;
    let base = control_plane_base(&config, None);
    let gateway = Gateway::new(config.clone()).await.unwrap();
    let meta = Box::pin(gateway.build_meta_mcp()).await.unwrap().meta_mcp;
    std::fs::write(grants_path(dir.path()), "not: [valid").unwrap();
    let store = build_control_plane_store(&config, &base).unwrap();

    let started = start_identity_grant_audit(&config, &meta, store.as_ref(), &base.path).await;

    assert!(started.is_err(), "the start was not refused");
}

/// A directory this process cannot write does not prove there is no writer
/// (root or the file's owner can still run the CLI there), so the grant file
/// is never read without the lock: with `fail_on_error` the start is refused.
#[tokio::test]
async fn an_unwritable_grant_directory_is_not_read_without_the_lock() {
    #[cfg(unix)]
    if rustix::process::geteuid().is_root() {
        return; // root ignores directory modes
    }
    let dir = tempfile::tempdir().unwrap();
    let ro = dir.path().join("ro");
    std::fs::create_dir(&ro).unwrap();
    let grants = ro.join("grants.yaml");
    write_identity_grants_file(&grants, &IdentityGrantFile::new(vec![row("g1", "r")]))
        .await
        .unwrap();
    // Unix takes the write mode away; Windows denies the user write and append (DACL).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    #[cfg(windows)]
    crate::private_fs::test_support::deny_user("ro-grant-dir", &ro, "WD,AD");
    let mut config = config(dir.path(), true);
    config.security.identity_grants.path = grants.to_string_lossy().into_owned();
    config.security.identity_grants.fail_on_error = true;

    let s = Box::pin(Started::run(config)).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    crate::private_fs::test_support::remove_deny("ro-grant-dir", &ro);

    assert!(
        s.is_err(),
        "a grant file was read without the journal lock in an unwritable directory"
    );
}

/// A grant directory that does not exist yet is an unreadable grant file:
/// with `fail_on_error: false` the start keeps its audited sink, and the file
/// created later is served by the next reload.
#[tokio::test]
async fn a_missing_grant_directory_still_reloads_later() {
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("later").join("grants.yaml");
    let mut config = config(dir.path(), true);
    config.security.identity_grants.path = grants.to_string_lossy().into_owned();
    config.security.identity_grants.fail_on_error = false;
    let s = Box::pin(Started::run(config.clone())).await.unwrap();
    apply_change(&grants, true, add(row("g1", "r")))
        .await
        .unwrap();

    reload_with(&config, s.sink.clone()).await;

    let (live, _) = s.meta.identity_grant_sink();
    assert!(
        live.read().values().any(|g| g.grant_id == "g1"),
        "a grant directory missing at startup disabled later reloads"
    );
}

/// The first audited start with an unreadable journal still keeps a
/// baseline: a grant later written directly into the file is recorded.
#[tokio::test]
async fn a_first_start_with_an_unreadable_journal_keeps_a_baseline() {
    let dir = tempfile::tempdir().unwrap();
    let path = grants_path(dir.path());
    write_identity_grants_file(&path, &IdentityGrantFile::new(vec![row("g1", "r")]))
        .await
        .unwrap();
    let journal = crate::identity_grants::journal::journal_path(&path);
    std::fs::write(&journal, b"").unwrap();
    // A journal anyone may write is not one the gateway trusts: mode 0666 on
    // Unix, an Everyone full-control DACL on Windows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    #[cfg(windows)]
    {
        let user = crate::private_fs::test_support::user_sid();
        crate::private_fs::test_support::plant_any(
            "open-journal",
            &journal,
            &format!("O:{user}D:(A;;FA;;;WD)"),
        );
    }
    let config = config(dir.path(), true);
    let s = Box::pin(Started::run(config.clone())).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    crate::private_fs::test_support::plant_owner_only("open-journal", &journal);
    write_identity_grants_file(
        &path,
        &IdentityGrantFile::new(vec![row("g1", "r"), row("g2", "r")]),
    )
    .await
    .unwrap();

    reload_with(&config, s.sink.clone()).await;

    assert!(
        s.records()
            .iter()
            .any(|r| r.1 == "g2" && matches!(r.0, V::OutOfBand | V::Indeterminate)),
        "a direct edit after an unreadable first journal went unrecorded: {:?}",
        s.records()
    );
}
