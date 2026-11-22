// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The rig every config history route row runs on: gateway.yaml on disk
//! with three keys (the root admin, a viewer, and a CLI key root approved),
//! a live config recording into its own history store, the audit log when
//! the row wants one, a reload context, and requests sent through the whole
//! router so admission, the CLI-key rule and the handlers all take part.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt as _;

use super::super::keys_create_fixture_tests::{ROOT, Setup, item, root_item, yaml_of};
use crate::config_reload::history::{Bounds, ConfigHistory, HistoryHook};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The viewer key's secret: authenticated, not an admin.
pub(super) const VIEWER: &str = "history-viewer-secret";
/// The CLI key's secret: an admin key bound to root's approval.
pub(super) const CLI: &str = "history-cli-secret";
/// The config file's name in the rig's directory.
const CONFIG_FILE: &str = "gateway.yaml";
const AUDIT_FILE: &str = "history-rows-audit.jsonl";

/// Whether the rig's gateway keeps an audit log.
#[derive(Clone, Copy)]
pub(super) enum Audit {
    Logged,
    Unlogged,
}

/// Whether the rig's live config records into a history store.
#[derive(Clone, Copy)]
pub(super) enum History {
    Kept,
    /// No hook, as a gateway with no config file at start.
    Absent,
}

/// Who sends a request.
#[derive(Clone, Copy)]
pub(super) enum Caller<'a> {
    Root,
    Viewer,
    Cli,
    /// A browser session, by its cookie pair.
    Session(&'a str),
    Nobody,
}

/// gateway.yaml with the three keys, then `tail` (top-level lines).
pub(super) fn config_text(tail: &str) -> String {
    // The CLI key names root as its approver: root's quota principal and tag.
    let resolved = crate::gateway::auth::ResolvedAuthConfig::from_config(
        &Setup::default().running,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let approver = resolved
        .validate_token(ROOT)
        .and_then(|client| client.quota_principal)
        .expect("root resolves with a quota principal");
    let bound = format!(
        "      cli_host: bench\n      admin: true\n      approved_by:\n        digest_tag: \"{tag}\"\n        quota_principal: \"{quota}\"\n",
        tag = crate::gateway::auth::secret_tag(ROOT),
        quota = approver.limit_store_key(),
    );
    let keys = [
        root_item(),
        item("viewer", VIEWER, ""),
        item("cli:bench:history", CLI, &bound),
    ];
    format!("{}{tail}", yaml_of(&keys))
}

/// As [`config_text`], but the CLI key is gone: root and the viewer only.
pub(super) fn config_text_without_cli(tail: &str) -> String {
    format!(
        "{}{tail}",
        yaml_of(&[root_item(), item("viewer", VIEWER, "")])
    )
}

/// The `env_files:` block that lists `paths`, for a `config_text` tail.
pub(super) fn env_files(paths: &[&std::path::Path]) -> String {
    use std::fmt::Write as _;
    let mut block = String::from("env_files:\n");
    for path in paths {
        let _ = writeln!(block, "  - '{}'", path.display());
    }
    block
}

/// Write `bytes` owner-only as `name` in `dir`; its path.
pub(super) fn put(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    crate::gateway::test_helpers::write_owner_only(&path, bytes).expect("the file writes");
    path
}

/// One gateway under test.
pub(super) struct Rig {
    pub(super) state: Arc<AppState>,
    pub(super) ctx: Arc<ReloadContext>,
    pub(super) store: Arc<ConfigHistory>,
    pub(super) dir: Arc<tempfile::TempDir>,
    _fixtures: crate::gateway::router::tests::FixtureDir,
}

impl Rig {
    /// A gateway started on `text` with the default history bounds.
    pub(super) async fn start(text: &str, audit: Audit) -> Self {
        Self::start_bounded(text, audit, Bounds::default()).await
    }

    pub(super) async fn start_bounded(text: &str, audit: Audit, bounds: Bounds) -> Self {
        let dir = crate::test_dir_keep::kept_tempdir();
        Self::start_in(dir, text, audit, bounds, History::Kept).await
    }

    /// A gateway started in `dir` (where a row may have written env files
    /// first), recording into a history store unless `history` is Absent.
    pub(super) async fn start_in(
        dir: Arc<tempfile::TempDir>,
        text: &str,
        audit: Audit,
        bounds: Bounds,
        history: History,
    ) -> Self {
        let config = dir.path().join(CONFIG_FILE);
        crate::gateway::test_helpers::write_owner_only(&config, text).expect("gateway.yaml");
        let mut loaded =
            crate::config::Config::load_evaluated(Some(&config)).expect("the start config loads");
        // As a serving gateway starts: one live env, whose startup inputs the
        // first version records and which every later reload re-reads.
        let env = Arc::new(loaded.live_env());
        let started = env.take_startup_inputs().expect("the startup inputs");
        let store = Arc::new(ConfigHistory::open(dir.path(), bounds, 1));
        let (mut state, fixtures) =
            crate::gateway::router::tests::audience_state(&loaded.config.auth, (None, None), |m| m)
                .await;
        let table = Arc::clone(state.live_config.generation().auth());
        let hook = HistoryHook {
            config_path: config.display().to_string(),
            store: Arc::clone(&store),
        };
        let live = LiveConfig::with_auth(loaded.config, table);
        let live = match history {
            History::Kept => live.with_history(hook),
            History::Absent => live,
        };
        let live = Arc::new(live.with_startup_revision(
            &crate::gateway::record_principal::test_record_key(),
            Some(started),
        ));
        let ctx = Arc::new(
            ReloadContext::new(
                config.clone(),
                Arc::clone(&live),
                Arc::clone(&state.backends),
                crate::config::FailsafeConfig::default(),
                Duration::from_secs(30),
            )
            .expect("a reload context")
            .with_env(Arc::clone(&env)),
        );
        let only = Arc::get_mut(&mut state).expect("the state is not shared yet");
        only.config_path = Some(config);
        only.live_config = live;
        if let Audit::Logged = audit {
            only.transparency_log = Some(audit_log(&dir));
        }
        state.meta_mcp.set_reload_context(Arc::clone(&ctx));
        Self {
            state,
            ctx,
            store,
            dir,
            _fixtures: fixtures,
        }
    }

    /// Where gateway.yaml lives.
    pub(super) fn path(&self) -> PathBuf {
        self.dir.path().join(CONFIG_FILE)
    }

    /// What gateway.yaml holds now.
    pub(super) fn bytes(&self) -> Vec<u8> {
        std::fs::read(self.path()).expect("gateway.yaml reads")
    }

    /// Rewrite gateway.yaml on disk, no reload.
    pub(super) fn write(&self, text: &str) {
        crate::gateway::test_helpers::write_owner_only(self.path(), text).expect("rewrite");
    }

    /// Rewrite gateway.yaml and apply it, as an edit the file watch picks up.
    pub(super) async fn reload_to(&self, text: &str) {
        self.write(text);
        self.ctx.reload_outcome().await.expect("the edit applies");
    }

    /// The newest kept version whose gateway.yaml holds `bytes`.
    pub(super) fn version_of(&self, bytes: &[u8]) -> String {
        let config = self.path().display().to_string();
        self.store
            .snapshots()
            .iter()
            .rev()
            .find(|kept| {
                kept.files
                    .iter()
                    .any(|file| file.path == config && file.bytes.as_deref() == Some(bytes))
            })
            .map(|kept| kept.revision.clone())
            .expect("a kept version holds those bytes")
    }

    /// The revision the gateway serves (what it published last).
    pub(super) fn served(&self) -> String {
        self.state
            .live_config
            .applied_now()
            .published
            .map(|applied| applied.revision.clone())
            .expect("the gateway publishes a revision")
    }

    /// The newest kept copy of `revision`.
    pub(super) fn kept(&self, revision: &str) -> crate::config_reload::history::Snapshot {
        self.store
            .snapshots()
            .into_iter()
            .rev()
            .find(|kept| kept.revision == revision)
            .expect("that revision is kept")
    }

    /// The env-file paths a kept version recorded, as the store holds them.
    pub(super) fn env_paths(&self, revision: &str) -> Vec<String> {
        let config = self.path().display().to_string();
        self.kept(revision)
            .files
            .iter()
            .map(|file| file.path.clone())
            .filter(|path| *path != config)
            .collect()
    }

    /// Every `gateway.yaml.<time>.rejected` beside the file.
    pub(super) fn rejected(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir(self.dir.path())
            .expect("the dir lists")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("gateway.yaml.") && name.ends_with(".rejected")
                    })
            })
            .collect();
        found.sort();
        found
    }

    /// The writer's steps on gateway.yaml since the last call, then cleared.
    pub(super) fn steps(&self) -> Vec<&'static str> {
        crate::config_reload::write_order::take(&crate::identity_grants::journal::resolved(
            &self.path(),
        ))
    }

    /// The audit log's lines (empty when the rig keeps none).
    pub(super) fn audit_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.path().join(AUDIT_FILE))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// One request through the router; the answer's status and JSON body.
    pub(super) async fn send(
        &self,
        method: &str,
        uri: &str,
        body: Option<&Value>,
        caller: Caller<'_>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_611))));
        match caller {
            Caller::Root => {
                request = request.header(header::AUTHORIZATION, format!("Bearer {ROOT}"));
            }
            Caller::Viewer => {
                request = request.header(header::AUTHORIZATION, format!("Bearer {VIEWER}"));
            }
            Caller::Cli => request = request.header(header::AUTHORIZATION, format!("Bearer {CLI}")),
            Caller::Session(cookie) => request = request.header(header::COOKIE, cookie),
            Caller::Nobody => {}
        }
        let request = match body {
            Some(json) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string())),
            None => request.body(Body::empty()),
        }
        .expect("a request");
        let response = crate::gateway::router::create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
            .await
            .expect("the body reads");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub(super) async fn history(&self, caller: Caller<'_>) -> (StatusCode, Value) {
        self.send("GET", routes::UI_CONFIG_HISTORY, None, caller)
            .await
    }

    pub(super) async fn restore(&self, version: &str, caller: Caller<'_>) -> (StatusCode, Value) {
        let body = serde_json::json!({ "version": version });
        self.send("POST", routes::UI_CONFIG_RESTORE, Some(&body), caller)
            .await
    }

    /// A browser session minted by the CLI key: its cookie pair.
    pub(super) async fn cli_session(&self) -> String {
        let link = self
            .send("POST", "/ui/api/dashboard-link", None, Caller::Cli)
            .await;
        assert_eq!(link.0, StatusCode::OK, "{}", link.1);
        let link = link.1["link"]
            .as_str()
            .expect("a dashboard link")
            .to_owned();
        let (_, code) = link
            .split_once("/dashboard?bootstrap=")
            .expect("a bootstrap code");
        let request = Request::builder()
            .uri(format!("/dashboard?bootstrap={code}"))
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_611))))
            .body(Body::empty())
            .expect("a request");
        let response = crate::gateway::router::create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response.headers()[header::SET_COOKIE]
            .to_str()
            .expect("a cookie")
            .split(';')
            .next()
            .expect("its pair")
            .to_owned()
    }
}

fn audit_log(dir: &Arc<tempfile::TempDir>) -> Arc<crate::security::TransparencyLogger> {
    use crate::security::transparency_log::TransparencyLogConfig;
    let config = TransparencyLogConfig {
        key_id: "config-history-rows".into(),
        path: dir.path().join(AUDIT_FILE).display().to_string(),
        enabled: true,
        ..TransparencyLogConfig::default()
    };
    let log = crate::security::TransparencyLogger::open(Arc::new(config)).expect("the audit log");
    log.keep_test_dir(Arc::clone(dir));
    Arc::new(log)
}
