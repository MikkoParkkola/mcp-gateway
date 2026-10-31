// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reload refusals for the API key table (ADR-023, amended): a key list that
//! would flip multi-user status, or collide with the running bearer, is
//! refused whole, and the running table keeps working.

use std::sync::Arc;

use crate::config::Config;
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::test_helpers::write_owner_only;

const A: &str = "reload-keys-a-secret";
const B: &str = "reload-keys-b-secret";

/// One key entry in YAML.
fn key_yaml(secret: &str, admin: bool) -> String {
    format!(
        "    - name: {secret}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n      admin: {admin}\n",
        crate::config::api_key_digest_spec(secret.as_bytes())
    )
}

/// An `auth` section: `head` holds the settings, then `keys`.
fn auth_yaml(head: &str, keys: &[(&str, bool)]) -> String {
    let mut text = format!("auth:\n  enabled: true\n{head}  api_keys:\n");
    for (secret, admin) in keys {
        text.push_str(&key_yaml(secret, *admin));
    }
    text
}

/// A gateway running `text`, with a reload context over its file.
struct Running {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    live: Arc<LiveConfig>,
    ctx: ReloadContext,
}

impl Running {
    fn start(text: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, text).expect("write");
        let config = Config::load(Some(&path)).expect("the running config loads");
        let auth = ResolvedAuthConfig::from_config(
            &config.auth,
            crate::gateway::record_principal::TEST_RECORD_KEY,
        );
        let live = Arc::new(LiveConfig::with_auth(config, Arc::new(auth)));
        let ctx = ReloadContext::new(
            path.clone(),
            Arc::clone(&live),
            Arc::new(crate::backend::BackendRegistry::new()),
            crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        )
        .expect("the registry pairs with the config");
        Self {
            _dir: dir,
            path,
            live,
            ctx,
        }
    }

    async fn reload(&self, text: &str) -> Result<(), String> {
        write_owner_only(&self.path, text).expect("write");
        self.ctx.reload_outcome().await.map(|_| ())
    }

    fn accepts(&self, secret: &str) -> bool {
        self.live
            .generation()
            .auth()
            .validate_token(secret)
            .is_some()
    }

    fn is_admin(&self, secret: &str) -> bool {
        self.live
            .generation()
            .auth()
            .validate_token(secret)
            .is_some_and(|client| client.admin)
    }
}

/// A refusal names the key table and leaves the published generation as it
/// was.
fn assert_refused(err: &str, before: &Arc<crate::config_reload::Generation>, gw: &Running) {
    assert!(err.contains("auth.api_keys"), "{err}");
    assert!(
        Arc::ptr_eq(before, &gw.live.generation()),
        "a refused key edit published"
    );
}

/// K8 (i): a running single-user gateway with one key; adding a second key
/// would make it multi-user, so the edit is refused and the old key works.
#[tokio::test]
async fn k8_adding_a_key_that_makes_the_gateway_multi_user_is_refused() {
    let gw = Running::start(&auth_yaml("  single_user: true\n", &[(A, false)]));
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml(
            "  single_user: true\n",
            &[(A, false), (B, false)],
        ))
        .await
        .expect_err("a flip to multi-user is refused");
    assert!(
        err.contains("multi-user") && err.contains("restart"),
        "{err}"
    );
    assert_refused(&err, &before, &gw);
    assert!(gw.accepts(A), "the running key stopped working");
    assert!(!gw.accepts(B), "the refused key was published");
}

/// K8 (ii): single-user asserted with two keys is multi-user by count;
/// removing one would flip it back, so that is refused too. Control: with
/// `single_user: false` the gateway is multi-user at any count, and the
/// same removal publishes.
#[tokio::test]
async fn k8_removing_a_key_that_makes_the_gateway_single_user_is_refused() {
    let gw = Running::start(&auth_yaml(
        "  single_user: true\n",
        &[(A, false), (B, false)],
    ));
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml("  single_user: true\n", &[(A, false)]))
        .await
        .expect_err("a flip to single-user is refused");
    assert!(
        err.contains("single-user") && err.contains("restart"),
        "{err}"
    );
    assert_refused(&err, &before, &gw);
    assert!(
        gw.accepts(B),
        "the key the refused edit removed stopped working"
    );

    let control = Running::start(&auth_yaml(
        "  single_user: false\n",
        &[(A, false), (B, false)],
    ));
    control
        .reload(&auth_yaml("  single_user: false\n", &[(A, false)]))
        .await
        .expect("multi-user at any count: the removal publishes");
    assert!(!control.accepts(B), "the removed key still works");
}

/// K8 (iii): a flip combined with promoting an existing key to admin
/// publishes neither.
#[tokio::test]
async fn k8_a_flip_with_a_promotion_publishes_neither() {
    let gw = Running::start(&auth_yaml("  single_user: true\n", &[(A, false)]));
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml(
            "  single_user: true\n",
            &[(A, true), (B, false)],
        ))
        .await
        .expect_err("refused whole");
    assert_refused(&err, &before, &gw);
    assert!(!gw.is_admin(A), "the promotion was published");
}

/// K8 (iv): the edited `single_user` differs from the running one; the
/// running one decides, both ways.
#[tokio::test]
async fn k8_the_running_settings_judge_the_flip() {
    // Running multi-user (`single_user: false`); the edit asserts single-user
    // and drops to one key. Judged on the running setting: no flip.
    let gw = Running::start(&auth_yaml(
        "  single_user: false\n",
        &[(A, false), (B, false)],
    ));
    gw.reload(&auth_yaml("  single_user: true\n", &[(A, false)]))
        .await
        .expect("the running setting is multi-user either way: it publishes");
    assert!(!gw.accepts(B), "the removed key still works");

    // Running single-user with one key; the edit says multi-user and adds a
    // key. Judged on the running setting: a flip, refused.
    let gw = Running::start(&auth_yaml("  single_user: true\n", &[(A, false)]));
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml(
            "  single_user: false\n",
            &[(A, false), (B, false)],
        ))
        .await
        .expect_err("the running single-user setting decides");
    assert_refused(&err, &before, &gw);
}

/// K9: a key-table refusal applies nothing else in the same edit: the backend
/// it adds never starts, the env overlay stays, and the shared per-client
/// store keeps the usage a client already spent.
#[tokio::test]
async fn k9_a_key_refusal_applies_nothing_in_the_same_edit() {
    let gw = Running::start(&auth_yaml("  single_user: true\n", &[(A, false)]).replace(
        "      admin: false\n",
        "      admin: false\n      rate_limit: 1\n",
    ));
    let env = Arc::new(crate::config::LiveEnv::new(
        Arc::new(crate::config::EnvOverlay::none()),
        crate::config::ResolvedEnvFiles::default(),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let ctx = ReloadContext::new(
        gw.path.clone(),
        Arc::clone(&gw.live),
        Arc::clone(&registry),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
    .with_env(Arc::clone(&env));
    let overlay = env.get();
    let auth = Arc::clone(gw.live.generation().auth());
    let client = auth.validate_token(A).expect("A authenticates");
    assert!(
        auth.check_authenticated_client_rate_limit(&client),
        "first call"
    );
    assert!(
        !auth.check_authenticated_client_rate_limit(&client),
        "premise: spent"
    );
    let before = gw.live.generation();

    let dir = gw.path.parent().expect("a directory");
    write_owner_only(dir.join("k9.env"), "K9_VALUE=changed\n").expect("write env");
    let edit = format!(
        "env_files:\n  - {}\nbackends:\n  added:\n    http_url: \"http://127.0.0.1:9/mcp\"\n{}",
        dir.join("k9.env").display(),
        auth_yaml("  single_user: true\n", &[(A, false), (B, false)])
    );
    write_owner_only(&gw.path, edit).expect("write");
    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the flip refuses the edit");
    assert_refused(&err, &before, &gw);
    assert!(registry.get("added").is_none(), "a backend started");
    assert!(
        Arc::ptr_eq(&overlay, &env.get()),
        "the env overlay was published"
    );
    let now = Arc::clone(gw.live.generation().auth());
    let client = now.validate_token(A).expect("A still authenticates");
    assert!(
        !now.check_authenticated_client_rate_limit(&client),
        "a refused reload gave the client a fresh window"
    );
}

/// K10: with `bearer_token: auto`, a reloaded key whose digest is the
/// generated bearer's is refused.
#[tokio::test]
async fn k10_a_key_equal_to_the_generated_bearer_is_refused() {
    let gw = Running::start(&auth_yaml("  bearer_token: auto\n", &[(A, false)]));
    let bearer = gw
        .live
        .generation()
        .auth()
        .bearer_token
        .clone()
        .expect("auto generated a bearer");
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml(
            "  bearer_token: auto\n",
            &[(A, false), (&bearer, false)],
        ))
        .await
        .expect_err("a key sharing the running bearer is refused");
    assert_refused(&err, &before, &gw);
}

/// K10: the edited bearer differs from the running one; the RUNNING bearer
/// decides the collision.
/// (A key equal to the edited bearer never reaches this check: the edit is
/// refused at load, as at startup.)
#[tokio::test]
async fn k10_the_running_bearer_decides_a_collision() {
    let gw = Running::start(&auth_yaml(
        "  bearer_token: running-bearer-secret\n",
        &[(A, false)],
    ));
    let before = gw.live.generation();
    let err = gw
        .reload(&auth_yaml(
            "  bearer_token: edited-bearer-secret\n",
            &[(A, false), ("running-bearer-secret", false)],
        ))
        .await
        .expect_err("collides with the running bearer");
    assert_refused(&err, &before, &gw);
}
