// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the Gateway page reads as "a restart is pending": one read of the
//! published snapshot. With a revision published it is the stored set, the
//! config fields plus one environment marker; without one it is the config
//! comparison alone. A variable's name never appears.

use super::*;
use crate::config_reload::ENV_RESTART;
use crate::config_reload::history::Source;
use crate::config_reload::revision::{CapabilityPart, RawInputs};

const SECRET: &str = "GW_PENDING_READ_SECRET";

fn revision_key() -> [u8; 32] {
    crate::gateway::record_principal::test_record_key().config_revision_key()
}

/// A process started on `config`, with a revision published.
fn keyed(config: Config) -> LiveConfig {
    LiveConfig::new(config)
        .with_revision_key(revision_key())
        .with_applied(RawInputs::default())
}

/// `config` prepared against `live`, as a reload publishes it.
fn prepared(live: &LiveConfig, config: Config) -> Arc<Generation> {
    // invariant: these fixtures only edit sections that always prepare.
    Arc::new(
        live.prepare(config, &crate::config::EnvOverlay::none())
            .expect("the config prepares"),
    )
}

/// A file asking for something only a restart applies.
fn budget_edit() -> Config {
    let mut config = Config::default();
    config.error_budget.threshold = Some(0.25);
    config
}

/// A reload publishing `config`, with `env` the startup values it changed.
fn reload(live: &LiveConfig, config: Config, env: &[&str]) {
    let env: Vec<String> = env.iter().map(ToString::to_string).collect();
    live.set_applied(
        prepared(live, config),
        RawInputs::default(),
        &env,
        Source::File,
    );
}

/// A reload that found the config file unchanged.
fn reload_unchanged(live: &LiveConfig, env: &[&str]) {
    let env: Vec<String> = env.iter().map(ToString::to_string).collect();
    live.set_inputs(RawInputs::default(), &env);
}

/// P1. Nothing waits: the read is empty.
#[test]
fn nothing_pending_reads_empty() {
    assert!(keyed(Config::default()).pending_restart().is_empty());
}

/// P2, P3. A restart-only edit is listed, and a later reload that changes
/// nothing keeps it.
#[test]
fn a_restart_only_edit_stays_listed_through_a_no_change_reload() {
    let live = keyed(Config::default());
    reload(&live, budget_edit(), &[]);
    assert_eq!(live.pending_restart(), vec!["error_budget"]);
    reload_unchanged(&live, &[]);
    assert_eq!(live.pending_restart(), vec!["error_budget"]);
}

/// P4. A changed startup value is listed as the marker, never by its name.
#[test]
fn a_changed_startup_value_is_listed_by_marker_never_by_name() {
    let live = keyed(Config::default());
    reload_unchanged(&live, &[SECRET]);
    let pending = live.pending_restart();
    assert_eq!(pending, vec![ENV_RESTART]);
    assert!(!pending.contains(&SECRET), "{pending:?}");
}

/// P5. A file put back to what runs clears the read.
#[test]
fn a_file_put_back_to_what_runs_clears_it() {
    let live = keyed(Config::default());
    reload(&live, budget_edit(), &[]);
    assert_eq!(live.pending_restart(), vec!["error_budget"], "fixture");
    reload(&live, Config::default(), &[]);
    assert!(
        live.pending_restart().is_empty(),
        "{:?}",
        live.pending_restart()
    );
}

/// P6. A `~` entry whose env file assigns HOME, nothing changed on disk since
/// startup: the reload still reports HOME (the conservative rule), so the
/// marker outlives values that are already back where they started, and the
/// badge waits for a restart.
#[tokio::test]
async fn the_marker_outlives_values_already_back_at_startup() {
    let start = super::env_files::tilde_home_start();
    start.home.finish_startup();
    let live = Arc::new(keyed(start.startup.config.clone()));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let env = crate::config::LiveEnv::new(
        start.startup.overlay.clone(),
        start.startup.env_paths.clone(),
    );
    let ctx = ReloadContext::new(
        start.cfg.clone(),
        Arc::clone(&live),
        registry,
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the reload context builds")
    .with_env(Arc::new(env));

    let outcome = ctx.reload_outcome().await.expect("the reload applies");
    assert!(
        outcome.pending_restart_fields.iter().any(|f| f == "HOME"),
        "fixture: the rule reports HOME beside a `~` entry: {outcome:?}"
    );
    assert_eq!(live.pending_restart(), vec![ENV_RESTART]);
}

/// P8. With no revision published, the config fields are read and no marker
/// appears, whatever the reload passed.
#[test]
fn without_a_published_revision_the_config_fields_are_read() {
    let live = LiveConfig::new(Config::default());
    reload(&live, budget_edit(), &[SECRET]);
    assert_eq!(live.pending_restart(), vec!["error_budget"]);
}

/// P10. A config edit and a changed startup value pending together: each
/// survives the other's reloads and the capability and grants publishes, and
/// the marker leaves only when the value is put back.
#[test]
fn mixed_sources_each_leave_only_with_their_own_cause() {
    let live = keyed(Config::default());
    let both = vec!["error_budget", ENV_RESTART];

    reload(&live, budget_edit(), &[]);
    assert_eq!(live.pending_restart(), vec!["error_budget"], "config edit");
    reload_unchanged(&live, &[SECRET]);
    assert_eq!(live.pending_restart(), both, "then a changed startup value");

    let mut live_field_only = budget_edit();
    live_field_only.server.public_url = Some("https://gw.example.test".to_owned());
    reload(&live, live_field_only, &[SECRET]);
    assert_eq!(live.pending_restart(), both, "a config-changing reload");
    reload_unchanged(&live, &[SECRET]);
    assert_eq!(live.pending_restart(), both, "a no-change reload");

    live.set_capabilities(
        1,
        CapabilityPart::Loaded(vec![("caps/p10.yaml".to_owned(), [0x10; 32])]),
    );
    assert_eq!(live.pending_restart(), both, "a capability publish");
    live.set_grants(Some(b"[]\n"));
    assert_eq!(live.pending_restart(), both, "a grants publish");

    reload_unchanged(&live, &[]);
    assert_eq!(
        live.pending_restart(),
        vec!["error_budget"],
        "the value put back"
    );
}

/// P11. A restart boots what was published: the new process reads empty.
#[test]
fn a_restart_clears_it() {
    let before = keyed(Config::default());
    reload(&before, budget_edit(), &[SECRET]);
    assert_eq!(
        before.pending_restart(),
        vec!["error_budget", ENV_RESTART],
        "fixture"
    );
    let restarted = keyed((*before.get()).clone());
    // The new process runs the edited config, not the one it started from.
    assert_eq!(restarted.running().error_budget.threshold, Some(0.25));
    assert!(
        restarted.pending_restart().is_empty(),
        "{:?}",
        restarted.pending_restart()
    );
}
