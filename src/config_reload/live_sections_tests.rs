// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart classification for the settings that apply on reload (ADR-023).
//!
//! A reload compares the file with the running process and names each section
//! that will only take effect after a restart. A setting that now applies on
//! reload must leave that report, and every other setting in its section must
//! stay in it, alone or in a combined edit.

use serde_json::{Value, json};

use super::{LiveConfig, compute_diff};
use crate::config::Config;

/// One named change to a config.
type Edit = Box<dyn Fn(&mut Config)>;
/// One named change to a field's serialized value.
type ValueEdit = fn(&mut Value);

/// The restart-pending sections after publishing `wanted` over `running`.
fn pending(running: &Config, wanted: Config) -> Vec<&'static str> {
    let live = LiveConfig::new(running.clone());
    live.set(wanted);
    live.pending_restart_fields()
}

// R1: the two security flags apply on reload, so an edit to only them is not
// restart-pending.
#[test]
fn r1_a_security_flag_only_edit_is_not_restart_pending() {
    let running = Config::default();
    let mut sanitize = running.clone();
    sanitize.security.sanitize_input = !running.security.sanitize_input;
    assert_eq!(
        pending(&running, sanitize),
        Vec::<&str>::new(),
        "sanitize_input"
    );

    let mut ssrf = running.clone();
    ssrf.security.ssrf_protection = !running.security.ssrf_protection;
    assert_eq!(
        pending(&running, ssrf),
        Vec::<&str>::new(),
        "ssrf_protection"
    );
}

// R2: every other security field stays restart-pending, including the
// collusion lists, which stay restart-only until their evidence is judged
// against the current rules.
#[test]
fn r2_any_other_security_field_stays_restart_pending() {
    let running = Config::default();
    let edits: Vec<(&str, Edit)> = vec![
        (
            "trust_configured_backends",
            Box::new(|c| {
                c.security.trust_configured_backends = !c.security.trust_configured_backends;
            }),
        ),
        (
            "provenance_stamping",
            Box::new(|c| c.security.provenance_stamping = !c.security.provenance_stamping),
        ),
        #[cfg(feature = "firewall")]
        (
            "collusion.sources",
            Box::new(|c| {
                c.security
                    .firewall
                    .collusion
                    .sources
                    .push("mail".to_string());
            }),
        ),
    ];
    for (name, edit) in edits {
        let mut wanted = running.clone();
        edit(&mut wanted);
        assert!(
            pending(&running, wanted).contains(&"security"),
            "a change to security.{name} must stay restart-pending"
        );
    }
}

// R3: a hot flag edited together with a restart-only security field still
// leaves the section pending.
#[test]
fn r3_a_combined_security_edit_stays_restart_pending() {
    let running = Config::default();
    let mut wanted = running.clone();
    wanted.security.sanitize_input = !running.security.sanitize_input;
    wanted.security.trust_configured_backends = !running.security.trust_configured_backends;
    assert!(pending(&running, wanted).contains(&"security"));
}

// R4: the existing dashboard_session exclusion, pinned. A change to only it is
// not pending; a change to another auth field is.
#[test]
fn r4_dashboard_session_alone_is_not_pending_and_other_auth_is() {
    let running = Config::default();
    let mut session = running.clone();
    session.auth.dashboard_session.idle_timeout_secs =
        running.auth.dashboard_session.idle_timeout_secs + 1;
    assert_eq!(pending(&running, session), Vec::<&str>::new());

    let mut enabled = running.clone();
    enabled.auth.enabled = !running.auth.enabled;
    assert!(pending(&running, enabled).contains(&"auth"));
}

// R5: the idempotency section is captured at startup, so an edit to it alone
// must be reported as needing a restart. Today it is in no tracked section.
#[test]
fn r5_an_idempotency_only_edit_is_restart_pending() {
    let running = Config::default();
    let mut wanted = running.clone();
    wanted
        .idempotency
        .read_only_tools
        .push(crate::config::IdempotencyReadOnlyTool {
            server: "files".to_string(),
            tool: "read".to_string(),
        });
    assert!(
        pending(&running, wanted).contains(&"idempotency"),
        "the idempotency section is read once at startup"
    );
}

/// Change the first bool, number, string or empty list found in `v`, depth
/// first. `false` when
/// nothing in it can be changed without knowing the field's meaning.
fn perturb(v: &mut Value) -> bool {
    match v {
        Value::Bool(b) => {
            *b = !*b;
            true
        }
        Value::Number(n) => {
            let next = match (n.as_u64(), n.as_f64()) {
                (Some(u), _) => json!(u + 1),
                (None, Some(f)) => json!(f + 1.0),
                _ => return false,
            };
            *v = next;
            true
        }
        // A duration (`30s`) gets one more of its unit; any other string gets
        // a suffix. An enum refuses it, and the load names the key.
        Value::String(text) => {
            let digits = text.chars().take_while(char::is_ascii_digit).count();
            *text = match text[..digits].parse::<u64>() {
                Ok(n) => format!("{}{}", n + 1, &text[digits..]),
                Err(_) => format!("{text}-edited"),
            };
            true
        }
        Value::Array(items) if items.is_empty() => {
            items.push(json!("10.0.0.1"));
            true
        }
        Value::Object(m) => m.values_mut().any(perturb),
        _ => false,
    }
}

/// One field changed alone: its name, the pending report, and whether the
/// reload saw a change at all.
type Report = (String, Vec<&'static str>, bool);

/// Every key of `section` except `skip`, each changed alone through the
/// serialized config. Returns the pending report per key, and the keys that
/// could not be changed generically, so a new field cannot slip past.
fn each_field_alone(section: &str, skip: &[&str]) -> (Vec<Report>, Vec<String>) {
    // Fields with no bool or number inside: one hand-picked valid edit each.
    let by_hand: &[(&str, ValueEdit)] = &[
        ("posture", |v| *v = json!("hardened")),
        ("hardened", |v| v["private_backends"] = json!(["10.0.0.1"])),
        ("caller_identity", |v| v["authority"] = json!("edited")),
        ("signature_chain", |v| {
            *v = json!({"signing_key": "env:CHAIN_SEED", "key_id": "k1"});
        }),
        ("idempotency_key", |v| *v = json!("required")),
        ("shutdown_timeout", |v| *v = json!("31s")),
    ];
    let running = Config::default();
    let base = serde_json::to_value(&running).expect("config serializes");
    let keys: Vec<String> = base[section]
        .as_object()
        .expect("section is an object")
        .keys()
        .filter(|k| !skip.contains(&k.as_str()))
        .cloned()
        .collect();
    let (mut reports, mut stuck) = (Vec::new(), Vec::new());
    for key in keys {
        let mut v = base.clone();
        let field = &mut v[section][&key];
        let edited = match by_hand.iter().find(|(name, _)| *name == key) {
            Some((_, edit)) => {
                edit(field);
                true
            }
            None => perturb(field),
        };
        if !edited {
            stuck.push(key);
            continue;
        }
        let wanted: Config = serde_json::from_value(v)
            .unwrap_or_else(|e| panic!("{section}.{key} changed is not a valid config: {e}"));
        let changed = !compute_diff(&running, &wanted).is_empty();
        reports.push((key, pending(&running, wanted), changed));
    }
    (reports, stuck)
}

// R2 (every field): each security field other than the two hot flags,
// changed alone, keeps the section restart-pending.
#[test]
fn r2_each_other_security_field_alone_stays_restart_pending() {
    let (reports, stuck) = each_field_alone("security", &["sanitize_input", "ssrf_protection"]);
    let missed: Vec<&str> = reports
        .iter()
        .filter(|(_, p, _)| !p.contains(&"security"))
        .map(|(k, _, _)| k.as_str())
        .collect();
    assert!(missed.is_empty(), "not restart-pending: {missed:?}");
    assert!(
        stuck.is_empty(),
        "no generic edit, add one to R2: {stuck:?}"
    );
}

// R5 (every field): each server field beyond host, port and public_url, and
// each events field, changed alone, is reported as a change and as
// restart-pending.
#[test]
fn r5_each_server_and_events_field_alone_is_restart_pending() {
    let mut failures = Vec::new();
    for (section, skip) in [
        ("server", &["host", "port", "public_url"][..]),
        ("events", &[][..]),
    ] {
        let (reports, stuck) = each_field_alone(section, skip);
        for (key, pending, changed) in &reports {
            if !pending.contains(&section) {
                failures.push(format!(
                    "{section}.{key}: pending {pending:?}, not {section}"
                ));
            }
            if !changed {
                failures.push(format!("{section}.{key}: not a change"));
            }
        }
        failures.extend(
            stuck
                .iter()
                .map(|k| format!("{section}.{k}: no generic edit")),
        );
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// `running` with `environment` set through JSON, so the row compiles before
/// the key exists.
fn with_environment(running: &Config, name: &str) -> Config {
    let mut v = serde_json::to_value(running).expect("config serializes");
    v["environment"] = json!(name);
    serde_json::from_value(v).expect("still a config")
}

// E2: an environment-only edit is a change that applied, not restart-pending.
#[test]
fn e2_an_environment_only_edit_applies_without_a_restart() {
    let running = Config::default();
    let wanted = with_environment(&running, "staging");
    assert!(
        !compute_diff(&running, &wanted).is_empty(),
        "the edit is reported as a change"
    );
    assert_eq!(pending(&running, wanted), Vec::<&str>::new());
}

// E3: a misspelt key still fails the strict load and names the key path.
#[test]
fn e3_a_misspelt_environment_key_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "environmnt: staging\n").expect("write");
    let err = Config::load(Some(&path)).expect_err("typo refuses");
    assert!(format!("{err:#}").contains("environmnt"), "{err:#}");
}

// E4: the key loads through the strict loader from a file, not only through
// serde, so an operator's `environment:` is accepted and read back.
#[test]
fn e4_an_environment_key_in_a_file_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, "environment: staging\n").expect("write");
    let loaded = Config::load(Some(&path)).expect("loads");
    let v = serde_json::to_value(&loaded).expect("serializes");
    assert_eq!(v["environment"], json!("staging"), "{v}");
}

// G6 and G5: the generation is prepared before `apply_patch`. A reload whose
// preparation refuses starts no backend and publishes nothing; the same file
// reloaded with nothing refusing publishes exactly once.
#[tokio::test]
async fn g6_a_refused_preparation_changes_nothing_and_g5_one_publish() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        "backends:\n  added:\n    http_url: \"http://127.0.0.1:9/mcp\"\n",
    )
    .expect("write");
    let registry = std::sync::Arc::new(crate::backend::BackendRegistry::new());
    let live = std::sync::Arc::new(LiveConfig::new(Config::default()));
    let ctx = super::ReloadContext::new(
        path,
        std::sync::Arc::clone(&live),
        std::sync::Arc::clone(&registry),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    let before = live.generation();

    let fired = super::generation::refuse_hook::arm("g6 refusal");
    let err = ctx
        .reload_outcome()
        .await
        .expect_err("the preparation refused");
    assert!(
        fired.load(Ordering::SeqCst),
        "the refusal hook never ran: preparation moved off this thread"
    );
    assert!(err.contains("g6 refusal"), "{err}");
    assert!(registry.get("added").is_none(), "a backend started");
    assert!(
        std::sync::Arc::ptr_eq(&before, &live.generation()),
        "published"
    );
    assert_eq!(live.seq(), 0, "a refused reload published");

    ctx.reload_outcome().await.expect("the same file applies");
    assert!(registry.get("added").is_some(), "the backend was not added");
    assert_eq!(live.seq(), 1, "one reload, one publication");
}

// G7: the meta-tool's reload context and the file watcher publish through
// the same holder, so either one changes what the next request takes. The
// meta-tool path runs first, before any watcher can race it.
#[tokio::test]
async fn g7_the_meta_tool_and_the_watcher_both_publish_the_flag() {
    use std::sync::Arc;
    use std::time::Duration;
    let write = |path: &std::path::Path, text: &str| {
        crate::gateway::test_helpers::write_owner_only(path, text)
    };
    let flag = |on: bool| format!("security:\n  sanitize_input: {on}\n");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write(&path, &flag(true)).expect("write");
    let initial = Config::load(Some(&path)).expect("loads");
    let live = Arc::new(LiveConfig::new(initial.clone()));
    let registry = Arc::new(crate::backend::BackendRegistry::new());

    let meta_tool = super::ReloadContext::new(
        path.clone(),
        Arc::clone(&live),
        Arc::clone(&registry),
        crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    write(&path, &flag(false)).expect("write");
    meta_tool
        .reload_outcome()
        .await
        .expect("the meta-tool reload applies");
    assert!(
        !live.generation().sanitize_input(),
        "meta-tool: not published"
    );

    let (_shutdown, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let _watcher = super::ConfigWatcher::start_with_hook(
        path.clone(),
        Arc::clone(&live),
        registry,
        &initial,
        Arc::new(crate::config::LiveEnv::new(
            Arc::new(crate::config::EnvOverlay::none()),
            crate::config::ResolvedEnvFiles::default(),
        )),
        None,
        None,
        shutdown_rx,
        None,
        None,
        super::refusals::ReloadReporting::default(),
    )
    .expect("the watcher starts");
    write(&path, &flag(true)).expect("write");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !live.generation().sanitize_input() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "watcher: the edit was never published"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// F7: a reload of a file that does not parse is refused, and the running
// generation, the flag it carries included, stays published.
#[tokio::test]
async fn f7_a_malformed_file_leaves_the_running_generation() {
    use std::sync::Arc;
    let write = |path: &std::path::Path, text: &str| {
        crate::gateway::test_helpers::write_owner_only(path, text)
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write(&path, "security:\n  sanitize_input: true\n").expect("write");
    let live = Arc::new(LiveConfig::new(Config::load(Some(&path)).expect("loads")));
    let ctx = super::ReloadContext::new(
        path.clone(),
        Arc::clone(&live),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    let before = live.generation();

    write(&path, "security:\n  sanitize_input: false\n  : [unclosed\n").expect("write");
    ctx.reload_outcome()
        .await
        .expect_err("a malformed file is refused");
    assert!(Arc::ptr_eq(&before, &live.generation()), "published");
    assert!(live.generation().sanitize_input(), "the flag changed");
    assert_eq!(live.seq(), 0, "a refused reload published");
}

/// ADR-029 (amended): each generation compiles its own firewall policy from
/// its own config, so a reload's policy is not the running one's.
#[cfg(feature = "firewall")]
#[test]
fn each_generation_compiles_its_own_firewall_policy() {
    let running = super::Generation::of(Config::default());
    let mut config = Config::default();
    config.security.firewall.credential_redaction = false;
    let wanted = super::Generation::of(config);
    assert!(running.firewall_policy().redacts(), "the default redacts");
    assert!(
        !wanted.firewall_policy().redacts(),
        "the reload's own switch"
    );
}

/// ADR-029 (amended): a reload whose detector settings differ from the running
/// detector keeps the previous generation's collusion view, never the
/// startup's, so a pending parameter edit cannot drop a live `block`.
#[cfg(feature = "firewall")]
#[test]
fn a_held_collusion_edit_keeps_the_previous_view_not_the_startup_one() {
    use crate::security::firewall::CollusionAction;
    let startup = super::Generation::of(Config::default());
    assert_eq!(startup.collusion_view().action(), CollusionAction::Off);
    let mut block = Config::default();
    block.security.firewall.collusion.action = CollusionAction::Block;
    let live = super::Generation::after(block, &startup);
    assert_eq!(
        live.collusion_view().action(),
        CollusionAction::Block,
        "premise: the running detector runs it, so it applies"
    );
    let mut held = Config::default();
    held.security.firewall.collusion.action = CollusionAction::Observe;
    held.security.firewall.collusion.window_secs += 1;
    let next = super::Generation::after(held, &live);
    assert_eq!(
        next.collusion_view().action(),
        CollusionAction::Block,
        "a held edit keeps the previous view"
    );
}

/// Until the relay gate judges with the generation's view (ADR-029's PR2), a
/// collusion edit reports a restart: the line never claims a live change the
/// gate does not apply.
#[cfg(feature = "firewall")]
#[test]
fn a_collusion_edit_reports_a_restart_until_the_relay_gate_reads_it_live() {
    let running = Config::default();
    let mut wanted = running.clone();
    wanted.security.firewall.collusion.action = crate::security::firewall::CollusionAction::Block;
    assert!(pending(&running, wanted).contains(&"security"));
}
