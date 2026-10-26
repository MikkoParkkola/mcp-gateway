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
    let edits: Vec<(&str, Box<dyn Fn(&mut Config)>)> = vec![
        (
            "trust_configured_backends",
            Box::new(|c| {
                c.security.trust_configured_backends = !c.security.trust_configured_backends
            }),
        ),
        (
            "provenance_stamping",
            Box::new(|c| c.security.provenance_stamping = !c.security.provenance_stamping),
        ),
        (
            "collusion.sources",
            Box::new(|c| {
                c.security
                    .firewall
                    .collusion
                    .sources
                    .push("mail".to_string())
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
        // A duration reads " 1ms" as one more millisecond; any other string
        // stays a string. An enum refuses it, and the load names the key.
        Value::String(text) => {
            text.push_str(" 1ms");
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
    let by_hand: &[(&str, fn(&mut Value))] = &[
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
    for (section, skip) in [
        ("server", &["host", "port", "public_url"][..]),
        ("events", &[][..]),
    ] {
        let (reports, stuck) = each_field_alone(section, skip);
        let missed: Vec<&str> = reports
            .iter()
            .filter(|(_, p, _)| p.is_empty())
            .map(|(k, _, _)| k.as_str())
            .collect();
        assert!(
            missed.is_empty(),
            "{section}: not restart-pending: {missed:?}"
        );
        let unseen: Vec<&str> = reports
            .iter()
            .filter(|(_, _, changed)| !changed)
            .map(|(k, _, _)| k.as_str())
            .collect();
        assert!(unseen.is_empty(), "{section}: not a change: {unseen:?}");
        assert!(stuck.is_empty(), "{section}: no generic edit: {stuck:?}");
    }
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
